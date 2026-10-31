"""``aqt egress report``, ``prune`` and ``status``, and the command line."""

import json
import os
import time
from datetime import UTC, datetime

from aqt_evidence import JsonlSink, actor, new_record, read_jsonl
from aqt_evidence.schemas import validate_payload

from aqt_egress import cli
from aqt_egress.report import build, parse_since, render
from aqt_egress.settings import egress_state
from aqt_egress.store import BodyStore

SERVICE = actor("service", "service:aqt-egress")


def rec(type_, action, data, when):
    record = new_record(type_, SERVICE, action, data=data)
    record["time"] = when
    return record


def request(session, host, port, when, *, comm="curl", method="GET", up=10, down=100, status=200, **extra):
    return rec("egress.request", "observed", {
        "session": session, "mode": "observe", "decision": "allowed", "method": method,
        "destination": {"host": host, "port": port, "via": "proxy"},
        "process": {"chain": [{"pid": 5, "comm": comm}, {"pid": 2, "comm": "sh"}], "chain_status": "complete"},
        "request": {"bytes": up}, "response": {"bytes": down, "status": status}, **extra}, when)


def sample():
    return [
        rec("egress.session", "started", {"session": "egs_a", "command": ["agent"], "store": "excerpt",
                                          "project": {"path": "/p"}}, "2026-10-30T10:00:00.000000Z"),
        request("egs_a", "api.example", 443, "2026-10-30T10:00:01.000000Z"),
        rec("egress.session", "ended", {"session": "egs_a", "exit_code": 0}, "2026-10-30T10:05:00.000000Z"),
        rec("egress.session", "started", {"session": "egs_b", "command": ["agent", "--x"], "store": "full"},
            "2026-10-31T10:00:00.000000Z"),
        request("egs_b", "api.example", 443, "2026-10-31T10:00:01.000000Z", method="POST", up=500),
        request("egs_b", "api.example", 443, "2026-10-31T10:00:02.000000Z", comm="node"),
        request("egs_b", "collector.example", 443, "2026-10-31T10:00:03.000000Z", error="reset"),
        rec("egress.lookup", "observed", {"session": "egs_b", "name": "leak.example", "types": ["TXT"], "count": 3,
                                          "process": {"chain": [{"comm": "dig"}]}}, "2026-10-31T10:01:00.000000Z"),
    ]


def test_report_groups_sessions_destinations_processes():
    report = build(sample())
    first, second = report["sessions"]
    assert first["session"] == "egs_a" and first["exit_code"] == 0 and first["requests"] == 1
    assert first["destinations"][0]["new"] is True
    api, collector = second["destinations"]
    assert api["host"] == "api.example" and api["new"] is False and api["requests"] == 2
    assert api["methods"] == {"GET": 1, "POST": 1} and api["bytes_up"] == 510 and api["bytes_down"] == 200
    assert api["processes"] == {"curl < sh": 1, "node < sh": 1}
    assert collector["new"] is True and collector["errors"] == 1
    assert second["lookups"] == [{"name": "leak.example", "types": ["TXT"], "count": 3, "process": "dig"}]
    text = render(report)
    assert "collector.example:443" in text and "NEW" in text and "leak.example  TXT  3x  dig" in text
    assert "no end" not in text.split("session egs_a")[1].splitlines()[0]
    assert "-> no end" in text.split("session egs_b")[1].splitlines()[0]


def test_report_filters():
    assert [s["session"] for s in build(sample(), session="egs_b")["sessions"]] == ["egs_b"]
    assert [s["session"] for s in build(sample(), since="2026-10-31T00:00:00.000000Z")["sessions"]] == ["egs_b"]
    now = datetime(2026, 10, 31, 12, tzinfo=UTC)
    assert parse_since("1d", now=now) == "2026-10-30T12:00:00.000000Z"
    assert parse_since("2026-10-31", now=now).startswith("2026-10-31T00:00:00")


def test_report_cli_reads_evidence_files(env, tmp_path, capsys):
    path = tmp_path / "e.jsonl"
    sink = JsonlSink(path)
    for record in sample():
        sink.append(record)
    assert cli.main(["report", "--evidence", str(path), "--json"]) == 0
    assert len(json.loads(capsys.readouterr().out)["sessions"]) == 2
    assert cli.main(["report", "--evidence", str(path), "--since", "nonsense"]) == 2


def test_prune_command_records_what_it_removed(env, monkeypatch, capsys):
    sink = env / "records.jsonl"
    monkeypatch.setenv("AQT_SINK", f"file:{sink}")
    store = BodyStore(egress_state() / "bodies").ensure()
    old = store.put(b"old body")
    os.utime(store.path(old["sha256"]), (time.time() - 40 * 86400,) * 2)
    store.put(b"recent body")
    assert cli.main(["prune", "--retention-days", "30", "--dry-run"]) == 0
    assert "would remove 1" in capsys.readouterr().out and not sink.exists()
    assert cli.main(["prune", "--retention-days", "3"]) == 2            # below the 7-day minimum
    assert cli.main(["prune"]) == 0                                      # default 90 days: nothing to remove
    assert cli.main(["prune", "--retention-days", "30"]) == 0
    records = list(read_jsonl(sink))
    assert [r["data"]["removed"] for r in records] == [0, 1]
    assert records[1]["type"] == "egress.pruned" and records[1]["data"]["retention_days"] == 30
    assert validate_payload(records[1]) == [] and "cutoff" in records[1]["data"]
    assert len(list(store.objects())) == 1


def test_status_and_usage(env, capsys):
    value = cli.status()
    assert value["ca"] is False and value["last_session"] is None and "box_detail" in value
    assert cli.main(["run"]) == 2 and "no command" in capsys.readouterr().err
    assert cli.main(["nonsense"]) == 2


def test_x2_11_records_from_another_sender_are_unverified():
    records = sample()
    for record in records:
        record["observed"] = {"pid": 4242, "via": "socket"}
    forged = request("egs_b", "forged.example", 443, "2026-10-31T10:00:04.000000Z")
    forged["observed"] = {"pid": 777, "via": "socket"}           # sent from inside the box
    report = build(records + [forged])
    second = report["sessions"][1]
    assert [d["host"] for d in second["destinations"]] == ["api.example", "collector.example"]
    assert second["unverified"] == [{"id": forged["id"], "type": "egress.request", "sender_pid": 777}]
    assert "not from this session's proxy process" in render(report)
