import json

import pytest

from aqt_evidence import canonical_json, new_record, record_content_hash, sign_record, verify_chain

from aqt_trail.state import open_writer, read_records, service_keys
from aqt_trail.writer import LogBroken, Refused, WriterBusy

from conftest import agent, event, observed_stub


def test_append_sets_writer_fields(writer, config):
    record = event("demo.start", time="2020-01-01T00:00:00.000000Z")
    stored, created = writer.append(record, observed_stub())
    assert created
    assert stored["observed"]["client_time"] == "2020-01-01T00:00:00.000000Z"
    assert stored["time"] > "2026"
    assert stored["chain"] == {"seq": 0, "prev": "sha256:" + "0" * 64}
    assert record_content_hash(stored) == record_content_hash(record)
    assert verify_chain(read_records(config.trail_path), keys=service_keys(config), require_signature=True).ok


@pytest.mark.parametrize("field,value", [("chain", {"seq": 0, "prev": "sha256:" + "0" * 64}),
                                         ("observed", {"pid": 1})])
def test_writer_fields_are_refused_and_logged(writer, config, field, value):
    record = event()
    record[field] = value
    with pytest.raises(Refused) as caught:
        writer.append(record, observed_stub())
    assert caught.value.code == "invalid_record"
    refusal = read_records(config.trail_path)[-1]
    assert refusal["type"] == "trail.refused" and refusal["action"] == "refused"
    assert refusal["actor"]["id"] == "human:alice"
    assert refusal["data"]["reason_code"] == "invalid_record"
    assert refusal["data"]["attempted_id"] == record["id"]


def test_client_signature_is_refused(writer, signer_key):
    with pytest.raises(Refused):
        writer.append(sign_record(event(), signer_key), observed_stub())


@pytest.fixture
def signer_key(tmp_path):
    from aqt_evidence import generate_key, load_signer
    generate_key(tmp_path / "client.key")
    return load_signer(tmp_path / "client.key")


def test_human_decision_needs_reason(writer):
    record = event("approve", meaning="approved")
    del record["reason"]
    with pytest.raises(Refused, match="needs a reason"):
        writer.append(record, observed_stub())


def test_idempotent_by_id_and_duplicate_id(writer, config):
    record = event()
    first, created = writer.append(record, observed_stub())
    again, created_again = writer.append(dict(record), observed_stub())
    assert created and not created_again and again == first
    changed = dict(record, action="something-else")
    with pytest.raises(Refused) as caught:
        writer.append(changed, observed_stub())
    assert caught.value.code == "duplicate_id"
    assert len([r for r in read_records(config.trail_path) if r["type"] == "trail.event"]) == 1


def test_single_writer_lock(writer, config):
    with pytest.raises(WriterBusy):
        open_writer(config)


def test_torn_last_line_is_repaired_and_recorded(config):
    w = open_writer(config)
    w.append(event(), observed_stub())
    w.close()
    with open(config.trail_path, "ab") as handle:
        handle.write(b'{"partial": ')
    w = open_writer(config)
    w.close()
    records = read_records(config.trail_path)
    assert records[-1]["action"] == "log.repaired"
    assert records[-1]["data"]["removed_bytes"] == len(b'{"partial": ')
    assert verify_chain(records, keys=service_keys(config), require_signature=True).ok


def test_writer_refuses_to_continue_a_broken_log(config):
    w = open_writer(config)
    for i in range(3):
        w.append(event(f"a{i}"), observed_stub())
    w.close()
    lines = config.trail_path.read_bytes().splitlines(keepends=True)
    config.trail_path.write_bytes(lines[0] + lines[2])
    with pytest.raises(LogBroken):
        open_writer(config)


def test_clock_jump_backwards_is_recorded(config):
    times = iter(["2026-10-21T10:00:00.000000Z", "2026-10-21T09:00:00.000000Z", "2026-10-21T09:00:00.000000Z"])
    w = open_writer(config)
    w.clock = lambda: next(times)
    w.append(event("one"), observed_stub())
    w.append(event("two"), observed_stub())
    w.close()
    records = read_records(config.trail_path)
    assert [r["action"] for r in records] == ["one", "clock.jump", "two"]
    assert records[1]["data"]["direction"] == "backward"


def test_drain_writes_gap_then_spooled_records(writer, config):
    spooled = [event("a", who=agent()), event("b")]
    bad = event("c")
    bad["sig"] = [{"alg": "ed25519", "key": "k", "value": "v"}]
    result = writer.drain([*spooled, bad, "not json {"], source="spool.jsonl")
    records = read_records(config.trail_path)
    assert records[0]["type"] == "trail.gap"
    assert records[0]["data"]["count"] == 2 and records[0]["data"]["spool_ids"] == [r["id"] for r in spooled]
    assert [r["observed"]["via"] for r in records[1:3]] == ["spool", "spool"]
    assert "pid" not in records[1]["observed"]
    assert len(result.refused) == 2 and all(r["type"] == "trail.refused" for r in records[3:])
    again = writer.drain(spooled, source="spool.jsonl")
    assert again.gap is None and len(again.already_stored) == 2


def test_stored_records_are_canonical_lines(writer, config):
    writer.append(event(data={"n": 1}), observed_stub())
    line = config.trail_path.read_bytes().splitlines()[0]
    assert json.loads(line)["data"] == {"n": 1}
    assert line == canonical_json(json.loads(line))


# -- writer-owned names, types and payloads (C-5, A-3) ------------------------------------------
WRITER = {"kind": "service", "id": "service:aqt-trail"}


@pytest.mark.parametrize("kind,action,who,data", [
    ("trail.anchor", "external-head", WRITER, {"imprint": "sha256:" + "0" * 64}),
    ("trail.anchor", "rfc3161", None, {"checkpoint": []}),
    ("trail.anchor", "rfc3161", None, {"checkpoint": {}}),
    ("trail.gap", "spool.drained", None, {"count": 0}),
    ("trail.event", "service.stop", WRITER, {"signal": "SIGTERM"}),
    ("trail.event", "service.start", None, None),
    ("trail.event", "clock.jump", None, None),
    ("x-demo.thing", "log.repaired", None, None),
    ("trail.event", "note", {"kind": "service", "id": " Service:AQT-Trail "}, None),
])
def test_writer_owned_records_are_refused(writer, config, kind, action, who, data):
    record = new_record(kind, who or agent(), action, data=data)
    with pytest.raises(Refused) as caught:
        writer.append(record, observed_stub())
    assert caught.value.code == "invalid_record"
    records = read_records(config.trail_path)
    assert [r["type"] for r in records] == ["trail.refused"]
    assert records[0]["actor"]["id"] != "service:aqt-trail"  # a refusal never carries the writer's name
    assert records[0]["data"]["attempted_id"] == record["id"]
    result = writer.drain([record], source="spool.jsonl")  # the drain path applies the same check
    assert not result.appended and len(result.refused) == 1 and result.gap is None
    assert not [r for r in read_records(config.trail_path) if r["id"] == record["id"]]


def _review(tmp_path, records, **change):
    from aqt_evidence import generate_key, load_signer
    from aqt_trail.review import build_review, load_profile, run_review
    from aqt_trail.config import DEFAULTS
    if not (tmp_path / "dora.key").exists():
        generate_key(tmp_path / "dora.key")
    sheet = run_review(records, load_profile("default", DEFAULTS["review"]), log_id="trail_test")
    record = build_review(sheet, records, reviewer_id="human:dora", signer=load_signer(tmp_path / "dora.key"),
                          dispositions={"all": "ok"}, notes={}, reason="weekly review", conclusion="ok", registry={})
    for path, value in change.items():
        target = record
        *parents, last = path.split("__")
        for key in parents:
            target = target[key]
        if value is DELETE:
            del target[last]
        else:
            target[last] = value
    return record


DELETE = object()


@pytest.mark.parametrize("change", [
    {"data__signature__statement__subject": None},
    {"data__signature": DELETE},
    {"data__signature__statement": "x"},
    {"data__findings": "none"},
    {"data__head": "x"},
    {"data": []},
])
def test_malformed_review_is_refused_and_a_real_one_is_stored(writer, config, tmp_path, change):
    writer.append(event("work", who=agent()), observed_stub())
    records = read_records(config.trail_path)
    with pytest.raises(Refused, match="trail.review|data"):
        writer.append(_review(tmp_path, records, **change), observed_stub())
    good = _review(tmp_path, read_records(config.trail_path)[:1])
    assert writer.append(good, observed_stub())[1] is True


def test_client_refusal_records_need_their_payload(writer):
    from aqt_trail.review import refusal_record
    assert writer.append(refusal_record("human:dora", "agent_context", "inside an agent"), observed_stub())[1]
    bad = refusal_record("human:dora", "agent_context", "inside an agent")
    bad["data"] = {"attempted_action": "review.sign"}
    with pytest.raises(Refused, match="trail.refused needs"):
        writer.append(bad, observed_stub())


# -- drain keeps ids unique (C-9) ---------------------------------------------------------------
def test_drain_stores_each_id_once(writer, config):
    import copy
    same = event("note", who=agent())
    variant = dict(copy.deepcopy(same), action="different")
    result = writer.drain([same, copy.deepcopy(same), variant], source="spool.jsonl")
    assert len(result.appended) == 1 and result.already_stored == [same["id"]] and len(result.refused) == 1
    records = read_records(config.trail_path)
    assert [r["action"] for r in records if r["id"] == same["id"]] == ["note"]
    refusal = records[-1]
    assert refusal["type"] == "trail.refused" and refusal["data"]["reason_code"] == "duplicate_id"
    again = writer.drain([variant], source="spool.jsonl")  # across batches, too
    assert again.gap is None and len(again.refused) == 1


# -- lock file and write failures (C-13, C-16) --------------------------------------------------
def test_lock_file_is_private(config):
    import os
    import stat as stat_
    config.state.mkdir(parents=True, exist_ok=True)
    lock = config.state / "trail.lock"
    lock.touch()
    os.chmod(lock, 0o644)  # left by an older version
    w = open_writer(config)
    try:
        assert stat_.S_IMODE(os.stat(lock).st_mode) == 0o600
    finally:
        w.close()


def test_short_writes_are_completed(writer, config, monkeypatch):
    import os
    real = os.write

    def short(fd, data):
        return real(fd, bytes(data[:max(1, len(data) // 3)])) if fd == writer._fd else real(fd, data)
    monkeypatch.setattr(os, "write", short)
    writer.append(event("one"), observed_stub())
    writer.append(event("two"), observed_stub())
    monkeypatch.undo()
    records = read_records(config.trail_path)
    assert [r["action"] for r in records] == ["one", "two"]
    assert verify_chain(records, keys=service_keys(config), require_signature=True).ok


def test_failed_fsync_leaves_nothing_and_the_writer_continues(writer, config, monkeypatch):
    import errno
    import os
    writer.append(event("before"), observed_stub())
    size = config.trail_path.stat().st_size
    real, calls = os.fsync, []

    def failing(fd):
        if fd == writer._fd and not calls:
            calls.append(fd)
            raise OSError(errno.EIO, "I/O error")
        return real(fd)
    monkeypatch.setattr(os, "fsync", failing)
    with pytest.raises(OSError):
        writer.append(event("lost"), observed_stub())
    assert config.trail_path.stat().st_size == size  # no half line, no unacknowledged record
    monkeypatch.setattr(os, "fsync", real)
    writer.append(event("after"), observed_stub())
    writer.close()
    records = read_records(config.trail_path)
    assert [r["action"] for r in records] == ["before", "after"]
    assert verify_chain(records, keys=service_keys(config), require_signature=True).ok
    open_writer(config).close()  # the log still links


def test_write_that_cannot_be_undone_stops_the_writer(writer, config, monkeypatch):
    import errno
    import os
    real_fsync, real_truncate = os.fsync, os.ftruncate
    monkeypatch.setattr(os, "fsync", lambda fd: (_ for _ in ()).throw(OSError(errno.EIO, "I/O error"))
                        if fd == writer._fd else real_fsync(fd))
    monkeypatch.setattr(os, "ftruncate", lambda fd, n: (_ for _ in ()).throw(OSError(errno.EIO, "I/O error")))
    with pytest.raises(OSError):
        writer.append(event("unsure"), observed_stub())
    monkeypatch.setattr(os, "fsync", real_fsync)
    monkeypatch.setattr(os, "ftruncate", real_truncate)
    with pytest.raises(Refused) as caught:
        writer.append(event("next"), observed_stub())
    assert caught.value.code == "unavailable" and "restart" in caught.value.message
