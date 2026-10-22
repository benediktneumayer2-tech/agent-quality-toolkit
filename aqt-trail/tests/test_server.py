import os
import stat

import pytest

from aqt_evidence import SocketSink

from aqt_trail import server as server_module
from aqt_trail.client import TrailClient, TrailRefused, request, spool_append
from aqt_trail.config import spool_path
from aqt_trail.observe import observe, processes
from aqt_trail.server import drain_local_spool
from aqt_trail.state import open_writer, read_records

from conftest import event, human


def test_socket_append_observes_the_peer(server, config):
    stored = TrailClient(config.socket_path).append(event("hello"))
    observed = stored["observed"]
    assert observed["via"] == "socket"
    assert observed["pid"] == os.getpid() and observed["uid"] == os.getuid() and observed["gid"] == os.getgid()
    assert observed["process_chain"] and observed["processes"][0]["start_time"] is not None
    assert stat.S_IMODE(os.stat(config.socket_path).st_mode) == 0o600
    records = read_records(config.trail_path)
    assert [r["action"] for r in records] == ["service.start", "hello"]


def test_aqt_evidence_socket_sink_is_compatible(server, config):
    stored = SocketSink(config.socket_path).append(event("via-library"))
    assert stored["chain"]["seq"] == 1


def test_refusal_codes_over_the_socket(server, config):
    record = event()
    record["observed"] = {"pid": 1}
    with pytest.raises(TrailRefused) as caught:
        TrailClient(config.socket_path).append(record)
    assert caught.value.code == "invalid_record"
    response = request(config.socket_path, {"op": "nonsense"})
    assert response == {"ok": False, "code": "invalid_record", "message": "unknown op 'nonsense'"}
    assert read_records(config.trail_path)[-1]["type"] == "trail.refused"


def test_unauthorized_uid(server, config, monkeypatch):
    monkeypatch.setattr(server_module, "peer_credentials", lambda _s: (os.getpid(), 4242, 4242))
    response = request(config.socket_path, {"op": "append", "record": event()})
    assert response["code"] == "unauthorized"
    refusal = read_records(config.trail_path)[-1]
    assert refusal["data"]["reason_code"] == "unauthorized" and refusal["observed"]["uid"] == 4242


def test_head_and_checkpoint_ops(server, config):
    TrailClient(config.socket_path).append(event())
    head = request(config.socket_path, {"op": "head"})
    assert head["ok"] and head["seq"] == 1
    response = request(config.socket_path, {"op": "checkpoint", "export": True})
    assert response["checkpoint"]["seq"] == 1 and response["anchor"]["action"] == "external-head"


def test_client_spools_when_writer_is_down_then_drain_on_start(config):
    client = TrailClient(config.socket_path)
    records = [event("while-down-1"), event("while-down-2")]
    for record in records:
        assert client.append(record) == record and client.last_spooled
    assert spool_path().exists() and stat.S_IMODE(os.stat(spool_path()).st_mode) == 0o600
    writer = open_writer(config)
    result = drain_local_spool(writer)
    writer.close()
    assert len(result.appended) == 2
    stored = read_records(config.trail_path)
    assert stored[0]["type"] == "trail.gap" and [r["action"] for r in stored[1:]] == ["while-down-1", "while-down-2"]
    assert spool_path().read_bytes() == b""


def test_drain_op_over_socket(server, config):
    spool_append(event("late"))
    from aqt_trail.client import locked_spool
    with locked_spool() as (entries, clear):
        response = request(config.socket_path, {"op": "drain", "records": entries, "source": "spool"})
        clear()
    assert response["ok"] and response["appended"] == 1
    gap = [r for r in read_records(config.trail_path) if r["type"] == "trail.gap"][0]
    assert gap["observed"]["via"] == "socket" and gap["observed"]["pid"] == os.getpid()


def test_resent_record_after_spool_is_not_duplicated(server, config):
    record = event("maybe-sent-twice")
    TrailClient(config.socket_path).append(record)
    spool_append(record)
    drain_local_spool(server.writer)
    actions = [r["action"] for r in read_records(config.trail_path)]
    assert actions.count("maybe-sent-twice") == 1 and "spool.drained" not in actions


def test_process_chain_and_harness_from_fake_proc(tmp_path):
    proc = tmp_path / "proc"
    for pid, comm, ppid in ((300, "python3", 200), (200, "bash", 100), (100, "claude", 1)):
        (proc / str(pid)).mkdir(parents=True)
        fields = ["S", str(ppid)] + ["0"] * 17 + [str(pid * 10)]
        (proc / str(pid) / "stat").write_text(f"{pid} ({comm}) " + " ".join(fields))
    chain, complete = processes(300, proc=proc)
    assert complete and [p["comm"] for p in chain] == ["python3", "bash", "claude"]
    assert chain[0]["start_time"] == 3000
    observed = observe(300, 1000, 1000, proc=proc)
    assert observed["harness"] == "claude-code" and observed["process_chain"][-1] == "claude"
    gone = observe(999, 1000, 1000, proc=proc)
    assert gone["process_chain"] == ["?"] and gone["chain_complete"] is False


def test_second_server_on_same_socket_is_refused(server, config):
    from aqt_trail.server import TrailServer
    with pytest.raises(RuntimeError, match="already listening"):
        TrailServer(config.socket_path, server.writer)


def test_attribution_mismatch_is_recorded_not_blocked(server, config):
    stored = TrailClient(config.socket_path).append(event("pretend", who=human("owner")))
    assert stored["actor"]["kind"] == "human"
    assert stored["observed"]["process_chain"]  # the review compares claim and observation
