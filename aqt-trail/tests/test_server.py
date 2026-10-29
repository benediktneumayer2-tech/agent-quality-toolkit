import os
import shutil
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
    records = read_records(config.trail_path)
    gap = [r for r in records if r["type"] == "trail.gap"][0]
    assert gap["observed"]["via"] == "socket" and gap["observed"]["pid"] == os.getpid()
    # the drained record keeps who sent it (C-3): spooled, but drained by an observed process
    late = [r for r in records if r["action"] == "late"][0]
    assert late["observed"]["via"] == "spool" and "pid" not in late["observed"]
    drained_by = late["observed"]["drained_by"]
    assert drained_by["via"] == "socket" and drained_by["pid"] == os.getpid() and "client_time" not in drained_by
    assert drained_by["process_chain"] == gap["observed"]["process_chain"]


def test_drain_op_cannot_hide_a_human_claim_sent_from_an_agent(server, config, monkeypatch, tmp_path):
    from aqt_trail import review
    proc = _fake_proc(tmp_path, ((300, "python3", 200, 200), (200, "bash", 100, 200), (100, "claude", 1, 100)))
    real = server_module.observe
    monkeypatch.setattr(server_module, "observe", lambda *a, **kw: real(300, os.getuid(), os.getgid(),
                                                                       via="socket", proc=proc))
    claimed = event("release.decided", who=human("owner"))
    request(config.socket_path, {"op": "drain", "records": [claimed], "source": "client spool"})
    stored = [r for r in read_records(config.trail_path) if r["id"] == claimed["id"]][0]
    assert stored["observed"]["drained_by"]["harness"] == "claude-code"
    assert stored["observed"]["drained_by"]["chain_status"] == "complete"


def test_checkpoint_op_uses_only_the_configured_tsa(server, config):
    TrailClient(config.socket_path).append(event())
    for url in ("http://127.0.0.1:9/tsr", "test:" + str(config.state / "elsewhere")):
        response = request(config.socket_path, {"op": "checkpoint", "anchor": True, "tsa_url": url})
        assert response["ok"] is False and response["code"] == "unauthorized" and "configured TSA" in response["message"]
        refusal = read_records(config.trail_path)[-1]
        assert refusal["type"] == "trail.refused" and refusal["data"]["attempted_action"] == "checkpoint"
    assert not (config.state / "elsewhere").exists()
    assert not [r for r in read_records(config.trail_path) if r["type"] == "trail.anchor"]
    # The built-in TEST ONLY authority in the writer's own state stays available (marked test: in the anchor).
    response = request(config.socket_path, {"op": "checkpoint", "anchor": True, "tsa_url": "test:"})
    assert response["ok"] and response["anchor"]["data"]["tsa"]["url"] == "test:"
    server.anchor["tsa_url"] = "test:" + str(config.state / "configured")
    response = request(config.socket_path, {"op": "checkpoint", "anchor": True, "tsa_url": server.anchor["tsa_url"]})
    assert response["ok"] and (config.state / "configured").exists()


def test_resent_record_after_spool_is_not_duplicated(server, config):
    record = event("maybe-sent-twice")
    TrailClient(config.socket_path).append(record)
    spool_append(record)
    drain_local_spool(server.writer)
    actions = [r["action"] for r in read_records(config.trail_path)]
    assert actions.count("maybe-sent-twice") == 1 and "spool.drained" not in actions


def _fake_proc(tmp_path, entries):
    """/proc/<pid>/stat files for (pid, comm, ppid[, session]); start time pid * 10."""
    proc = tmp_path / "proc"
    for pid, comm, ppid, *session in entries:
        (proc / str(pid)).mkdir(parents=True)
        fields = ["S", str(ppid), "0", str(session[0] if session else 0)] + ["0"] * 15 + [str(pid * 10)]
        (proc / str(pid) / "stat").write_text(f"{pid} ({comm}) " + " ".join(fields))
    return proc


def test_process_chain_and_harness_from_fake_proc(tmp_path):
    proc = _fake_proc(tmp_path, ((300, "python3", 200), (200, "bash", 100), (100, "claude", 1)))
    chain, complete = processes(300, proc=proc)
    assert complete and [p["comm"] for p in chain] == ["python3", "bash", "claude"]
    assert chain[0]["start_time"] == 3000
    observed = observe(300, 1000, 1000, proc=proc)
    assert observed["harness"] == "claude-code" and observed["process_chain"][-1] == "claude"
    assert observed["chain_status"] == "complete" and "chain_detail" not in observed
    gone = observe(999, 1000, 1000, proc=proc)
    assert gone["process_chain"] == ["?"] and gone["chain_complete"] is False
    assert gone["chain_status"] == "unavailable"


@pytest.mark.parametrize("entries,status,detail", [
    # a terminal: bash leads its session, the peer belongs to it
    (((300, "python3", 200, 200), (200, "bash", 100, 200), (100, "gnome-terminal-", 1, 100)), "complete", None),
    # the parent exited during the walk
    (((300, "python3", 4000, 300),), "partial", "exited"),
    # reparented to the user manager: its session leader (the agent's shell) is not an ancestor
    (((300, "python3", 100, 250), (100, "systemd", 1, 100)), "partial", "reparented"),
    # an ancestor further up was reparented to init
    (((300, "python3", 200, 200), (200, "bash", 1, 150)), "partial", "reparented"),
    # the parent started after its child: the parent pid was reused
    (((300, "python3", 400, 300), (400, "bash", 1, 400)), "partial", "pid reused"),
])
def test_chain_status(tmp_path, entries, status, detail):
    observed = observe(300, 1000, 1000, proc=_fake_proc(tmp_path, entries))
    assert observed["chain_status"] == status
    assert (detail is None and "chain_detail" not in observed) or detail in observed["chain_detail"]
    assert observed["harness"] is None


def test_chain_status_unavailable_without_pid_or_when_the_sender_exited(tmp_path):
    import socket
    import subprocess
    import sys
    import tempfile
    from aqt_trail.observe import peer_credentials, peer_pidfd
    assert observe(None, 1000, 1000)["chain_status"] == "unavailable"
    folder = tempfile.mkdtemp(prefix="aqtp", dir="/tmp")
    path = os.path.join(folder, "s")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    listener.listen()
    child = subprocess.Popen([sys.executable, "-c", "import socket, sys; s = socket.socket(socket.AF_UNIX); "
                              f"s.connect({path!r}); sys.stdin.read()"], stdin=subprocess.PIPE)
    connection, _ = listener.accept()
    pidfd = peer_pidfd(connection)
    try:
        if pidfd is None:
            pytest.skip("SO_PEERPIDFD needs Linux >= 6.5")
        pid, uid, gid = peer_credentials(connection)
        assert pid == child.pid
        assert observe(pid, uid, gid, pidfd=pidfd)["chain_status"] != "unavailable"
        child.stdin.close()
        child.wait(timeout=10)
        exited = observe(pid, uid, gid, pidfd=pidfd)
        assert exited["chain_status"] == "unavailable" and "exited" in exited["chain_detail"]
    finally:
        if pidfd is not None:
            os.close(pidfd)
        connection.close()
        listener.close()
        if child.poll() is None:
            child.kill()
        shutil.rmtree(folder, ignore_errors=True)


def test_socket_observation_has_a_chain_status(server, config):
    stored = TrailClient(config.socket_path).append(event("hello"))
    assert stored["observed"]["chain_status"] in ("complete", "partial", "unavailable")
    assert stored["observed"]["chain_status"] != "unavailable"  # the sender is alive and readable


def test_second_server_on_same_socket_is_refused(server, config):
    from aqt_trail.server import TrailServer
    with pytest.raises(RuntimeError, match="already listening"):
        TrailServer(config.socket_path, server.writer)


def test_attribution_mismatch_is_recorded_not_blocked(server, config):
    stored = TrailClient(config.socket_path).append(event("pretend", who=human("owner")))
    assert stored["actor"]["kind"] == "human"
    assert stored["observed"]["process_chain"]  # the review compares claim and observation
