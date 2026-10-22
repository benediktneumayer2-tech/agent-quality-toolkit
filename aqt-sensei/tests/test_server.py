"""Real Unix sockets: rights per socket, owner authentication, refusals on record.

The kernel reports this test process as the peer; a fake /proc tree decides
which process the bridge believes it is talking to.
"""

import pytest

from aqt_sensei.agent import call
from aqt_sensei.config import read_token
from aqt_sensei.peer import describe_pid
from aqt_sensei.server import Server

from conftest import ADVISOR_PID, WORKER_PID, FakeProc, pair_up, records

OWNER_PID, OWNER_SHELL = 5100, 5000
AGENT_IN_WORKER = 4110
STRAY_AGENT = 6100


@pytest.fixture
def proc(tmp_path):
    fake = FakeProc(tmp_path / "proc")
    fake.add(1, "systemd", 0)
    fake.add(OWNER_SHELL, "bash", 1, tty="/dev/pts/9")
    fake.add(OWNER_PID, "aqt-sensei", OWNER_SHELL, tty="/dev/pts/9")
    fake.add(WORKER_PID, "bash", 1, tty="/dev/pts/1")
    fake.add(4105, "claude", WORKER_PID, tty="/dev/pts/1", env={"CLAUDECODE": "1"})
    fake.add(AGENT_IN_WORKER, "aqt-sensei", 4105, env={"CLAUDECODE": "1"})
    fake.add(STRAY_AGENT, "aqt-sensei", 1, env={"CODEX_THREAD_ID": "t"}, tty="/dev/pts/7")
    fake.add(ADVISOR_PID, "bwrap", 1)
    fake.add(4210, "python3", ADVISOR_PID, env={"AQT_AGENT_SESSION": "1"})
    return fake


@pytest.fixture
def server(bridge, paths, proc):
    who = {"pid": OWNER_PID}
    server = Server(bridge, paths, proc=proc.root,
                    describe=lambda pid, uid, gid, proc: describe_pid(who["pid"], uid, gid, proc=proc))
    server.who = who
    server.start()
    yield server
    server.shutdown()


def owner(server, paths, payload, pid=OWNER_PID, token=True):
    server.who["pid"] = pid
    if token:
        payload = {**payload, "token": read_token(paths.token_file)}
    return call(paths.owner_socket, payload)


def make_pair(server, paths, project):
    reply = owner(server, paths, {"op": "pair", "worker": "%1", "advisor": "claude", "project": str(project),
                                  "mode": "confirm", "reason": "pair over the socket"})
    assert reply["status"] == "available", reply
    pair = reply["pair"]
    pane = server.bridge.host.store[pair["advisor"]["pane_id"]].info
    pane.agent, pane.status, pane.root_pid, pane.tty = True, "idle", ADVISOR_PID, "/dev/pts/2"
    server.bridge.tick()
    return pair


def test_sockets_are_private(server, paths):
    for path in (paths.owner_socket, paths.agent_socket):
        assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert oct(paths.runtime.stat().st_mode & 0o777) == "0o700"


def test_owner_round_trip_and_advisor_socket(server, paths, project, sink_path):
    pair = make_pair(server, paths, project)
    advisor_socket = paths.advisor_socket(pair["id"])
    assert advisor_socket.exists()
    server.who["pid"] = AGENT_IN_WORKER
    asked = call(paths.agent_socket, {"op": "ask", "text": "why does it fail?", "pane_hint": "%1"})
    assert asked["status"] == "available" and asked["state"] == "awaiting_approval"
    approved = owner(server, paths, {"op": "approve", "message_id": asked["message_id"], "reason": "ok"})
    assert approved["status"] == "available"
    decision = records(sink_path, "sensei.decision")[0]
    assert decision["data"]["peer"]["process_chain"][0] == "aqt-sensei"
    assert decision["data"]["peer"]["via"] == "socket" and "observed" not in decision
    # like the trail's `observed` (aqt-spec observed.schema.json), fields without a value are left out
    assert "client_time" not in decision["data"]["peer"]
    assert all(value is not None for process in decision["data"]["peer"]["processes"] for value in process.values())
    server.who["pid"] = 4210
    status = call(advisor_socket, {"op": "status"})
    assert status["status"] == "available" and "you are the sensei" in status["output"]


def test_owner_refusals_are_recorded(server, paths, project, sink_path):
    make_pair(server, paths, project)
    cases = [(dict(pid=OWNER_PID, token=False), "token"),
             (dict(pid=AGENT_IN_WORKER), "paired-pane"),
             (dict(pid=STRAY_AGENT), "agent-session")]
    for kwargs, code in cases:
        reply = owner(server, paths, {"op": "mode", "pair_id": "x", "mode": "auto", "reason": "r"}, **kwargs)
        assert reply["status"] == "error" and reply["code"] == code
    refused = records(sink_path, "sensei.refused")
    assert [r["data"]["reason_code"] for r in refused] == ["token", "paired-pane", "agent-session"]
    assert refused[0]["action"] == "refused" and refused[0]["data"]["attempted_action"] == "mode"
    assert "env:CODEX_THREAD_ID" in refused[2]["data"]["agent_markers"]


def test_owner_needs_a_terminal_that_is_not_a_paired_pane(server, paths, project, proc):
    make_pair(server, paths, project)
    proc.add(7000, "aqt-sensei", 1)                      # no terminal on stdin
    proc.add(7001, "aqt-sensei", 1, tty="/dev/pts/1")    # the worker pane's terminal
    assert owner(server, paths, {"op": "list"}, pid=7000)["code"] == "no-terminal"
    assert owner(server, paths, {"op": "list"}, pid=7001)["code"] == "paired-terminal"
    assert owner(server, paths, {"op": "list"}, pid=OWNER_PID)["status"] == "available"


def test_advisor_socket_allows_only_advisor_ops(server, paths, project, sink_path):
    pair = make_pair(server, paths, project)
    server.who["pid"] = 4210
    for op in ("ask", "approve", "mode", "pair"):
        reply = call(paths.advisor_socket(pair["id"]), {"op": op, "text": "x", "mode": "auto"})
        assert reply["status"] == "error" and reply["code"] == "op-not-allowed"
    refused = records(sink_path, "sensei.refused")
    assert refused and refused[0]["actor"]["kind"] == "agent" and refused[0]["actor"]["role"] == "advisor"


def test_agent_socket_needs_a_paired_worker_process(server, paths, project, sink_path):
    make_pair(server, paths, project)
    server.who["pid"] = STRAY_AGENT
    reply = call(paths.agent_socket, {"op": "ask", "text": "x", "pane_hint": "%1"})
    assert reply["code"] == "not-paired"
    server.who["pid"] = AGENT_IN_WORKER
    assert call(paths.agent_socket, {"op": "reply", "text": "x"})["code"] == "op-not-allowed"
    assert {r["data"]["reason_code"] for r in records(sink_path, "sensei.refused")} == {"not-paired", "op-not-allowed"}


def test_end_closes_the_advisor_socket(server, paths, project):
    pair = make_pair(server, paths, project)
    assert owner(server, paths, {"op": "end", "pair_id": pair["id"], "reason": "done"})["status"] == "available"
    assert not paths.advisor_socket(pair["id"]).exists()


def test_second_daemon_refuses_to_start(server, bridge, paths):
    with pytest.raises(RuntimeError, match="already running"):
        Server(bridge, paths).start()
