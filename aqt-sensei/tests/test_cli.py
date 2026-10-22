"""The console script end to end against an in-process bridge."""

import json

import pytest

from aqt_sensei.cli import main
from aqt_sensei.config import Paths, read_token
from aqt_sensei.peer import describe_pid
from aqt_sensei.server import Server

from conftest import ADVISOR_PID, WORKER_PID, FakeProc, records

OWNER_PID = 5100


@pytest.fixture
def env(paths, monkeypatch):
    for key, value in paths.env().items():
        monkeypatch.setenv(key, value)
    return paths


@pytest.fixture
def live(env, bridge, tmp_path, config, monkeypatch):
    proc = FakeProc(tmp_path / "proc")
    proc.add(1, "systemd", 0)
    proc.add(5000, "bash", 1, tty="/dev/pts/9")
    proc.add(OWNER_PID, "aqt-sensei", 5000, tty="/dev/pts/9")
    proc.add(WORKER_PID, "bash", 1, tty="/dev/pts/1")
    proc.add(4110, "aqt-sensei", WORKER_PID)
    who = {"pid": OWNER_PID}
    server = Server(bridge, env, proc=proc.root,
                    describe=lambda pid, uid, gid, proc: describe_pid(who["pid"], uid, gid, proc=proc))
    server.who = who
    server.start()
    yield server
    server.shutdown()


def run(capsys, *argv):
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_init_creates_config_and_keeps_token(tmp_path, monkeypatch, capsys):
    paths = Paths(config_file=tmp_path / "c" / "sensei.toml", token_file=tmp_path / "c" / "t",
                  state=tmp_path / "s", runtime=tmp_path / "r")
    for key, value in paths.env().items():
        monkeypatch.setenv(key, value)
    code, out, _ = run(capsys, "init", "--owner-id", "alice")
    assert code == 0 and 'id = "alice"' in paths.config_file.read_text()
    token = read_token(paths.token_file)
    assert token and oct(paths.token_file.stat().st_mode & 0o777) == "0o600"
    run(capsys, "init")
    assert read_token(paths.token_file) == token


def test_offline_bridge_exit_2(env, capsys):
    assert run(capsys, "list")[0] == 2
    code, _, err = run(capsys, "ask", "hello")
    assert code == 2 and "offline" in err


def test_usage_error_exit_2(capsys):
    assert run(capsys, "approve")[0] == 2


def test_owner_flow_through_the_cli(live, env, project, capsys, sink_path):
    code, out, err = run(capsys, "pair", "--worker", "%1", "--advisor", "claude", "--project", str(project),
                         "--mode", "confirm", "--reason", "try it", "--json")
    assert code == 0, err
    pair = json.loads(out)["pair"]
    pane = live.bridge.host.store[pair["advisor"]["pane_id"]].info
    pane.agent, pane.status, pane.root_pid = True, "idle", ADVISOR_PID
    live.bridge.tick()

    live.who["pid"] = 4110  # the worker's own shell tool
    code, out, _ = run(capsys, "ask", "why?")
    assert code == 0 and "owner's approval" in out
    code, _, err = run(capsys, "mode", pair["id"], "auto", "--reason", "self-approve")
    assert code == 1 and "paired agent pane" in err

    live.who["pid"] = OWNER_PID
    code, out, _ = run(capsys, "list")
    assert code == 0 and pair["id"] in out and "awaiting_approval" in out
    message_id = next(m["id"] for m in live.bridge.messages.values() if m["kind"] == "ask")
    code, out, _ = run(capsys, "show", message_id)
    assert out.startswith("[Worker → Sensei · 1]")
    assert run(capsys, "approve", message_id, "--reason", "fine")[0] == 0
    assert run(capsys, "budget", pair["id"], "--max-exchanges", "3", "--reason", "cap")[0] == 0
    assert run(capsys, "end", pair["id"], "--reason", "done")[0] == 0
    types = {r["type"] for r in records(sink_path)}
    assert {"sensei.pair", "sensei.message", "sensei.decision", "sensei.budget", "sensei.refused"} <= types


def test_hook_state(env, capsys, monkeypatch):
    monkeypatch.setenv("TMUX_PANE", "%7")
    assert run(capsys, "hook-state", "working")[0] == 0
    assert json.loads((env.pane_state / "_7.state").read_text())["state"] == "working"
    monkeypatch.delenv("TMUX_PANE")
    assert run(capsys, "hook-state", "idle")[0] == 0  # outside tmux: a no-op, never an error
