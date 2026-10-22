"""tmux and Herdr backends against stand-in binaries (no real server is touched)."""

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from aqt_sensei.hosts import HerdrHost, HostError, TmuxHost, strip_ansi, write_pane_state


def fake_binary(folder: Path, name: str, script: str) -> Path:
    path = folder / name
    path.write_text(f"#!{sys.executable}\n" + script)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


TMUX = r'''
import json, os, sys
log = os.environ["FAKE_LOG"]
args = sys.argv[1:]
command = args[2:] if args[:1] == ["-L"] else args
with open(log, "a") as handle:
    handle.write(json.dumps({"args": args, "stdin": sys.stdin.read() if "load-buffer" in args else None}) + "\n")
if command[:1] == ["list-panes"]:
    print("%1\t4100\t/dev/pts/1\tclaude\tworker")
    print("%2\t4200\t/dev/pts/2\tbash\tshell")
elif command[:1] == ["capture-pane"]:
    print(open(os.environ["FAKE_SCREEN"]).read())
elif command[:1] == ["split-window"]:
    print("%3")
'''


@pytest.fixture
def tmux(tmp_path, monkeypatch):
    binary = fake_binary(tmp_path, "tmux", TMUX)
    screen = tmp_path / "screen"
    screen.write_text("thinking...\n")
    monkeypatch.setenv("FAKE_LOG", str(tmp_path / "log"))
    monkeypatch.setenv("FAKE_SCREEN", str(screen))
    now = {"t": 0.0}
    host = TmuxHost(binary=str(binary), socket_name="aqt-test", state_dir=tmp_path / "panes", quiet_seconds=3,
                    paste_delay=0, clock=lambda: now["t"])
    host.now, host.screen, host.log = now, screen, tmp_path / "log"
    return host


def calls(host):
    return [json.loads(line) for line in host.log.read_text().splitlines()]


def test_tmux_heuristic_needs_quiet_and_prompt(tmux):
    assert tmux.panes()["%1"].status == "unknown"            # first look
    assert tmux.panes()["%2"].agent is False                  # a plain shell
    tmux.now["t"] = 5
    assert tmux.panes()["%1"].status == "unknown"            # quiet, but no prompt visible
    tmux.screen.write_text("done.\n> \n")
    assert tmux.panes()["%1"].status == "working"            # the screen changed
    tmux.now["t"] = 7
    assert tmux.panes()["%1"].status == "unknown"            # not quiet long enough
    tmux.now["t"] = 9
    assert tmux.panes()["%1"].status == "idle"


def test_tmux_hook_state_wins(tmux):
    write_pane_state(tmux.state_dir, "%1", "blocked")
    assert tmux.panes()["%1"].status == "blocked"
    with pytest.raises(ValueError):
        write_pane_state(tmux.state_dir, "%1", "sleeping")


def test_tmux_delivery_uses_bracketed_paste_on_its_own_socket(tmux):
    tmux.deliver("%1", "[Worker → Sensei · 1]\nhello; rm -rf /")
    log = calls(tmux)
    assert all(entry["args"][:2] == ["-L", "aqt-test"] for entry in log)
    load, paste, enter = [entry["args"][2:] for entry in log]
    assert load[0] == "load-buffer" and log[0]["stdin"].endswith("rm -rf /")
    assert paste[:3] == ["paste-buffer", "-p", "-d"] and paste[-1] == "%1"
    assert enter == ["send-keys", "-t", "%1", "Enter"]


def test_tmux_split_and_run(tmux):
    assert tmux.split("%1", "/tmp", {"AQT_AGENT_SESSION": "1"}) == "%3"
    tmux.run("%3", ["python3", "-m", "aqt_sensei", "launch", "--pair", "sp-1"])
    split, typed, enter = [entry["args"][2:] for entry in calls(tmux)]
    assert "-e" in split and "AQT_AGENT_SESSION=1" in split and "-d" in split
    assert typed[-1] == "python3 -m aqt_sensei launch --pair sp-1"


HERDR = r'''
import json, sys
args = sys.argv[1:]
if args[:2] == ["pane", "list"]:
    print(json.dumps({"result": {"type": "pane_list", "panes": [
        {"pane_id": "w1:p1", "agent": "claude", "agent_status": "idle",
         "agent_session": {"source": "herdr:claude", "value": "abc"}, "terminal_title_stripped": "work"},
        {"pane_id": "w1:p2", "agent": None, "agent_status": "unknown"}]}}))
elif args[:2] == ["pane", "process-info"]:
    print(json.dumps({"result": {"type": "pane_process_info", "process_info": {"pane_id": args[-1], "shell_pid": 4100, "tty": "/dev/pts/4"}}}))
elif args[:2] == ["pane", "read"]:
    print(json.dumps({"result": {"type": "pane_read", "read": {"text": "line one\nline two"}}}))
elif args[:2] == ["agent", "prompt"]:
    print(json.dumps({"error": {"code": "agent_blocked", "message": "agent is blocked"}})); sys.exit(1)
'''


def test_herdr_parsing_and_errors(tmp_path):
    host = HerdrHost(binary=str(fake_binary(tmp_path, "herdr", HERDR)))
    panes = host.panes()
    assert panes["w1:p1"].status == "idle" and panes["w1:p1"].session == "abc"
    assert panes["w1:p1"].root_pid == 4100 and panes["w1:p1"].tty == "/dev/pts/4"
    assert panes["w1:p2"].agent is False and panes["w1:p2"].status == "unknown"
    assert host.capture("w1:p1", 50) == "line one\nline two"
    with pytest.raises(HostError, match="blocked"):
        host.deliver("w1:p1", "hello")


def test_strip_ansi():
    assert strip_ansi("\x1b[1;31mred\x1b[0m \x1b]0;title\x07ok") == "red ok"
