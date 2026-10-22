"""Opt-in (AQT_SENSEI_REAL=1): the tmux backend against a real tmux server on a private socket.

The test starts its own server with `tmux -L aqt-test-<random>`, never the
user's server, and kills only that server at the end.
"""

import os
import secrets
import shutil
import subprocess
import sys
import time

import pytest

from aqt_sensei.hosts import TmuxHost

pytestmark = pytest.mark.skipif(os.environ.get("AQT_SENSEI_REAL") != "1" or not shutil.which("tmux"),
                                reason="opt-in: needs tmux and AQT_SENSEI_REAL=1")

AGENT = r'''
import sys
print("fake agent ready", flush=True)
while True:
    sys.stdout.write("> "); sys.stdout.flush()
    line = sys.stdin.readline()
    if not line:
        break
    print("got: " + line.strip(), flush=True)
'''


@pytest.fixture
def server(tmp_path):
    name = f"aqt-test-{secrets.token_hex(4)}"
    script = tmp_path / "agent.py"
    script.write_text(AGENT)
    env = {k: v for k, v in os.environ.items() if k != "TMUX"}
    subprocess.run(["tmux", "-L", name, "-f", "/dev/null", "new-session", "-d", "-s", "t", "-x", "120", "-y", "30",
                    sys.executable, "-u", str(script)], check=True, env=env)
    yield name, tmp_path
    subprocess.run(["tmux", "-L", name, "kill-server"], env=env)
    socket_dir = os.environ.get("TMUX_TMPDIR") or "/tmp"
    stale = os.path.join(socket_dir, f"tmux-{os.getuid()}", name)
    if os.path.exists(stale):
        os.unlink(stale)  # only this test's own socket


def wait_for(predicate, timeout=10.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.2)
    return False


def test_real_tmux_status_delivery_and_split(server):
    name, folder = server
    host = TmuxHost(socket_name=name, state_dir=folder / "panes", quiet_seconds=0.6, paste_delay=0.2)
    pane = next(iter(host.panes()))
    assert wait_for(lambda: "fake agent ready" in host.capture(pane, 50))
    assert wait_for(lambda: host.panes()[pane].status == "idle")
    assert host.panes()[pane].agent and host.panes()[pane].root_pid
    host.deliver(pane, "[Sensei → Worker · 1] hello from the bridge")
    assert wait_for(lambda: "got: [Sensei → Worker · 1] hello from the bridge" in host.capture(pane, 50))
    new = host.split(pane, str(folder), {"AQT_AGENT_SESSION": "1"})
    assert new in host.panes() and host.panes()[new].agent is False  # a plain shell
    host.run(new, ["printf", "%s\\n", "ran in split"])
    assert wait_for(lambda: "ran in split" in host.capture(new, 50))
    host.close(new)
    assert new not in host.panes()
