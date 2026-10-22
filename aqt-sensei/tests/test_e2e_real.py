"""Opt-in (AQT_SENSEI_REAL=1): one full exchange with real tmux, real sockets and real bubblewrap.

A scripted worker runs in a pane of a private tmux server (`tmux -L aqt-e2e-…`,
default shell /bin/sh, never the user's server). When the bridge's intro
arrives it runs `aqt-sensei ask`. The bridge splits the pane and launches a
scripted advisor inside bwrap; on the question it answers with the in-sandbox
`sensei reply` shim, and the answer is delivered back to the worker.
"""

import os
import secrets
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from aqt_sensei.config import read_token
from aqt_sensei.agent import call
from aqt_sensei.hosts import TmuxHost
from aqt_sensei.peer import Peer, describe_pid
from aqt_sensei.server import Server
from aqt_sensei.bridge import Bridge
from aqt_sensei.ledger import Ledger

from conftest import records

pytestmark = pytest.mark.skipif(
    os.environ.get("AQT_SENSEI_REAL") != "1" or not shutil.which("tmux") or not shutil.which("bwrap"),
    reason="opt-in: needs tmux, bwrap and AQT_SENSEI_REAL=1")

WORKER = r'''
import os, subprocess, sys
print("worker ready", flush=True)
while True:
    sys.stdout.write("> "); sys.stdout.flush()
    line = sys.stdin.readline()
    if not line:
        break
    print("got: " + line.strip(), flush=True)
    if "[Bridge → Worker · intro]" in line:
        done = subprocess.run([sys.argv[1], "ask", "How do I fix the failing test?"], capture_output=True, text=True)
        print("ask exit", done.returncode, done.stdout.strip(), done.stderr.strip(), flush=True)
'''

ADVISOR = r'''
import os, subprocess, sys
print("advisor ready in", os.getcwd(), flush=True)
try:
    open(os.path.join(sys.argv[1], "hacked.txt"), "w").write("x")
    print("PROJECT WRITE SUCCEEDED", flush=True)
except OSError as error:
    print("project write blocked:", error.strerror, flush=True)
while True:
    sys.stdout.write("> "); sys.stdout.flush()
    line = sys.stdin.readline()
    if not line:
        break
    print("got: " + line.strip(), flush=True)
    if "[Worker → Sensei ·" in line:
        done = subprocess.run(["sensei", "reply", "Use the fixture from conftest."], capture_output=True, text=True)
        print("reply exit", done.returncode, done.stdout.strip(), done.stderr.strip(), flush=True)
'''


def wait_for(predicate, timeout=30.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.3)
    return False


@pytest.fixture
def tmux(tmp_path, paths):
    name = f"aqt-e2e-{secrets.token_hex(4)}"
    env = {k: v for k, v in os.environ.items() if k != "TMUX"}
    env.update(paths.env())
    worker = tmp_path / "worker.py"
    worker.write_text(WORKER)
    cli = str(Path(sys.executable).parent / "aqt-sensei")
    command = " ".join([*(f"{k}={v}" for k, v in paths.env().items()), sys.executable, "-u", str(worker), cli])
    subprocess.run(["tmux", "-L", name, "-f", "/dev/null", "new-session", "-d", "-s", "e2e", "-x", "160", "-y", "40",
                    "/bin/sh", "-c", f"exec env {command}"], check=True, env=env)
    subprocess.run(["tmux", "-L", name, "set", "-g", "default-shell", "/bin/sh"], check=True, env=env)
    yield name
    subprocess.run(["tmux", "-L", name, "kill-server"], env=env)
    stale = os.path.join(os.environ.get("TMUX_TMPDIR") or "/tmp", f"tmux-{os.getuid()}", name)
    if os.path.exists(stale):
        os.unlink(stale)


def test_real_exchange(tmux, paths, config, project, sink_path):
    (project / "advisor.py").write_text(ADVISOR)
    host = TmuxHost(socket_name=tmux, state_dir=paths.pane_state, quiet_seconds=0.6, paste_delay=0.2)
    ledger = Ledger(sink_spec=config.sink, spool=paths.state / "spool.jsonl", owner_id=config.owner_actor_id)
    bridge = Bridge(paths=paths, config=config, host=host, ledger=ledger)
    me = os.getpid()

    def describe(pid, uid, gid, proc):
        if pid == me:  # the test plays the owner at a terminal
            return Peer(pid, uid, gid, [pid], ["aqt-sensei"], [None], "/dev/pts/99", {})
        return describe_pid(pid, uid, gid, proc=proc)

    server = Server(bridge, paths, describe=describe)
    server.start()
    stop = threading.Event()
    loop = threading.Thread(target=server.run, args=(stop, 0.3), daemon=True)
    loop.start()
    try:
        worker = next(iter(host.panes()))
        assert wait_for(lambda: "worker ready" in host.capture(worker, 50))
        reply = call(paths.owner_socket, {
            "op": "pair", "worker": worker, "advisor": f"python3 -u {project / 'advisor.py'} {project}",
            "project": str(project), "mode": "auto", "max_exchanges": 2, "network": "none",
            "worker_platform": "custom", "reason": "real e2e", "token": read_token(paths.token_file)})
        assert reply["status"] == "available", reply
        pair = reply["pair"]
        advisor = pair["advisor"]["pane_id"]
        assert wait_for(lambda: "advisor ready" in host.capture(advisor, 80)), host.capture(advisor, 80)
        assert "project write blocked" in host.capture(advisor, 80)
        assert not (project / "hacked.txt").exists()
        assert wait_for(lambda: "reply exit 0" in host.capture(advisor, 200)), host.capture(advisor, 200)
        assert wait_for(lambda: "got: Use the fixture from conftest." in host.capture(worker, 200)), \
            host.capture(worker, 200)
        assert "[Sensei → Worker · 1/2]" in host.capture(worker, 200)
        assert "ask exit 0" in host.capture(worker, 200)
        types = [(r["type"], r["action"]) for r in records(sink_path)]
        assert ("sensei.pair", "attached") in types and ("sensei.budget", "consumed") in types
        senders = {r["data"]["from"] for r in records(sink_path, "sensei.message") if r["action"] == "delivered"}
        assert senders == {"bridge", "worker", "advisor"}
        peers = [r["data"]["peer"] for r in records(sink_path, "sensei.message") if "peer" in r["data"]]
        assert any(p["process_chain"] and p["via"] == "socket" for p in peers)
    finally:
        stop.set()
        loop.join(5)
        server.shutdown()
