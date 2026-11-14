"""The writer on Windows: a real ``aqt-trail serve`` behind its named pipe, and two client processes
(``aqt-trail append`` and the ``aqt_evidence`` sink a tool finds by itself) writing at the same time."""

import json
import os
import subprocess
import sys
import time

import pytest

from aqt_evidence import SinkUnavailable, platform, writer_request
from aqt_trail.state import read_records

from conftest import event

pytestmark = pytest.mark.skipif(not platform.IS_WINDOWS, reason="named pipes are the writer's transport on Windows only")

SINK_CLIENT = """
import json, os, sys
from aqt_evidence import actor, new_record, open_sink, resolve_sink
route = resolve_sink()
record = new_record("trail.event", actor("agent", "agent:test:two"), "client-two", reason="pipe test")
stored = open_sink().append(record)
print(json.dumps({"pid": os.getpid(), "route": route, "seq": stored.get("chain", {}).get("seq")}))
"""


def _wait_for_writer(address, process, log, seconds=30.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"the writer exited with {process.returncode}: "
                                 f"{log.read_text(encoding='utf-8', errors='replace')[-2000:]}")
        try:
            if writer_request(address, {"op": "ping"}, timeout=0.5).get("ok"):
                return
        except SinkUnavailable:
            time.sleep(0.2)
    raise AssertionError("the writer did not answer on its pipe")


def test_a_real_writer_and_two_clients(config, tmp_path):
    address = str(config.socket_path)
    assert platform.is_pipe(address) and address.startswith("\\\\.\\pipe\\aqt-trail-")
    log = open(tmp_path / "writer.log", "wb")
    writer = subprocess.Popen([sys.executable, "-m", "aqt_trail.cli", "serve"], stdout=log, stderr=subprocess.STDOUT)
    try:
        _wait_for_writer(address, writer, tmp_path / "writer.log")
        one_input = tmp_path / "one.json"
        one_input.write_text(json.dumps(event("client-one")), encoding="utf-8")
        one = subprocess.Popen([sys.executable, "-m", "aqt_trail.cli", "append", str(one_input)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        two = subprocess.Popen([sys.executable, "-c", SINK_CLIENT], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out_one, err_one = one.communicate(timeout=60)
        out_two, err_two = two.communicate(timeout=60)
        assert one.returncode == 0 and b"stored 1, spooled 0" in out_one, err_one
        assert two.returncode == 0, err_two
        answer = json.loads(out_two)
        assert answer["route"]["kind"] == "unix" and answer["route"]["target"] == address and answer["route"]["writer"]
        assert answer["seq"] is not None          # stored by the writer, not spooled
    finally:
        writer.terminate()
        writer.wait(timeout=30)
        log.close()
    records = {record["action"]: record for record in read_records(config.trail_path)}
    for action, pid in (("client-one", one.pid), ("client-two", answer["pid"])):
        observed = records[action]["observed"]
        # a venv's python.exe may be a launcher that runs the interpreter as its child: the started process is
        # then the parent of the one that connected
        assert observed["via"] == "socket" and pid in [entry["pid"] for entry in observed["processes"][:2]]
        assert observed["sid"] == platform.user_id() and "uid" not in observed and "gid" not in observed
        assert observed["process_chain"][0] == "python"            # python.exe, named as on Linux
        assert observed["chain_status"] in ("complete", "partial")  # the sender was alive and readable
    assert one.pid != answer["pid"]


def test_a_pipe_of_another_user_gets_nothing(server, config, monkeypatch):
    from aqt_evidence import pipes
    monkeypatch.setattr(pipes, "owner", lambda _handle: "S-1-5-21-1-2-3-1001")
    with pytest.raises(SinkUnavailable, match="belongs to S-1-5-21-1-2-3-1001"):
        writer_request(config.socket_path, {"op": "append", "record": event("never-sent")})
    assert "never-sent" not in [record["action"] for record in read_records(config.trail_path)]
