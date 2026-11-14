"""The transport-free core: ``aqt core --stdio`` (protocol 1, JSON lines) against a real trail writer."""

import base64
import io
import json
import os
import subprocess
import sys
import threading
import time

from conftest import PASSPHRASE, SIGNER, trail_records

from aqt_ui.config import UiConfig
from aqt_ui.core import PROTOCOL, Core, QueueWatch, Response, queue_seconds, serve
from aqt_ui.guard import Guard, Mode, parent_peer, startup_mode

APP_PARENT = ["aqt-desktop", "gnome-shell", "systemd"]


def core_for(mode=None, parent=APP_PARENT):
    """A core whose guard sees ``parent`` as the process that started it; its log is kept."""
    mode = mode or Mode(True)
    lines: list[str] = []
    core = Core(UiConfig(), mode, Guard(mode, environ={}, peer_lookup=lambda _c, _s: parent), log=lines.append)
    core.log_lines = lines
    return core


def run(core, *requests, workers=4):
    """Feed request lines to the stdio loop until end of input: (raw stdout, ready event, responses by id)."""
    stdin = io.BytesIO(b"".join(json.dumps(r).encode() + b"\n" for r in requests))
    stdout = io.BytesIO()
    assert serve(core, stdin, stdout, workers=workers) == 0
    lines = [json.loads(line) for line in stdout.getvalue().splitlines()]
    assert lines[0]["event"] == "ready"
    return stdout.getvalue(), lines[0], {line["id"]: line for line in lines[1:]}


def get(core, path, request_id="g"):
    return run(core, {"id": request_id, "method": "GET", "path": path, "body": None})[2][request_id]


def release(core, case_id, sha):
    body = {"reason": "Injection only in an HTML comment; text needed", "passphrase": PASSPHRASE,
            "content_sha256": sha, "signer_id": SIGNER}
    raw, _, answers = run(core, {"id": "d", "method": "POST", "path": f"/api/quarantine/{case_id}/release",
                                 "body": body})
    return raw, answers["d"]


def test_ready_event_first_and_end_of_input_exits_cleanly(env):
    core = core_for()
    raw, ready, answers = run(core)
    assert answers == {} and raw.count(b"\n") == 1
    assert ready["body"] == {**core.session_info(), "protocol": PROTOCOL}
    assert set(ready["body"]) == {"mode", "version", "installed", "install", "projects", "protocol"}


def test_get_round_trip_against_a_trail(trail, held_case):
    core = core_for()
    _, _, answers = run(core, {"id": "r", "method": "GET", "path": "/api/trail/records?limit=500", "body": None},
                        {"id": "q", "method": "GET", "path": "/api/quarantine?state=all", "body": None},
                        {"id": "c", "method": "GET", "path": f"/api/quarantine/{held_case}", "body": None},
                        {"id": "x", "method": "GET", "path": "/api/nothing", "body": None})
    records = answers["r"]
    assert records["status"] == 200 and records["content_type"].startswith("application/json")
    assert records["body"]["total"] == len(trail_records(trail))
    assert {r["id"] for r in records["body"]["rows"]} == {r["id"] for r in trail_records(trail)}
    assert [c["case_id"] for c in answers["q"]["body"]["cases"]] == [held_case]
    assert answers["c"]["body"]["state"] == "held"
    assert answers["x"]["status"] == 404 and answers["x"]["body"]["ok"] is False


def test_downloads_come_as_text_or_base64_with_their_file_name(trail, held_case):
    core = core_for()
    sha = get(core, f"/api/quarantine/{held_case}")["body"]["content_sha256"]
    _, _, answers = run(core, *({"id": fmt, "method": "GET", "path": f"/api/signatures/manifest?sha256={sha}&format={fmt}",
                                 "body": None} for fmt in ("md", "html")),
                        {"id": "export", "method": "GET", "path": "/api/trail/export", "body": None})
    md, page, export = answers["md"], answers["html"], answers["export"]
    assert md["status"] == 200 and md["content_type"] == "text/markdown; charset=utf-8"
    assert md["filename"] == "signature-manifest.md" and sha in md["text"] and "body" not in md
    assert page["content_type"] == "application/octet-stream" and page["filename"] == "signature-manifest.html"
    assert page["text"].lstrip().lower().startswith("<!doctype html")
    assert export["content_type"] == "application/gzip" and export["filename"].endswith(".tar.gz")
    assert base64.b64decode(export["base64"])[:2] == b"\x1f\x8b"


def test_decision_is_refused_in_read_only_mode_without_a_record(trail, held_case):
    core = core_for(Mode(False, "started with --read-only", explicit=True))
    sha = get(core, f"/api/quarantine/{held_case}")["body"]["content_sha256"]
    before = len(trail_records(trail))
    raw, answer = release(core, held_case, sha)
    assert answer["status"] == 403 and answer["body"]["message"] == "refused: this aqt core was started with --read-only"
    assert len(trail_records(trail)) == before
    assert PASSPHRASE.encode() not in raw


def test_decision_from_an_app_started_by_an_agent_is_refused_and_recorded(trail, held_case):
    core = core_for(parent=["aqt-desktop", "bash", "claude", "systemd"])
    sha = get(core, f"/api/quarantine/{held_case}")["body"]["content_sha256"]
    _, answer = release(core, held_case, sha)
    assert answer["status"] == 403 and answer["body"]["reason_code"] == "agent_context"
    assert trail_records(trail)[-1]["type"] == "quarantine.refused"


def test_decision_is_accepted_with_a_human_parent(trail, held_case, env):
    core = core_for()
    sha = get(core, f"/api/quarantine/{held_case}")["body"]["content_sha256"]
    raw, answer = release(core, held_case, sha)
    assert answer["status"] == 200 and answer["body"]["ok"], answer
    assert answer["body"]["record_type"] == "quarantine.released"
    assert any(r["id"] == answer["body"]["record_id"] for r in trail_records(trail))
    assert get(core, f"/api/quarantine/{held_case}")["body"]["state"] == "released"
    assert any("decision" in line and "aqt-desktop" in line for line in core.log_lines)
    assert PASSPHRASE.encode() not in raw and all(PASSPHRASE not in line for line in core.log_lines)


def test_overlapping_requests_are_answered_by_id_one_line_each(env):
    fast_done = threading.Event()

    class Slow(Core):
        def handle(self, method, path, query, body=None, **kw):
            if path == "/api/slow":
                assert fast_done.wait(5), "the fast request was not answered while the slow one ran"
            else:
                fast_done.set()
            return Response(200, {"path": path, "query": query, "body": body})

    core = Slow(UiConfig(), Mode(False, "test"), log=lambda line: None)
    raw, _, answers = run(core, {"id": "a", "method": "GET", "path": "/api/slow", "body": None},
                          {"id": "b", "method": "POST", "path": "/api/fast?x=1", "body": {"k": "v"}},
                          {"id": 7, "method": "GET", "path": "/api/session"},
                          {"id": "c", "method": "DELETE", "path": "/api/session"})
    order = [json.loads(line).get("id") for line in raw.splitlines()[1:]]
    assert order.index("b") < order.index("a")
    assert answers["a"]["body"]["path"] == "/api/slow"
    assert answers["b"]["body"] == {"path": "/api/fast", "query": {"x": "1"}, "body": {"k": "v"}}
    assert answers[7]["status"] == 400 and answers["c"]["status"] == 405


def test_core_start_needs_no_terminal_but_no_agent():
    tty_less = io.StringIO()
    assert startup_mode(environ={}, chain=["aqt", *APP_PARENT], stdin=tty_less, terminal=False).decisions
    under_agent = startup_mode(environ={}, chain=["aqt", "aqt-desktop", "claude", "bash"], stdin=tty_less,
                               terminal=False)
    assert not under_agent.decisions and "process:claude" in under_agent.markers
    assert "outside any agent session" in under_agent.reason
    assert not startup_mode(environ={"CLAUDECODE": "1"}, chain=["aqt"], terminal=False).decisions
    peer = parent_peer()
    assert peer.pid == os.getppid() and (peer.chain or not sys.platform.startswith("linux"))


def test_mode_check_prints_the_start_up_verdict_of_its_caller():
    """The desktop app asks this before it opens another machine: started by an agent, the answer is read-only."""
    def check(*args, **env):
        done = subprocess.run([sys.executable, "-c", "import sys; from aqt_ui.core import main; sys.exit(main(sys.argv[1:]))",
                               "--mode-check", *args], env={**os.environ, **env}, capture_output=True, text=True, timeout=60)
        assert done.returncode == 0 and len(done.stdout.splitlines()) == 1, done.stderr
        return json.loads(done.stdout)
    agent = check(CLAUDECODE="1")
    assert agent["decisions"] is False and "env:CLAUDECODE" in agent["markers"] and agent["harness"] == "claude-code"
    assert "outside any agent session" in agent["reason"]
    assert check("--read-only") == {"decisions": False, "reason": "started with --read-only", "markers": [],
                                    "harness": None, "explicit": True}


NOISY = """
import subprocess, sys
from aqt_ui import core
handle = core.Core.handle
def noisy(self, *args, **kw):
    print("stray print")
    subprocess.run([sys.executable, "-c", "print('child output')"])
    return handle(self, *args, **kw)
core.Core.handle = noisy
from aqt_ui.cli import main
sys.exit(main(["core", "--stdio", "--read-only"]))
"""


def test_stdout_carries_only_protocol_lines(env):
    request = json.dumps({"id": "1", "method": "GET", "path": "/api/session", "body": None}) + "\n"
    done = subprocess.run([sys.executable, "-c", NOISY], input=request.encode(), capture_output=True, timeout=60)
    assert done.returncode == 0, done.stderr.decode()
    lines = [json.loads(line) for line in done.stdout.splitlines()]
    lines = [line for line in lines if line.get("event") != "queue"]       # the queue watcher may have looked
    assert [line.get("event") or line.get("id") for line in lines] == ["ready", "1"]
    assert lines[1]["status"] == 200 and lines[1]["body"]["mode"]["explicit"] is True
    assert b"stray print" in done.stderr and b"child output" in done.stderr


# -- the queue event --------------------------------------------------------------------------------------
def held(case_url="https://news.example/item"):
    """A new held quarantine case, as the hook would open it."""
    from conftest import INJECTION
    from aqt_quarantine.config import load_config
    from aqt_quarantine.engine import Engine, Source
    from aqt_quarantine.store import Store
    config = load_config()
    result = Engine(config, Store(config.state_dir, sink=config.sink)).scan(
        INJECTION, Source("WebFetch", case_url, "claude-code", "worker-1", "toolu_2"))
    assert result.band == "hold", result
    return result.case_id


def test_queue_watch_counts_first_then_reports_new_and_removed_cases(trail, signer):
    core = core_for()
    watch = QueueWatch(core)
    first = watch.poll()
    assert first["new"] == [] and first["removed"] == [] and first["count"] == len(watch.known)
    assert watch.poll() is None                                       # nothing changed: no event
    case_id = held()
    change = watch.poll()
    assert change["count"] == first["count"] + 1 and change["removed"] == []
    [entry] = change["new"]
    assert entry["id"] == f"quarantine:{case_id}" and entry["kind"] == "quarantine" and entry["key"] == "case_held"
    assert entry["title"] == "Quarantine holds content from news.example"
    assert entry["args"]["source"] == "news.example" and entry["args"]["case"] == case_id
    assert watch.poll() is None
    sha = get(core, f"/api/quarantine/{case_id}")["body"]["content_sha256"]
    _, answer = release(core, case_id, sha)
    assert answer["status"] == 200, answer
    assert watch.poll() == {"count": first["count"], "new": [], "removed": [f"quarantine:{case_id}"]}


def test_queue_event_follows_the_ready_event_while_the_core_runs(env):
    read, write = os.pipe()
    stdout = io.BytesIO()
    core = core_for()
    with os.fdopen(read, "rb") as stdin:
        runner = threading.Thread(target=serve, args=(core, stdin, stdout), kwargs={"queue_seconds": 0.05})
        runner.start()
        deadline = time.monotonic() + 10
        while stdout.getvalue().count(b"\n") < 2 and time.monotonic() < deadline:
            time.sleep(0.02)
        os.close(write)                          # end of input: the core stops, and so does the watcher
        runner.join(10)
    assert not runner.is_alive()
    lines = [json.loads(line) for line in stdout.getvalue().splitlines()]
    assert [line.get("event") for line in lines[:2]] == ["ready", "queue"]
    body = lines[1]["body"]
    assert body["new"] == [] and body["removed"] == [] and body["count"] >= 1     # a fresh HOME: no trail yet
    assert all(line.get("event") == "queue" for line in lines[1:])               # nothing changed after that
    assert queue_seconds({}) == 5.0 and queue_seconds({"AQT_CORE_QUEUE_SECONDS": "0"}) == 0
    assert queue_seconds({"AQT_CORE_QUEUE_SECONDS": "x"}) == 5.0
