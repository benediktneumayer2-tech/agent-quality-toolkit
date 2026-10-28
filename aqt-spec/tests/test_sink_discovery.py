"""Sink discovery: AQT_SINK, then the aqt-trail socket (or its spool), then the fallback file."""

import json
import shutil
import socket
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from aqt_evidence import (JsonlSink, SinkError, SocketSink, actor, evidence_sources, new_record, open_sink,
                          read_jsonl, resolve_sink, spool_file, state_dir)
from aqt_evidence import sink as sink_module


def record():
    return new_record("trail.event", actor("agent", "agent:claude-code:s1"), "step")


class FakeWriter:
    """Answers each connection like aqt-trail: ``ping`` -> ok, ``append`` -> the stored record."""

    def __init__(self, path: Path, ping_answer: dict | None = None):
        self.path, self.requests = path, []
        self.ping_answer = ping_answer or {"ok": True, "version": "test"}
        path.parent.mkdir(parents=True, exist_ok=True)
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(path))
        self.server.listen(8)
        self.server.settimeout(0.05)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.server.accept()
            except (TimeoutError, OSError):
                continue
            with connection:
                connection.settimeout(2)
                data = b""
                while chunk := connection.recv(65536):
                    data += chunk
                request = json.loads(data) if data else None
                self.requests.append(request)
                if request and request.get("op") == "append":
                    answer = {"ok": True, "record": request["record"]}
                else:
                    answer = self.ping_answer
                connection.sendall(json.dumps(answer).encode() + b"\n")

    def close(self):
        self.stop.set()
        self.thread.join()
        self.server.close()


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Throw-away XDG dirs, a short runtime dir (AF_UNIX path limit), no AQT_* overrides."""
    runtime = Path(tempfile.mkdtemp(prefix="aqt", dir="/tmp" if len(str(tmp_path)) > 60 else None))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    for name in ("AQT_SINK", "AQT_EVIDENCE", "AQT_TRAIL_STATE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(sink_module, "_warned", set())
    writers = []

    def start(path=None, **kwargs):
        writer = FakeWriter(path or runtime / "aqt" / "trail.sock", **kwargs)
        writers.append(writer)
        return writer

    yield SimpleNamespace(tmp=tmp_path, runtime=runtime, start=start)
    for writer in writers:
        writer.close()
    shutil.rmtree(runtime, ignore_errors=True)


def init_trail(env, state=None):
    state = state or env.tmp / "state" / "aqt" / "trail"
    state.mkdir(parents=True, exist_ok=True)
    (state / "trail.json").write_text("{}\n")
    return state


def test_no_trail_and_no_writer_uses_the_fallback_file_with_a_warning(env, capsys):
    route = resolve_sink()
    fallback = state_dir() / "evidence.jsonl"
    assert route["kind"] == "file" and route["target"] == str(fallback) and route["source"] == "default"
    assert route["writer"] is False and "fallback file" in route["warning"]
    sink = open_sink()
    assert isinstance(sink, JsonlSink) and sink.path == fallback
    first = sink.append(record())
    assert [r["id"] for r in read_jsonl(fallback)] == [first["id"]]
    assert capsys.readouterr().err == ""  # no trail here: the fallback is the normal place, status shows it


def test_a_writer_at_the_default_socket_is_discovered_with_a_ping_only(env, capsys):
    writer = env.start()
    route = resolve_sink()
    assert route == {"kind": "unix", "target": str(writer.path), "source": "discovered", "writer": True,
                     "warning": None}
    assert writer.requests == [{"op": "ping"}]  # never an empty connection or a record
    sink = open_sink()
    assert isinstance(sink, SocketSink) and sink.path == str(writer.path)
    first = record()
    assert sink.append(first)["id"] == first["id"] and not sink.last_spooled
    assert writer.requests[-1] == {"op": "append", "record": first}
    assert not (state_dir() / "evidence.jsonl").exists() and capsys.readouterr().err == ""


def test_socket_from_trail_toml_and_trail_state_from_env(env, monkeypatch):
    configured = env.runtime / "w.sock"
    (env.tmp / "config" / "aqt").mkdir(parents=True)
    (env.tmp / "config" / "aqt" / "trail.toml").write_text(f'[writer]\nsocket = "{configured}"\n')
    writer = env.start(configured)
    assert resolve_sink()["target"] == str(configured) and resolve_sink()["writer"] is True
    writer.close()
    custom = init_trail(env, env.tmp / "elsewhere")
    monkeypatch.setenv("AQT_TRAIL_STATE", str(custom))
    route = resolve_sink()
    assert (route["kind"], route["target"], route["writer"]) == ("unix", str(configured), False)


def test_initialised_trail_without_writer_spools_and_warns_once(env, capsys):
    init_trail(env)
    route = resolve_sink()
    assert route["kind"] == "unix" and route["source"] == "discovered" and route["writer"] is False
    assert "spooled" in route["warning"] and str(spool_file()) in route["warning"]
    sink = open_sink()
    first, second = record(), record()
    sink.append(first)
    open_sink().append(second)
    assert sink.last_spooled
    assert [r["id"] for r in read_jsonl(spool_file())] == [first["id"], second["id"]]
    assert not (state_dir() / "evidence.jsonl").exists()
    err = capsys.readouterr().err
    assert err.count("aqt: warning:") == 1 and "spooled" in err
    assert spool_file() in evidence_sources()  # readers still find the spooled records


def test_initialised_trail_with_writer_needs_no_probe_in_open_sink(env):
    init_trail(env)
    writer = env.start()
    first = record()
    open_sink().append(first)
    assert writer.requests == [{"op": "append", "record": first}]  # route known: no ping per tool call
    assert resolve_sink()["writer"] is True and writer.requests[-1] == {"op": "ping"}


def test_explicit_aqt_sink_always_wins(env, monkeypatch, capsys):
    writer = env.start()
    init_trail(env)
    explicit = env.tmp / "mine.jsonl"
    monkeypatch.setenv("AQT_SINK", f"file:{explicit}")
    assert resolve_sink() == {"kind": "file", "target": str(explicit), "source": "env", "writer": None,
                              "warning": None}
    sink = open_sink()
    assert isinstance(sink, JsonlSink) and sink.path == explicit
    sink.append(record())
    assert writer.requests == [] and evidence_sources()[0] == explicit

    other = env.runtime / "other.sock"
    monkeypatch.setenv("AQT_SINK", f"unix:{other}")
    route = resolve_sink()
    assert (route["kind"], route["target"], route["source"], route["writer"]) == ("unix", str(other), "env", False)
    assert "spooled" in route["warning"]
    sink = open_sink()
    sink.append(record())
    assert sink.path == str(other) and sink.last_spooled  # still the configured socket, spooled as before
    assert "aqt: warning:" in capsys.readouterr().err
    other_writer = env.start(other)
    assert resolve_sink()["writer"] is True and resolve_sink()["warning"] is None
    assert other_writer.requests and writer.requests == []

    monkeypatch.setenv("AQT_SINK", "tcp:localhost")
    with pytest.raises(SinkError):
        resolve_sink()
    with pytest.raises(SinkError):
        open_sink()


def test_a_refused_ping_is_a_warning(env):
    env.start(ping_answer={"ok": False, "code": "unauthorized", "message": "uid 1 may not append"})
    route = resolve_sink()
    assert route["kind"] == "unix" and route["writer"] is True and "unauthorized" in route["warning"]


def test_a_hung_writer_does_not_block_discovery(env, monkeypatch):
    monkeypatch.setattr(sink_module, "PROBE_TIMEOUT", 0.05)
    path = env.runtime / "aqt" / "trail.sock"
    path.parent.mkdir(parents=True)
    hung = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    hung.bind(str(path))
    hung.listen(1)  # accepts into the backlog, never answers
    try:
        route = resolve_sink()
    finally:
        hung.close()
    assert route["kind"] == "file" and route["writer"] is False


def test_evidence_sources_follow_the_trail_state(env, monkeypatch):
    custom = init_trail(env, env.tmp / "elsewhere")
    (custom / "trail.jsonl").write_text("")
    monkeypatch.setenv("AQT_TRAIL_STATE", str(custom))
    assert evidence_sources() == [custom / "trail.jsonl"]
    assert evidence_sources({}) == []  # environ supplies the AQT_* variables
