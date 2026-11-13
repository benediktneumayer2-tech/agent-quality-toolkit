"""Records: built on the proxy's event loop, appended by one background thread.

Records go where ``aqt_evidence.open_sink()`` sends them (spec section 10.1): to the aqt-trail writer
when one runs, else to the fallback file. While a trail's writer does not answer, they wait in
aqt-egress's **own** spool (``$XDG_STATE_HOME/aqt/egress/spool.jsonl``, hidden in the box and opened
without following symlinks), never in the shared spool, which the box can write for its hooks.
``drain_spool`` moves them into the trail later (at the start and end of each session, and with
``aqt egress drain``). The writer attributes the records to this process; what the box sent is in
``data.process``.
"""

from __future__ import annotations

import json
import os
import queue
import sys
import threading
from pathlib import Path

from aqt_evidence import SinkUnavailable, SocketSink, actor, canonical_json, new_record, open_sink, platform

from .settings import egress_state, private_dir

ACTOR = actor("service", "service:aqt-egress")
SPOOL_NAME = "spool.jsonl"


def spool_path() -> Path:
    return egress_state() / SPOOL_NAME


def _open_spool(path: Path, flags: int) -> int:
    private_dir(path.parent)
    return platform.open_nofollow(path, flags | platform.O_CLOEXEC, 0o600)


def spool_append(record: dict, path: Path | None = None) -> None:
    fd = _open_spool(path or spool_path(), os.O_WRONLY | os.O_CREAT | os.O_APPEND)
    with os.fdopen(fd, "ab") as handle:
        platform.lock(handle)
        handle.write(canonical_json(record) + b"\n")
        handle.flush()
        os.fsync(handle.fileno())


class EgressSink:
    """``open_sink()``'s route, with aqt-egress's own spool instead of the shared one."""

    def __init__(self, sink=None, *, spool: Path | None = None):
        sink = sink if sink is not None else open_sink()
        self.spool = spool or spool_path()
        self.socket = SocketSink(sink.path, spool=False) if isinstance(sink, SocketSink) else None
        self.other = None if self.socket else sink

    def append(self, record: dict) -> str:
        """Append ``record``; returns the route: ``trail``, ``spooled`` or ``file``."""
        if self.other is not None:
            self.other.append(record)
            return "file"
        try:
            self.socket.append(record)
            return "trail"
        except SinkUnavailable:
            spool_append(record, self.spool)
            return "spooled"


def drain_spool(sink: EgressSink | None = None) -> dict:
    """Send the records waiting in aqt-egress's spool to the trail writer ({"op": "drain"})."""
    sink = sink or EgressSink()
    if sink.socket is None or not sink.spool.exists():
        return {"drained": 0}
    fd = _open_spool(sink.spool, os.O_RDWR)
    with os.fdopen(fd, "r+b") as handle:
        platform.lock(handle)
        entries = [json.loads(line) for line in handle.read().splitlines() if line.strip()]
        if not entries:
            return {"drained": 0}
        try:
            answer = sink.socket.request({"op": "drain", "records": entries, "source": "aqt-egress spool"})
        except SinkUnavailable as error:
            return {"drained": 0, "waiting": len(entries), "error": str(error)}
        if not answer.get("ok"):
            return {"drained": 0, "waiting": len(entries), "error": answer.get("message", "drain refused")}
        handle.seek(0)
        handle.truncate()
        handle.flush()
        os.fsync(handle.fileno())
    return {"drained": len(entries), "appended": answer.get("appended", 0)}


class RecordWriter:
    def __init__(self, sink=None, *, log=None):
        self.sink = sink if isinstance(sink, EgressSink) else EgressSink(sink)
        self.queue: queue.Queue = queue.Queue()
        self.routes = {"trail": 0, "spooled": 0, "file": 0}
        self.failed = 0
        self.last_error: str | None = None
        self.log = log
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._run, name="aqt-egress-records", daemon=True)
        self.thread.start()

    @property
    def written(self) -> int:
        return sum(self.routes.values())

    def record(self, type_: str, action: str, data: dict, *, subject=None, links=None) -> dict:
        return new_record(type_, ACTOR, action, subject=subject, links=links, data=data)

    def emit(self, type_: str, action: str, data: dict, *, subject: dict | None = None,
             links: list[dict] | None = None) -> str:
        """Queue a record; returns its id at once."""
        record = self.record(type_, action, data, subject=subject, links=links)
        self.queue.put(record)
        return record["id"]

    def submit(self, build) -> None:
        """Queue ``build() -> (type, action, data, subject, links)``; it runs on the record thread
        (where the body store does its work), then the record is appended."""
        self.queue.put(build)

    def append_now(self, record: dict) -> bool:
        """Append in the calling thread (records that must exist before traffic flows)."""
        try:
            route = self.sink.append(record)
        except Exception as error:  # noqa: BLE001 - counted, reported in the ended record
            self._failed(f"{type(error).__name__}: {error}", record.get("type", "?"))
            return False
        with self.lock:
            self.routes[route] += 1
        return True

    def _failed(self, message: str, name: str) -> None:
        with self.lock:
            self.failed += 1
            self.last_error = message
        if self.log:
            self.log(f"{name} not written: {message}")

    def _run(self) -> None:
        while True:
            item = self.queue.get()
            if item is None:
                return
            try:
                if callable(item):
                    type_, action, data, subject, links = item()
                    item = self.record(type_, action, data, subject=subject, links=links)
            except Exception as error:  # noqa: BLE001
                self._failed(f"{type(error).__name__}: {error}", "deferred record")
                continue
            self.append_now(item)

    def close(self, timeout: float = 30.0) -> None:
        """Write what is queued; what is still queued after ``timeout`` counts as lost."""
        self.queue.put(None)
        self.thread.join(timeout)
        lost = self.queue.qsize()
        if lost:
            with self.lock:
                self.failed += lost
                self.last_error = f"{lost} record(s) still queued at shutdown"

    def report(self) -> None:
        if self.failed:
            print(f"aqt-egress: {self.failed} record(s) could not be written ({self.last_error})", file=sys.stderr)
