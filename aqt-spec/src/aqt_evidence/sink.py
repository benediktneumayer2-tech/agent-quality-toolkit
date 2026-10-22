"""Where tools write their records.

``AQT_SINK`` selects the destination:
- ``file:/path/evidence.jsonl`` appends records as JSON lines (locked, fsynced);
- ``unix:/path/aqt-trail.sock`` sends them to an aqt-trail writer service.
Without ``AQT_SINK`` records go to ``$XDG_STATE_HOME/aqt/evidence.jsonl``.

Trail socket protocol (one JSON object per line, one request per connection):
request ``{"op": "append", "record": {...}}``; response
``{"ok": true, "record": {...stored record with chain, time and observed...}}`` or
``{"ok": false, "code": "...", "message": "..."}`` with ``code`` one of
``invalid_record``, ``unauthorized``, ``duplicate_id``, ``unavailable``, ``internal``.
Appends are idempotent by record ``id``.

When the socket cannot be reached, ``SocketSink`` spools the record to
``$XDG_STATE_HOME/aqt/spool/spool.jsonl`` and sets ``last_spooled``; aqt-trail
drains the spool later behind a ``trail.gap`` record. ``spool=False`` raises instead.
"""

from __future__ import annotations

import fcntl
import json
import os
import socket
from pathlib import Path
from typing import Iterator, Protocol

from .canonical import canonical_json
from .record import validate_record


class SinkError(RuntimeError):
    pass


class SinkUnavailable(SinkError):
    """The aqt-trail socket could not be reached (nothing was stored by the service)."""


ERROR_CODES = ("invalid_record", "unauthorized", "duplicate_id", "unavailable", "internal")


class Sink(Protocol):
    def append(self, record: dict) -> dict: ...


def state_dir() -> Path:
    return Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state") / "aqt"


def spool_file() -> Path:
    """Where ``SocketSink`` spools records while aqt-trail is unavailable."""
    return state_dir() / "spool" / "spool.jsonl"


class JsonlSink:
    """Append-only JSON-lines file. Does not chain; aqt-trail does."""

    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)

    def append(self, record: dict) -> dict:
        errors = validate_record(record)
        if errors:
            raise SinkError("; ".join(errors))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "ab") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                handle.write(canonical_json(record) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)
        return record


class SocketSink:
    """Client for an aqt-trail writer listening on a Unix socket."""

    def __init__(self, path: str | os.PathLike, *, timeout: float = 5.0, spool: bool = True,
                 spool_path: str | os.PathLike | None = None):
        self.path, self.timeout = str(path), timeout
        self.spool, self.spool_path = spool, spool_path
        self.last_spooled = False

    def request(self, payload: dict) -> dict:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(self.timeout)
            try:
                client.connect(self.path)
                client.sendall(canonical_json(payload) + b"\n")
                client.shutdown(socket.SHUT_WR)
                chunks = []
                while chunk := client.recv(65536):
                    chunks.append(chunk)
            except OSError as error:
                raise SinkUnavailable(f"aqt-trail socket {self.path}: {error}") from error
        try:
            return json.loads(b"".join(chunks).decode("utf-8"))
        except ValueError as error:
            raise SinkError("aqt-trail sent an unreadable response") from error

    def append(self, record: dict) -> dict:
        """Send ``record``; on an unreachable socket spool it (unless ``spool=False``).
        Returns the stored record, or the record itself when spooled."""
        self.last_spooled = False
        try:
            response = self.request({"op": "append", "record": record})
        except SinkUnavailable:
            if not self.spool:
                raise
            JsonlSink(self.spool_path or spool_file()).append(record)
            self.last_spooled = True
            return record
        if not response.get("ok"):
            raise SinkError(f"{response.get('code', 'error')}: {response.get('message', 'append refused')}")
        return response["record"]


def open_sink(spec: str | None = None) -> Sink:
    spec = spec or os.environ.get("AQT_SINK")
    if not spec:
        return JsonlSink(state_dir() / "evidence.jsonl")
    if spec.startswith("file:"):
        return JsonlSink(spec[5:])
    if spec.startswith("unix:"):
        return SocketSink(spec[5:])
    raise SinkError("AQT_SINK must start with file: or unix:")


def read_jsonl(path: str | os.PathLike) -> Iterator[dict]:
    """Yield records from a JSON-lines file; a bad line raises with its line number."""
    with open(path, "rb") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except ValueError as error:
                raise SinkError(f"{path}:{number}: not valid JSON") from error


def evidence_sources(environ: dict | None = None) -> list[Path]:
    """Files other tools read records from: ``AQT_EVIDENCE`` (colon-separated paths) or,
    by default, the default sink file and the aqt-trail log, when they exist."""
    environ = os.environ if environ is None else environ
    if environ.get("AQT_EVIDENCE"):
        return [Path(part) for part in environ["AQT_EVIDENCE"].split(":") if part]
    sink = environ.get("AQT_SINK", "")
    candidates = [Path(sink[5:])] if sink.startswith("file:") else [state_dir() / "evidence.jsonl"]
    candidates.append(state_dir() / "trail" / "trail.jsonl")
    return [path for path in candidates if path.exists()]


def iter_evidence(paths: list[Path] | None = None) -> Iterator[dict]:
    """All records from ``paths`` (default ``evidence_sources()``), file by file, deduplicated by id."""
    seen: set[str] = set()
    for path in evidence_sources() if paths is None else paths:
        for record in read_jsonl(path):
            identity = record.get("id") if isinstance(record, dict) else None
            if identity in seen:
                continue
            if identity:
                seen.add(identity)
            yield record
