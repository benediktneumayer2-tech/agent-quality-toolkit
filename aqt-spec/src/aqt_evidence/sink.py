"""Where tools write their records.

``open_sink()`` without an argument uses ``resolve_sink()``, which picks, in this order:
1. ``AQT_SINK``: ``file:/path/evidence.jsonl`` appends records as JSON lines (locked,
   fsynced); ``unix:/path/aqt-trail.sock`` sends them to an aqt-trail writer service.
2. The aqt-trail writer socket at its default place (``[writer] socket`` in
   ``$XDG_CONFIG_HOME/aqt/trail.toml``, else ``$XDG_RUNTIME_DIR/aqt/trail.sock``, else
   ``aqt-trail.sock`` in the trail state directory), when a writer answers there or a
   trail has been initialised (``trail.json`` in the trail state directory). A trail
   whose writer is down gets the records through the spool below.
3. The fallback file ``$XDG_STATE_HOME/aqt/evidence.jsonl`` (not chained, not in a trail).
Degraded routes carry a warning in ``resolve_sink()``; spooling also prints one line on
stderr per process.

Trail socket protocol (one JSON object per line, one request per connection):
request ``{"op": "append", "record": {...}}``; response
``{"ok": true, "record": {...stored record with chain, time and observed...}}`` or
``{"ok": false, "code": "...", "message": "..."}`` with ``code`` one of
``invalid_record``, ``unauthorized``, ``duplicate_id``, ``unavailable``, ``internal``.
Appends are idempotent by record ``id``. Discovery checks the writer with the aqt-trail
request ``{"op": "ping"}``, which stores nothing.

When the socket cannot be reached, ``SocketSink`` spools the record to
``$XDG_STATE_HOME/aqt/spool/spool.jsonl`` and sets ``last_spooled``; aqt-trail
drains the spool later behind a ``trail.gap`` record. ``spool=False`` raises instead.
"""

from __future__ import annotations

import fcntl
import json
import os
import socket
import sys
import tomllib
from pathlib import Path
from typing import Iterator, Protocol

from .canonical import canonical_json
from .record import validate_record


class SinkError(RuntimeError):
    pass


class SinkUnavailable(SinkError):
    """The aqt-trail socket could not be reached (nothing was stored by the service)."""


ERROR_CODES = ("invalid_record", "unauthorized", "duplicate_id", "unavailable", "internal")
PROBE_TIMEOUT = 0.5  # seconds for the discovery ping; a local writer answers in about a millisecond
_warned: set[str] = set()


def _warn_once(message: str) -> None:
    if message not in _warned:
        _warned.add(message)
        print(f"aqt: warning: {message}", file=sys.stderr)


def _spool_warning(socket_path, spool) -> str:
    return (f"no aqt-trail writer answers at {socket_path}; records are spooled to {spool} "
            "and reach the trail when the writer runs (aqt-trail serve)")


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
            spool = self.spool_path or spool_file()
            JsonlSink(spool).append(record)
            self.last_spooled = True
            _warn_once(_spool_warning(self.path, spool))
            return record
        if not response.get("ok"):
            raise SinkError(f"{response.get('code', 'error')}: {response.get('message', 'append refused')}")
        return response["record"]


def _trail_location(environ) -> tuple[Path, Path]:
    """aqt-trail's state directory and writer socket, computed as ``aqt_trail.config`` does
    (``trail.toml`` ``[trail] state`` and ``[writer] socket``, ``AQT_TRAIL_STATE``, XDG dirs)."""
    config = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "aqt" / "trail.toml"
    try:
        with open(config, "rb") as handle:
            values = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        values = {}
    trail, writer = (values.get(name) if isinstance(values.get(name), dict) else {} for name in ("trail", "writer"))
    state = Path(trail.get("state") or environ.get("AQT_TRAIL_STATE") or state_dir() / "trail")
    if writer.get("socket"):
        return state, Path(writer["socket"])
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    return state, (Path(runtime) / "aqt" / "trail.sock" if runtime else state / "aqt-trail.sock")


def _ping(path) -> dict | None:
    """The writer's answer to ``{"op": "ping"}``, or None when nothing answers. (aqt-trail
    records a connection that closes without a request as a refused request; a ping stores nothing.)"""
    try:
        answer = SocketSink(path, timeout=PROBE_TIMEOUT, spool=False).request({"op": "ping"})
    except SinkError:
        return None
    return answer if isinstance(answer, dict) else None


def _resolve(environ, *, probe: bool) -> dict:
    def route(kind, target, source, writer=None, warning=None):
        return {"kind": kind, "target": str(target), "source": source, "writer": writer, "warning": warning}

    def answered(target, answer):
        if answer.get("ok"):
            return route("unix", target, source, True)
        return route("unix", target, source, True, f"the aqt-trail writer at {target} refused the check: "
                                                     f"{answer.get('code', 'error')}: {answer.get('message', '')}")

    spec = environ.get("AQT_SINK")
    if spec:
        source = "env"
        if spec.startswith("file:"):
            return route("file", spec[5:], source)
        if not spec.startswith("unix:"):
            raise SinkError("AQT_SINK must start with file: or unix:")
        target = spec[5:]
    else:
        source = "discovered"
        trail, target = _trail_location(environ)
        if not (trail / "trail.json").exists():  # no trail here: only a writer that answers counts
            answer = _ping(target)
            if answer is not None:
                return answered(target, answer)
            fallback = state_dir() / "evidence.jsonl"
            return route("file", fallback, "default", False,
                         f"no aqt-trail writer answers at {target}; records go to the fallback file {fallback}, "
                         "not into a trail (aqt-trail init and aqt-trail serve, or set AQT_SINK)")
    if not probe:
        return route("unix", target, source)
    answer = _ping(target)
    if answer is None:
        return route("unix", target, source, False, _spool_warning(target, spool_file()))
    return answered(target, answer)


def resolve_sink(environ: dict | None = None) -> dict:
    """Where ``open_sink()`` sends records, and how sure that is.

    Returns ``kind`` (``"file"`` or ``"unix"``), ``target`` (path), ``source`` (``"env"`` for
    ``AQT_SINK``, ``"discovered"`` for the aqt-trail socket, ``"default"`` for the fallback
    file), ``writer`` (True when a writer answered a ping, False when none did, None when not
    asked: a ``file:`` ``AQT_SINK``) and ``warning`` (None, or why records may be missing from
    the trail). ``environ`` supplies the ``AQT_*`` variables; directories come from the
    process environment, as in ``state_dir()``. A malformed ``AQT_SINK`` raises ``SinkError``.
    """
    return _resolve(os.environ if environ is None else environ, probe=True)


def open_sink(spec: str | None = None) -> Sink:
    """The sink for ``spec`` (``file:PATH`` or ``unix:PATH``) or, without one, for ``resolve_sink()``.
    It only pings when that decides the route (no initialised trail here)."""
    if not spec:
        route = _resolve(os.environ, probe=False)
        spec = f"{route['kind']}:{route['target']}"
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
    """Files other tools read records from: ``AQT_EVIDENCE`` (colon-separated paths) or, by
    default, the sink file, the aqt-trail log and the spool (records not yet in the trail),
    when they exist."""
    environ = os.environ if environ is None else environ
    if environ.get("AQT_EVIDENCE"):
        return [Path(part) for part in environ["AQT_EVIDENCE"].split(":") if part]
    sink = environ.get("AQT_SINK", "")
    candidates = [Path(sink[5:])] if sink.startswith("file:") else [state_dir() / "evidence.jsonl"]
    candidates += [_trail_location(environ)[0] / "trail.jsonl", spool_file()]
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
