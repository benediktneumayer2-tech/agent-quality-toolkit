"""``aqt-trail serve``: the writer behind a Unix socket (on Windows a named pipe, ``PipeTrailServer``).

Protocol (one JSON request per connection, client closes its write side):
``append`` (aqt-spec spec §10.2), ``drain`` (spooled records), ``checkpoint``
(signed head, optional RFC 3161 anchor from the configured TSA or external-head
note), ``head``, ``ping``.
Errors use the spec §10.2 codes ``invalid_record``, ``unauthorized``, ``duplicate_id``,
``unavailable`` and ``internal``.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import socketserver
import threading
import time
from pathlib import Path

from aqt_evidence import bytes_hash, canonical_json, platform

from . import __version__
from .anchors import checkpoint, record_external_head
from .client import locked_spool
from .config import Config, spool_path
from .observe import observe, peer_credentials, peer_pidfd
from .state import open_writer
from .writer import Refused, TrailWriter


def drain_local_spool(writer: TrailWriter, path: str | os.PathLike | None = None, *, drainer: dict | None = None):
    """Drain a spool file the writer process can read; returns the ``DrainResult`` or None."""
    path = Path(path) if path else spool_path()
    try:
        with locked_spool(path) as (entries, clear):
            if not entries:
                return None
            result = writer.drain(entries, source=str(path), drainer=drainer)
            clear()
            return result
    except PermissionError:
        return None


class _Handler(socketserver.BaseRequestHandler):
    server: "TrailServer"

    def _read(self) -> bytes:
        self.request.settimeout(5.0)
        chunks, size = [], 0
        while chunk := self.request.recv(65536):
            chunks.append(chunk)
            size += len(chunk)
            if size > self.server.max_request_bytes:
                raise ValueError("request too large")
        return b"".join(chunks)

    def handle(self):
        try:
            response = self._dispatch()
        except Exception as error:  # never let one client take the writer down
            response = {"ok": False, "code": "internal", "message": f"{type(error).__name__}: {error}"[:300]}
        try:
            self.request.sendall(canonical_json(response) + b"\n")
        except OSError:
            pass

    def _dispatch(self) -> dict:
        writer = self.server.writer
        pid, uid, gid = peer_credentials(self.request)
        pidfd = peer_pidfd(self.request)
        try:
            observed = observe(pid, uid, gid, via="socket", pidfd=pidfd)
        finally:
            if pidfd is not None:
                os.close(pidfd)
        try:
            raw = self._read()
        except (OSError, ValueError) as error:
            return {"ok": False, "code": "invalid_record", "message": str(error)}
        try:
            payload = json.loads(raw)
            op = payload.get("op") if isinstance(payload, dict) else None
        except ValueError:
            refused = writer.refuse("invalid_record", "request is not JSON", raw.decode("utf-8", "replace")[:2000],
                                    observed)
            return {"ok": False, "code": refused.code, "message": refused.message}
        if uid not in self.server.allowed_uids:
            refused = writer.refuse("unauthorized", f"uid {uid} may not append", payload.get("record"), observed,
                                    attempted_action=str(op))
            return {"ok": False, "code": refused.code, "message": refused.message}
        if op == "ping":
            return {"ok": True, "version": __version__}
        if op == "head":
            with writer.lock:
                return {"ok": True, "log_id": writer.log_id, "seq": writer.seq, "head": writer.head}
        if op == "append":
            try:
                stored, created = writer.append(payload.get("record"), observed)
            except Refused as refused:
                return {"ok": False, "code": refused.code, "message": refused.message}
            return {"ok": True, "record": stored, "created": created}
        if op == "checkpoint":
            wanted = str(payload.get("tsa_url") or "")
            if payload.get("anchor") and not self.server.tsa_allowed(wanted):
                refused = writer.refuse("unauthorized", f"the writer anchors only with its configured TSA "
                                        f"([anchor] tsa_url), not {wanted[:200]!r}", None, observed,
                                        attempted_action="checkpoint")
                return {"ok": False, "code": refused.code, "message": refused.message}
            point, anchor = self.server.checkpoint(anchor=bool(payload.get("anchor")),
                                                   export=bool(payload.get("export")), tsa_url=wanted)
            return {"ok": True, "checkpoint": point, "anchor": anchor}
        if op == "drain":
            records = payload.get("records")
            if not isinstance(records, list):
                return {"ok": False, "code": "invalid_record", "message": "drain needs a list of records"}
            result = writer.drain(records, source=str(payload.get("source", "client spool"))[:300], drainer=observed)
            return {"ok": True, "appended": len(result.appended), "already_stored": len(result.already_stored),
                    "refused": len(result.refused), "gap": result.gap["id"] if result.gap else None}
        refused = writer.refuse("invalid_record", f"unknown op {op!r}", payload.get("record"), observed,
                                attempted_action=str(op))
        return {"ok": False, "code": refused.code, "message": refused.message}


class _TrailService:
    """What the writer's server does on every system; the transport is the subclass's."""

    def _setup(self, writer: TrailWriter, *, allowed_uids, max_request_bytes: int, spool, drain_interval_s: float,
               anchor: dict | None) -> None:
        self.writer, self.max_request_bytes = writer, max_request_bytes
        self.anchor = anchor or {}
        self.allowed_uids = set(allowed_uids or []) | {platform.user_id()}
        self.spool, self.drain_interval_s, self._last_drain = spool, drain_interval_s, time.monotonic()

    def tsa_allowed(self, url: str) -> bool:
        """A client may name only the configured TSA, or ``test:`` (the TEST ONLY authority in the
        writer's own state directory, which ``verify`` trusts only with ``--test-tsa``). Any other URL,
        and ``test:<dir>``, comes from the writer's configuration or not at all."""
        return url in ("", "test:", str(self.anchor.get("tsa_url", "")))

    def checkpoint(self, *, anchor: bool = False, export: bool = False, tsa_url: str = ""):
        if anchor and not self.tsa_allowed(tsa_url):
            raise ValueError(f"the writer anchors only with its configured TSA, not {tsa_url[:200]!r}")
        url = (tsa_url or self.anchor.get("tsa_url", "")) if anchor else ""
        if anchor and not url:
            raise ValueError("no TSA configured ([anchor] tsa_url or --tsa)")
        point, record = checkpoint(self.writer, tsa_url=url,
                                   timeout=float(self.anchor.get("timeout_s", 10)),
                                   test_dir=self.writer.state / "test-tsa")
        if export:
            record = record_external_head(self.writer, point)
        return point, record

    def service_actions(self):
        if self.drain_interval_s and time.monotonic() - self._last_drain >= self.drain_interval_s:
            self._last_drain = time.monotonic()
            drain_local_spool(self.writer, self.spool)


if hasattr(socketserver, "UnixStreamServer"):   # every system with Unix sockets (not Windows)
    class UnixTrailServer(_TrailService, socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        """The writer behind a Unix socket (Linux, macOS)."""
        daemon_threads = True
        allow_reuse_address = False

        def __init__(self, socket_path: str | os.PathLike, writer: TrailWriter, *, mode: int = 0o600,
                     group: str = "", allowed_uids: list[int] | None = None, max_request_bytes: int = 16 << 20,
                     spool: str | os.PathLike | None = None, drain_interval_s: float = 30,
                     anchor: dict | None = None):
            self._setup(writer, allowed_uids=allowed_uids, max_request_bytes=max_request_bytes, spool=spool,
                        drain_interval_s=drain_interval_s, anchor=anchor)
            path = Path(socket_path)
            self.socket_path = path
            if len(os.fsencode(path)) > 104:
                raise ValueError(f"socket path is too long for AF_UNIX ({len(os.fsencode(path))} bytes): {path}; "
                                 "set [writer] socket to a shorter path")
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists() or path.is_socket():
                probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    probe.connect(str(path))
                except OSError:
                    path.unlink()  # stale socket from a writer that is gone
                else:
                    raise RuntimeError(f"a writer is already listening on {path}")
                finally:
                    probe.close()
            old = os.umask(0o177)
            try:
                socketserver.UnixStreamServer.__init__(self, str(path), _Handler)
            finally:
                os.umask(old)
            if group:
                import grp   # POSIX only, and only for the separate-user mode
                os.chown(path, -1, grp.getgrnam(group).gr_gid)
            os.chmod(path, mode)

        def server_close(self):
            super().server_close()
            try:
                self.socket_path.unlink()
            except OSError:
                pass


class PipeTrailServer(_TrailService):
    """The writer on Windows: the same requests over a named pipe that only the user can open
    (``aqt_evidence.pipes``). ``serve_forever``, ``shutdown`` and ``server_close`` behave as in
    ``socketserver``; each client gets a thread."""

    def __init__(self, socket_path: str | os.PathLike, writer: TrailWriter, *, mode: int = 0o600,
                 group: str = "", allowed_uids: list | None = None, max_request_bytes: int = 16 << 20,
                 spool: str | os.PathLike | None = None, drain_interval_s: float = 30,
                 anchor: dict | None = None):
        from aqt_evidence import pipes
        self._setup(writer, allowed_uids=allowed_uids, max_request_bytes=max_request_bytes, spool=spool,
                    drain_interval_s=drain_interval_s, anchor=anchor)
        name = str(socket_path)
        if not platform.is_pipe(name):
            raise ValueError(f"on Windows the writer listens on a named pipe (\\\\.\\pipe\\<name>), not on {name}; "
                             "set [writer] socket to such a name or leave it empty")
        if group:
            raise ValueError(platform.not_available("[writer] socket_group (separate-user mode)"))
        self.socket_path = Path(name)
        try:
            self._listener = pipes.PipeListener(name)
        except FileExistsError:
            raise RuntimeError(f"a writer is already listening on {name}") from None
        self._stop, self._stopped = threading.Event(), threading.Event()
        self._stopped.set()

    def serve_forever(self, poll_interval: float = 0.5) -> None:
        self._stopped.clear()
        try:
            while not self._stop.is_set():
                try:
                    connection = self._listener.accept(timeout=poll_interval)
                except InterruptedError:     # Ctrl+C: the signal handler decides
                    continue
                if connection is not None:
                    threading.Thread(target=self._handle, args=(connection,), daemon=True).start()
                self.service_actions()
        finally:
            self._stop.clear()
            self._stopped.set()

    def _handle(self, connection) -> None:
        try:
            _Handler(connection, None, self)
        finally:
            connection.close()

    def shutdown(self) -> None:
        """Stop ``serve_forever`` and wait until it has returned."""
        if not self._stopped.is_set():
            self._stop.set()
            self._stopped.wait()

    def server_close(self) -> None:
        self._listener.close()


TrailServer = PipeTrailServer if platform.IS_WINDOWS else UnixTrailServer


def build_server(config: Config, writer: TrailWriter) -> TrailServer:
    section = config.section("writer")
    # uids are numbers on POSIX and SID strings (S-1-5-21-...) on Windows
    uids = [str(u) if platform.IS_WINDOWS else int(u) for u in section["allowed_uids"]]
    return TrailServer(config.socket_path, writer, mode=int(str(section["socket_mode"]), 8),
                       group=section["socket_group"], allowed_uids=uids,
                       max_request_bytes=int(section["max_request_bytes"]),
                       drain_interval_s=float(section["drain_interval_s"]), anchor=config.section("anchor"))


def start_event(config: Config, writer: TrailWriter) -> dict:
    return writer.write_internal("trail.event", "service.start", data={
        "version": __version__, "log_id": writer.log_id, "key_id": writer.signer.key_id, "pid": os.getpid(),
        "socket": str(config.socket_path), "config_sha256": bytes_hash(json.dumps(config.values, sort_keys=True, default=str).encode())})


def run_service(config: Config, *, ready=None) -> int:
    writer = open_writer(config)
    try:
        server = build_server(config, writer)
    except Exception:
        writer.close()
        raise
    stop_reason = {"value": "stopped"}

    def stop(signum, _frame):
        stop_reason["value"] = signal.Signals(signum).name
        threading.Thread(target=server.shutdown, daemon=True).start()

    # Windows: Ctrl+C and Ctrl+Break (SIGBREAK, what a console or a parent sends a process group) stop the writer
    # with its service.stop record; SIGTERM there is TerminateProcess, which ends it without one
    for which in (signal.SIGTERM, signal.SIGINT, *([signal.SIGBREAK] if hasattr(signal, "SIGBREAK") else [])):
        signal.signal(which, stop)
    try:
        start_event(config, writer)
        drain_local_spool(writer)
        if ready:
            ready(server)
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        writer.write_internal("trail.event", "service.stop", data={"signal": stop_reason["value"]})
        writer.close()
    return 0
