"""``aqt-trail serve``: the writer behind a Unix socket.

Protocol (one JSON request per connection, client closes its write side):
``append`` (aqt-spec spec §10.2), ``drain`` (spooled records), ``checkpoint``
(signed head, optional RFC 3161 anchor or external-head note), ``head``, ``ping``.
Errors use the spec §10.2 codes ``invalid_record``, ``unauthorized``, ``duplicate_id``,
``unavailable`` and ``internal``.
"""

from __future__ import annotations

import grp
import json
import os
import signal
import socket
import socketserver
import threading
import time
from pathlib import Path

from aqt_evidence import bytes_hash, canonical_json

from . import __version__
from .anchors import checkpoint, record_external_head
from .client import locked_spool
from .config import Config, spool_path
from .observe import observe, peer_credentials
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
        observed = observe(pid, uid, gid, via="socket")
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
            point, anchor = self.server.checkpoint(anchor=bool(payload.get("anchor")),
                                                   export=bool(payload.get("export")),
                                                   tsa_url=str(payload.get("tsa_url") or ""))
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


class TrailServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, socket_path: str | os.PathLike, writer: TrailWriter, *, mode: int = 0o600,
                 group: str = "", allowed_uids: list[int] | None = None, max_request_bytes: int = 16 << 20,
                 spool: str | os.PathLike | None = None, drain_interval_s: float = 30,
                 anchor: dict | None = None):
        self.writer, self.max_request_bytes = writer, max_request_bytes
        self.anchor = anchor or {}
        self.allowed_uids = set(allowed_uids or []) | {os.getuid()}
        self.spool, self.drain_interval_s, self._last_drain = spool, drain_interval_s, time.monotonic()
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
            super().__init__(str(path), _Handler)
        finally:
            os.umask(old)
        if group:
            os.chown(path, -1, grp.getgrnam(group).gr_gid)
        os.chmod(path, mode)

    def checkpoint(self, *, anchor: bool = False, export: bool = False, tsa_url: str = ""):
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

    def server_close(self):
        super().server_close()
        try:
            self.socket_path.unlink()
        except OSError:
            pass


def build_server(config: Config, writer: TrailWriter) -> TrailServer:
    section = config.section("writer")
    return TrailServer(config.socket_path, writer, mode=int(str(section["socket_mode"]), 8),
                       group=section["socket_group"], allowed_uids=[int(u) for u in section["allowed_uids"]],
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

    for which in (signal.SIGTERM, signal.SIGINT):
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
