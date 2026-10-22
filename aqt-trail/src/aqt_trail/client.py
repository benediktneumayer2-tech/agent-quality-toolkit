"""Client side: send records to the writer, spool them when it is down.

The spool is the shared file of aqt-spec spec §10.4,
``$XDG_STATE_HOME/aqt/spool/spool.jsonl`` (locked, mode 0600), so records
spooled by ``aqt_evidence.SocketSink`` and by this client are drained together.
"""

from __future__ import annotations

import fcntl
import json
import os
import socket
from contextlib import contextmanager
from pathlib import Path

from aqt_evidence import SinkError, canonical_json

from .config import spool_path


class TrailRefused(SinkError):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message


def request(socket_path: str | os.PathLike, payload: dict, *, timeout: float = 5.0) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(timeout)
        try:
            client.connect(str(socket_path))
            client.sendall(canonical_json(payload) + b"\n")
            client.shutdown(socket.SHUT_WR)
            chunks = []
            while chunk := client.recv(65536):
                chunks.append(chunk)
        except OSError as error:
            raise SinkError(f"aqt-trail socket {socket_path}: {error}") from error
    try:
        return json.loads(b"".join(chunks).decode("utf-8"))
    except ValueError as error:
        raise SinkError("aqt-trail sent an unreadable response") from error


def spool_append(record: dict, path: str | os.PathLike | None = None) -> Path:
    path = Path(path) if path else spool_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "ab") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)
    return path


@contextmanager
def locked_spool(path: str | os.PathLike | None = None):
    """Yield the spooled entries under the spool lock; call ``clear()`` once they are stored.

    An unparseable line is passed on as a string, so the writer records it as
    a refusal instead of dropping it silently.
    """
    path = Path(path) if path else spool_path()
    if not path.exists():
        yield [], (lambda: None)
        return
    fd = os.open(path, os.O_RDWR)
    with os.fdopen(fd, "rb+") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            entries = []
            for line in handle.read().splitlines():
                if not line.strip():
                    continue
                try:
                    entries.append(json.loads(line))
                except ValueError:
                    entries.append(line.decode("utf-8", "replace"))

            def clear():
                handle.seek(0)
                handle.truncate(0)
                handle.flush()
                os.fsync(handle.fileno())

            yield entries, clear
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


class TrailClient:
    """An ``aqt_evidence`` sink that talks to the writer and spools when it is unavailable."""

    def __init__(self, socket_path: str | os.PathLike, *, spool: str | os.PathLike | None = None,
                 timeout: float = 5.0, use_spool: bool = True):
        self.socket_path, self.spool, self.timeout, self.use_spool = socket_path, spool, timeout, use_spool
        self.last_spooled = False

    def request(self, payload: dict) -> dict:
        return request(self.socket_path, payload, timeout=self.timeout)

    def append(self, record: dict) -> dict:
        self.last_spooled = False
        try:
            response = self.request({"op": "append", "record": record})
        except SinkError:
            if not self.use_spool:
                raise
            # The outcome may be unknown (timeout after sending); appends are idempotent
            # by id, so a later drain returns the stored record instead of a duplicate.
            spool_append(record, self.spool)
            self.last_spooled = True
            return record
        if not response.get("ok"):
            raise TrailRefused(response.get("code", "internal"), response.get("message", "append refused"))
        return response["record"]
