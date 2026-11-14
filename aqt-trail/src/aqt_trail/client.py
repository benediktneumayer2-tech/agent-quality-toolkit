"""Client side: send records to the writer, spool them when it is down.

The spool is the shared file of aqt-spec spec §10.4,
``$XDG_STATE_HOME/aqt/spool/spool.jsonl`` (locked, mode 0600), so records
spooled by ``aqt_evidence.SocketSink`` and by this client are drained together.
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from pathlib import Path

from aqt_evidence import SinkError, platform, writer_request

from .config import spool_path


class TrailRefused(SinkError):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message


def request(socket_path: str | os.PathLike, payload: dict, *, timeout: float = 5.0) -> dict:
    """One request to the writer (its Unix socket, or its named pipe on Windows); ``SinkError`` when it
    cannot be reached or answers unreadably."""
    return writer_request(socket_path, payload, timeout=timeout)


def spool_append(record: dict, path: str | os.PathLike | None = None) -> Path:
    path = Path(path) if path else spool_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = platform.open_fd(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "ab") as handle:
        platform.lock(handle)
        try:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        finally:
            platform.unlock(handle)
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
    fd = platform.open_fd(path, os.O_RDWR)
    with os.fdopen(fd, "rb+") as handle:
        platform.lock(handle)
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
            platform.unlock(handle)


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
