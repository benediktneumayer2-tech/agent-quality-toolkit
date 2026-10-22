"""The single writer of a trail log.

Only ``TrailWriter`` appends to ``trail.jsonl``. For every record it checks the
envelope, refuses writer-owned fields, restamps the time (the client's time
moves to ``observed.client_time``), adds ``observed``, links the record into
the hash chain, signs it with the service key, appends one canonical JSON line
and fsyncs. Refused attempts are themselves recorded as ``trail.refused``.
"""

from __future__ import annotations

import fcntl
import json
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from aqt_evidence import (ACTOR_KINDS, GENESIS, Signer, actor, bytes_hash, canonical_json, content_hash, link,
                          new_record, record_content_hash, record_hash, sign_record, utc_now, validate_record)

from .observe import agent_markers, observe_self, unobserved

SERVICE_ACTOR = actor("service", "service:aqt-trail", role="audit-trail-writer")
WRITER_FIELDS = ("sig", "chain", "observed")
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


class WriterBusy(RuntimeError):
    """Another writer holds the lock on this trail."""


class LogBroken(RuntimeError):
    """The existing log does not link; the writer will not continue it."""


class Refused(Exception):
    def __init__(self, code: str, message: str, refusal: dict | None = None):
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.refusal = code, message, refusal


@dataclass
class DrainResult:
    appended: list[str] = field(default_factory=list)
    already_stored: list[str] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)
    gap: dict | None = None


def _parse_time(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, TIME_FORMAT)
    except (TypeError, ValueError):
        return None


class TrailWriter:
    def __init__(self, state: str | os.PathLike, signer: Signer, log_id: str, *, clock=utc_now,
                 monotonic=time.monotonic, clock_jump_ms: int = 2000, file_mode: int = 0o600):
        self.state = Path(state)
        self.path = self.state / "trail.jsonl"
        self.signer, self.log_id = signer, log_id
        self.clock, self.monotonic, self.clock_jump_ms = clock, monotonic, clock_jump_ms
        self.file_mode = file_mode  # 0640 in separate-user mode so the owner's group can read and verify
        self.lock = threading.RLock()
        self._lock_file = None
        self._fd: int | None = None
        self.seq = -1
        self.head = GENESIS
        self.index: dict[str, tuple[int, int, str]] = {}   # id -> (offset, length, content hash)
        self.last_time: str | None = None
        self._last_mono: float | None = None
        self._size = 0

    # -- lifecycle ---------------------------------------------------------
    def open(self) -> "TrailWriter":
        self.state.mkdir(parents=True, exist_ok=True)
        self._lock_file = open(self.state / "trail.lock", "a")
        try:
            fcntl.flock(self._lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            self._lock_file.close()
            self._lock_file = None
            raise WriterBusy(f"another aqt-trail writer holds {self.state / 'trail.lock'}") from error
        repaired = self._load()
        self._fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, self.file_mode)
        os.fchmod(self._fd, self.file_mode)
        if repaired:
            self.write_internal("trail.event", "log.repaired", data=repaired,
                                reason="an incomplete last line (never acknowledged) was removed")
        return self

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        if self._lock_file is not None:
            fcntl.flock(self._lock_file, fcntl.LOCK_UN)
            self._lock_file.close()
            self._lock_file = None

    def __enter__(self):
        return self.open()

    def __exit__(self, *exc):
        self.close()

    def _load(self) -> dict | None:
        if not self.path.exists():
            return None
        repaired = None
        with open(self.path, "rb+") as handle:
            data = handle.read()
            end = data.rfind(b"\n") + 1
            if end < len(data):
                torn = data[end:]
                handle.truncate(end)
                handle.flush()
                os.fsync(handle.fileno())
                repaired = {"removed_bytes": len(torn), "removed_sha256": bytes_hash(torn)}
                data = data[:end]
        offset = 0
        for number, line in enumerate(data.splitlines(keepends=True), 1):
            try:
                record = json.loads(line)
                chain = record["chain"]
            except (ValueError, KeyError, TypeError) as error:
                raise LogBroken(f"line {number} of {self.path} is not a chained record") from error
            if chain.get("seq") != self.seq + 1 or chain.get("prev") != self.head:
                raise LogBroken(f"{self.path} is broken at line {number}; run 'aqt-trail verify'")
            self.seq, self.head = chain["seq"], record_hash(record)
            self.index[record["id"]] = (offset, len(line), record_content_hash(record))
            self.last_time = record.get("time")
            offset += len(line)
        self._size = offset
        return repaired

    # -- reading -----------------------------------------------------------
    def stored(self, record_id: str) -> dict | None:
        entry = self.index.get(record_id)
        if entry is None:
            return None
        with open(self.path, "rb") as handle:
            handle.seek(entry[0])
            return json.loads(handle.read(entry[1]))

    # -- writing -----------------------------------------------------------
    def _now(self) -> str:
        now = self.clock()
        mono = self.monotonic()
        jump = None
        if self.last_time and now < self.last_time:
            jump = {"direction": "backward", "previous": self.last_time, "current": now}
        elif self.last_time and self._last_mono is not None:
            previous, current = _parse_time(self.last_time), _parse_time(now)
            if previous and current:
                wall_ms = int((current - previous).total_seconds() * 1000)
                mono_ms = int((mono - self._last_mono) * 1000)
                if abs(wall_ms - mono_ms) > self.clock_jump_ms:
                    jump = {"direction": "forward" if wall_ms > mono_ms else "backward",
                            "previous": self.last_time, "current": now,
                            "wall_elapsed_ms": wall_ms, "monotonic_elapsed_ms": mono_ms}
        self._last_mono = mono
        if jump:
            self.last_time = now
            self._write(new_record("trail.event", SERVICE_ACTOR, "clock.jump", data=jump, time=now),
                        observe_self(), now)
        return now

    def _write(self, record: dict, observed: dict, now: str, client_time: str | None = None) -> dict:
        stored = dict(record)
        stored["time"] = now
        stored["observed"] = dict(observed, client_time=client_time) if client_time else dict(observed)
        stored = sign_record(link(stored, seq=self.seq + 1, prev=self.head), self.signer)
        problems = validate_record(stored)
        if problems:
            raise Refused("invalid_record", "; ".join(problems))
        line = canonical_json(stored) + b"\n"
        os.write(self._fd, line)
        os.fsync(self._fd)
        self.index[stored["id"]] = (self._size, len(line), record_content_hash(stored))
        self._size += len(line)
        self.seq, self.head, self.last_time = stored["chain"]["seq"], record_hash(stored), now
        return stored

    def write_internal(self, type: str, action: str, *, reason: str | None = None, data: dict | None = None,
                       subject: dict | None = None, links: list | None = None, who: dict | None = None,
                       observed: dict | None = None, meaning: str | None = None) -> dict:
        with self.lock:
            now = self._now()
            record = new_record(type, who or SERVICE_ACTOR, action, reason=reason, data=data, subject=subject,
                                links=links, meaning=meaning, time=now)
            return self._write(record, observed or observe_self(), now)

    def _check(self, record) -> tuple[str, str] | None:
        if not isinstance(record, dict):
            return "invalid_record", "record must be a JSON object"
        present = [key for key in WRITER_FIELDS if key in record]
        if present:
            return "invalid_record", f"writer-owned field(s) set by the client: {', '.join(present)}"
        problems = validate_record(record)
        if problems:
            return "invalid_record", "; ".join(problems)
        who = record["actor"]
        if who.get("kind") == "human" and "meaning" in record and not record.get("reason"):
            return "invalid_record", "a human decision (meaning set) needs a reason"
        return None

    def refuse(self, code: str, message: str, record, observed: dict, attempted_action: str = "append") -> Refused:
        """Record a refused attempt as ``trail.refused`` and return the exception to raise."""
        claimed = record.get("actor") if isinstance(record, dict) else None
        if not (isinstance(claimed, dict) and claimed.get("kind") in ACTOR_KINDS
                and isinstance(claimed.get("id"), str) and claimed["id"]):
            claimed = {"kind": "service", "id": "unidentified"}
        try:
            attempted = content_hash(record)
        except (ValueError, TypeError):
            attempted = bytes_hash(repr(record).encode("utf-8", "replace"))
        data = {"attempted_action": attempted_action, "reason_code": code, "message": message[:500],
                "agent_markers": agent_markers(observed), "attempted_sha256": attempted}
        if isinstance(record, dict):
            for key, name in (("type", "attempted_type"), ("id", "attempted_id"), ("action", "attempted_record_action")):
                if isinstance(record.get(key), str):
                    data[name] = record[key][:200]
        try:
            refusal = self.write_internal("trail.refused", "refused", data=data, who=claimed, observed=observed)
        except (Refused, ValueError):
            refusal = self.write_internal("trail.refused", "refused", data=data, observed=observed)
        return Refused(code, message, refusal)

    def append(self, record, observed: dict) -> tuple[dict, bool]:
        """Store a client record. Returns (stored record, created). Raises ``Refused``."""
        with self.lock:
            problem = self._check(record)
            if problem is None and record["id"] in self.index:
                if self.index[record["id"]][2] == record_content_hash(record):
                    return self.stored(record["id"]), False
                problem = ("duplicate_id", f"a different record with id {record['id']} is already stored")
            if problem:
                raise self.refuse(problem[0], problem[1], record, observed)
            now = self._now()
            return self._write(record, observed, now, client_time=record["time"]), True

    def drain(self, records: list, *, source: str, drainer: dict | None = None) -> DrainResult:
        """Append spooled records after one ``trail.gap`` marker (INTERFACES I3)."""
        result = DrainResult()
        with self.lock:
            fresh = []
            for record in records:
                problem = self._check(record)
                if problem is None and record["id"] in self.index:
                    if self.index[record["id"]][2] == record_content_hash(record):
                        result.already_stored.append(record["id"])
                        continue
                    problem = ("duplicate_id", f"a different record with id {record['id']} is already stored")
                fresh.append((record, problem))
            new = [record for record, problem in fresh if problem is None]
            if new:
                times = sorted(record["time"] for record in new)
                result.gap = self.write_internal(
                    "trail.gap", "spool.drained", reason="records were spooled while the writer was unavailable",
                    data={"reason": "writer-unavailable", "count": len(new), "first_time": times[0],
                          "last_time": times[-1], "spool_ids": [record["id"] for record in new], "source": source},
                    observed=drainer)
            for record, problem in fresh:
                if problem:
                    refusal = self.refuse(problem[0], problem[1], record, unobserved("spool"), "drain")
                    result.refused.append(refusal.refusal["id"])
                    continue
                stored = self._write(record, unobserved("spool"), self._now(), client_time=record["time"])
                result.appended.append(stored["id"])
        return result
