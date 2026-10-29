"""The single writer of a trail log.

Only ``TrailWriter`` appends to ``trail.jsonl``. For every record it checks the
envelope, refuses writer-owned fields, the writer's own name and writer-owned
record types and actions, checks the payload of client ``trail.review`` and
``trail.refused`` records, restamps the time (the client's time moves to
``observed.client_time``), adds ``observed``, links the record into the hash
chain, signs it with the service key, appends one canonical JSON line and
fsyncs. Refused attempts are themselves recorded as ``trail.refused``.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from aqt_evidence import (ACTOR_KINDS, GENESIS, Signer, actor, bytes_hash, canonical_json, content_hash, link,
                          new_record, record_content_hash, record_hash, sign_record, utc_now, validate_record)

from .observe import agent_markers, observe_self, unobserved
from .review import DISPOSITIONS

SERVICE_ACTOR = actor("service", "service:aqt-trail", role="audit-trail-writer")
WRITER_FIELDS = ("sig", "chain", "observed")
# Only the writer itself creates these; a client record with them is refused (``invalid_record``).
WRITER_TYPES = frozenset({"trail.anchor", "trail.gap"})
WRITER_ACTIONS = frozenset({"service.start", "service.stop", "clock.jump", "log.repaired"})
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^ed25519:[0-9a-f]{16}$")


def _text(value) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _signature_problem(signature) -> str | None:
    """Shape of a detached statement (aqt-spec ``schemas/signature.schema.json``)."""
    if not isinstance(signature, dict):
        return "data.signature must be a detached signed statement"
    if signature.get("alg") != "ed25519" or not _text(signature.get("value")) \
            or not _KEY_ID.match(str(signature.get("key", ""))):
        return "data.signature needs alg ed25519, key ed25519:<16 hex> and value"
    statement = signature.get("statement")
    if not isinstance(statement, dict):
        return "data.signature.statement must be an object"
    signer, subject = statement.get("signer"), statement.get("subject")
    if not isinstance(signer, dict) or not _text(signer.get("id")) or not _text(signer.get("name")):
        return "data.signature.statement.signer needs id and name"
    if not isinstance(subject, dict) or not _text(subject.get("kind")) or not _text(subject.get("ref")) \
            or not _SHA256.match(str(subject.get("sha256", ""))):
        return "data.signature.statement.subject needs kind, ref and sha256"
    if not _KEY_ID.match(str(statement.get("key", ""))) or not _text(statement.get("meaning")) \
            or not _text(statement.get("signed_at")) or statement.get("aqt_signature") is None:
        return "data.signature.statement needs aqt_signature, key, meaning and signed_at"
    return None


def payload_problem(record: dict) -> str | None:
    """Payload check of client ``trail.review`` and ``trail.refused`` records (their registered
    schemas plus what ``verify`` reads), so a malformed one is refused instead of stored for ever."""
    data = record.get("data")
    if record["type"] == "trail.review":
        if record["actor"].get("kind") != "human":
            return "a trail.review is signed by a human actor"
        if not isinstance(data, dict):
            return "trail.review needs data"
        if not _SHA256.match(str(data.get("head", ""))):
            return "trail.review data.head must be sha256:<64 hex>"
        findings = data.get("findings")
        if not isinstance(findings, list) or any(
                not isinstance(f, dict) or not _text(f.get("query")) or not _text(f.get("severity"))
                or not isinstance(f.get("record_ids"), list) or not all(isinstance(i, str) for i in f["record_ids"])
                or f.get("disposition") not in DISPOSITIONS for f in findings):
            return "trail.review data.findings must be a list of {query, severity, record_ids, disposition}"
        if "scope" in data and not isinstance(data["scope"], dict):
            return "trail.review data.scope must be an object"
        return _signature_problem(data.get("signature"))
    if record["type"] == "trail.refused":
        if not isinstance(data, dict) or not _text(data.get("attempted_action")) or not _text(data.get("reason_code")) \
                or not isinstance(data.get("agent_markers"), list) \
                or not all(isinstance(m, str) for m in data["agent_markers"]):
            return "trail.refused needs data.attempted_action, data.reason_code and data.agent_markers"
    return None


def writer_owned_problem(record: dict) -> str | None:
    """A client record that would pass for one the writer made itself."""
    who = str(record["actor"].get("id", "")).strip().lower()
    if who == SERVICE_ACTOR["id"]:
        return f"actor {SERVICE_ACTOR['id']} is the writer itself; clients use their own identity"
    if record["type"] in WRITER_TYPES:
        return f"{record['type']} records are written only by the writer"
    if str(record["action"]).strip().lower() in WRITER_ACTIONS:
        return f"action {record['action']!r} is reserved for the writer's own events"
    return None


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
        self.failed: str | None = None   # set when a failed write could not be undone; restart to repair

    # -- lifecycle ---------------------------------------------------------
    def open(self) -> "TrailWriter":
        self.state.mkdir(parents=True, exist_ok=True)
        # 0600: in separate-user mode the clients group may read the state directory, and flock()
        # also works on a read-only descriptor, so a readable lock file would let a client block the writer.
        lock_fd = os.open(self.state / "trail.lock", os.O_RDWR | os.O_CREAT, 0o600)
        os.fchmod(lock_fd, 0o600)
        self._lock_file = os.fdopen(lock_fd, "r+")
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
        if self.failed:
            raise Refused("unavailable", self.failed)
        stored = dict(record)
        stored["time"] = now
        stored["observed"] = dict(observed, client_time=client_time) if client_time else dict(observed)
        stored = sign_record(link(stored, seq=self.seq + 1, prev=self.head), self.signer)
        problems = validate_record(stored)
        if problems:
            raise Refused("invalid_record", "; ".join(problems))
        line = canonical_json(stored) + b"\n"
        self._append_line(line)
        self.index[stored["id"]] = (self._size, len(line), record_content_hash(stored))
        self._size += len(line)
        self.seq, self.head, self.last_time = stored["chain"]["seq"], record_hash(stored), now
        return stored

    def _append_line(self, line: bytes) -> None:
        """Write the whole line and fsync, or leave the file as it was: on an error the file is cut back
        to the last acknowledged record, so no half line or unacknowledged record stays behind. If even
        that fails, the writer refuses every record (``unavailable``) until it is restarted; ``open`` then
        removes a torn last line, and a complete one stays as stored (a retry by id finds it)."""
        try:
            view, written = memoryview(line), 0
            while written < len(line):
                written += os.write(self._fd, view[written:])
            os.fsync(self._fd)
        except OSError as error:
            try:
                os.ftruncate(self._fd, self._size)
                os.fsync(self._fd)
            except OSError as undo:
                self.failed = (f"a failed write ({error.strerror or error}) could not be undone "
                               f"({undo.strerror or undo}); restart the writer")
            raise

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
        problem = writer_owned_problem(record) or payload_problem(record)
        if problem:
            return "invalid_record", problem
        return None

    def refuse(self, code: str, message: str, record, observed: dict, attempted_action: str = "append") -> Refused:
        """Record a refused attempt as ``trail.refused`` and return the exception to raise."""
        claimed = record.get("actor") if isinstance(record, dict) else None
        if not (isinstance(claimed, dict) and claimed.get("kind") in ACTOR_KINDS
                and isinstance(claimed.get("id"), str) and claimed["id"]) \
                or claimed["id"].strip().lower() == SERVICE_ACTOR["id"]:
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
        """Append spooled records after one ``trail.gap`` marker (aqt-spec spec §10.4).

        ``drainer`` is the observation of a socket client that sent the records (the ``drain`` op); it
        is kept on the gap and, as ``observed.drained_by``, on every drained record. Without it the
        writer drained a spool file itself. A record id is stored once: a repeat with the same content
        counts as already stored, one with other content is refused (``duplicate_id``)."""
        result = DrainResult()
        spooled = unobserved("spool")
        if drainer is not None:
            spooled["drained_by"] = {key: value for key, value in drainer.items() if key != "client_time"}
        with self.lock:
            fresh, batch = [], {}
            for record in records:
                problem = self._check(record)
                if problem is None:
                    known = self.index[record["id"]][2] if record["id"] in self.index else batch.get(record["id"])
                    if known is not None:
                        if known == record_content_hash(record):
                            result.already_stored.append(record["id"])
                            continue
                        problem = ("duplicate_id", f"a different record with id {record['id']} is already stored")
                    else:
                        batch[record["id"]] = record_content_hash(record)
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
                    refusal = self.refuse(problem[0], problem[1], record, spooled, "drain")
                    result.refused.append(refusal.refusal["id"])
                    continue
                stored = self._write(record, spooled, self._now(), client_time=record["time"])
                result.appended.append(stored["id"])
        return result
