"""Working store: journal, outbox and case files under the state dir.

``journal.jsonl`` holds every record this tool wrote (aqt-spec 0.1). Case
state and trusted sources are folded from it, so there is one source of truth.
Each record is also sent to the configured evidence sink; when the sink does
not accept it, the record waits in ``outbox.jsonl`` (``aqt-quarantine flush``).
Original texts live in ``cases/<CASE>/original.txt`` (0600); records only carry
their hash.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import secrets
import stat
import sys
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Callable, Iterator

from aqt_evidence import JsonlSink, SinkError, canonical_json, content_hash, open_sink

CASE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
CASE_RE = re.compile(r"^Q[0-9A-HJKMNP-TV-Z]{6}$")


class StoreError(RuntimeError):
    pass


def normalise_case_id(value: str) -> str:
    case_id = value.strip().upper()
    if not CASE_RE.match(case_id):
        raise StoreError(f"not a case id: {value!r} (expected Q plus 6 characters)")
    return case_id


@dataclass
class Decision:
    record: dict
    status: str          # valid | unsigned | invalid | unknown-signer | revoked | mismatch | not-responsible
    honoured: bool
    note: str = ""


@dataclass
class Case:
    case_id: str
    opened: dict
    band: str                              # warn | hold
    state: str                             # held | warned | released | threat
    decisions: list[Decision] = field(default_factory=list)
    delivered: list[dict] = field(default_factory=list)
    refused: list[dict] = field(default_factory=list)
    released_by: dict | None = None
    threat_by: dict | None = None

    @property
    def data(self) -> dict:
        return self.opened.get("data", {})

    @property
    def session(self) -> str | None:
        return (self.data.get("source") or {}).get("session")

    @property
    def reached_model(self) -> bool:
        if self.band == "warn":
            return True
        return any(item.get("data", {}).get("kind") == "content" and item.get("data", {}).get("mode") != "failed"
                   for item in self.delivered)

    def delivered_kind(self, kind: str, decision_id: str) -> bool:
        return any(item.get("data", {}).get("kind") == kind and item.get("data", {}).get("decision") == decision_id
                   for item in self.delivered)


@dataclass
class TrustedSource:
    domain: str
    subdomains: bool
    expires: str
    record: dict

    def matches(self, host: str | None) -> bool:
        if not host:
            return False
        host = host.lower().rstrip(".")
        return host == self.domain or (self.subdomains and host.endswith("." + self.domain))

    def active(self, today: date | None = None) -> bool:
        return (today or date.today()).isoformat() <= self.expires


def _inert(value, limit: int = 80) -> str:
    """Journal text for a message: control and format characters as <U+XXXX>, at most ``limit`` characters."""
    text = str(value)[:limit]
    return "".join(char if char.isprintable() else f"<U+{ord(char):04X}>" for char in text)


@dataclass
class JournalProblem:
    """A journal line that ``Store.fold`` skipped: malformed, or a second opening record for a case.
    Its fields come from the journal and are made inert (no control or format characters)."""
    line: int
    record_id: str | None
    case_id: str | None
    message: str

    def __str__(self) -> str:
        return f"journal line {self.line} (record {self.record_id or 'without id'}) ignored: {self.message}"


Verifier = Callable[[dict], str]


class Store:
    def __init__(self, root: Path, *, sink: str | None = None):
        self.root = Path(root)
        self.journal = self.root / "journal.jsonl"
        self.outbox = self.root / "outbox.jsonl"
        self.cases_dir = self.root / "cases"
        self.sink_spec = sink
        self.ignored_sources: list[Decision] = []      # set by fold()
        self.journal_problems: list[JournalProblem] = []  # set by fold()

    # -- writing ---------------------------------------------------------------------------------
    def ensure(self) -> None:
        for directory in (self.root, self.cases_dir):
            directory.mkdir(parents=True, exist_ok=True)
            os.chmod(directory, 0o700)

    def _sink_is_journal(self) -> bool:
        spec = self.sink_spec
        return bool(spec and spec.startswith("file:")
                    and Path(spec[5:]).expanduser().resolve() == self.journal.resolve())

    def write(self, record: dict) -> dict:
        """Append to the journal (must succeed), then to the sink (spooled to the outbox on failure)."""
        self.ensure()
        try:
            JsonlSink(self.journal).append(record)
        except (OSError, SinkError) as error:
            raise StoreError(f"cannot write journal {self.journal}: {error}") from error
        if not self._sink_is_journal():
            self.flush(quiet=True)
            try:
                open_sink(self.sink_spec).append(record)
            except (OSError, SinkError) as error:
                self._to_outbox(record)
                print(f"aqt-quarantine: evidence sink unavailable ({error}); record kept in {self.outbox}",
                      file=sys.stderr)
        return record

    def _to_outbox(self, record: dict) -> None:
        fd = os.open(self.outbox, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "ab") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            handle.write(canonical_json(record) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())

    def flush(self, *, quiet: bool = False) -> tuple[int, int]:
        """Send outbox records to the sink. Returns (sent, still waiting)."""
        if not self.outbox.exists() or self._sink_is_journal():
            return 0, 0
        with open(self.outbox, "r+b") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            lines = [line for line in handle.read().splitlines() if line.strip()]
            if not lines:
                return 0, 0
            sink, sent, waiting = open_sink(self.sink_spec), 0, []
            for index, line in enumerate(lines):
                try:
                    sink.append(json.loads(line))
                    sent += 1
                except (OSError, SinkError, ValueError) as error:
                    waiting = lines[index:]
                    if not quiet:
                        print(f"aqt-quarantine: sink still unavailable: {error}", file=sys.stderr)
                    break
            handle.seek(0)
            handle.truncate()
            handle.write(b"".join(line + b"\n" for line in waiting))
            handle.flush()
            os.fsync(handle.fileno())
        return sent, len(waiting)

    def outbox_size(self) -> int:
        if not self.outbox.exists():
            return 0
        return sum(1 for line in self.outbox.read_bytes().splitlines() if line.strip())

    # -- case files ------------------------------------------------------------------------------
    def new_case_id(self) -> str:
        self.ensure()
        for _ in range(100):
            case_id = "Q" + "".join(secrets.choice(CASE_ALPHABET) for _ in range(6))
            try:
                (self.cases_dir / case_id).mkdir(mode=0o700)
                return case_id
            except FileExistsError:
                continue
        raise StoreError("could not allocate a case id")

    def save_original(self, case_id: str, text: str) -> str:
        path = self.cases_dir / case_id / "original.txt"
        temporary = path.with_name(f".original.{os.getpid()}.tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", errors="surrogatepass", newline="") as handle:
                handle.write(text)
            os.replace(temporary, path)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        return f"cases/{case_id}/original.txt"

    def load_original(self, case_id: str) -> str:
        """Open the original without following links, only if it is a single-link file of this user."""
        path = self.cases_dir / normalise_case_id(case_id) / "original.txt"
        try:
            info = path.lstat()
        except FileNotFoundError as error:
            raise StoreError(f"case {case_id} has no stored original") from error
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
            raise StoreError(f"{path}: unsafe file type or owner")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "r", encoding="utf-8", errors="surrogatepass", newline="") as handle:
            if (os.fstat(handle.fileno()).st_ino) != info.st_ino:
                raise StoreError(f"{path}: changed while opening")
            return handle.read()

    # -- reading ---------------------------------------------------------------------------------
    def records(self) -> Iterator[dict]:
        """Journal records in write order; torn or foreign lines are skipped."""
        for _, record in self._numbered():
            yield record

    def _numbered(self) -> Iterator[tuple[int, dict]]:
        if not self.journal.exists():
            return
        with open(self.journal, "rb") as handle:
            for number, line in enumerate(handle, 1):
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if isinstance(record, dict) and str(record.get("type", "")).startswith("quarantine."):
                    yield number, record

    def fold(self, verify: Verifier, *, require_signed: bool) -> tuple[dict[str, Case], list[TrustedSource]]:
        """Cases and trusted sources from the journal.

        A decision acts only through its signed ``data.decision`` (case id, content hash, overrule, domain,
        subdomains, expiry, action): ``verify`` reports a record whose unsigned fields differ as
        ``mismatch``. Decisions take effect in the order they were signed (``statement.signed_at``; unsigned
        ones by record time), not in journal order, and a signed statement counts once: a copy of it, byte
        for byte or under a new record id, is a replay and has no effect. Source decisions that are not
        honoured are kept in ``self.ignored_sources``; case decisions are listed in ``Case.decisions``.

        A case is what its first opening record (``quarantine.held``, or ``quarantine.passed`` with a case id)
        says; a later opening record for the same case id cannot change its band, evidence or content hash.
        Such lines, and lines too malformed to use, are skipped and listed in ``self.journal_problems``, so
        one bad line neither changes a case nor stops the hook from reading the journal."""
        cases: dict[str, Case] = {}
        sources: dict[str, TrustedSource] = {}
        pending: list[tuple[datetime, int, dict]] = []
        self.ignored_sources = []
        self.journal_problems = problems = []

        def honour(status: str) -> bool:
            return status == "valid" or (status == "unsigned" and not require_signed)

        def skip(number: int, record: dict, case_id, message: str) -> None:
            ident = record.get("id")
            problems.append(JournalProblem(number, _inert(ident) if isinstance(ident, str) else None,
                                           case_id if isinstance(case_id, str) and CASE_RE.match(case_id) else None,
                                           message))

        for index, (number, record) in enumerate(self._numbered()):
            kind, data = record.get("type"), record.get("data")
            shown_kind = _inert(kind, 40)
            data = {} if data is None else data
            if not isinstance(data, dict):
                skip(number, record, None, f"{shown_kind}: data is not an object")
                continue
            case_id = data.get("case_id")
            if kind == "quarantine.held" or (kind == "quarantine.passed" and case_id):
                problem = opening_problem(data)
                if problem:
                    skip(number, record, case_id, f"{shown_kind}: {problem}")
                elif case_id in cases:
                    skip(number, record, case_id, f"case {case_id} was opened by record "
                                                  f"{_inert(cases[case_id].opened.get('id'))}; a later {shown_kind} "
                                                  "cannot change it")
                elif kind == "quarantine.held":
                    cases[case_id] = Case(case_id, record, "hold", "held")
                else:
                    cases[case_id] = Case(case_id, record, "warn", "warned")
                continue
            if case_id is not None and not isinstance(case_id, str):
                skip(number, record, None, f"{shown_kind}: case_id is not a string")
                continue
            case = cases.get(case_id or "")
            if kind in DECISION_TYPES:
                pending.append((_signed_time(record), index, record))
            elif kind == "quarantine.delivered" and case:
                case.delivered.append(record)
            elif kind == "quarantine.refused" and case:
                case.refused.append(record)

        first_seen: dict[str, str] = {}               # signed statement hash -> first record carrying it
        for _, _, record in sorted(pending, key=lambda item: (item[0], item[1])):
            kind, data = record.get("type"), record.get("data") or {}
            terms = data["decision"] if isinstance(data.get("decision"), dict) else data
            try:
                status = verify(record)
            except (TypeError, ValueError, AttributeError, KeyError, RecursionError):   # malformed: never applied
                status = "invalid"
            decision = Decision(record, status, honour(status))
            signature = data.get("signature")
            if status == "valid" and isinstance(signature, dict) and isinstance(signature.get("statement"), dict):
                key = content_hash(signature["statement"])
                if key in first_seen:
                    decision.honoured, decision.note = False, f"replay of the signed decision in {first_seen[key]}"
                else:
                    first_seen[key] = record.get("id")
            if kind == "quarantine.source.trusted":
                self._fold_source(decision, terms, sources)
                continue
            case = cases.get(str(data.get("case_id", terms.get("case_id", ""))))
            if case is None:
                continue
            if decision.honoured and terms.get("case_id") != case.case_id:
                decision.honoured, decision.note = False, f"the signed decision is for case {terms.get('case_id')}"
            if kind == "quarantine.released":
                if decision.honoured and case.state == "threat" and not terms.get("overrule_threat"):
                    decision.honoured, decision.note = False, "case was declared a threat; release needs --overrule-threat"
                if decision.honoured and terms.get("content_sha256") != case.data.get("content_sha256"):
                    decision.honoured, decision.note = False, "released content hash does not match the case"
                if decision.honoured:
                    case.state, case.released_by = "released", record
            elif decision.honoured:
                case.state, case.threat_by = "threat", record
            case.decisions.append(decision)
        return cases, list(sources.values())

    def _fold_source(self, decision: Decision, terms: dict, sources: dict[str, TrustedSource]) -> None:
        record = decision.record
        domain = str(terms.get("domain", "")).lower()
        action = terms.get("action", record.get("action"))
        if decision.honoured and action == "trust" and not _is_date(terms.get("expires")):
            decision.honoured, decision.note = False, "trust without a valid expiry date"
        if not decision.honoured:
            self.ignored_sources.append(decision)
        elif action == "revoke":
            sources.pop(domain, None)
        elif action == "trust":
            sources[domain] = TrustedSource(domain, bool(terms.get("subdomains")), str(terms["expires"]), record)


DECISION_TYPES = ("quarantine.released", "quarantine.threat.declared", "quarantine.source.trusted")
_OBJECTS = ("source", "scores", "thresholds", "original", "trusted_source")
_LISTS = ("evidence", "detectors", "errors", "fired")


def opening_problem(data: dict) -> str | None:
    """Why the data of an opening record (held, or passed with a case id) cannot be used, or None.
    Checks the shape the readers (views, reports, the hook) rely on, not the values."""
    if not isinstance(data.get("case_id"), str) or not CASE_RE.match(data["case_id"]):
        return "no valid case_id"
    if not isinstance(data.get("content_sha256"), str):
        return "no content_sha256"
    for key in _OBJECTS:
        if key in data and not isinstance(data[key], dict):
            return f"{key} is not an object"
    for key in _LISTS:
        if key in data and not isinstance(data[key], list):
            return f"{key} is not a list"
    for key in ("score_ppm", "chars"):
        if key in data and (type(data[key]) is not int):
            return f"{key} is not an integer"
    for item in data.get("evidence", []):
        if not isinstance(item, dict) or type(item.get("start")) is not int or type(item.get("end")) is not int \
                or not all(isinstance(item.get(key), str) for key in ("label", "detector", "reason")) \
                or not isinstance(item.get("excerpt", ""), str):
            return "an evidence item is malformed"
    for item in data.get("detectors", []):
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not isinstance(item.get("version"), str):
            return "a detector entry is malformed"
    if not all(isinstance(item, dict) for item in data.get("errors", [])):
        return "an error entry is malformed"
    return None
_EARLIEST = datetime.min.replace(tzinfo=UTC)


def parse_time(value) -> datetime | None:
    """An RFC 3339 timestamp (``Z`` or an offset) as an aware datetime, or None."""
    if not isinstance(value, str) or not value:
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def _signed_time(record: dict) -> datetime:
    """When a decision was made: its signed ``signed_at``, else (unsigned) the record time."""
    signature = (record.get("data") or {}).get("signature")
    statement = signature.get("statement") if isinstance(signature, dict) else None
    when = parse_time(statement.get("signed_at")) if isinstance(statement, dict) else None
    return when or parse_time(record.get("time")) or _EARLIEST


def _is_date(value) -> bool:
    try:
        date.fromisoformat(value)
    except (TypeError, ValueError):
        return False
    return True
