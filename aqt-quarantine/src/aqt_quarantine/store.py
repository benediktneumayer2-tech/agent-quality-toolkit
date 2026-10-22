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
from datetime import date
from pathlib import Path
from typing import Callable, Iterator

from aqt_evidence import JsonlSink, SinkError, canonical_json, open_sink

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
    status: str          # valid | unsigned | invalid | unknown-signer | revoked | mismatch
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


Verifier = Callable[[dict], str]


class Store:
    def __init__(self, root: Path, *, sink: str | None = None):
        self.root = Path(root)
        self.journal = self.root / "journal.jsonl"
        self.outbox = self.root / "outbox.jsonl"
        self.cases_dir = self.root / "cases"
        self.sink_spec = sink

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
        if not self.journal.exists():
            return
        with open(self.journal, "rb") as handle:
            for line in handle:
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if isinstance(record, dict) and str(record.get("type", "")).startswith("quarantine."):
                    yield record

    def fold(self, verify: Verifier, *, require_signed: bool) -> tuple[dict[str, Case], list[TrustedSource]]:
        cases: dict[str, Case] = {}
        sources: dict[str, TrustedSource] = {}

        def honour(status: str) -> bool:
            return status == "valid" or (status == "unsigned" and not require_signed)

        for record in self.records():
            kind, data = record.get("type"), record.get("data") or {}
            case = cases.get(data.get("case_id", ""))
            if kind == "quarantine.held":
                cases[data["case_id"]] = Case(data["case_id"], record, "hold", "held")
            elif kind == "quarantine.passed" and data.get("case_id"):
                cases[data["case_id"]] = Case(data["case_id"], record, "warn", "warned")
            elif kind == "quarantine.released" and case:
                status = verify(record)
                decision = Decision(record, status, honour(status))
                if decision.honoured and case.state == "threat" and not data.get("overrule_threat"):
                    decision.honoured, decision.note = False, "case was declared a threat; release needs --overrule-threat"
                if decision.honoured and data.get("content_sha256") != case.data.get("content_sha256"):
                    decision.honoured, decision.note = False, "released content hash does not match the case"
                if decision.honoured:
                    case.state, case.released_by = "released", record
                case.decisions.append(decision)
            elif kind == "quarantine.threat.declared" and case:
                status = verify(record)
                decision = Decision(record, status, honour(status))
                if decision.honoured:
                    case.state, case.threat_by = "threat", record
                case.decisions.append(decision)
            elif kind == "quarantine.delivered" and case:
                case.delivered.append(record)
            elif kind == "quarantine.refused" and case:
                case.refused.append(record)
            elif kind == "quarantine.source.trusted":
                if not honour(verify(record)):
                    continue
                domain = str(data.get("domain", "")).lower()
                if record.get("action") == "revoke":
                    sources.pop(domain, None)
                else:
                    sources[domain] = TrustedSource(domain, bool(data.get("subdomains")), str(data.get("expires")),
                                                    record)
        return cases, list(sources.values())
