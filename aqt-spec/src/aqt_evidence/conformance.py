"""Conformance levels of an evidence file (spec §9).

- **L1 valid:** every line parses strictly, every envelope is valid (``validate_record``
  and, when ``jsonschema`` is installed, the envelope schema), types are registered (or
  ``x-`` extensions), registered payloads match their schemas (when ``jsonschema`` is
  installed), record IDs are unique, human decisions of decision types carry a reason.
- **L2 chained:** L1, and the hash chain verifies.
- **L3 signed and anchored:** L2, every record carries a valid signature by a pinned
  key, and at least one signed checkpoint from outside the writer matches the chain.
  A checkpoint covers the log only up to its seq: ``anchored_seq`` is the newest matching
  checkpoint and ``unanchored`` counts the records after it (shown in the summary).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Iterable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import CanonicalError, parse_record
from .chain import ChainResult, checkpoint_matches, verify_chain, verify_checkpoint
from .record import validate_record
from . import schemas


@dataclass
class ConformanceResult:
    target: int
    level: int
    count: int = 0
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    payloads_checked: bool = False
    chain: ChainResult | None = None
    anchored_seq: int | None = None  # L3: seq of the newest matching checkpoint
    unanchored: int | None = None  # L3: records after it, whose removal no checkpoint would reveal

    @property
    def ok(self) -> bool:
        return self.level >= self.target

    def summary(self) -> str:
        head = f"L{self.level} reached (target L{self.target}), {self.count} records"
        if not self.ok:
            return f"{head}; first problem: {self.problems[0] if self.problems else 'unknown'}"
        if self.unanchored:
            head += (f"; anchored up to seq {self.anchored_seq}, {self.unanchored} later record(s) not covered by "
                     "a checkpoint")
        return head

    def as_dict(self) -> dict:
        return {"target": self.target, "level": self.level, "ok": self.ok, "count": self.count,
                "problems": self.problems, "warnings": self.warnings, "payloads_checked": self.payloads_checked,
                "chain": None if self.chain is None else self.chain.__dict__, "anchored_seq": self.anchored_seq,
                "unanchored": self.unanchored}


def read_strict(path: str | os.PathLike) -> tuple[list[dict], list[str]]:
    """Read a JSONL file with ``parse_record``; returns records and parse problems."""
    records, problems = [], []
    with open(path, "rb") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                records.append(parse_record(line))
            except CanonicalError as error:
                problems.append(f"line {number}: {error}")
    return records, problems


def _payloads_available() -> bool:
    try:
        import jsonschema  # noqa: F401
    except ImportError:
        return False
    return True


def check_level1(records: list[dict], *, check_payloads: bool = True) -> tuple[list[str], list[str], bool]:
    problems, warnings = [], []
    payloads = check_payloads and _payloads_available()
    types = schemas.registry()["types"]
    seen: set = set()
    for index, record in enumerate(records):
        where = f"record {index + 1}"
        errors = validate_record(record)
        if errors:
            problems.extend(f"{where}: {error}" for error in errors)
            continue
        type_ = record["type"]
        if record["id"] in seen:
            problems.append(f"{where}: duplicate id {record['id']}")
        seen.add(record["id"])
        if not schemas.is_registered(type_):
            problems.append(f"{where}: type {type_} is not registered (use the x-<org>. prefix for extensions)")
        entry = types.get(type_)
        if entry:
            if entry["human_reason"] and record["actor"]["kind"] == "human" and "reason" not in record:
                problems.append(f"{where}: a human {type_} decision needs a reason")
            if entry["meanings"] and "meaning" in record and record["meaning"] not in entry["meanings"]:
                warnings.append(f"{where}: meaning {record['meaning']} is unusual for {type_}")
        if payloads:
            problems.extend(f"{where}: {problem}" for problem in schemas.validate_schema(record, "envelope"))
            problems.extend(f"{where}: {problem}" for problem in schemas.validate_payload(record))
    if check_payloads and not payloads:
        warnings.append('payload schemas not checked (install "aqt-spec[schema]")')
    return problems, warnings, payloads


def conformance(records: Iterable[dict], level: int = 1, *, keys: dict[str, Ed25519PublicKey] | None = None,
                checkpoints: list[dict] | None = None, check_payloads: bool = True,
                parse_problems: list[str] | None = None) -> ConformanceResult:
    """Check ``records`` up to ``level`` (1, 2 or 3) and report the highest level reached."""
    if level not in (1, 2, 3):
        raise ValueError("level must be 1, 2 or 3")
    records = list(records)
    result = ConformanceResult(target=level, level=0, count=len(records))
    problems, warnings, result.payloads_checked = check_level1(records, check_payloads=check_payloads)
    result.problems = list(parse_problems or []) + problems
    result.warnings = warnings
    if result.problems:
        return result
    result.level = 1
    if level < 2:
        return result
    chain = verify_chain(records)
    result.chain = chain
    if not chain.ok:
        result.problems.append(f"chain {chain.summary()}")
        return result
    result.level = 2
    if level < 3:
        return result
    if not keys:
        result.problems.append("L3 needs pinned public keys (--key)")
        return result
    signed = verify_chain(records, keys=keys, require_signature=True)
    result.chain = signed
    result.warnings.extend(signed.warnings)
    if not signed.ok:
        result.problems.append(f"signatures: {signed.summary()}")
        return result
    good = [cp for cp in checkpoints or [] if verify_checkpoint(cp, keys)]
    bad = len(checkpoints or []) - len(good)
    if bad:
        result.problems.append(f"{bad} checkpoint(s) do not verify with the pinned keys")
        return result
    if not good:
        result.problems.append("L3 needs at least one signed checkpoint kept outside the writer (--checkpoint)")
        return result
    unmatched = [cp for cp in good if not checkpoint_matches(cp, records)]
    if unmatched:
        cp = unmatched[0]
        result.problems.append(f"checkpoint seq {cp.get('seq')} does not match the file (truncated or rewritten)")
        return result
    result.level = 3
    result.anchored_seq = max(cp["seq"] for cp in good)
    result.unanchored = signed.head_seq - result.anchored_seq
    return result
