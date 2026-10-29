"""Hash chains and checkpoints over evidence records.

Each chained record carries ``chain = {seq, prev}``; ``prev`` is the record hash
of the previous record (``GENESIS`` for the first). Because the record hash
covers ``chain``, editing, inserting, deleting or reordering any record breaks
verification from that point on. A checkpoint is a signed statement of the
chain head (``seq`` and hash) that can be anchored outside the writer's reach.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import CanonicalError, canonical_json
from .crypto import Signer, verify_record_signatures, verify_signature
from .record import is_hash, is_time, record_hash, utc_now, validate_record

GENESIS = "sha256:" + "0" * 64


def link(record: dict, *, seq: int, prev: str) -> dict:
    """Return a copy of ``record`` placed at ``seq`` after ``prev`` (any old signatures dropped)."""
    linked = {key: value for key, value in record.items() if key != "sig"}
    linked["chain"] = {"seq": seq, "prev": prev}
    return linked


@dataclass
class ChainResult:
    ok: bool
    count: int = 0
    head_seq: int | None = None
    head_hash: str | None = None
    first_bad_seq: int | None = None
    reason: str | None = None
    warnings: list[str] = field(default_factory=list)

    def summary(self) -> str:
        if self.ok:
            return f"intact: {self.count} records, head seq {self.head_seq} {self.head_hash}"
        return f"broken from seq {self.first_bad_seq}: {self.reason}"


def verify_chain(records: Iterable[dict], *, keys: dict[str, Ed25519PublicKey] | None = None,
                 require_signature: bool = False, start_prev: str = GENESIS,
                 start_seq: int = 0) -> ChainResult:
    """Verify structure, sequence, links and (when ``keys`` are given) signatures.

    ``require_signature=True`` needs pinned ``keys``; without any it fails at ``start_seq``
    instead of checking nothing."""
    prev, expected, count, head = start_prev, start_seq, 0, None
    warnings: list[str] = []
    if require_signature and not keys:
        return ChainResult(False, 0, None, None, start_seq, "signatures required, but no pinned public key given")
    for record in records:
        chain = record.get("chain") if isinstance(record, dict) else None
        seq = chain.get("seq") if isinstance(chain, dict) else None
        bad = seq if isinstance(seq, int) else expected
        problems = validate_record(record)
        if problems:
            return ChainResult(False, count, expected - 1 if count else None, head, bad, "; ".join(problems), warnings)
        if chain is None:
            return ChainResult(False, count, None, head, bad, "record is not chained", warnings)
        if seq != expected:
            return ChainResult(False, count, expected - 1, head, expected, f"expected seq {expected}, found {seq}", warnings)
        if chain["prev"] != prev:
            return ChainResult(False, count, expected - 1, head, seq, "prev does not match the previous record hash", warnings)
        if keys is not None:
            results = verify_record_signatures(record, keys)
            if any(ok is False for _, ok in results):
                return ChainResult(False, count, expected - 1, head, seq, "invalid signature", warnings)
            if require_signature and not any(ok for _, ok in results):
                return ChainResult(False, count, expected - 1, head, seq, "no valid signature from a known key", warnings)
            if any(ok is None for _, ok in results):
                warnings.append(f"seq {seq}: signature by an unknown key")
        head = record_hash(record)
        prev, expected, count = head, expected + 1, count + 1
    return ChainResult(True, count, expected - 1 if count else None, head, None, None, warnings)


def checkpoint_body(*, log_id: str, seq: int, head: str, time: str | None = None) -> dict:
    return {"aqt_checkpoint": "0.1", "log": log_id, "seq": seq, "head": head, "time": time or utc_now()}


def make_checkpoint(*, log_id: str, seq: int, head: str, signer: Signer, time: str | None = None) -> dict:
    """A signed statement that ``log_id`` had ``head`` at ``seq``."""
    body = checkpoint_body(log_id=log_id, seq=seq, head=head, time=time)
    return {**body, "sig": {"alg": "ed25519", "key": signer.key_id, "value": signer.sign(canonical_json(body))}}


CHECKPOINT_MEMBERS = frozenset({"aqt_checkpoint", "log", "seq", "head", "time", "sig"})


def checkpoint_problems(checkpoint) -> list[str]:
    """Shape check of a checkpoint (``schemas/checkpoint.schema.json``); empty means well formed."""
    if not isinstance(checkpoint, dict):
        return ["a checkpoint must be a JSON object"]
    problems = []
    if set(checkpoint) != CHECKPOINT_MEMBERS:
        problems.append("a checkpoint has exactly aqt_checkpoint, log, seq, head, time and sig")
    if checkpoint.get("aqt_checkpoint") != "0.1":
        problems.append('aqt_checkpoint must be "0.1"')
    if not isinstance(checkpoint.get("log"), str) or not checkpoint["log"]:
        problems.append("log must be a non-empty string")
    if type(checkpoint.get("seq")) is not int or checkpoint["seq"] < 0:
        problems.append("seq must be an integer >= 0")
    if not is_hash(checkpoint.get("head")):
        problems.append("head must be sha256:<64 hex>")
    if not is_time(checkpoint.get("time")):
        problems.append("time must be RFC 3339 UTC with a Z suffix")
    sig = checkpoint.get("sig")
    if not isinstance(sig, dict) or sig.get("alg") != "ed25519" or not isinstance(sig.get("key"), str) \
            or not isinstance(sig.get("value"), str):
        problems.append("sig must be one object {alg: ed25519, key, value}")
    return problems


def verify_checkpoint(checkpoint: dict, keys: dict[str, Ed25519PublicKey]) -> bool:
    """True when ``checkpoint`` is well formed and signed by one of the pinned ``keys``."""
    if checkpoint_problems(checkpoint):
        return False
    body = {key: value for key, value in checkpoint.items() if key != "sig"}
    sig = checkpoint["sig"]
    public = keys.get(sig["key"])
    try:
        data = canonical_json(body)
    except CanonicalError:
        return False
    return public is not None and verify_signature(public, data, sig["value"])


def checkpoint_matches(checkpoint: dict, records: list[dict]) -> bool:
    """True when the record at the checkpoint's seq has exactly the checkpoint's head hash."""
    seq = checkpoint.get("seq") if isinstance(checkpoint, dict) else None
    if type(seq) is not int:
        return False
    for record in records:
        chain = record.get("chain") if isinstance(record, dict) else None
        if isinstance(chain, dict) and type(chain.get("seq")) is int and chain["seq"] == seq:
            try:
                return record_hash(record) == checkpoint.get("head")
            except CanonicalError:
                return False
    return False
