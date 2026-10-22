"""Detached signed statements (``data.signature``) and their verification.

Shape (aqt-spec spec §6.3, ``schemas/signature.schema.json``)::

    "signature": {"statement": {...}, "alg": "ed25519", "key": "ed25519:<16 hex>", "value": "<base64>"}

The value is an Ed25519 signature over ``canonical_json(statement)``. Statement fields::

    {"aqt_signature": "0.1", "record_type": "<record type that carries it>",
     "signer": {"id": "human:alice", "name": "Alice Example", "role": "quality-manager"},
     "key": "ed25519:<16 hex>", "meaning": "approved", "reason": "...",
     "signed_at": "<RFC 3339 UTC>", "tz": "<IANA zone>", "nonce": "<16 hex>",
     "subject": {"kind": "file|record|action|hash|key", "ref": "...", "sha256": "sha256:..."}}

Optional: ``expires_at`` (approvals), ``outcome`` (resolutions). Because name, role,
meaning, time and reason are inside the signed bytes, the manifestation cannot be
changed without breaking the signature; because the subject hash is inside, the
signature cannot be moved to other content.
"""

from __future__ import annotations

import secrets
from dataclasses import asdict, dataclass, field

from aqt_evidence import MEANINGS, Signer, sign_statement, verify_statement

from .registry import Registry, SignerEntry, parse_time

STATEMENT_VERSION = "0.1"
# Worst first; a signature's status is the worst that applies.
STATUS_ORDER = ("invalid", "unknown-signer", "revoked", "invalidated", "valid")


def build_statement(*, record_type: str, signer: SignerEntry, key: str, meaning: str, reason: str,
                    subject: dict, signed_at: str, tz: str, **extra) -> dict:
    statement = {
        "aqt_signature": STATEMENT_VERSION, "record_type": record_type,
        "signer": {"id": signer.id, "name": signer.name, "role": signer.role}, "key": key,
        "meaning": meaning, "reason": reason, "signed_at": signed_at, "tz": tz,
        "subject": {k: subject[k] for k in ("kind", "ref", "sha256")}, "nonce": secrets.token_hex(8),
    }
    statement.update({k: v for k, v in extra.items() if v is not None})
    return statement


def sign(statement: dict, key: Signer) -> dict:
    """The ``data.signature`` block (``aqt_evidence.sign_statement``)."""
    return sign_statement(statement, key)


@dataclass
class SignatureStatus:
    """One signature and what it is worth now."""
    record_id: str | None
    record_type: str | None
    status: str
    detail: str = ""
    signer_id: str | None = None
    name: str | None = None
    role: str | None = None
    meaning: str | None = None
    reason: str | None = None
    signed_at: str | None = None
    tz: str | None = None
    key: str | None = None
    subject: dict = field(default_factory=dict)
    expires_at: str | None = None

    @property
    def valid(self) -> bool:
        return self.status == "valid"

    def worsen(self, status: str, detail: str) -> None:
        if STATUS_ORDER.index(status) < STATUS_ORDER.index(self.status):
            self.status, self.detail = status, detail

    def as_dict(self) -> dict:
        return asdict(self)


def _is_hash(value) -> bool:
    return isinstance(value, str) and value.startswith("sha256:") and len(value) == 71


def check_block(block, registry: Registry, *, record: dict | None = None) -> SignatureStatus:
    """Verify a ``data.signature`` block against the pinned registry (no content check)."""
    rid = record.get("id") if isinstance(record, dict) else None
    rtype = record.get("type") if isinstance(record, dict) else None
    status = SignatureStatus(rid, rtype, "valid")
    if not isinstance(block, dict) or not isinstance(block.get("statement"), dict):
        status.worsen("invalid", "no signed statement")
        return status
    st = block["statement"]
    signer = st.get("signer") if isinstance(st.get("signer"), dict) else {}
    subject = st.get("subject") if isinstance(st.get("subject"), dict) else {}
    status.signer_id, status.name, status.role = signer.get("id"), signer.get("name"), signer.get("role")
    status.meaning, status.reason, status.signed_at, status.tz = (st.get("meaning"), st.get("reason"),
                                                                 st.get("signed_at"), st.get("tz"))
    status.key, status.subject, status.expires_at = block.get("key"), subject, st.get("expires_at")
    problems = []
    if st.get("aqt_signature") != STATEMENT_VERSION:
        problems.append("unsupported statement version")
    if block.get("alg") != "ed25519":
        problems.append("alg must be ed25519")
    if st.get("key") != block.get("key"):
        problems.append("statement key differs from the signing key")
    if st.get("meaning") not in MEANINGS:
        problems.append("meaning is not a known meaning")
    if not isinstance(st.get("reason"), str) or not st["reason"].strip():
        problems.append("reason missing")
    if not _is_hash(subject.get("sha256")) or not subject.get("kind") or not subject.get("ref"):
        problems.append("subject needs kind, ref and sha256")
    try:
        signed_at = parse_time(st.get("signed_at", ""))
    except (TypeError, ValueError):
        problems.append("signed_at is not a timestamp")
        signed_at = None
    if record is not None:
        if st.get("record_type") != rtype:
            problems.append(f"statement record_type {st.get('record_type')!r} does not match record type {rtype!r}")
        if "meaning" in record and record["meaning"] != st.get("meaning"):
            problems.append("record meaning differs from the signed meaning")
    if problems:
        status.worsen("invalid", "; ".join(problems))
        return status
    found = registry.find_key(block.get("key", ""))
    if found is None:
        status.worsen("unknown-signer", "key is not in the signer registry")
        return status
    entry, key = found
    if entry.id != signer.get("id"):
        status.worsen("invalid", f"key belongs to {entry.id}, statement names {signer.get('id')}")
        return status
    if not verify_statement(block, {key.key_id: key.public_key()}):
        status.worsen("invalid", "signature does not verify (statement altered or wrong key)")
        return status
    if (entry.name, entry.role) != (signer.get("name"), signer.get("role")):
        status.detail = "registry name or role changed since signing; the signed values are shown"
    if signed_at < parse_time(key.enrolled_at):
        status.worsen("unknown-signer", "signed before the key was enrolled")
    elif key.revoked_at and signed_at >= parse_time(key.revoked_at):
        status.worsen("revoked", f"key revoked at {key.revoked_at}")
    return status


def statement_of(record: dict) -> dict | None:
    data = record.get("data") if isinstance(record, dict) else None
    block = data.get("signature") if isinstance(data, dict) else None
    if isinstance(block, dict) and isinstance(block.get("statement"), dict):
        return block["statement"]
    return None
