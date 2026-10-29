"""aqt-signoff: signatures with meaning bound to exact content, and approved actions.

Functions used by other AQT tools (see README, Python API)::

    verify_subject(sha256, *, meaning=None, sources=None) -> list[SignatureStatus]
    is_approved(sha256, *, meaning="approved", policy=None, sources=None, authors=None) -> bool
    check_signers(*, sources=None) -> dict
"""

from __future__ import annotations

from .actions import Actions, Claim
from .core import PolicyResult, Signoff, VerifyReport
from .errors import AlreadyClaimed, AuthFailed, Conflict, NotFound, Refused, SignoffError, UsageError
from .registry import Registry, StaticPassphrase, TtyAuthenticator
from .settings import Policy, Settings, load_settings
from .statements import SignatureStatus, build_statement, check_block, sign, statement_digest

__version__ = "0.1.0"


def _open(sources) -> Signoff:
    return Signoff(load_settings(evidence=list(sources) if sources is not None else None))


def verify_subject(sha256: str, *, meaning: str | None = None, sources=None) -> list[SignatureStatus]:
    """Every signature over ``sha256`` found in the evidence ``sources`` (default: ``iter_evidence``
    sources), each verified against the signer registry."""
    return _open(sources).signatures_for(sha256, meaning=meaning)


def is_approved(sha256: str, *, meaning: str = "approved", policy: Policy | dict | None = None,
                sources=None, authors=None) -> bool:
    """True when valid signatures with ``meaning`` over ``sha256`` satisfy the policy
    (``policy`` argument, else the configured policy for that meaning, else one signature).

    Authors for ``distinct_from_author`` are ``authors`` plus, always, the actor of every evidence
    record whose ``record_content_hash`` is ``sha256`` and every ``authored`` signer, as in
    ``Signoff.verify_record``."""
    so = _open(sources)
    if isinstance(policy, dict):
        policy = Policy.from_dict(policy)
    records = so.records()
    statuses = so.signatures_for(sha256, records=records)
    results = so.evaluate_policies(statuses, sha256, required=[meaning],
                                   authors=set(authors or ()) | so.record_authors(sha256, records),
                                   policies={meaning: policy} if policy else None)
    return results[meaning].met


def check_signers(*, sources=None) -> dict:
    """``{"ok", "registry", "evidence", "keys": [{signer, name, role, key_id, state, counts, problems,
    notes, enrolled_at, revoked_at, enrolled_role, enrolment}]}``: every registry key and whether an
    enrolment record in the evidence backs it. A key with ``counts`` False is ignored by every check."""
    return _open(sources).check_signers()


__all__ = [
    "Actions", "AlreadyClaimed", "AuthFailed", "Claim", "Conflict", "NotFound", "Policy", "PolicyResult", "Refused",
    "Registry", "Settings", "SignatureStatus", "Signoff", "SignoffError", "StaticPassphrase", "TtyAuthenticator",
    "UsageError", "VerifyReport", "build_statement", "check_block", "check_signers", "is_approved", "load_settings",
    "sign", "statement_digest", "verify_subject",
]
