"""Approval state of a plan from aqt-signoff signatures (aqt-spec spec §6.3 and §10.5; aqt-signoff Python API).

The approval target is the latest baseline/begin/semantic reconciliation record.
A signature subject is ``{kind: record, ref: <id>, sha256: record_content_hash(record)}``.
``signed``: aqt-signoff is installed and confirms it. ``unverified``: a matching
``signoff.signature`` record exists but aqt-signoff is not installed to verify it.
``invalid``: aqt-signoff is installed and rejects the signature(s). ``stale``:
an earlier target was approved, the plan changed semantically since.
"""

from __future__ import annotations

from pathlib import Path

from aqt_evidence import iter_evidence, record_content_hash

from .ledger import Ledger


def _signoff_check(sha: str, sources: list[Path] | None) -> bool | None:
    try:
        import aqt_signoff  # type: ignore
    except ImportError:
        return None
    try:
        return bool(aqt_signoff.is_approved(sha, meaning="approved", sources=sources))
    except Exception:  # an incompatible or broken install: fall back to unverified
        return None


def _signature_records(sha: str, sources: list[Path] | None) -> list[dict]:
    try:
        records = list(iter_evidence(sources))
    except Exception:
        return []
    found = []
    for record in records:
        if record.get("type") != "signoff.signature":
            continue
        subj = record.get("subject") or {}
        meaning = record.get("meaning") or (record.get("data") or {}).get("meaning")
        if subj.get("kind") == "record" and subj.get("sha256") == sha and meaning == "approved":
            found.append(record)
    return found


def approval_state(ledger: Ledger, plan_id: str, sources: list[Path] | None = None) -> dict:
    state = ledger.plan_state(plan_id) or {}
    targets = [ledger.record(rid) for rid in state.get("approval_targets", [])]
    targets = [t for t in targets if t]
    if not targets:
        return {"state": "unsigned", "record": None, "sha256": None, "signature": None}
    latest = targets[-1]
    for index, target in enumerate(reversed(targets)):
        sha = record_content_hash(target)
        verified = _signoff_check(sha, sources)
        signatures = _signature_records(sha, sources)
        if verified or signatures:
            if index > 0:
                kind = "stale"
            elif verified:
                kind = "signed"
            elif verified is None:
                kind = "unverified"   # aqt-signoff not installed: found, not checked
            else:
                kind = "invalid"      # aqt-signoff checked the signature(s) and rejected them
            return {"state": kind, "record": latest["id"], "sha256": record_content_hash(latest),
                    "approved_record": target["id"],
                    "signature": signatures[-1]["id"] if signatures else None}
    return {"state": "unsigned", "record": latest["id"], "sha256": record_content_hash(latest), "signature": None}
