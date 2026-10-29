"""Approved scope versus actual diff (``reconcile-diff``)."""

from __future__ import annotations

from pathlib import Path

from aqt_evidence import new_record, subject

from .actors import current_actor
from .approval import approval_state
from .config import PROJECT_FILE
from .errors import refused
from .globs import matches_any
from .ledger import Ledger
from .plan import Plan
from .plans import read_plan, require_valid, status
from .receipts import Freshness, evaluate


def compare(ledger: Ledger, rel: str, plan: Plan, freshness: Freshness | None = None,
            sources: list[Path] | None = None) -> dict:
    state = ledger.plan_state(plan.id) or {}
    base = state.get("base_commit") or plan.base_commit
    declared = plan.declared_paths
    allowed = list(ledger.config.gate.always_allowed_paths)
    changed = []
    if ledger.git and base:
        changed = [{"path": p, "status": s} for s, p in ledger.git.changed_since(base) if p != rel]
    unapproved = [c["path"] for c in changed
                  if declared and not matches_any(c["path"], declared) and not matches_any(c["path"], allowed)]
    untouched = [g for g in declared if not any(matches_any(c["path"], [g]) for c in changed)]
    settings = [c["path"] for c in changed if c["path"] == PROJECT_FILE]
    items = evaluate(ledger, plan, freshness)
    missing = [item_id for item_id, entry in items.items() if entry["state"] != "ok"]
    if not ledger.git or not base:
        result = "no_base"
    elif not declared:
        result = "scope_undeclared"
    elif unapproved or missing or settings:
        result = "findings"
    else:
        result = "clean"
    return {"plan_id": plan.id, "plan_ref": plan.id, "base_commit": base,
            "approval": approval_state(ledger, plan.id, sources), "declared_paths": declared,
            "changed": changed, "unapproved": unapproved, "untouched_declared": untouched,
            "missing_evidence": missing, "settings_changed": settings, "result": result}


def reconcile_diff(ledger: Ledger, plan_path: str, sources: list[Path] | None = None) -> dict:
    rel, plan = read_plan(ledger, plan_path)
    require_valid(plan, rel)
    if status(ledger, rel)["state"] == "unregistered":
        raise refused("plan_unregistered", f"{rel} is not registered")
    data = compare(ledger, rel, plan, sources=sources)
    record = new_record("change.reconciliation", current_actor(ledger.config.actor), "reconcile-diff",
                        subject=subject("plan", plan.id, sha256=plan.raw_hash), data=data)
    return ledger.emit(record)
