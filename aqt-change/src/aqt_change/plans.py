"""Plan ledger operations: new, add, status, reconcile, begin.

Reconciliation rules adapted from Project Tracker Next
(``services/plan_maintenance.py``): identity and lifecycle fields are immutable,
event history is append-only, editorial is refused when the structure changed,
semantic changes keep completed items and are refused for terminal plans.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

from aqt_evidence import new_record, subject

from . import plan as planmod
from .actors import current_actor
from .errors import ChangeError, refused, usage
from .ledger import Ledger, atomic_write, read_json
from .plan import Plan, basis_hash, item_diff, parse_plan, structure

STATES_OK = ("clean", "status_neutral")


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def read_plan(ledger: Ledger, path: str | os.PathLike) -> tuple[str, Plan]:
    rel = ledger.rel(path)
    try:
        text = ledger.abs(rel).read_text(encoding="utf-8")
    except FileNotFoundError as error:
        raise usage("plan_not_found", f"plan file not found: {rel}") from error
    return rel, parse_plan(text)


def require_valid(plan: Plan, rel: str) -> None:
    if plan.errors:
        raise refused("plan_invalid", f"{rel}: " + "; ".join(plan.errors[:5]), errors=plan.errors[:20])


def write_plan(ledger: Ledger, rel: str, text: str) -> None:
    path = ledger.abs(rel)
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o644
    atomic_write(path, text.encode("utf-8"), mode)


def accepted_plan(ledger: Ledger, state: dict) -> Plan:
    data = ledger.get_object("objects", state["accepted_raw"])
    if data is None:
        raise ChangeError("ledger_corrupt", f"accepted snapshot of {state['plan_id']} is missing", exit_code=2)
    return parse_plan(data.decode("utf-8"))


def external(ledger: Ledger) -> bool:
    return ledger.config.lifecycle_owner == "external"


def status(ledger: Ledger, path: str | os.PathLike, *, ratchet: bool = True) -> dict:
    rel, plan = read_plan(ledger, path)
    result = {"path": rel, "plan_id": plan.id, "status": plan.status, "current_raw": plan.raw_hash,
              "errors": plan.errors, "items": {"added": [], "removed": [], "changed": []}}
    if plan.errors:
        return {**result, "state": "invalid"}
    current_basis = basis_hash(plan)
    result["current_basis"] = current_basis
    state = ledger.plan_state(plan.id)
    if not state:
        return {**result, "state": "unregistered"}
    result.update(accepted_raw=state["accepted_raw"], accepted_basis=state["accepted_basis"],
                  base_commit=state.get("base_commit"))
    if state["path"] != rel:
        return {**result, "state": "conflict",
                "errors": [f"plan id {plan.id} is registered for {state['path']}"]}
    if plan.raw_hash == state["accepted_raw"]:
        return {**result, "state": "clean"}
    accepted = accepted_plan(ledger, state)
    result["items"] = item_diff(accepted, plan)
    seen = state.get("seen_events", [])
    current_events = [event.identity() for event in plan.events]
    if current_events[: len(seen)] != seen:
        return {**result, "state": "history_rewritten"}
    if not external(ledger) and accepted.lifecycle != plan.lifecycle:
        if _finish_pending(ledger, plan):
            return {**result, "state": "finish_pending"}
        return {**result, "state": "lifecycle_changed"}
    if current_basis != state["accepted_basis"]:
        return {**result, "state": "unreconciled"}
    if ratchet and len(current_events) > len(seen):
        state["seen_events"] = current_events
        ledger.save_plan_state(plan.id, state)
    return {**result, "state": "status_neutral"}


def _finish_pending(ledger: Ledger, plan: Plan) -> bool:
    """True when an unfinished finish attempt wrote exactly this plan version."""
    folder = ledger.state / "attempts" / plan.id
    for path in folder.glob("*.json") if folder.is_dir() else []:
        attempt = read_json(path) or {}
        if attempt.get("phase") != "completed" and attempt.get("after_raw") == plan.raw_hash:
            return True
    return False


def _record(ledger: Ledger, action: str, plan: Plan, rel: str, *, kind: str, before: str | None,
            reason: str | None, items: dict | None = None, extra: dict | None = None,
            basis_before: str | None = None) -> dict:
    data = {"plan_id": plan.id, "plan_ref": plan.id, "path": rel, "kind": kind, "status": plan.status,
            "basis_before": basis_before, "basis_after": basis_hash(plan),
            "items": items or {"added": [], "removed": [], "changed": []},
            "snapshot": plan.raw_hash, "lifecycle_owner": ledger.config.lifecycle_owner, **(extra or {})}
    record = new_record("change.plan.reconciled", current_actor(ledger.config.actor), action,
                        subject=subject("plan", plan.id, sha256=plan.raw_hash),
                        before={"sha256": before} if before else None, after={"sha256": plan.raw_hash},
                        reason=reason, data={k: v for k, v in data.items() if v is not None})
    return ledger.emit(record)


def _accept(ledger: Ledger, plan: Plan, rel: str, record: dict, state: dict | None, *,
            target: bool, **updates) -> dict:
    ledger.put_object("objects", plan.text.encode("utf-8"))
    state = dict(state or {"plan_id": plan.id, "path": rel, "history": [], "approval_targets": []})
    state.update(accepted_raw=plan.raw_hash, accepted_basis=basis_hash(plan),
                 seen_events=[e.identity() for e in plan.events], status=plan.status, **updates)
    state["history"] = [*state.get("history", []),
                        {"record": record["id"], "action": record["action"], "kind": record["data"]["kind"],
                         "raw": plan.raw_hash, "time": record["time"]}]
    if target:
        state["approval_targets"] = [*state.get("approval_targets", []), record["id"]]
    ledger.save_plan_state(plan.id, state)
    return state


def add(ledger: Ledger, path: str | os.PathLike) -> dict:
    rel, plan = read_plan(ledger, path)
    require_valid(plan, rel)
    state = ledger.plan_state(plan.id)
    if state:
        if state["path"] != rel:
            raise refused("plan_id_conflict", f"plan id {plan.id} is already registered for {state['path']}")
        return {"ok": True, "result": "already_registered", "plan_id": plan.id, "path": rel}
    record = _record(ledger, "baseline", plan, rel, kind="baseline", before=None, reason=None,
                     extra={"base_commit": plan.base_commit})
    _accept(ledger, plan, rel, record, None, target=True, base_commit=plan.base_commit)
    return {"ok": True, "result": "registered", "plan_id": plan.id, "path": rel, "record": record["id"],
            "accepted_raw": plan.raw_hash}


def new(ledger: Ledger, path: str | os.PathLike, plan_id: str, title: str, implementation: str | None,
        follows: str | None = None) -> dict:
    rel = ledger.rel(path)
    target = ledger.abs(rel)
    if target.exists():
        raise usage("plan_exists", f"{rel} already exists")
    if ledger.plan_state(plan_id):
        raise refused("plan_id_conflict", f"plan id {plan_id} is already registered")
    try:
        text = planmod.new_plan_text(plan_id, title, implementation or "default", follows)
    except ValueError as error:
        raise usage("plan_id_invalid", str(error)) from error
    target.parent.mkdir(parents=True, exist_ok=True)
    write_plan(ledger, rel, text)
    result = add(ledger, rel)
    return {**result, "result": "created"}


def reconcile(ledger: Ledger, path: str | os.PathLike, kind: str, reason: str | None,
              expect: str | None = None) -> dict:
    if kind not in ("editorial", "semantic"):
        raise usage("kind_invalid", "kind must be editorial or semantic")
    reason = (reason or "").strip() or None
    rel, plan = read_plan(ledger, path)
    require_valid(plan, rel)
    state = ledger.plan_state(plan.id)
    if not state:
        raise refused("plan_unregistered", f"{rel} is not registered; run 'aqt-change plan add' first")
    if state["path"] != rel:
        raise refused("plan_id_conflict", f"plan id {plan.id} is registered for {state['path']}")
    if expect and expect != plan.raw_hash:
        raise refused("source_conflict", "the plan changed since the version you edited",
                      expected=expect, current=plan.raw_hash)
    if plan.raw_hash == state["accepted_raw"]:
        return {"ok": True, "result": "already_reconciled", "plan_id": plan.id}
    old = accepted_plan(ledger, state)
    changed_identity = [k for k in planmod.IDENTITY_KEYS if old.tracker.get(k) != plan.tracker.get(k)]
    if changed_identity:
        raise refused("plan_identity_changed", "reconciliation cannot change plan identity fields",
                      changed_fields=changed_identity)
    if not external(ledger) and old.lifecycle != plan.lifecycle:
        raise refused("plan_lifecycle_changed", "lifecycle fields (status, started_at, completed_at, git) are "
                      "written by begin/finish only; restore them, then reconcile")
    seen = state.get("seen_events", [])
    if [e.identity() for e in plan.events][: len(seen)] != seen:
        raise refused("plan_event_history_changed", "event history is append-only: restore the existing entries, "
                      "then reconcile", existing_event_count=len(seen))
    status_value = plan.status or "planned"
    active = status_value in planmod.ACTIVE
    terminal = status_value in planmod.TERMINAL
    diff = item_diff(old, plan)
    if kind == "editorial":
        if structure(old) != structure(plan):
            raise refused("plan_editorial_structure_changed",
                          "the edit changes structured plan meaning (items, identity, aqt block); reconcile it as semantic",
                          items=diff)
        if (active or terminal) and not reason:
            raise refused("plan_reason_required", f"editorial corrections to a {status_value} plan need a reason")
    else:
        if terminal:
            raise refused("terminal_plan_semantic_change", "semantic changes to a terminal plan need a follow-up "
                          "plan ('aqt-change plan new --follows')", status=status_value)
        if not reason:
            raise refused("plan_reason_required", "semantic changes need a reason")
        if active:
            for prior in old.items:
                if not prior.checked:
                    continue
                current = plan.item(prior.id)
                if current is None or not current.checked or current.text != prior.text:
                    raise refused("plan_checked_item_changed", "an active plan must keep completed items "
                                  "(ID, text and check state)", item_id=prior.id)
    if ledger.plan_states() and any(s["plan_id"] == plan.id and s["path"] != rel for s in ledger.plan_states()):
        raise refused("plan_id_conflict", f"plan id {plan.id} conflicts with another registered plan")
    record = _record(ledger, "reconcile", plan, rel, kind=kind, before=state["accepted_raw"], reason=reason,
                     items=diff, basis_before=state["accepted_basis"],
                     extra={"scope_changed": old.aqt != plan.aqt,
                            "events_appended": len(plan.events) - len(seen)})
    _accept(ledger, plan, rel, record, state, target=(kind == "semantic"))
    return {"ok": True, "result": "reconciled", "plan_id": plan.id, "kind": kind, "record": record["id"],
            "items": diff, "accepted_raw": plan.raw_hash}


def begin(ledger: Ledger, path: str | os.PathLike, reason: str | None = None) -> dict:
    rel, plan = read_plan(ledger, path)
    require_valid(plan, rel)
    current = status(ledger, rel)
    if current["state"] == "unregistered":
        add(ledger, rel)
    elif current["state"] not in STATES_OK:
        raise refused("plan_unreconciled", f"{rel} is {current['state']}; reconcile before begin",
                      state=current["state"])
    state = ledger.plan_state(plan.id)
    if external(ledger):
        if any(h["action"] == "begin" for h in state.get("history", [])):
            return {"ok": True, "result": "unchanged", "plan_id": plan.id, "base_commit": state.get("base_commit")}
        base = plan.base_commit or ledger.head()
        record = _record(ledger, "begin", plan, rel, kind="baseline", before=None, reason=reason,
                         extra={"base_commit": base})
        _accept(ledger, plan, rel, record, state, target=True, base_commit=base)
        return {"ok": True, "result": "started", "plan_id": plan.id, "base_commit": base, "record": record["id"]}
    status_value = plan.status or "planned"
    if status_value == "in_progress":
        return {"ok": True, "result": "unchanged", "plan_id": plan.id, "base_commit": state.get("base_commit")}
    if status_value == "draft":
        raise refused("planning_required", "a draft plan must become 'planned' (reconcile) before begin")
    if status_value in planmod.TERMINAL:
        raise refused("follow_up_required", f"plan is {status_value}; create a follow-up plan")
    if status_value == "blocked" and not reason:
        raise refused("resume_reason_required", "resuming a blocked plan needs --reason")
    base = ledger.head()
    git_meta = {"base_commit": base, "branches": [ledger.git.branch() or "HEAD"]} if base else None
    before_raw = plan.raw_hash
    text = planmod.set_tracker(plan.text, status="in_progress",
                               started_at=plan.tracker.get("started_at") or now_iso(),
                               git=git_meta if status_value != "blocked" else plan.tracker.get("git"))
    if status_value == "blocked":
        base = plan.base_commit or base
    updated = parse_plan(text)
    if basis_hash(updated) != basis_hash(plan):
        raise ChangeError("internal_basis_changed", "begin would change the plan basis", exit_code=2)
    write_plan(ledger, rel, text)
    record = _record(ledger, "begin", updated, rel, kind="baseline", before=before_raw, reason=reason,
                     extra={"base_commit": base})
    _accept(ledger, updated, rel, record, state, target=True, base_commit=base)
    return {"ok": True, "result": "started", "plan_id": plan.id, "base_commit": base, "record": record["id"]}


def active_plans(ledger: Ledger) -> list[tuple[str, Plan]]:
    found = []
    for state in ledger.plan_states():
        path = ledger.abs(state["path"])
        if not path.exists():
            continue
        plan = parse_plan(path.read_text(encoding="utf-8"))
        if plan.status == "in_progress":
            found.append((state["path"], plan))
    return found


def plan_root_files(ledger: Ledger) -> list[str]:
    return [state["path"] for state in ledger.plan_states()]

