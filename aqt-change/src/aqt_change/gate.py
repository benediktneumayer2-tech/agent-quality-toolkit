"""The release gate: GO / NO-GO / MANUAL_VERIFY_REQUIRED, derived only from records.

Waivers never turn the gate into GO (the derived decision is kept separate from
the waiver, as in BMAD TEA; idea only).
"""

from __future__ import annotations

from pathlib import Path

from . import antigaming
from .config import INDEPENDENCE
from .ledger import Ledger
from .plan import Plan
from .plans import STATES_OK, read_plan, require_valid, status
from .receipts import Freshness, evaluate, run, utc_stamp
from .scope import compare

RANK = {name: index for index, name in enumerate(("none", *INDEPENDENCE))}


def latest_finish(ledger: Ledger, plan_id: str) -> dict | None:
    finishes = list(ledger.records("change.finish", plan_id))
    return finishes[-1] if finishes else None


def fresh_reviews(ledger: Ledger, plan: Plan, freshness: Freshness) -> list[dict]:
    fresh = []
    for review in ledger.records("change.review", plan.id):
        data = review["data"]
        if data.get("tree_fingerprint") == freshness.fingerprint(data.get("fingerprint_excludes") or []):
            fresh.append(review)
    return fresh


def policy_for(ledger: Ledger, plan: Plan) -> dict:
    policy = ledger.config.gate.as_dict()
    plan_review = plan.aqt.get("review") if isinstance(plan.aqt.get("review"), dict) else {}
    wanted = str(plan_review.get("min_independence", "none"))
    if wanted in RANK and RANK[wanted] > RANK[policy["min_review_independence"]]:
        policy["min_review_independence"] = wanted
    return policy


def evaluate_gate(ledger: Ledger, rel: str, plan: Plan, *, sources: list[Path] | None = None,
                  waivers: list[dict] | None = None, for_finish: bool = False) -> dict:
    nogo: list[dict] = []
    manual: list[dict] = []
    policy = policy_for(ledger, plan)
    current = status(ledger, rel)
    if current["state"] not in STATES_OK:
        nogo.append({"code": "plan_unreconciled", "detail": current["state"]})
    finish = latest_finish(ledger, plan.id)
    if waivers is None:
        waivers = (finish["data"].get("waivers") if finish else None) or []
    waived = {w["item"] for w in waivers}
    freshness = Freshness(ledger)
    items = evaluate(ledger, plan, freshness)
    receipts = []
    for item_id, entry in items.items():
        if entry["state"] != "ok":
            if item_id in waived:
                manual.append({"code": "waiver_present", "item": item_id})
            else:
                nogo.append({"code": f"receipt_{entry['state']}", "item": item_id})
            continue
        if entry["manual"]:
            receipts.append(entry["receipt"])
            if entry.get("attested_by") != "human":
                manual.append({"code": "manual_item_agent_attested", "item": item_id})
        else:
            receipts += [c["receipt"] for c in entry["commands"]]
    for item_id in sorted(waived - set(items)):
        manual.append({"code": "waiver_present", "item": item_id})
    scope = compare(ledger, rel, plan, freshness, sources)
    if scope["result"] == "scope_undeclared":
        manual.append({"code": "scope_undeclared", "detail": "the plan declares no aqt.paths"})
    elif scope["result"] == "no_base":
        manual.append({"code": "scope_unverifiable", "detail": "no Git base commit to compare against"})
    if scope["unapproved"]:
        nogo.append({"code": "unapproved_change", "detail": ", ".join(scope["unapproved"][:20])})
    warnings = antigaming.scan(ledger.git, scope["base_commit"], {rel}) if ledger.git else []
    for warning in warnings:
        entry = {"code": "anti_gaming_warning", "detail": f"{warning['code']}: {warning.get('path', '')}"}
        (nogo if policy["warnings_block"] else manual).append(entry)
    approval = scope["approval"]
    if approval["state"] == "invalid":
        manual.append({"code": "approval_invalid", "detail": "aqt-signoff rejected the approval signature"})
    elif approval["state"] == "stale":
        manual.append({"code": "approval_stale", "detail": "the plan changed semantically after approval"})
    elif policy["require_signed_approval"] and approval["state"] == "unverified":
        manual.append({"code": "approval_unverified", "detail": "signature found; aqt-signoff not available to verify"})
    elif policy["require_signed_approval"] and approval["state"] == "unsigned":
        manual.append({"code": "approval_unsigned"})
    reviews = fresh_reviews(ledger, plan, freshness)
    every = list(ledger.records("change.review", plan.id))
    if every and every[-1]["data"]["verdict"] == "FAIL":
        # a FAIL stays open until a later review replaces it, even when the code changed since
        nogo.append({"code": "review_fail", "detail": every[-1]["id"]})
    for review in reviews:
        verdict = review["data"]["verdict"]
        if verdict == "FAIL":
            continue
        elif verdict == "CONCERNS":
            manual.append({"code": "review_concerns", "detail": review["id"]})
        elif verdict == "WAIVED":
            manual.append({"code": "review_waived", "detail": review["id"]})
    wanted = policy["min_review_independence"]
    if wanted != "none":
        best = max((RANK[r["data"]["independence"]] for r in reviews if r["data"]["verdict"] == "PASS"), default=0)
        if best < RANK[wanted]:
            manual.append({"code": "review_independence_below_policy", "detail": f"needs {wanted}"})
    if not for_finish and not finish:
        nogo.append({"code": "not_finished"})
    decision = "NO-GO" if nogo else ("MANUAL_VERIFY_REQUIRED" if manual else "GO")
    return {"aqt_gate": "0.1", "plan_id": plan.id, "decision": decision, "reasons": nogo + manual,
            "approval": approval, "receipts": [r for r in receipts if r], "items": items,
            "reviews": [r["id"] for r in reviews], "waivers": waivers, "warnings": warnings, "scope": scope,
            "finish": finish["id"] if finish else None, "evaluated_at": utc_stamp(),
            "policy": policy, "policy_sha256": _policy_hash(policy)}


def _policy_hash(policy: dict) -> str:
    from aqt_evidence import content_hash
    return content_hash(policy)


def gate(ledger: Ledger, plan_path: str, *, sources: list[Path] | None = None, rerun: bool = False) -> dict:
    rel, plan = read_plan(ledger, plan_path)
    require_valid(plan, rel)
    if rerun and any(item.commands for item in plan.verification):
        run(ledger, [], plan_path=rel, all_items=True, echo=False)
        rel, plan = read_plan(ledger, rel)
    result = evaluate_gate(ledger, rel, plan, sources=sources)
    result["rerun"] = rerun
    return result


def public(result: dict) -> dict:
    """The gate JSON without bulky helper sections."""
    keep = ("aqt_gate", "plan_id", "decision", "reasons", "approval", "receipts", "reviews", "waivers",
            "finish", "evaluated_at", "policy_sha256", "rerun")
    return {key: result[key] for key in keep if key in result}
