"""The release gate: GO / NO-GO / MANUAL_VERIFY_REQUIRED, derived only from records.

Waivers never turn the gate into GO (the derived decision is kept separate from
the waiver, as in BMAD TEA; idea only).
"""

from __future__ import annotations

from pathlib import Path

from . import antigaming
from .config import INDEPENDENCE
from .config import PROJECT_FILE
from .ledger import TRAIL_REQUIRED, TRUST_NOGO, TRUST_TEXT, Ledger
from .plan import Plan
from .plans import STATES_OK, read_plan, require_valid, status
from .receipts import HIDDEN_FIX, Freshness, evaluate, hidden_text, run, trust_blocks, trust_note, utc_stamp
from .scope import compare

RANK = {name: index for index, name in enumerate(("none", *INDEPENDENCE))}


def latest_finish(ledger: Ledger, plan_id: str) -> dict | None:
    finishes = list(ledger.records("change.finish", plan_id))
    return finishes[-1] if finishes else None


def counted_reviews(ledger: Ledger, plan: Plan, freshness: Freshness) -> tuple[list[dict], list[dict]]:
    """(reviews that count, the others with their trail status). With a trail in use, a review counts
    when the trail log confirms it; a FAIL verdict counts from anywhere (a doubt needs no proof)."""
    counted, unverified = [], []
    for review in ledger.records("change.review", plan.id):
        trust = freshness.trail.status(review)
        if trust == "ok" or review["data"].get("verdict") == "FAIL":
            counted.append(review)
        else:
            unverified.append({"review": review, "trust": trust})
    return counted, unverified


def fresh_reviews(ledger: Ledger, plan: Plan, freshness: Freshness, reviews: list[dict] | None = None) -> list[dict]:
    fresh = []
    for review in ledger.records("change.review", plan.id) if reviews is None else reviews:
        data = review["data"]
        if data.get("tree_fingerprint") == freshness.fingerprint(data.get("fingerprint_excludes") or [],
                                                                  plan.declared_paths):
            fresh.append(review)
    return fresh


def policy_for(ledger: Ledger, plan: Plan) -> dict:
    """The user's ``[gate]`` policy, made stricter by the project's ``[gate]`` (``.aqt/change.toml``) and the
    plan's ``aqt.review.min_independence``: the strictest value of each wins."""
    policy = ledger.config.gate.as_dict()
    project = ledger.project_settings(plan.id)["gate"]
    for name in ("require_signed_approval", "warnings_block"):
        policy[name] = bool(policy[name] or project[name])
    plan_review = plan.aqt.get("review") if isinstance(plan.aqt.get("review"), dict) else {}
    for wanted in (project["min_review_independence"], str(plan_review.get("min_independence", "none"))):
        if wanted in RANK and RANK[wanted] > RANK[policy["min_review_independence"]]:
            policy["min_review_independence"] = wanted
    return policy


def left_out_text(left: list[dict], limit: int = 20) -> str:
    """``Git.left_out()`` as one line."""
    text = ", ".join(f"{entry['path']} ({entry['state']})" for entry in left[:limit])
    return text + (f" and {len(left) - limit} more" if len(left) > limit else "")


def left_out(ledger: Ledger, rel: str, plan: Plan, snapshot: dict | None, committed: set[str]) -> list[dict]:
    """Files whose tested content (``snapshot``) a commit of HEAD plus ``committed`` would not hold (see
    ``Git.left_out``); the plan file is left out, finish writes and commits it."""
    if not ledger.git or snapshot is None:
        return []
    return ledger.git.left_out(snapshot, committed | {rel}, plan.declared_paths,
                               ledger.project_settings(plan.id)["fingerprint_exclude"])


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
    freshness = Freshness(ledger, plan.id)
    if freshness.trail.missing:
        nogo.append({"code": "trail_required", "detail": TRAIL_REQUIRED})
    base = ledger.base_problem(plan.id, freshness.trail)
    if base:
        (nogo if base.pop("nogo") else manual).append(base)
    items = evaluate(ledger, plan, freshness)
    receipts = []
    for item_id, entry in items.items():
        if entry["state"] != "ok":
            if item_id in waived:
                manual.append({"code": "waiver_present", "item": item_id})
            elif entry["state"] == "unverified":
                reason = {"code": "receipt_unverified", "item": item_id, "detail": trust_note(entry)}
                (nogo if trust_blocks(entry) else manual).append(reason)
            else:
                nogo.append({"code": f"receipt_{entry['state']}", "item": item_id})
            continue
        for receipt_id in entry.get("modified", []):
            manual.append({"code": "command_modified_worktree", "item": item_id, "detail": f"{receipt_id}: "
                           "the working tree changed while the command ran, so the receipt does not show what "
                           "the tree it names does; run the check again on an unchanged tree"})
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
    if scope["allowed_by_user_config"]:
        manual.append({"code": "allowed_by_user_config", "detail": "outside the plan's paths, allowed only by "
                       "always_allowed_paths in the user configuration (not in " + PROJECT_FILE + "): "
                       + ", ".join(scope["allowed_by_user_config"][:20])})
    if scope.get("settings_changed"):
        manual.append({"code": "project_settings_changed", "detail": f"the change edits {PROJECT_FILE} "
                       "(aqt-change project settings such as require_trail); a human checks it"})
    hidden = freshness.hidden()
    sparse = [h for h in hidden if h["state"] == "sparse"]
    hidden = [h for h in hidden if h["state"] != "sparse"]
    if hidden:
        nogo.append({"code": "hidden_worktree_change", "detail": "Git does not show working-tree changes of "
                     f"tracked files, so a commit would leave them out ({HIDDEN_FIX}): " + hidden_text(hidden)})
    if sparse:
        manual.append({"code": "sparse_checkout", "detail": f"{len(sparse)} tracked file(s) outside the sparse "
                       "checkout were not in the working tree when the receipts ran"})
    local = ledger.git.local_ignored() if ledger.git else []
    if local:
        manual.append({"code": "locally_ignored_files", "detail": "untracked files that only .git/info/exclude, "
                       "core.excludesFile or an untracked .gitignore ignore (a clean checkout lacks them, and a test "
                       "run may load them): "
                       + ", ".join(local[:20]) + (f" and {len(local) - 20} more" if len(local) > 20 else "")})
    if finish and not for_finish and not any(entry["state"] == "stale" for entry in items.values()):
        # the working tree is the tested tree (stale receipts are NO-GO anyway): HEAD must hold it
        left = left_out(ledger, rel, plan, freshness.snapshot, set())
        if left:
            manual.append({"code": "tested_change_not_committed", "detail": "HEAD does not hold the tested "
                           "working-tree content of " + left_out_text(left)})
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
    every, unverified = counted_reviews(ledger, plan, freshness)
    for entry in unverified:
        reason = {"code": "review_unverified", "detail": f"{entry['review']['id']} {TRUST_TEXT[entry['trust']]}"}
        (nogo if entry["trust"] in TRUST_NOGO else manual).append(reason)
    reviews = fresh_reviews(ledger, plan, freshness, every)
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
            "trail": freshness.trail.summary(), "policy": policy, "policy_sha256": _policy_hash(policy)}


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
            "finish", "evaluated_at", "trail", "policy_sha256", "rerun")
    return {key: result[key] for key in keep if key in result}
