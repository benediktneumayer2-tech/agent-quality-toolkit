"""Review records bound to the diff they reviewed."""

from __future__ import annotations

import json
from pathlib import Path

from aqt_evidence import HumanCheckError, new_record, subject

from . import actors
from .config import INDEPENDENCE
from .errors import refused, usage
from .ledger import Ledger
from .plans import read_plan, require_valid, status

VERDICTS = ("PASS", "CONCERNS", "FAIL", "WAIVED")


def record_refusal(ledger: Ledger, attempted: str, code: str, context) -> dict:
    record = new_record("change.refused", actors.current_actor(ledger.config.actor, context), "refused",
                        reason=f"{attempted} refused: {code}",
                        data={"attempted_action": attempted, "reason_code": code,
                              "agent_markers": list(getattr(context, "markers", []) or [])})
    return ledger.emit(record)


def load_findings(path: str | None) -> list[dict]:
    if not path:
        return []
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise usage("findings_invalid", f"cannot read findings JSON: {error}") from error
    items = raw.get("findings") if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        raise usage("findings_invalid", "findings must be a list or {\"findings\": [...]}")
    findings = []
    for entry in items:
        if not isinstance(entry, dict) or not entry.get("title"):
            raise usage("findings_invalid", "each finding needs at least a title")
        clean = {"severity": str(entry.get("severity", "info")), "title": str(entry["title"])[:300]}
        if entry.get("path"):
            clean["path"] = str(entry["path"])
        if isinstance(entry.get("line"), int):
            clean["line"] = entry["line"]
        findings.append(clean)
    return findings


def add_review(ledger: Ledger, plan_path: str, *, reviewer: str, independence: str, verdict: str,
               reason: str, harness: str | None = None, model: str | None = None,
               findings_file: str | None = None, base: str | None = None,
               qualification: str | None = None) -> dict:
    if independence not in INDEPENDENCE:
        raise usage("independence_invalid", f"independence must be one of {', '.join(INDEPENDENCE)}")
    verdict = verdict.upper()
    if verdict not in VERDICTS:
        raise usage("verdict_invalid", f"verdict must be one of {', '.join(VERDICTS)}")
    if not reason or not reason.strip():
        raise usage("reason_required", "a review needs --reason (summary)")
    rel, plan = read_plan(ledger, plan_path)
    require_valid(plan, rel)
    if status(ledger, rel)["state"] == "unregistered":
        raise refused("plan_unregistered", f"{rel} is not registered")
    context = actors.agent_context()
    if independence == "human":
        try:
            context = actors.human_check()
        except HumanCheckError as error:
            record_refusal(ledger, "review.add(human)", "human_required", error.context)
            raise refused("human_required", str(error), markers=error.context.markers) from error
        reviewer_kind = "human"
    else:
        reviewer_kind = "agent"
    findings = load_findings(findings_file)
    state = ledger.plan_state(plan.id) or {}
    base = base or state.get("base_commit") or plan.base_commit or ledger.head()
    tree = ledger.fingerprint([rel], scope=plan.declared_paths, plan_id=plan.id)
    diff_sha = ledger.git.diff_sha256(base, {rel}) if (ledger.git and base) else tree
    data = {"plan_id": plan.id, "plan_ref": plan.id,
            "reviewer": {k: v for k, v in {"kind": reviewer_kind, "id": reviewer, "harness": harness,
                                          "model": model}.items() if v},
            "independence": independence, "verdict": verdict, "findings": findings,
            "diff_sha256": diff_sha,
            "diff": {"base": base, "head": ledger.head(), "tree_fingerprint": tree},
            "fingerprint_excludes": [rel], "tree_fingerprint": tree}
    if qualification:
        data["qualification"] = qualification
    links = [{"rel": "qualification", "ref": qualification}] if qualification else None
    record = new_record("change.review", actors.current_actor(ledger.config.actor, context), "review",
                        subject=subject("plan", plan.id, sha256=plan.raw_hash), reason=reason.strip(),
                        meaning="reviewed", links=links, data={k: v for k, v in data.items() if v is not None})
    return ledger.emit(record)
