"""Overview: trail status band, ALCOA++ strip, the "Needs you" queue and tool health.

The queue is derived on every request from the tools' own state; nothing is stored.
"""

from __future__ import annotations

from datetime import UTC, datetime

from . import ViewProblem, evidence_fingerprint, fingerprint, installed
from .trail import TrailView, parse_time

SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3}
TOOLS = [("aqt-trail", "aqt_trail", "trail."), ("aqt-quarantine", "aqt_quarantine", "quarantine."),
         ("aqt-signoff", "aqt_signoff", "signoff."), ("aqt-change", "aqt_change", "change."),
         ("aqt-capa", "aqt_capa", "capa."), ("aqt-validate", "aqt_validate", "validate."),
         ("aqt-sensei", "aqt_sensei", "sensei.")]


def item(severity: str, view: str, title: str, detail: str = "", ref: str | None = None, code: str = "",
         key: str = "", **args) -> dict:
    """One queue entry. ``key`` and ``args`` let the page show the title in the chosen language;
    ``title`` and ``detail`` are the English words."""
    return {"severity": severity, "view": view, "title": title, "detail": detail, "ref": ref, "code": code,
            "key": key or code, "args": {name: value for name, value in args.items() if value is not None}}


def _age_hours(value) -> float | None:
    moment = parse_time(value) if value else None
    return (datetime.now(UTC) - moment).total_seconds() / 3600 if moment else None


def build(app) -> dict:
    """Everything the home screen shows. ``app`` provides the view adapters and settings."""
    trail: TrailView = app.trail
    status = trail.status()
    alcoa = trail.alcoa()
    needs: list[dict] = []
    counts = {"trail": 0, "quarantine": 0, "changes": 0, "signatures": 0, "capa": 0, "qualifications": 0}

    # trail
    if status["state"] == "broken":
        check = status["check"] or {}
        needs.append(item("critical", "trail", f"Trail broken from seq {check.get('first_bad_seq')}",
                          check.get("reason") or "", code="trail_broken", seq=check.get("first_bad_seq")))
    elif status["state"] == "changed":
        needs.append(item("critical", "trail", "Trail changed since the last check",
                          f"{status['changed']}; the last result no longer applies. Verify the trail again.",
                          code="trail_changed"))
    elif status["state"] == "problems":
        needs.append(item("critical", "trail", "Trail verification found problems",
                          "; ".join((status["check"] or {}).get("problems", [])[:2]), code="trail_problems"))
    for result in alcoa:
        if result["status"] == "fail":
            needs.append(item("critical", "trail", f"ALCOA++ {result['attribute']} failed", result["detail"],
                              code=result["id"], key="alcoa_fail", attribute=result["attribute"]))
    refusals = trail.refusals_since(24)
    if refusals:
        tools = sorted({row["type"].split(".")[0] for row in refusals})
        needs.append(item("medium", "trail", f"{len(refusals)} refused decision attempt(s) in the last 24 h",
                          "An agent or another process tried to decide: " + ", ".join(tools),
                          ref="type=*.refused", code="refusals", n=len(refusals), tools=", ".join(tools)))
    writer = status["writer"]
    if status["state"] != "missing" and not writer["running"]:
        needs.append(item("medium", "trail", "Trail writer is not running",
                          f"Start it with: aqt-trail serve (socket {writer['socket']})", code="writer_down",
                          socket=writer["socket"]))
    if writer["spooled"]:
        needs.append(item("medium", "trail", f"{writer['spooled']} record(s) waiting in the spool",
                          "They reach the trail with: aqt-trail drain", code="spooled", n=writer["spooled"]))
    if status["records"]:
        review_age = _age_hours(status["last_review"])
        if review_age is None or review_age > 24 * app.config.review_due_days:
            needs.append(item("low", "trail", "Audit-trail review due",
                              f"No signed review in {app.config.review_due_days} days: prepare and sign it in the "
                              "Trail view", ref="review", code="review_due", days=app.config.review_due_days))
        anchor_age = _age_hours(status["last_anchor"])
        if anchor_age is None or anchor_age > 24:
            needs.append(item("low", "trail", "Trail head not anchored for 24 h",
                              "aqt-trail checkpoint --anchor", code="unanchored"))
    counts["trail"] = sum(1 for n in needs if n["view"] == "trail" and n["severity"] in ("critical", "high"))

    # quarantine
    tools_state: dict[str, str | None] = {}
    if installed("aqt_quarantine"):
        try:
            cases = app.quarantine().cases()
            for case in cases["cases"]:
                if case["state"] in ("held", "warned"):
                    needs.append(item("high", "quarantine",
                                      f"{'Held' if case['state'] == 'held' else 'Warned'} case {case['case_id']}",
                                      f"{case['domain'] or case['tool'] or 'unknown source'}, score {case['score_ppm']} ppm",
                                      ref=case["case_id"], code=case["state"], key=f"case_{case['state']}",
                                      case=case["case_id"], source=case["domain"] or case["tool"] or "?",
                                      score=case["score_ppm"]))
                    counts["quarantine"] += 1
        except (ViewProblem, OSError, ValueError) as error:
            tools_state["aqt-quarantine"] = str(error)

    # changes and prepared actions
    try:
        changes = app.changes
        for action in changes.actions():
            if action["status"] in ("prepared", "expired"):
                needs.append(item("high", "changes", f"Prepared action {action['id']} awaits approval",
                                  (action.get("spec") or {}).get("description") or action.get("detail") or "",
                                  ref=action["id"], code="action_prepared", action=action["id"]))
                counts["changes"] += 1
            elif action["status"] == "unknown":
                needs.append(item("high", "changes", f"Outcome of action {action['id']} unknown",
                                  action.get("detail") or "", ref=action["id"], code="action_unknown",
                                  action=action["id"]))
                counts["changes"] += 1
        for project in changes.gates():
            for plan in project["plans"]:
                if plan.get("decision") in ("NO-GO", "MANUAL_VERIFY_REQUIRED"):
                    first = (plan.get("reasons") or [{}])[0]
                    needs.append(item("high", "changes", f"Gate {plan['decision']} for {plan['plan_id']}",
                                      first.get("text", ""), ref=plan["plan_id"], code=first.get("code", ""),
                                      key="gate", decision=plan["decision"], plan=plan["plan_id"],
                                      reason_code=first.get("code")))
                    counts["changes"] += 1
    except (ViewProblem, OSError, ValueError) as error:
        tools_state["aqt-change"] = str(error)

    # CAPA
    if installed("aqt_capa"):
        try:
            capa = capa_counts(app)
            if capa["candidates"]:
                needs.append(item("medium", "capa", f"{capa['candidates']} CAPA candidate(s) to accept or dismiss",
                                  "aqt-capa found new candidates in the evidence", ref="candidates",
                                  code="capa_candidates", n=capa["candidates"]))
            if capa["overdue"]:
                needs.append(item("medium", "capa", f"{capa['overdue']} deviation(s) overdue",
                                  "Investigation not recorded by the due date", code="capa_overdue",
                                  n=capa["overdue"]))
            counts["capa"] = capa["candidates"] + capa["overdue"]
        except Exception as error:  # noqa: BLE001 - one tool's problem must not hide the others
            tools_state["aqt-capa"] = f"{type(error).__name__}: {error}"

    # qualifications
    from .qualifications import qualifications
    quals = qualifications(app.config.qualification_warn_days)
    for row in quals["qualifications"]:
        if row["state"] in ("expired", "expiring", "triggered"):
            words = {"expired": "expired", "expiring": f"expires in {row['days_left']} day(s)",
                     "triggered": "requalification triggered: " + ", ".join(row["triggers"])}[row["state"]]
            needs.append(item("medium", "qualifications", f"Qualification of {row['subject_id']} {words}",
                              f"{row['kind']}, valid until {row['valid_until']}", ref=row["subject_id"],
                              code=row["state"], key=f"qualification_{row['state']}", subject=row["subject_id"],
                              days=row.get("days_left"), triggers=", ".join(row["triggers"]),
                              kind=row["kind"], until=row["valid_until"]))
            counts["qualifications"] += 1

    needs.sort(key=lambda n: SEVERITY[n["severity"]])
    return {"status": status, "alcoa": alcoa, "needs": needs, "counts": {"overview": len(needs), **counts},
            "tools": tool_health(trail, tools_state), "refusals": refusals[-20:],
            "checked_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")}


_CAPA_CACHE: dict = {}


def capa_counts(app) -> dict:
    """aqt-capa's counts for the queue, recomputed only when the evidence or its index changed:
    opening aqt-capa reads the whole trail while its index is empty."""
    from aqt_capa import load_config
    db = load_config().db_path

    def key():
        return evidence_fingerprint(), fingerprint(db, f"{db}-wal")
    if _CAPA_CACHE.get("key") != key():
        counts = app.capa().counts()
        _CAPA_CACHE.update(key=key(), counts=counts)
    return _CAPA_CACHE["counts"]


def tool_health(trail: TrailView, problems: dict) -> list[dict]:
    trail.index.refresh()
    last = trail.index.last_time
    out = []
    for package, module, prefix in TOOLS:
        present = installed(module)
        out.append({"package": package, "installed": present, "last_record": last.get(prefix),
                    "problem": problems.get(package),
                    "install": None if present else f"uv pip install -e {package}"})
    return out


__all__ = ["build"]
