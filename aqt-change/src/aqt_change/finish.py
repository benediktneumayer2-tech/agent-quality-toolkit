"""``finish``: one checked, idempotent, crash-resumable completion.

Phase machine adapted from the author's Project Tracker Next (see NOTICE):

    preflight (nothing written on failure)
      -> prepared                        attempt stored with the exact final plan
      -> plan_written_commit_pending     final plan written atomically
      -> commit_created_record_pending   exact-path commit with AQT trailers (or skipped)
      -> completed                       change.finish written; replay returns the stored result

The same idempotency key with different inputs fails with ``idempotency_conflict``.
"""

from __future__ import annotations

import re
from pathlib import Path

from aqt_evidence import content_hash, new_record, subject

from . import plan as planmod
from .actors import current_actor
from .errors import ChangeError, refused, usage
from .gate import evaluate_gate
from .gitio import trailers
from .ledger import TRAIL_REQUIRED, Ledger, read_json, write_json
from .plan import basis_hash, parse_plan
from .plans import STATES_OK, external, now_iso, read_plan, require_valid, status, write_plan
from .receipts import trust_note

KEY_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def _attempt_path(ledger: Ledger, plan_id: str, key: str) -> Path:
    return ledger.state / "attempts" / plan_id / f"{key}.json"


def finish(ledger: Ledger, plan_path: str, *, key: str, summary: str, paths: list[str] | None = None,
           message: str | None = None, waivers: dict[str, str] | None = None, ack_warnings: str | None = None,
           no_commit: bool = False, remaining: str | None = None, sources: list[Path] | None = None) -> dict:
    if not KEY_RE.match(key or ""):
        raise usage("idempotency_key_invalid", "--key must be 1-128 characters of letters, digits, . _ : -")
    if not summary or not summary.strip():
        raise usage("summary_required", "finish needs --summary")
    rel, plan = read_plan(ledger, plan_path)
    require_valid(plan, rel)
    waiver_list = [{"item": item, "reason": reason.strip()} for item, reason in sorted((waivers or {}).items())]
    request = {"path": rel, "summary": summary.strip(), "paths": sorted(set(paths or [])),
               "message": (message or "").strip(), "waivers": waiver_list,
               "ack_warnings": (ack_warnings or "").strip(), "no_commit": bool(no_commit),
               "remaining": (remaining or "").strip()}
    request_sha = content_hash(request)
    attempt_file = _attempt_path(ledger, plan.id, key)
    existing = read_json(attempt_file)
    if existing:
        if existing["request_sha256"] != request_sha:
            raise refused("idempotency_conflict", "this idempotency key was already used with different inputs",
                          phase=existing["phase"])
        return _resume(ledger, existing, attempt_file)
    attempt = _preflight(ledger, rel, plan, key, request, request_sha, sources)
    write_json(attempt_file, attempt)
    return _resume(ledger, attempt, attempt_file)


def _preflight(ledger, rel, plan, key, request, request_sha, sources) -> dict:
    ext = external(ledger)
    if not ext and plan.status != "in_progress":
        raise refused("finish_status_invalid", f"finish needs an in-progress plan (status: {plan.status})",
                      phase="preflight_failed")
    current = status(ledger, rel)
    if current["state"] not in STATES_OK:
        raise refused("plan_unreconciled", f"{rel} is {current['state']}; reconcile first", phase="preflight_failed")
    verification_ids = {item.id for item in plan.verification}
    for waiver in request["waivers"]:
        if waiver["item"] not in verification_ids:
            raise usage("waiver_item_unknown", f"cannot waive unknown verification item {waiver['item']}")
        if not waiver["reason"]:
            raise usage("waiver_reason_required", f"waiver for {waiver['item']} needs a reason")
    preview = evaluate_gate(ledger, rel, plan, sources=sources, waivers=request["waivers"], for_finish=True)
    if any(r["code"] == "trail_required" for r in preview["reasons"]):
        raise refused("finish_trail_required", "cannot check the receipts: " + TRAIL_REQUIRED,
                      phase="preflight_failed")
    hidden = [r for r in preview["reasons"] if r["code"] == "hidden_worktree_change"]
    if hidden:
        raise refused("finish_hidden_changes", hidden[0]["detail"] + "; the commit would not contain what the "
                      "receipts tested. Fix this and run the checks again", phase="preflight_failed")
    waived = {w["item"] for w in request["waivers"]}
    blocking = [{"item": i, "state": e["state"]} for i, e in preview["items"].items()
                if e["state"] != "ok" and i not in waived]
    if blocking:
        notes = {i: trust_note(e) for i, e in preview["items"].items() if e["state"] == "unverified"}
        raise refused("finish_evidence_missing", "verification items lack fresh passing receipts: "
                      + ", ".join(f"{b['item']} ({b['state']}" + (f": {notes[b['item']]}" if notes.get(b["item"]) else "")
                                  + ")" for b in blocking),
                      phase="preflight_failed", items=blocking)
    warnings = [{"code": "open_tasks", "detail": ", ".join(t.id for t in plan.tasks if not t.checked)}] \
        if any(not t.checked for t in plan.tasks) else []
    warnings += [r for r in preview["reasons"] if r["code"] in ("anti_gaming_warning", "unapproved_change",
                                                                 "review_fail", "approval_stale")]
    if warnings and not request["ack_warnings"]:
        raise refused("finish_ack_required", "finish warnings need --ack-warnings with a reason: "
                      + "; ".join(f"{w['code']} {w.get('detail', '')}".strip() for w in warnings),
                      phase="preflight_failed", warnings=warnings)
    commit_enabled = bool(not ext and ledger.git and not request["no_commit"])
    clean_paths = ledger.git.preflight_commit(request["paths"] + [rel]) if commit_enabled else request["paths"]
    receipts = preview["receipts"]
    ok_items = {i for i, e in preview["items"].items() if e["state"] == "ok"}
    completed_at = now_iso()
    final_text = plan.text
    if not ext:
        final_text = planmod.tick_items(final_text, ok_items)
        final_text = planmod.set_tracker(final_text, status="completed", completed_at=completed_at)
        final_text = planmod.append_completion(final_text, _completion_entry(
            plan, preview, request, key, completed_at, ledger))
        final = parse_plan(final_text)
        if basis_hash(final) != basis_hash(plan):
            raise ChangeError("internal_basis_changed", "finish would change the plan basis", exit_code=2)
    final_plan = parse_plan(final_text)
    after_raw = ledger.put_object("objects", final_text.encode("utf-8"))
    done_tasks = [t.id for t in final_plan.tasks if t.checked]
    open_tasks = [t.id for t in final_plan.tasks if not t.checked]
    message = request["message"] or f"Finish {plan.id}: {plan.title or plan.id}"
    lines = [f"AQT-Plan: {plan.id} {basis_hash(plan)}", *[f"AQT-Task: {t}" for t in done_tasks]]
    if receipts:
        lines.append("AQT-Receipts: " + ", ".join(receipts))
    lines.append(f"AQT-Finish: {plan.id}/{key}")
    verification = {}
    for item_id, entry in preview["items"].items():
        if item_id in waived and entry["state"] != "ok":
            verification[item_id] = "waived"
        elif entry["manual"]:
            verification[item_id] = [entry["receipt"]]
        else:
            verification[item_id] = [c["receipt"] for c in entry["commands"]]
    return {
        "key": key, "request_sha256": request_sha, "plan_id": plan.id, "path": rel, "phase": "prepared",
        "before_raw": plan.raw_hash, "after_raw": after_raw, "before_head": ledger.head(),
        "commit_enabled": commit_enabled, "paths": clean_paths, "message": message.rstrip() + "\n\n" + "\n".join(lines),
        "receipts": receipts, "reviews": preview["reviews"], "waivers": request["waivers"],
        "warnings": warnings, "warnings_ack": request["ack_warnings"] or None, "gate": preview["decision"],
        "tasks": {"done": done_tasks, "open": open_tasks}, "verification": verification,
        "completed_at": completed_at, "lifecycle_owner": ledger.config.lifecycle_owner,
        "commit": None, "error": None, "result": None,
    }


def _completion_entry(plan, preview, request, key, completed_at, ledger) -> str:
    lines = [f"### {completed_at} — Completed (aqt-change)", "", f"**Summary:** {request['summary']}", "",
             "**Verification (runner receipts):**", ""]
    waived = {w["item"]: w["reason"] for w in request["waivers"]}
    for item_id, entry in preview["items"].items():
        if entry["state"] != "ok" and item_id in waived:
            lines.append(f"- {item_id}: waived — {waived[item_id]}")
        elif entry["manual"]:
            lines.append(f"- {item_id}: attested by {entry.get('attested_by')} — {entry['receipt']}")
        else:
            for command in entry["commands"]:
                counts = command.get("counts") or {}
                summary = f" ({counts.get('passed', 0)} passed of {counts.get('total', 0)})" if counts else ""
                lines.append(f"- {item_id} `{command['command']}`: {command['outcome']}{summary} — {command['receipt']}")
    if not preview["items"]:
        lines.append("- no verification items")
    lines.append("")
    lines.append(f"**Gate at finish:** {preview['decision']}")
    if request["ack_warnings"]:
        lines.append(f"**Completion warning override:** {request['ack_warnings']}")
    if request["remaining"]:
        lines.append(f"**Remaining work:** {request['remaining']}")
    lines.append(f"**Finish key:** `{key}`")
    return "\n".join(lines) + "\n"


def _save(attempt_file: Path, attempt: dict, **updates) -> dict:
    attempt.update(updates)
    write_json(attempt_file, attempt)
    return attempt


def _resume(ledger: Ledger, attempt: dict, attempt_file: Path) -> dict:
    if attempt["phase"] == "completed":
        return {**attempt["result"], "replayed": True}
    rel = attempt["path"]
    if attempt["phase"] == "prepared":
        if attempt["lifecycle_owner"] != "external":
            current = parse_plan(ledger.abs(rel).read_text(encoding="utf-8")).raw_hash
            if current == attempt["before_raw"]:
                text = ledger.get_object("objects", attempt["after_raw"]).decode("utf-8")
                write_plan(ledger, rel, text)
            elif current != attempt["after_raw"]:
                _save(attempt_file, attempt, error="source_conflict")
                raise refused("source_conflict", "the plan changed after finish preflight; use a new key",
                              phase="prepared")
        _save(attempt_file, attempt, phase="plan_written_commit_pending", error=None)
    if attempt["phase"] == "plan_written_commit_pending":
        commit = None
        if attempt["commit_enabled"]:
            head = ledger.head()
            marker = f"{attempt['plan_id']}/{attempt['key']}"
            if head and head != attempt["before_head"] and ("AQT-Finish", marker) in trailers(ledger.git.message(head)):
                commit = head
            else:
                try:
                    commit = ledger.git.commit_exact_paths(attempt["paths"], attempt["message"])
                except ChangeError as error:
                    _save(attempt_file, attempt, error=error.code)
                    raise ChangeError(error.code, error.message + " — fix it and rerun finish with the same key",
                                      details={"phase": attempt["phase"], **error.details}, exit_code=1) from error
        _save(attempt_file, attempt, phase="commit_created_record_pending", commit=commit,
              head=commit or ledger.head(), error=None)
    if attempt["phase"] == "commit_created_record_pending":
        if attempt["commit"]:
            marker = (f"AQT-Finish", f"{attempt['plan_id']}/{attempt['key']}")
            if marker not in trailers(ledger.git.message(attempt["commit"])):
                _save(attempt_file, attempt, error="finish_evidence_incomplete")
                raise refused("finish_evidence_incomplete", "the commit lacks the AQT-Finish trailer",
                              phase=attempt["phase"], commit=attempt["commit"])
        record = next((r for r in ledger.records("change.finish", attempt["plan_id"])
                       if r["data"].get("idempotency_key") == attempt["key"]), None)
        if record is None:
            record = ledger.emit(_finish_record(ledger, attempt))
        state = ledger.plan_state(attempt["plan_id"]) or {}
        final = parse_plan(ledger.abs(rel).read_text(encoding="utf-8"))
        if final.raw_hash == attempt["after_raw"]:
            ledger.put_object("objects", final.text.encode("utf-8"))
            state.update(accepted_raw=final.raw_hash, accepted_basis=basis_hash(final),
                         seen_events=[e.identity() for e in final.events], status=final.status)
        state["history"] = [*state.get("history", []),
                            {"record": record["id"], "action": "finish", "kind": "finish",
                             "raw": attempt["after_raw"], "time": record["time"]}]
        ledger.save_plan_state(attempt["plan_id"], state)
        result = {"ok": True, "result": "completed", "phase": "completed", "plan_id": attempt["plan_id"],
                  "record": record["id"], "commit": attempt["commit"], "gate": attempt["gate"],
                  "receipts": attempt["receipts"], "waivers": attempt["waivers"]}
        _save(attempt_file, attempt, phase="completed", result=result, error=None)
        return result
    raise ChangeError("finish_phase_unknown", f"unknown finish phase {attempt['phase']}", exit_code=2)


def _finish_record(ledger: Ledger, attempt: dict) -> dict:
    links = [{"rel": "receipt", "ref": r} for r in attempt["receipts"]]
    links += [{"rel": "review", "ref": r} for r in attempt["reviews"]]
    state = ledger.plan_state(attempt["plan_id"]) or {}
    if state.get("history"):
        links.append({"rel": "plan-version", "ref": state["history"][-1]["record"]})
    data = {"plan_ref": attempt["plan_id"], "plan_id": attempt["plan_id"], "path": attempt["path"],
            "idempotency_key": attempt["key"], "request_sha256": attempt["request_sha256"],
            "commit": attempt["commit"], "head": attempt.get("head"), "paths": attempt["paths"],
            "tasks": attempt["tasks"], "verification": attempt["verification"], "receipts": attempt["receipts"],
            "waivers": attempt["waivers"], "warnings_ack": attempt["warnings_ack"],
            "warnings": attempt["warnings"], "gate": attempt["gate"],
            "lifecycle_owner": attempt["lifecycle_owner"], "completed_at": attempt["completed_at"]}
    return new_record("change.finish", current_actor(ledger.config.actor), "finish",
                      subject=subject("plan", attempt["plan_id"], sha256=attempt["after_raw"]),
                      before={"sha256": attempt["before_raw"]}, after={"sha256": attempt["after_raw"]},
                      reason=data["warnings_ack"], links=links or None,
                      data={k: v for k, v in data.items() if v is not None})
