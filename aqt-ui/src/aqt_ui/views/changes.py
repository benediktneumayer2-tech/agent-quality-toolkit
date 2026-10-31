"""Changes view: release gates of the configured projects (aqt-change) and prepared actions
(aqt-signoff), with approval of one prepared action bound to the hash shown.

The specification of an action is shown, and can be approved or rejected, only when its
canonical hash (``aqt_evidence.content_hash``, as ``aqt-signoff prepare`` computes it) equals
the stored action hash: the hash that is signed is then the hash of the text on screen."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable

from . import NotFound, Stale, UsageProblem, evidence_fingerprint, fingerprint, installed, refusal_text, require
from .signatures import open_signoff

# Gate reason codes in words; the code stays visible next to the sentence.
REASONS = {
    "plan_unreconciled": "The plan changed and was not reconciled with the ledger",
    "receipt_missing": "A verification item has no test run receipt",
    "receipt_stale": "Code changed after the last test run",
    "receipt_failed": "The last test run of an item failed",
    "unapproved_change": "Files outside the approved scope were changed",
    "review_fail": "The latest review failed",
    "not_finished": "The change was not finished yet",
    "anti_gaming_warning": "A test or check was weakened in this change",
    "waiver_present": "An item was waived instead of verified",
    "manual_item_agent_attested": "A manual check was attested by an agent, not a person",
    "approval_stale": "The plan changed after it was approved",
    "approval_invalid": "The approval signature does not verify",
    "approval_unsigned": "The plan has no signed approval",
    "approval_unverified": "An approval exists but aqt-signoff is not available to verify it",
    "review_concerns": "A review raised concerns",
    "review_waived": "A review was waived",
    "review_independence_below_policy": "No review is independent enough for the policy",
    "scope_undeclared": "The plan declares no paths, so the scope cannot be compared",
    "scope_unverifiable": "There is no Git base commit to compare against",
    "receipt_unverified": "A test run receipt is not confirmed by the audit trail",
    "review_unverified": "A review is not confirmed by the audit trail",
    "trail_required": "The project requires the audit trail, and no trail log was found where the gate ran",
    "tested_change_not_committed": "The tested code is not the committed code",
    "command_modified_worktree": "A test run changed the files it tested; run the check again on an unchanged tree",
    "hidden_worktree_change": "A changed file is hidden from Git (index flags or a stat-cache setting)",
    "locally_ignored_files": "Files that only a local ignore rule hides could change the test result",
    "allowed_by_user_config": "Files are allowed only by the user's own settings, not by the project file",
    "project_settings_changed": "The project settings (.aqt/change.toml) changed during the plan",
    "plan_base_mismatch": "The plan's base commit does not match the one recorded when the plan began",
    "sparse_checkout": "Some files are outside the sparse checkout and could not be checked",
    "junit_missing": "The JUnit report of a test run is missing",
    "junit_stale": "The JUnit report is older than the test run",
    "junit_unreadable": "The JUnit report of a test run cannot be read",
}
GATE_TTL = 60.0   # seconds; gate evaluation fingerprints the working tree


def gate_cli(root: Path, rel: str) -> dict:
    """``aqt-change gate`` run in the project root. aqt-change resolves plan paths against the
    working directory, which a threaded server cannot change safely, so the CLI does it."""
    exe = shutil.which("aqt-change") or str(Path(sys.executable).parent / "aqt-change")
    done = subprocess.run([exe, "gate", rel], cwd=root, capture_output=True, text=True, timeout=120,
                          env=dict(os.environ))
    if done.returncode not in (0, 1) or not done.stdout.strip():
        raise ValueError((done.stderr or done.stdout).strip()[-500:] or f"aqt-change gate exited {done.returncode}")
    return json.loads(done.stdout)


class ChangesView:
    def __init__(self, projects: list[Path]):
        self.projects = list(projects)
        self._cache: dict[str, tuple[float, dict]] = {}
        self._lock = threading.Lock()

    # -- gates ---------------------------------------------------------------------------------------
    def _plan(self, ledger, state: dict, *, with_release: bool = True) -> dict:
        """One plan of a project: the gate as ``aqt-change gate`` gives it, the receipts per item, the
        reviews, the ``change.finish`` record and (``with_release``) whether it was signed "released"."""
        from aqt_change import ChangeError
        from aqt_change.plans import read_plan
        from aqt_change.receipts import Freshness, evaluate
        rel = state.get("path")
        plan = {"plan_id": state.get("plan_id") or Path(str(rel)).stem, "path": rel, "decision": None,
                "reasons": [], "receipts": [], "approval": None, "error": None}
        try:
            public = gate_cli(ledger.root, rel)
            _, parsed = read_plan(ledger, str(ledger.abs(rel)))
            items = evaluate(ledger, parsed, Freshness(ledger))
        except (ChangeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            plan["error"] = str(error)
            return plan
        plan.update(decision=public["decision"], plan_id=public.get("plan_id") or plan["plan_id"],
                    reasons=[{**r, "text": REASONS.get(r.get("code"), r.get("code"))} for r in public["reasons"]],
                    approval=public.get("approval"), finish=public.get("finish"),
                    evaluated_at=public.get("evaluated_at"), reviews=public.get("reviews", []))
        for item_id, item in items.items():
            plan["receipts"].append({"item": item_id, "text": item.get("text"), "state": item.get("state"),
                                     "manual": item.get("manual"), "receipt": item.get("receipt"),
                                     "attested_by": item.get("attested_by"),
                                     "commands": [{"command": c.get("command"), "state": c.get("state"),
                                                   "receipt": c.get("receipt"), "counts": c.get("counts"),
                                                   "outcome": c.get("outcome")}
                                                  for c in item.get("commands", [])]})
        fresh = set(plan["reviews"])
        plan["review_records"] = [
            {"id": r.get("id"), "time": r.get("time"), "verdict": (r.get("data") or {}).get("verdict"),
             "reviewer": ((r.get("data") or {}).get("reviewer") or {}).get("id") or (r.get("actor") or {}).get("id"),
             "independence": (r.get("data") or {}).get("independence"), "reason": r.get("reason"),
             "counts": r.get("id") in fresh}
            for r in ledger.records("change.review", plan["plan_id"])]
        approval = plan["approval"] or {}
        target = ledger.record(approval["record"]) if approval.get("record") else None
        plan["approval_time"] = (target or {}).get("time")
        finish = ledger.record(plan["finish"]) if plan.get("finish") else None
        plan["finish_record"] = None if finish is None else {
            "id": finish.get("id"), "time": finish.get("time"), "by": (finish.get("actor") or {}).get("id"),
            "commit": (finish.get("data") or {}).get("commit"), "gate": (finish.get("data") or {}).get("gate")}
        plan["release"] = release_state(plan.get("finish")) if with_release else None
        return plan

    def _project(self, root: Path) -> dict:
        from aqt_change import ChangeError, Ledger
        entry = {"root": str(root), "project": self.index_of(root), "plans": [], "error": None}
        try:
            ledger = Ledger.open(root)
        except (ChangeError, OSError) as error:
            entry["error"] = str(error)
            return entry
        for state in ledger.plan_states():
            entry["plans"].append(self._plan(ledger, state))
        return entry

    def index_of(self, root: Path) -> int | None:
        return next((i for i, p in enumerate(self.projects) if str(p) == str(root)), None)

    def project_root(self, index) -> Path:
        """The configured project at ``index`` (the change pages name projects by their position in
        ui.toml, never by a path from the request)."""
        try:
            return self.projects[int(index)]
        except (ValueError, TypeError, IndexError):
            raise UsageProblem(f"project {index} is not configured in ui.toml [changes] projects") from None

    def _cached(self, root: Path, fresh: bool = False) -> dict:
        key = str(root)
        with self._lock:
            cached = self._cache.get(key)
        if cached and not fresh and time.monotonic() - cached[0] < GATE_TTL:
            return cached[1]
        value = self._project(root)
        with self._lock:
            self._cache[key] = (time.monotonic(), value)
        return value

    def forget(self, root: Path) -> None:
        with self._lock:
            self._cache.pop(str(root), None)

    def gates(self, *, fresh: bool = False) -> list[dict]:
        if not installed("aqt_change"):
            return []
        return [self._cached(root, fresh) for root in self.projects]

    def fresh_plan(self, root: Path, plan_id: str, *, with_release: bool = False) -> dict | None:
        """A fresh gate evaluation of one plan (not the cache)."""
        from aqt_change import ChangeError, Ledger
        try:
            ledger = Ledger.open(root)
        except (ChangeError, OSError) as error:
            raise UsageProblem(str(error)) from error
        for state in ledger.plan_states():
            if plan_id in (state.get("plan_id"), Path(str(state.get("path"))).stem):
                return self._plan(ledger, state, with_release=with_release)
        return None

    # -- one change: the page with the timeline -----------------------------------------------------
    def change(self, index, plan_id: str, *, fresh: bool = False) -> dict:
        require("aqt_change", "aqt-change")
        root = self.project_root(index)
        entry = self._cached(root, fresh)
        if entry["error"]:
            raise UsageProblem(entry["error"])
        plan = next((p for p in entry["plans"] if p["plan_id"] == plan_id), None)
        if plan is None:
            raise NotFound(f"no plan {plan_id} in {root}")
        policy = None
        if installed("aqt_signoff"):
            policy = open_signoff().settings.policy("released").as_dict()
        return {"project": int(index), "root": str(root), "plan": plan, "steps": timeline(plan),
                "release_policy": policy, "signers": _signers(),
                "installed": {"aqt-change": True, "aqt-signoff": installed("aqt_signoff")}}

    def sign_release(self, index, plan_id: str, *, shown_record: str, shown_sha256: str, reason: str,
                     passphrase: str, signer_id: str | None, human_check: Callable) -> dict:
        """Sign the finished change shown with the meaning "released", as ``aqt-signoff sign --record
        <change.finish record> --meaning released``. In this order: the guard (refusals are recorded),
        a fresh gate evaluation that must be GO, the change.finish record and its hash must be the ones
        shown, no valid "released" signature by this signer yet; then aqt-signoff's own checks (the
        [policy.released] roles, distinct from the author) and the key unlock."""
        so = open_signoff(passphrase=passphrase, human_check=human_check)
        root_box: list[Path] = []

        def sign():
            signer = so.signer_entry(signer_id or None)
            so.require_human("sign", so.signer_actor(signer))         # the guard first; refusals are recorded
            root = self.project_root(index)
            root_box.append(root)
            plan = self.fresh_plan(root, plan_id)
            if plan is None:
                raise NotFound(f"no plan {plan_id} in {root}")
            if plan.get("error") or plan.get("decision") != "GO":
                codes = ", ".join(r.get("code", "") for r in plan.get("reasons") or []) or plan.get("error") or "-"
                raise Stale(f"the gate of {plan_id} is {plan.get('decision') or 'not evaluated'} now ({codes}); "
                            "only a GO change can be released. Nothing was signed.")
            if not plan.get("finish") or plan["finish"] != shown_record:
                raise Stale("the change.finish record is not the one shown; nothing was signed. Reload the change.")
            subject, _ = so.record_subject(plan["finish"])
            if not shown_sha256 or subject["sha256"] != shown_sha256:
                raise Stale("the change.finish record changed since it was shown; nothing was signed. Reload the "
                            "change.")
            report = so.verify_record(plan["finish"], required=["released"], record_invalidations=False)
            if any(s.valid and s.meaning == "released" and s.signer_id == signer.id for s in report.current):
                raise UsageProblem(f"{signer.id} has already signed this change as released ({plan['finish']}); "
                                   "nothing was signed")
            return so.sign(subject, "released", reason, signer_id=signer.id)
        stored, refusal = signoff_call(so, sign)
        if refusal:
            return refusal
        for root in root_box:
            self.forget(root)                                         # the release state changed
        return {"ok": True, "message": f"change {plan_id} released", "record_id": stored.get("id"),
                "record_type": stored.get("type"), "time": stored.get("time")}

    # -- prepared actions --------------------------------------------------------------------------------
    @staticmethod
    def actions() -> list[dict]:
        if not installed("aqt_signoff"):
            return []
        so = open_signoff()
        return so.actions.list()

    def summary(self) -> dict:
        return {"installed": {"aqt-change": installed("aqt_change"), "aqt-signoff": installed("aqt_signoff")},
                "projects": self.gates(), "actions": self.actions(), "reasons": REASONS,
                "signers": _signers()}

    @staticmethod
    def action(action_id: str) -> dict:
        from aqt_signoff import SignoffError
        so = open_signoff()
        try:
            view = so.actions.show(action_id)
        except SignoffError as error:
            raise NotFound(str(error)) from error
        problem = spec_problem(view)
        return {**view, "spec_ok": problem is None, "spec_error": problem, "signers": _signers()}

    @staticmethod
    def decide_action(action_id: str, kind: str, *, expected_hash: str, reason: str, passphrase: str,
                      signer_id: str | None, human_check: Callable) -> dict:
        """Approve or reject the exact action version shown: after the guard, the hash shown must be
        the stored hash and the hash of the stored specification (aqt-signoff checks it again)."""
        so = open_signoff(passphrase=passphrase, human_check=human_check)
        call = {"approve": so.actions.approve, "reject": so.actions.reject}.get(kind)
        if call is None:
            raise UsageProblem(f"unknown decision {kind}")

        def decide():
            signer = so.signer_entry(signer_id or None)
            so.require_human(kind, so.signer_actor(signer))           # the guard first; refusals are recorded
            current = so.actions.show(action_id)
            problem = spec_problem(current)
            if problem or current["action_sha256"] != expected_hash:
                raise Stale(f"nothing was signed: {problem or 'the action is not the version shown. Reload it.'}")
            return call(action_id, expected_hash, reason, signer_id=signer.id)
        view, refusal = signoff_call(so, decide)
        if refusal:
            return refusal
        row = so.actions.get(action_id)
        stored = (row.get("approvals") or [None])[-1] if kind == "approve" else row.get("rejection")
        return {"ok": True, "message": f"{kind} recorded for {action_id}; status now {view['status']}",
                "status": view["status"], "record_id": (stored or {}).get("id"),
                "time": (stored or {}).get("time"), "approvals": view.get("approvals") or []}


    # -- plan approval ---------------------------------------------------------------------------------
    def approve_plan(self, root: str, plan_id: str, *, shown_record: str, shown_sha256: str, reason: str,
                     passphrase: str, signer_id: str | None, human_check: Callable) -> dict:
        """Sign the plan version shown (its approval target record) with the meaning "approved",
        as ``aqt-signoff sign --record <target> --meaning approved``. The project folder is passed
        explicitly; nothing depends on the server's working directory."""
        from aqt_change import ChangeError, Ledger
        from aqt_change.approval import approval_state
        so = open_signoff(passphrase=passphrase, human_check=human_check)
        project = next((p for p in self.projects if str(p) == str(root)), None)

        def sign():
            signer = so.signer_entry(signer_id or None)
            so.require_human("sign", so.signer_actor(signer))         # the guard first; refusals are recorded
            if project is None:
                raise UsageProblem(f"{root} is not a configured project")
            try:
                ledger = Ledger.open(project)
            except (ChangeError, OSError) as error:
                raise UsageProblem(str(error)) from error
            state = approval_state(ledger, plan_id)
            if not state.get("record"):
                raise UsageProblem(f"plan {plan_id} has no version to approve")
            if state["record"] != shown_record or state["sha256"] != shown_sha256:
                raise Stale("the plan version is not the one shown; nothing was signed. Reload the gate.")
            if state["state"] == "signed":
                raise UsageProblem(f"this version of plan {plan_id} is already approved")
            subject, _ = so.record_subject(state["record"])
            if subject["sha256"] != shown_sha256:
                raise Stale("the plan version is not the one shown; nothing was signed. Reload the gate.")
            return so.sign(subject, "approved", reason, signer_id=signer.id)
        stored, refusal = signoff_call(so, sign)
        if refusal:
            return refusal
        self.forget(project)                                          # the gate changes with the approval
        return {"ok": True, "message": f"plan {plan_id} approved", "record_id": stored.get("id"),
                "record_type": stored.get("type"), "time": stored.get("time")}


_RELEASES: dict = {}


def release_state(finish_id: str | None) -> dict | None:
    """Whether the change.finish record is released: its signatures verified as ``aqt-signoff verify
    --record <finish> --require released`` does, without recording anything. Kept until the evidence,
    the signer registry or the signoff settings change (verifying reads the whole evidence)."""
    if not finish_id:
        return None
    if not installed("aqt_signoff"):
        return {"record": finish_id, "state": "unavailable", "install": "aqt-signoff"}
    from aqt_signoff import SignoffError
    from aqt_signoff.manifest import rows
    so = open_signoff()
    key = (finish_id, evidence_fingerprint(), fingerprint(so.settings.registry_path, so.settings.config_path))
    if key in _RELEASES:
        return _RELEASES[key]
    try:
        report = so.verify_record(finish_id, required=["released"], record_invalidations=False)
    except SignoffError as error:
        return {"record": finish_id, "state": "missing", "detail": str(error)}
    value = {"record": finish_id, "sha256": report.subject.get("sha256"),
             "state": "released" if report.ok else "unreleased", "summary": report.summary(),
             "policy": report.policies["released"].as_dict(),
             "signatures": [r for r in rows(report) if r["meaning"] == "released"]}
    if len(_RELEASES) > 256:
        _RELEASES.clear()
    _RELEASES[key] = value
    return value


# The steps of a change and the reason codes that hold each one up.
CHECK_CODES = ("receipt_", "junit_", "command_modified_worktree", "tested_change_not_committed")
PERSON_CHECK_CODES = ("manual_item_agent_attested", "waiver_present")
REVIEW_CODES = ("review_fail", "review_independence_below_policy", "review_unverified")
PERSON_REVIEW_CODES = ("review_concerns", "review_waived")


def timeline(plan: dict) -> list[dict]:
    """Plan -> Checks -> Review -> Gate -> Release, each ``done``, ``person`` (a STOP that waits for a
    person), ``evidence`` (waits for evidence: the agent's work, a check run, a review) or ``open``
    (not done, but nothing waits for it: a plan version the gate policy does not require to be
    signed). The first ``person`` or ``evidence`` step is the current one. A prepared action is not
    shown: nothing in its specification names the change it belongs to."""
    codes = [r.get("code", "") for r in plan.get("reasons") or []]
    approval = plan.get("approval") or {}
    release = plan.get("release") or {}

    def having(*names):
        return [c for c in codes if any(c == n or (n.endswith("_") and c.startswith(n)) for n in names)]
    steps = []
    plan_codes = having("approval_")
    steps.append({"id": "plan", "codes": plan_codes, "state": "done" if approval.get("state") == "signed"
                  else "evidence" if not approval.get("record") else "person" if plan_codes else "open"})
    person = having(*PERSON_CHECK_CODES)
    waiting = having(*CHECK_CODES)
    steps.append({"id": "checks", "codes": waiting + person,
                  "state": "evidence" if waiting else "person" if person else "done"})
    person = having(*PERSON_REVIEW_CODES)
    waiting = having(*REVIEW_CODES)
    steps.append({"id": "review", "codes": waiting + person,
                  "state": "evidence" if waiting else "person" if person else "done"})
    decision = plan.get("decision")
    steps.append({"id": "gate", "codes": codes, "decision": decision,
                  "state": "done" if decision == "GO" else "person" if decision == "MANUAL_VERIFY_REQUIRED"
                  else "evidence"})
    if release.get("state") == "released":
        state = "done"
    elif plan.get("finish") and decision == "GO" and release.get("state") == "unreleased":
        state = "person"
    else:
        state = "evidence"
    steps.append({"id": "release", "codes": [], "state": state, "finished": bool(plan.get("finish"))})
    current = next((step for step in steps if step["state"] in ("person", "evidence")), None)
    for step in steps:
        step["current"] = step is current
    return steps


def spec_problem(view: dict) -> str | None:
    """None when the stored specification has the stored action hash, else why not."""
    from aqt_evidence import content_hash
    spec = view.get("spec")
    try:
        computed = content_hash(spec)
    except Exception:  # noqa: BLE001 - a specification that cannot be hashed cannot be approved
        computed = None
    if (computed != view.get("action_sha256") or not isinstance(spec, dict) or spec.get("action_id") != view.get("id")
            or spec.get("version") != view.get("version")):
        return ("the stored specification does not match its action hash; it may have been changed after it was "
                "prepared. It cannot be approved or rejected here.")
    return None


def signoff_call(so, call: Callable) -> tuple:
    """(result, None) or (None, refusal) for a call into aqt-signoff, with its errors in UI terms."""
    from aqt_signoff import AuthFailed, Conflict, NotFound as SignoffNotFound, Refused, SignoffError, UsageError
    try:
        return call(), None
    except Refused as error:
        code = getattr(error, "code", None)
        return None, {"ok": False, "message": str(error), "reason_code": code, "reason_text": refusal_text(code),
                      "record_id": _last_refusal(so)}
    except AuthFailed as error:
        return None, {"ok": False, "message": f"the key could not be unlocked ({getattr(error, 'code', 'auth_failed')})",
                      "reason_code": "auth_failed", "reason_text": refusal_text("auth_failed"),
                      "record_id": _last_record(so, "signoff.auth.failed")}
    except Conflict as error:
        raise Stale(str(error)) from error
    except SignoffNotFound as error:
        raise NotFound(str(error)) from error
    except (UsageError, SignoffError) as error:
        raise UsageProblem(str(error)) from error


def _signers() -> list[dict]:
    if not installed("aqt_signoff"):
        return []
    from .signatures import signer_rows
    return [row for row in signer_rows(open_signoff()) if row["active_key"]]


def _last_record(so, record_type: str) -> str | None:
    found = [r for r in so.records() if r.get("type") == record_type]
    return found[-1].get("id") if found else None


def _last_refusal(so) -> str | None:
    return _last_record(so, "signoff.refused")
