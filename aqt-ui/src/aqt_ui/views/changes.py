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

from . import NotFound, Stale, UsageProblem, installed
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

    # -- gates -----------------------------------------------------------------------------------------
    def _project(self, root: Path) -> dict:
        from aqt_change import ChangeError, Ledger
        from aqt_change.plans import read_plan
        from aqt_change.receipts import Freshness, evaluate
        entry = {"root": str(root), "plans": [], "error": None}
        try:
            ledger = Ledger.open(root)
        except (ChangeError, OSError) as error:
            entry["error"] = str(error)
            return entry
        for state in ledger.plan_states():
            rel = state.get("path")
            plan = {"plan_id": state.get("plan_id") or Path(str(rel)).stem, "path": rel, "decision": None,
                    "reasons": [], "receipts": [], "approval": None, "error": None}
            try:
                public = gate_cli(ledger.root, rel)
                _, parsed = read_plan(ledger, str(ledger.abs(rel)))
                items = evaluate(ledger, parsed, Freshness(ledger))
            except (ChangeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                plan["error"] = str(error)
                entry["plans"].append(plan)
                continue
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
            entry["plans"].append(plan)
        return entry

    def gates(self, *, fresh: bool = False) -> list[dict]:
        if not installed("aqt_change"):
            return []
        out = []
        for root in self.projects:
            key = str(root)
            with self._lock:
                cached = self._cache.get(key)
            if cached and not fresh and time.monotonic() - cached[0] < GATE_TTL:
                out.append(cached[1])
                continue
            value = self._project(root)
            with self._lock:
                self._cache[key] = (time.monotonic(), value)
            out.append(value)
        return out

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
        return {**view, "spec_ok": problem is None, "spec_error": problem}

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
        with self._lock:
            self._cache.pop(str(project), None)                       # the gate changes with the approval
        return {"ok": True, "message": f"plan {plan_id} approved", "record_id": stored.get("id"),
                "record_type": stored.get("type"), "time": stored.get("time")}


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
        return None, {"ok": False, "message": str(error), "reason_code": getattr(error, "code", None),
                      "record_id": _last_refusal(so)}
    except AuthFailed as error:
        return None, {"ok": False, "message": f"the key could not be unlocked ({getattr(error, 'code', 'auth_failed')})",
                      "reason_code": "auth_failed", "record_id": _last_record(so, "signoff.auth.failed")}
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
