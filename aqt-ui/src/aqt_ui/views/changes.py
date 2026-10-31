"""Changes view: release gates of the configured projects (aqt-change) and prepared actions
(aqt-signoff), with approval of one prepared action bound to the hash shown.

The specification of an action is shown, and can be approved or rejected, only when its
canonical hash (``aqt_evidence.content_hash``, as ``aqt-signoff prepare`` computes it) equals
the stored action hash: the hash that is signed is then the hash of the text on screen."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable

from aqt_evidence import Text

from . import NotFound, Stale, UsageProblem, coded_fields, fingerprint, installed, message, refusal_text, require
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
PROJECT_INDEX = re.compile(r"[0-9]{1,4}")          # a project is named by its position in ui.toml
STABLE_ID = re.compile(r"[A-Za-z0-9._-]{1,200}")   # a plan id, as aqt-change plan new allows it
CLAIMED = re.compile(r"[A-Za-z0-9._:@+-]{1,128}")   # a signer id named by a request, before it is looked up


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
        self._release_locks: dict[str, threading.Lock] = {}

    # -- gates ---------------------------------------------------------------------------------------
    def _plan(self, ledger, state: dict, *, evidence: Callable[[], list], with_release: bool = True) -> dict:
        """One plan of a project: the gate as ``aqt-change gate`` gives it, the receipts per item, the
        reviews, the ``change.finish`` record bound to this change (``bind_finish``: read from ``evidence``,
        the records aqt-signoff reads) and (``with_release``) whether that record was signed "released".
        The plan is named by its registered id (the state's), for the page and for signing alike. Anything
        unexpected in the agent-writable mirror turns this one plan into an error entry."""
        from aqt_change import ChangeError
        from aqt_change.plans import read_plan
        from aqt_change.receipts import Freshness, evaluate
        rel = state.get("path")
        plan = {"plan_id": str(state.get("plan_id") or Path(str(rel)).stem), "path": rel, "decision": None,
                "reasons": [], "receipts": [], "approval": None, "error": None}
        try:
            public = gate_cli(ledger.root, rel)
            _, parsed = read_plan(ledger, str(ledger.abs(rel)))
            items = evaluate(ledger, parsed, Freshness(ledger))
        except (ChangeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            plan["error"] = str(error)
            return plan
        try:
            self._details(ledger, plan, public, items, evidence, with_release)
        except Exception as error:  # noqa: BLE001 - one malformed mirror line must not take down the queue
            problem = Text("ui.changes.plan_unreadable", "plan {plan} cannot be shown: {error}", plan=plan["plan_id"],
                           error=f"{type(error).__name__}: {error}")
            plan.update(error=problem, **coded_fields("error", problem), finish_record=None, release=None)
        return plan

    @staticmethod
    def _details(ledger, plan: dict, public: dict, items: dict, evidence: Callable[[], list],
                 with_release: bool) -> None:
        plan.update(decision=public["decision"],
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
        plan["review_records"] = [review_row(r, fresh) for r in ledger.records("change.review", plan["plan_id"])
                                  if isinstance(r, dict)]
        approval = plan["approval"] or {}
        target = ledger.record(approval["record"]) if approval.get("record") else None
        plan["approval_time"] = text_field(target, "time")
        plan["finish_record"], plan["release"] = None, None
        plan["head"] = ledger.head() if ledger.git else None          # what the gate evaluated, shown beside the finish
        if not plan.get("finish"):
            return
        record, problem = bind_finish(ledger, plan["plan_id"], plan["path"], plan["finish"], evidence(),
                                      public.get("receipts") or [])
        if problem:
            plan.update(finish_problem=problem, **coded_fields("finish_problem", problem))
            plan["release"] = {"record": plan["finish"], "state": "unbound", "detail": problem,
                               **coded_fields("detail", problem)}
            return
        plan["finish_record"] = finish_view(record)
        plan["release"] = release_state(plan["finish"]) if with_release else None

    def _project(self, root: Path) -> dict:
        from aqt_change import ChangeError, Ledger
        entry = {"root": str(root), "project": self.index_of(root), "plans": [], "error": None}
        try:
            ledger = Ledger.open(root)
        except (ChangeError, OSError) as error:
            entry["error"] = str(error)
            return entry
        evidence = once(signer_records)                          # read once for all plans of the project
        for state in ledger.plan_states():
            entry["plans"].append(self._plan(ledger, state, evidence=evidence))
        return entry

    def index_of(self, root: Path) -> int | None:
        return next((i for i, p in enumerate(self.projects) if str(p) == str(root)), None)

    def project_index(self, index) -> int:
        """The position of a configured project in ui.toml, given as plain decimal digits (the change pages
        name projects by position, never by a path from the request)."""
        text = str(index)
        if not PROJECT_INDEX.fullmatch(text) or int(text) >= len(self.projects):
            raise UsageProblem(Text("ui.changes.no_project", "project {project} is not configured in ui.toml "
                                    "[changes] projects", project=text[:20]))
        return int(text)

    def project_root(self, index) -> Path:
        return self.projects[self.project_index(index)]

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

    def fresh_plan(self, root: Path, plan_id: str, *, evidence: Callable[[], list],
                   with_release: bool = False) -> dict | None:
        """A fresh gate evaluation of one plan (not the cache), picked by its registered id as on the page."""
        from aqt_change import ChangeError, Ledger
        try:
            ledger = Ledger.open(root)
        except (ChangeError, OSError) as error:
            raise UsageProblem(message(error)) from error
        for state in ledger.plan_states():
            if str(state.get("plan_id") or Path(str(state.get("path"))).stem) == plan_id:
                return self._plan(ledger, state, evidence=evidence, with_release=with_release)
        return None

    # -- one change: the page with the timeline -----------------------------------------------------
    def change(self, index, plan_id: str, *, fresh: bool = False) -> dict:
        require("aqt_change", "aqt-change")
        position = self.project_index(index)
        plan_id = plan_ref(plan_id)
        root = self.projects[position]
        entry = self._cached(root, fresh)
        if entry["error"]:
            raise UsageProblem(entry["error"])
        plan = next((p for p in entry["plans"] if p["plan_id"] == plan_id), None)
        if plan is None:
            raise NotFound(f"no plan {plan_id} in {root}")
        policy = None
        if installed("aqt_signoff"):
            policy = open_signoff().settings.policy("released").as_dict()
        return {"project": position, "root": str(root), "plan": plan, "steps": timeline(plan),
                "release_policy": policy, "signers": _signers(),
                "installed": {"aqt-change": True, "aqt-signoff": installed("aqt_signoff")}}

    def sign_release(self, index, plan_id: str, *, shown_record: str, shown_sha256: str, shown_path: str,
                     reason: str, passphrase: str, signer_id: str | None, human_check: Callable) -> dict:
        """Sign the finished change shown with the meaning "released", as ``aqt-signoff sign --record
        <change.finish record> --meaning released``. In this order: the guard (refusals are recorded, also
        for a signer that is not registered), the plan by its registered id and the path shown, a fresh gate
        evaluation that must be GO, the change.finish record bound to this change (``bind_finish``: in the
        evidence aqt-signoff reads and, with a trail, in the trail; type, plan, path, a commit of this
        repository; the same as the local copy), that record and its hash as shown, no valid "released"
        signature by this signer yet; then aqt-signoff's own checks ([policy.released] roles, distinct from
        the author) and the key unlock. One release of one record is signed at a time."""
        so = open_signoff(passphrase=passphrase, human_check=human_check)
        root_box: list[Path] = []

        def sign():
            guard_first(so, "sign", signer_id)                         # before anything else; refusals are recorded
            signer = so.signer_entry(signer_id or None)
            root = self.project_root(index)
            root_box.append(root)
            plan = self.fresh_plan(root, plan_ref(plan_id), evidence=so.records)
            if plan is None:
                raise NotFound(f"no plan {plan_id} in {root}")
            if plan["path"] != shown_path:
                raise Stale(Text("ui.release.other_plan", "the plan {plan} is now {path}, not the one shown; nothing "
                                 "was signed. Reload the change.", plan=plan_id, path=str(plan["path"])))
            if plan.get("error") or plan.get("decision") != "GO":
                codes = ", ".join(r.get("code", "") for r in plan.get("reasons") or []) or plan.get("error") or "-"
                raise Stale(f"the gate of {plan_id} is {plan.get('decision') or 'not evaluated'} now ({codes}); "
                            "only a GO change can be released. Nothing was signed.")
            if plan.get("finish_problem"):
                raise Stale(Text("ui.release.unbound", "nothing was signed: {why}", why=plan["finish_problem"]))
            if not plan.get("finish") or plan["finish"] != shown_record:
                raise Stale("the change.finish record is not the one shown; nothing was signed. Reload the change.")
            subject, _ = so.record_subject(plan["finish"])
            if not shown_sha256 or subject["sha256"] != shown_sha256 \
                    or subject["sha256"] != plan["finish_record"]["sha256"]:
                raise Stale("the change.finish record changed since it was shown; nothing was signed. Reload the "
                            "change.")
            with self.release_lock(plan["finish"]):
                report = so.verify_record(plan["finish"], required=["released"], record_invalidations=False)
                if any(s.valid and s.meaning == "released" and s.signer_id == signer.id for s in report.current):
                    raise UsageProblem(f"{signer.id} has already signed this change as released "
                                       f"({plan['finish']}); nothing was signed")
                return so.sign(subject, "released", reason, signer_id=signer.id)
        stored, refusal = signoff_call(so, sign)
        if refusal:
            return refusal
        for root in root_box:
            self.forget(root)                                         # the release state changed
        forget_release(shown_record)
        done = Text("ui.changes.released", "change {plan} released", plan=plan_id)
        return {"ok": True, "message": done, **coded_fields("message", done), "record_id": stored.get("id"),
                "record_type": stored.get("type"), "time": stored.get("time")}

    def release_lock(self, record_id: str) -> threading.Lock:
        """One lock per change.finish record: two tabs cannot both pass the "already signed" check."""
        with self._lock:
            return self._release_locks.setdefault(record_id, threading.Lock())

    # -- prepared actions --------------------------------------------------------------------------------
    @staticmethod
    def actions() -> list[dict]:
        if not installed("aqt_signoff"):
            return []
        so = open_signoff()
        return [{**view, **coded_fields("detail", view.get("detail"))} for view in so.actions.list()]

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
            raise NotFound(message(error)) from error
        problem = spec_problem(view)
        return {**view, **coded_fields("detail", view.get("detail")), "spec_ok": problem is None,
                "spec_error": problem, **coded_fields("spec_error", problem), "signers": _signers()}

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
            guard_first(so, kind, signer_id)                           # before anything else; refusals are recorded
            signer = so.signer_entry(signer_id or None)
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
        done = Text("ui.changes.action_approved", "approve recorded for {action}; status now {status}",
                    action=action_id, status=view["status"]) if kind == "approve" else \
            Text("ui.changes.action_rejected", "reject recorded for {action}; status now {status}", action=action_id,
                 status=view["status"])
        return {"ok": True, "message": done, **coded_fields("message", done), "status": view["status"],
                "record_id": (stored or {}).get("id"),
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
            guard_first(so, "sign", signer_id)                         # before anything else; refusals are recorded
            signer = so.signer_entry(signer_id or None)
            if project is None:
                raise UsageProblem(f"{root} is not a configured project")
            try:
                ledger = Ledger.open(project)
            except (ChangeError, OSError) as error:
                raise UsageProblem(message(error)) from error
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
        done = Text("ui.changes.plan_approved", "plan {plan} approved", plan=plan_id)
        return {"ok": True, "message": done, **coded_fields("message", done), "record_id": stored.get("id"),
                "record_type": stored.get("type"), "time": stored.get("time")}


_RELEASES: dict = {}
_RELEASES_LOCK = threading.Lock()                  # request threads read, fill and evict it


def release_state(finish_id: str | None) -> dict | None:
    """Whether the change.finish record is released: its signatures verified as ``aqt-signoff verify
    --record <finish> --require released`` does, without recording anything. Only called for a record
    that ``bind_finish`` tied to the change. Kept until a file aqt-signoff reads (its own sources: the
    configured evidence or the default ones plus its sink file), the signer registry or the signoff
    settings change (verifying reads the whole evidence)."""
    if not finish_id:
        return None
    if not installed("aqt_signoff"):
        return {"record": finish_id, "state": "unavailable", "install": "aqt-signoff"}
    from aqt_signoff import SignoffError
    from aqt_signoff.manifest import rows
    so = open_signoff()
    key = (finish_id, fingerprint(*so.sources()), fingerprint(so.settings.registry_path, so.settings.config_path))
    with _RELEASES_LOCK:
        if key in _RELEASES:
            return _RELEASES[key]
    try:
        report = so.verify_record(finish_id, required=["released"], record_invalidations=False)
    except SignoffError as error:
        return {"record": finish_id, "state": "missing", "detail": message(error), **coded_fields("detail", error)}
    summary, policy = report.summary(), report.policies["released"].as_dict()
    value = {"record": finish_id, "sha256": report.subject.get("sha256"),
             "state": "released" if report.ok else "unreleased", "summary": summary,
             **coded_fields("summary", summary), "policy": {**policy, **coded_fields("note", policy["note"])},
             "signatures": [{**r, **coded_fields("detail", r["detail"])} for r in rows(report)
                            if r["meaning"] == "released"]}
    with _RELEASES_LOCK:
        if len(_RELEASES) > 256:
            _RELEASES.clear()
        _RELEASES[key] = value
    return value


def forget_release(finish_id: str) -> None:
    with _RELEASES_LOCK:
        for key in [key for key in _RELEASES if key[0] == finish_id]:
            _RELEASES.pop(key, None)


def signer_records() -> list[dict]:
    """The records a signature would be made over: what aqt-signoff reads (its configured evidence or the
    default sources plus its sink file), else the default evidence sources."""
    if installed("aqt_signoff"):
        return open_signoff().records()
    from aqt_evidence import iter_evidence
    return [r for r in iter_evidence() if isinstance(r, dict)]


def once(load: Callable[[], list]) -> Callable[[], list]:
    """``load`` called at most once, on first use."""
    box: list = []

    def get() -> list:
        if not box:
            box.append(load())
        return box[0]
    return get


def bind_finish(ledger, plan_id: str, rel: str, finish_id: str, records: list[dict],
                gate_receipts: list) -> tuple[dict | None, Text | None]:
    """(the change.finish record a release of this change signs, None), or (None, why it cannot be signed).

    The gate names the finish record from aqt-change's local mirror, which the agent's user can write. A
    release signs the copy in ``records`` (what aqt-signoff reads), so that copy must be this change's:
    a ``change.finish`` record of plan ``plan_id`` at ``rel``; the same content as the mirror's copy; with
    a trail in use, in the trail log as aqt-change's own check confirms it (``TrailCheck``, with
    ``trail_keys`` honoured); its commit (or the head it recorded) in this repository's history, a
    commit carrying the trailer ``AQT-Finish: <plan>/<key>`` that finish writes; no later finish of the
    plan in this repository. And it must be a finish of what the fresh gate evaluated
    (``gate_receipts``): the plan version the plan state accepts now, the receipts the gate counts now and,
    for a finish that committed, HEAD or a commit with HEAD's tree. A finish without a commit (``finish
    --no-commit``) records only the head before the change; receipts and plan version bind it."""
    from aqt_change.gitio import trailers
    from aqt_change.ledger import TRUST_TEXT, TrailCheck
    from aqt_evidence import record_content_hash

    def ours(record: dict) -> bool:
        data = record.get("data") if isinstance(record.get("data"), dict) else {}
        return record.get("type") == "change.finish" and data.get("plan_id") == plan_id and data.get("path") == rel

    def in_history(record: dict) -> str | None:
        data = record["data"]
        commit = data.get("commit") or data.get("head")
        if not isinstance(commit, str) or commit not in ledger.git.existing_commits({commit}):
            return None
        done = ledger.git.run("merge-base", "--is-ancestor", commit, "HEAD", check=False)
        return commit if done.returncode == 0 else None

    found = next((r for r in records if r.get("id") == finish_id), None)
    if found is None:
        return None, Text("ui.release.not_in_evidence", "the change.finish record {record} is not in the evidence "
                          "that aqt-signoff reads", record=finish_id)
    if not ours(found):
        return None, Text("ui.release.other_record", "{record} in the evidence is not the change.finish record of "
                          "plan {plan} ({path})", record=finish_id, plan=plan_id, path=str(rel))
    try:
        signed = record_content_hash(found)
        local = {record_content_hash(r) for r in ledger.records() if isinstance(r, dict) and r.get("id") == finish_id}
    except (ValueError, TypeError):
        signed, local = None, set()
    if local != {signed}:
        return None, Text("ui.release.mirror_differs", "the local aqt-change copy of {record} is not the copy in the "
                          "evidence, so it is not known which record this change means", record=finish_id)
    settings = ledger.project_settings(plan_id)
    trust = TrailCheck([found], required=settings["require_trail"], keys=settings["trail_keys"],
                       types=("change.finish",)).status(found)
    if trust != "ok":
        return None, Text("ui.release.not_in_trail", "the change.finish record {record}: {why}", record=finish_id,
                          why=TRUST_TEXT[trust])
    if ledger.git is None:
        return None, Text("ui.release.no_repository", "the project has no Git repository, so {record} cannot be tied "
                          "to it", record=finish_id)
    commit = in_history(found)
    if commit is None:
        named = found["data"].get("commit") or found["data"].get("head")
        return None, Text("ui.release.other_repository", "the commit {commit} of {record} is not in the history of "
                          "this repository", commit=str(named), record=finish_id)
    if found["data"].get("commit"):
        marker = f"{plan_id}/{found['data'].get('idempotency_key')}"
        if ("AQT-Finish", marker) not in trailers(ledger.git.message(commit)):
            return None, Text("ui.release.no_trailer", "the commit {commit} does not carry the trailer AQT-Finish: "
                              "{marker}", commit=commit, marker=marker)
    later = [r for r in records if r is not found and ours(r) and str(r.get("time") or "") > str(found.get("time") or "")
             and in_history(r)]
    if later:
        return None, Text("ui.release.not_latest", "{later} is a later change.finish record of plan {plan} than "
                          "{record}", later=str(later[-1].get("id")), plan=plan_id, record=finish_id)
    # what the fresh gate evaluated: this plan version, these receipts, this tree
    accepted = (ledger.plan_state(plan_id) or {}).get("accepted_raw")
    version = found.get("subject").get("sha256") if isinstance(found.get("subject"), dict) else None
    if not accepted or version != accepted:
        return None, Text("ui.release.other_plan_version", "the change moved on since it was finished: {record} is "
                          "for another version of the plan than the accepted one. Finish it again (aqt-change "
                          "finish).", record=finish_id)
    named = found["data"].get("receipts")
    if not isinstance(named, list) or set(map(str, named)) != set(map(str, gate_receipts)):
        return None, Text("ui.release.other_receipts", "the change moved on since it was finished: the receipts of "
                          "{record} are not the ones the gate counts now. Finish it again (aqt-change finish).",
                          record=finish_id)
    if found["data"].get("commit"):
        head = ledger.head()
        if commit != head and tree_of(ledger, commit) != tree_of(ledger, head):
            return None, Text("ui.release.other_head", "the change moved on since it was finished: HEAD {head} is not "
                              "the finished commit {commit} and holds other files. Finish it again (aqt-change "
                              "finish).", head=str(head), commit=commit)
    return found, None


def tree_of(ledger, commit: str | None) -> str | None:
    if not commit:
        return None
    done = ledger.git.run("rev-parse", "--verify", "--quiet", f"{commit}^{{tree}}", check=False)
    if done.returncode != 0:
        return None
    return done.stdout.decode().strip() or None


def finish_view(record: dict) -> dict:
    """What the page shows of the bound finish record: all of it from the copy that is signed. ``by`` is the
    actor the record names; ``observed`` is what the trail writer saw of its sender (absent without a writer)."""
    from aqt_evidence import record_content_hash
    data = record.get("data") or {}
    seen = record.get("observed") if isinstance(record.get("observed"), dict) else {}
    chain = seen.get("process_chain") if isinstance(seen.get("process_chain"), list) else []
    observed = {"via": text_field(seen, "via"), "harness": text_field(seen, "harness"),
                "chain_status": text_field(seen, "chain_status"),
                "process_chain": [str(p) for p in chain[:8]]} if seen else None
    return {"id": record.get("id"), "time": record.get("time"), "by": (record.get("actor") or {}).get("id"),
            "commit": data.get("commit"), "head": data.get("head"), "gate": data.get("gate"),
            "sha256": record_content_hash(record), "observed": observed}


def review_row(record: dict, counting: set) -> dict:
    data = record.get("data") if isinstance(record.get("data"), dict) else {}
    reviewer = data.get("reviewer")
    reviewer = reviewer.get("id") if isinstance(reviewer, dict) else None
    return {"id": text_field(record, "id"), "time": text_field(record, "time"), "verdict": text_field(data, "verdict"),
            "reviewer": reviewer if isinstance(reviewer, str) else text_field(record.get("actor"), "id"),
            "independence": text_field(data, "independence"), "reason": text_field(record, "reason"),
            "counts": record.get("id") in counting}


def text_field(value, name: str) -> str | None:
    """``value[name]`` when ``value`` is a mapping and the field a string (mirror lines can hold anything)."""
    found = value.get(name) if isinstance(value, dict) else None
    return found if isinstance(found, str) else None


def plan_ref(plan_id) -> str:
    """A plan id from a request: a stable id (letters, digits, . _ -), else refused."""
    text = str(plan_id or "")
    if not STABLE_ID.fullmatch(text) or text in (".", ".."):
        raise UsageProblem(Text("ui.changes.bad_plan_id", "{plan} is not a plan id (letters, digits, . _ -)",
                                plan=text[:80]))
    return text


def guard_first(so, attempted: str, signer_id) -> None:
    """The human check before the signer is looked up: an agent's request is refused and recorded under the
    signer id it names, also when that id is not registered."""
    from aqt_evidence import actor
    claimed = str(signer_id or so.settings.signer or "")
    so.require_human(attempted, actor("human", claimed if CLAIMED.fullmatch(claimed) else "human:unknown"))


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
    elif release.get("state") == "unbound":                 # a person looks: the finish record is not this change's
        state = "person"
    elif plan.get("finish") and decision == "GO" and release.get("state") == "unreleased":
        state = "person"
    else:
        state = "evidence"
    steps.append({"id": "release", "codes": [], "state": state, "finished": bool(plan.get("finish")),
                  "unbound": release.get("state") == "unbound"})
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
        return Text("ui.changes.spec_mismatch", "the stored specification does not match its action hash; it may "
                    "have been changed after it was prepared. It cannot be approved or rejected here.")
    return None


def signoff_call(so, call: Callable) -> tuple:
    """(result, None) or (None, refusal) for a call into aqt-signoff, with its errors in UI terms."""
    from aqt_signoff import AuthFailed, Conflict, NotFound as SignoffNotFound, Refused, SignoffError, UsageError
    try:
        return call(), None
    except Refused as error:
        code = getattr(error, "code", None)
        return None, {"ok": False, "message": message(error), **coded_fields("message", error), "reason_code": code,
                      "reason_text": refusal_text(code), "record_id": _last_refusal(so)}
    except AuthFailed as error:
        words = Text("ui.signoff.unlock_failed", "the key could not be unlocked ({code})",
                     code=getattr(error, "code", "auth_failed"))
        return None, {"ok": False, "message": words, **coded_fields("message", words), "reason_code": "auth_failed",
                      "reason_text": refusal_text("auth_failed"), "record_id": _last_record(so, "signoff.auth.failed")}
    except Conflict as error:
        raise Stale(message(error)) from error
    except SignoffNotFound as error:
        raise NotFound(message(error)) from error
    except (UsageError, SignoffError) as error:
        raise UsageProblem(message(error)) from error


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
