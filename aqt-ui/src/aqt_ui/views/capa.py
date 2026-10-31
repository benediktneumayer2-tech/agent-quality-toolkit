"""CAPA view (aqt-capa): candidates, deviations with their timeline, effectiveness, and the
human decisions (accept or dismiss a candidate, approve a corrective action, close a deviation).

``effectiveness(record=False)`` writes no evidence; it runs aqt-capa's scan first, which
refreshes its SQLite working index (not evidence), exactly as the CLI's read commands do.

Decisions: aqt-capa itself records accept, dismiss and close without a signature, under the
identity it is given. The UI gives it the signer chosen in the panel and lets aqt-capa record
the decision only after the passphrase has unlocked that signer's key (a failed unlock is
recorded by aqt-signoff as ``signoff.auth.failed``). The record names that signer but carries
no signature, so the record alone does not prove who decided (a limit of aqt-capa). A corrective
action is approved as the CLI recommends: an aqt-signoff signature with the meaning
"approved" over the implementation record (approval state ``signed-verified``).
"""

from __future__ import annotations

import dataclasses
from typing import Callable

from aqt_evidence import Text

from . import NotFound, Stale, UsageProblem, coded_fields, coded_list, message, require
from .changes import _signers, signoff_call
from .signatures import open_signoff

ATTEMPTED = {"accept": "candidate.accept", "dismiss": "candidate.dismiss", "close": "deviation.close"}


class CapaView:
    def __init__(self):
        require("aqt_capa", "aqt-capa")
        from aqt_capa import Capa, load_config
        self.capa = Capa(load_config())

    def summary(self) -> dict:
        capa = self.capa
        try:
            effectiveness = capa.effectiveness(record=False)
        except Exception as error:  # noqa: BLE001 - shown as a message in the view
            effectiveness, error_text = [], f"{type(error).__name__}: {error}"
        else:
            error_text = None
        deviations = capa.list()
        deviations.sort(key=lambda d: (d.get("state") == "closed", not d.get("overdue"), d.get("num") or 0))
        effectiveness.sort(key=lambda e: {"not-effective": 0, "pending": 1}.get(e.get("result"), 2))
        return {"candidates": capa.candidates(), "deviations": deviations, "signers": _signers(),
                "effectiveness": [{**{k: e.get(k) for k in ("action_id", "dev_id", "result", "reasons", "counts",
                                                            "window", "approval")},
                                   "reason_codes": coded_list(e.get("reasons"))} for e in effectiveness],
                "effectiveness_error": error_text,
                "counts": {"candidates": len(capa.candidates()),
                           "overdue": sum(1 for d in deviations if d.get("overdue")),
                           "open": sum(1 for d in deviations if d.get("state") != "closed"),
                           "not_effective": sum(1 for e in effectiveness if e.get("result") == "not-effective")}}

    def counts(self) -> dict:
        """Cheap counts for the home queue (no scan)."""
        deviations = self.capa.list()
        candidates = self.capa.candidates()
        times = sorted(str(c.get("time")) for c in candidates if c.get("time"))
        return {"candidates": len(candidates), "overdue": sum(1 for d in deviations if d.get("overdue")),
                "open": sum(1 for d in deviations if d.get("state") != "closed"), "oldest": times[0] if times else None}

    def deviation(self, dev_id: str) -> dict:
        from aqt_capa import CapaError
        try:
            shown = self.capa.show(dev_id)
        except CapaError as error:
            raise NotFound(message(error)) from error
        for item in shown["actions"]:           # what an approval is bound to
            row = self.capa.store.action(item["action_id"])
            item.update(implemented_record=row["implemented_record"], implemented_hash=row["implemented_hash"],
                        implementer=row["implementer"])
        shown["version"] = shown["timeline"][-1]["id"] if shown["timeline"] else None
        shown["signers"] = _signers()
        return shown

    # -- decisions ---------------------------------------------------------------------------------------
    def decide(self, kind: str, ref: str, *, reason: str, passphrase: str, signer_id: str | None,
               human_check: Callable, shown_version: str | None = None, no_action: bool = False) -> dict:
        """Accept or dismiss a candidate, or close a deviation, as the signer shown."""
        from aqt_capa import Capa, CapaError, load_config
        from aqt_capa.capa import Blocked, Refused
        from aqt_signoff import SignoffError
        if kind not in ATTEMPTED:
            raise UsageProblem(f"unknown decision {kind}")
        if not (reason or "").strip():
            raise UsageProblem("a reason is required")
        so = open_signoff(passphrase=passphrase)
        try:
            signer = so.signer_entry(signer_id or None)
        except SignoffError as error:
            raise UsageProblem(message(error)) from error
        config = dataclasses.replace(load_config(), identity_id=signer.id, identity_role=signer.role or None,
                                     identity_display=signer.name or None)
        capa = Capa(config, guard=human_check)
        written: list[dict] = []
        original = capa.write

        def write(record: dict) -> dict:
            stored = original(record)
            written.append(stored)
            return stored
        capa.write = write
        try:
            capa.require_human(ATTEMPTED[kind])               # records capa.refused itself
        except Refused as error:
            last = written[-1] if written else {}
            return {"ok": False, "message": message(error), **coded_fields("message", error),
                    "record_id": last.get("id"), "reason_code": (last.get("data") or {}).get("reason_code"),
                    "markers": (last.get("data") or {}).get("agent_markers", [])}
        if kind == "close":
            try:
                current = capa.show(ref)
            except CapaError as error:
                raise NotFound(message(error)) from error
            version = current["timeline"][-1]["id"] if current["timeline"] else None
            if not shown_version or version != shown_version:
                raise Stale("the deviation changed since it was shown; nothing was recorded. Reload it.")
        _, refusal = signoff_call(so, lambda: so.unlock(signer, f"CAPA {ATTEMPTED[kind]}"))
        if refusal:
            return refusal
        try:
            if kind == "accept":
                record = capa.accept(ref, reason=reason)
            elif kind == "dismiss":
                record = capa.dismiss(ref, reason=reason)
            else:
                record = capa.close(ref, reason=reason, no_action=no_action)
        except Refused as error:
            return {"ok": False, "message": message(error), **coded_fields("message", error),
                    "record_id": written[-1]["id"] if written else None}
        except (Blocked, CapaError) as error:
            raise UsageProblem(message(error)) from error
        data = record.get("data") or {}
        dev = data.get("dev_id")
        if dev and kind == "accept":
            done = Text("ui.capa.accept_recorded", "accept recorded ({dev})", dev=dev)
        elif dev and kind == "close":
            done = Text("ui.capa.close_recorded", "close recorded ({dev})", dev=dev)
        elif not dev and kind == "dismiss":
            done = Text("ui.capa.dismiss_recorded", "dismiss recorded")
        else:
            done = f"{kind} recorded" + (f" ({dev})" if dev else "")
        return {"ok": True, "message": done, **coded_fields("message", done),
                "record_id": record.get("id"), "record_type": record.get("type"), "time": record.get("time"),
                "dev_id": data.get("dev_id")}

    def approve_action(self, action_id: str, *, expected_hash: str, reason: str, passphrase: str,
                       signer_id: str | None, human_check: Callable) -> dict:
        """Approve the implemented corrective action shown: an aqt-signoff signature ("approved")
        over its implementation record, bound to that record's hash."""
        capa = self.capa
        act = capa.store.action(action_id)
        so = open_signoff(passphrase=passphrase, human_check=human_check)

        def sign():
            signer = so.signer_entry(signer_id or None)
            so.require_human("sign", so.signer_actor(signer))         # the guard first; refusals are recorded
            if act is None:
                raise NotFound(f"unknown action {action_id}")
            if act["state"] != "implemented" or not act["implemented_record"]:
                raise UsageProblem(f"{action_id} is {act['state']}; only an implemented action can be approved")
            if not expected_hash or expected_hash != act["implemented_hash"]:
                raise Stale("the action is not the one shown; nothing was signed. Reload the deviation.")
            if act["implementer"] == signer.id and not capa.cfg.allow_self_approval:
                raise UsageProblem(f"{signer.id} implemented {action_id}; approval needs another person")
            if capa.verify(action_id)[0]["status"] != "ok":
                raise UsageProblem(f"{act['path']} changed after implementation; run 'aqt-capa action implement' again")
            if capa.approval(act)["approved"]:
                raise UsageProblem(f"{action_id} is already approved")
            subject, _ = so.record_subject(act["implemented_record"])
            if subject["sha256"] != act["implemented_hash"]:
                raise Stale("the implementation record changed; nothing was signed. Reload the deviation.")
            return so.sign(subject, "approved", reason, signer_id=signer.id)
        stored, refusal = signoff_call(so, sign)
        if refusal:
            return refusal
        done = Text("ui.capa.action_approved", "{action} approved (signed)", action=action_id)
        return {"ok": True, "message": done, **coded_fields("message", done), "record_id": stored.get("id"),
                "record_type": stored.get("type"), "time": stored.get("time")}

    def trends(self) -> str:
        from aqt_capa import render_markdown, trends
        return render_markdown(trends(self.capa))
