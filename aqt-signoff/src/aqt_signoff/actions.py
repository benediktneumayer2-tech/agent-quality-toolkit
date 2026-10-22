"""Approved actions: prepare -> approve (exact hash, signed) -> claim (atomic) -> outcome.

An unknown outcome is final until a human resolves it; nothing is retried here.
"""

from __future__ import annotations

import os
import secrets
import subprocess
import time
from datetime import timedelta
from typing import TYPE_CHECKING

from aqt_evidence import SinkError, bytes_hash, content_hash, subject as make_subject

from .errors import AlreadyClaimed, Conflict, NotFound, Refused, UsageError
from .registry import parse_time
from .statements import SignatureStatus, check_block
from .store import encode

if TYPE_CHECKING:
    from .core import Signoff

KINDS = ("command", "http", "other")
EXCERPT = 400


def action_id_for(request_key: str) -> str:
    return "act_" + content_hash(["aqt-signoff.action", request_key])[7:31]


def check_spec(kind: str, spec: dict) -> dict:
    if kind not in KINDS:
        raise UsageError(f"kind must be one of {', '.join(KINDS)}")
    if not isinstance(spec, dict):
        raise UsageError("spec must be an object")
    if kind == "command":
        argv = spec.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
            raise UsageError("a command action needs spec.argv, a non-empty list of strings")
    if kind == "http" and (not spec.get("method") or not spec.get("url")):
        raise UsageError("an http action needs spec.method and spec.url")
    return spec


def _tail(*parts: bytes | None) -> str:
    text = b"".join(p for p in parts if p).decode("utf-8", errors="replace")
    return text[-EXCERPT:]


class Claim:
    """Returned by ``claim``. Report exactly one outcome; leaving the ``with`` block without one,
    or with an exception, records ``unknown``."""

    def __init__(self, actions: "Actions", action_id: str, claim_id: str, record: dict):
        self.actions, self.action_id, self.claim_id, self.record = actions, action_id, claim_id, record
        self.outcome: dict | None = None

    def _report(self, outcome: str, basis: str, evidence: dict | None) -> dict:
        self.outcome = self.actions.report_outcome(self.action_id, self.claim_id, outcome, basis=basis,
                                                   extra={"evidence": evidence} if evidence else None)
        return self.outcome

    def succeeded(self, evidence: dict | None = None) -> dict:
        return self._report("succeeded", "executor-report", evidence)

    def failed(self, evidence: dict | None = None) -> dict:
        return self._report("failed", "executor-report", evidence)

    def unknown(self, evidence: dict | None = None) -> dict:
        return self._report("unknown", "executor-report", evidence)

    def __enter__(self) -> "Claim":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if self.outcome is None:
            basis = "executor-exception" if exc_type else "no-report"
            self.outcome = self.actions.report_outcome(
                self.action_id, self.claim_id, "unknown", basis=basis,
                extra={"error": type(exc).__name__} if exc_type else None)
        return False


class Actions:
    def __init__(self, signoff: "Signoff"):
        self.so = signoff

    # ---- reading -------------------------------------------------------------------------------
    def get(self, action_id: str) -> dict:
        row = self.so.store.action(action_id)
        if row is None:
            raise NotFound(f"no action {action_id}")
        return row

    def valid_approvals(self, row: dict) -> tuple[list[SignatureStatus], list[SignatureStatus]]:
        """(counted approvals, approvals that are valid but expired)."""
        policy, now = self.so.settings.action_policy, self.so.clock()
        counted, expired, seen = [], [], set()
        for record in row["approvals"]:
            status = check_block(record.get("data", {}).get("signature"), self.so.registry, record=record)
            subject = status.subject
            if (not status.valid or subject.get("ref") != row["id"] or subject.get("sha256") != row["action_sha256"]
                    or status.meaning != "approved"):
                continue
            if policy.distinct_from_author and status.signer_id == row["preparer"].get("id"):
                continue
            if policy.roles and status.role not in policy.roles:
                continue
            if status.expires_at and parse_time(status.expires_at) <= now:
                expired.append(status)
                continue
            if status.signer_id not in seen:
                seen.add(status.signer_id)
                counted.append(status)
        return counted, expired

    def view(self, row: dict) -> dict:
        status, detail = row["status"], ""
        counted, expired = self.valid_approvals(row) if row["status"] in ("prepared", "approved") else ([], [])
        needed = self.so.settings.action_policy.min_signatures
        if status == "approved" and len(counted) < needed:
            status, detail = ("expired", "approval expired") if expired else ("prepared", "approval no longer valid")
        elif status == "prepared" and row["approvals"]:
            detail = f"{len(counted)} of {needed} approval(s)"
        elif status == "claimed":
            age_ms = int((self.so.clock() - parse_time(row["claimed_at"])).total_seconds() * 1000)
            if age_ms > self.so.settings.claim_grace_ms:
                status, detail = "unknown", "claimed, no outcome reported"
            else:
                detail = "running or interrupted; within the grace period"
        elif row.get("outcome"):
            detail = row["outcome"].get("basis", "")
            if row["outcome"].get("resolution"):
                detail = f"resolved by {row['outcome'].get('resolved_by')}: {row['outcome']['resolution']}"
        return {"id": row["id"], "version": row["version"], "status": status, "detail": detail,
                "action_sha256": row["action_sha256"], "spec": row["spec"], "preparer": row["preparer"],
                "approvals": [{"signer": s.signer_id, "role": s.role, "signed_at": s.signed_at,
                               "expires_at": s.expires_at, "reason": s.reason} for s in counted],
                "claim_id": row["claim_id"], "claimed_at": row["claimed_at"], "outcome": row["outcome"],
                "rejection": row["rejection"], "updated_at": row["updated_at"]}

    def show(self, action_id: str) -> dict:
        return self.view(self.get(action_id))

    def list(self, status: str | None = None) -> list[dict]:
        views = [self.view(row) for row in self.so.store.actions()]
        return [v for v in views if status is None or v["status"] == status]

    # ---- prepare -------------------------------------------------------------------------------
    def prepare(self, kind: str, request_key: str, spec: dict, *, description: str = "",
                payload: bytes | None = None, payload_sha256: str | None = None, who: dict | None = None,
                revise: str | None = None) -> dict:
        """Propose an action. Idempotent per request key; a different spec under the same key is a conflict."""
        check_spec(kind, spec)
        if payload is not None:
            payload_sha256 = bytes_hash(payload)
        if not revise and not request_key:
            raise UsageError("a request key is required (it makes prepare idempotent)")
        who = who or self.so.caller()
        store, now = self.so.store, self.so.now()
        existing = store.action(revise) if revise else store.action(action_id_for(request_key))
        if revise and existing is None:
            raise NotFound(f"no action {revise}")
        core = {"kind": kind, "description": description, "spec": spec, "payload_sha256": payload_sha256}
        if existing and not revise:
            old = {k: existing["spec"].get(k) for k in core}
            if old == core:
                return self.view(existing)
            raise Conflict(f"request key already used for a different action ({existing['id']}); "
                           "use a new key or --revise", code="request_key_conflict")
        if revise and existing["status"] in ("claimed", "unknown", "succeeded"):
            raise Conflict(f"{revise} is {existing['status']}; it cannot be revised", code="not_revisable")
        action_id = existing["id"] if existing else action_id_for(request_key)
        version = existing["version"] + 1 if existing else 1
        body = {"action_id": action_id, "version": version, **core}
        action_sha256 = content_hash(body)
        request_key_sha256 = existing["request_key_sha256"] if existing else content_hash(["key", request_key])
        data = {"action": body, "action_sha256": action_sha256, "request_key_sha256": request_key_sha256}
        if revise:
            data["supersedes"] = existing["action_sha256"]
        record = self.so.record("signoff.action.prepared", who, "revise" if revise else "prepare",
                                subject=make_subject("action", action_id, sha256=action_sha256),
                                reason=description or None, data=data)
        stored = self.so.emit(record)
        with store.transaction() as db:
            if revise:
                db.execute("UPDATE actions SET version=?, spec=?, action_sha256=?, prepared_record=?, status='prepared', "
                           "approvals='[]', rejection=NULL, claim_id=NULL, claimed_at=NULL, claim_record=NULL, "
                           "outcome=NULL, updated_at=? WHERE id=?",
                           (version, encode(body), action_sha256, stored["id"], now, action_id))
            else:
                db.execute("INSERT INTO actions (id, request_key_sha256, version, spec, action_sha256, preparer, "
                           "prepared_record, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                           (action_id, request_key_sha256, version, encode(body), action_sha256, encode(who),
                            stored["id"], "prepared", now, now))
        return self.show(action_id)

    # ---- human decisions -----------------------------------------------------------------------
    def _decision_checks(self, row: dict, expected_hash: str, signer, who: dict, attempted: str) -> None:
        if expected_hash != row["action_sha256"]:
            raise Conflict("the hash does not match the current action; run 'show' and review it again",
                           code="hash_mismatch")
        status = self.view(row)["status"]
        if status not in ("prepared", "approved", "expired"):
            raise Conflict(f"{row['id']} is {status}; no decision possible", code="not_open")
        policy = self.so.settings.action_policy
        subject = make_subject("action", row["id"], sha256=row["action_sha256"])
        if policy.distinct_from_author and signer.id == row["preparer"].get("id"):
            raise self.so.refuse(attempted, who, "self_approval",
                                 f"{signer.id} prepared this action and may not decide on it", subject=subject)
        if policy.roles and signer.role not in policy.roles:
            raise self.so.refuse(attempted, who, "role_not_allowed",
                                 f"role {signer.role!r} may not approve actions", subject=subject)

    def approve(self, action_id: str, expected_hash: str, reason: str, *, signer_id: str | None = None,
                valid_for_ms: int | None = None) -> dict:
        row = self.get(action_id)
        signer = self.so.signer_entry(signer_id)
        who = self.so.signer_actor(signer)
        self.so.require_human("approve", who)
        if not reason or not reason.strip():
            raise UsageError("an approval needs a reason")
        self._decision_checks(row, expected_hash, signer, who, "approve")
        counted, _ = self.valid_approvals(row)
        if any(s.signer_id == signer.id for s in counted):
            raise Conflict(f"{signer.id} has already approved this version", code="already_approved")
        expires_at = None
        if valid_for_ms:
            from .core import format_time
            expires_at = format_time(self.so.clock() + timedelta(milliseconds=valid_for_ms))
        key = self.so.unlock(signer, f"approve action {action_id}")
        record = self.so.signed_record(
            "signoff.action.approved", "approve", signer=signer, key=key, meaning="approved", reason=reason,
            subject=make_subject("action", action_id, sha256=row["action_sha256"]),
            links=[{"rel": "action", "ref": row["prepared_record"]}],
            data={"action_id": action_id, "version": row["version"], "action_sha256": row["action_sha256"],
                  "expires_at": expires_at},
            expires_at=expires_at)
        if expires_at is None:
            record["data"].pop("expires_at")
        stored = self.so.emit(record, key)
        with self.so.store.transaction() as db:
            current = self.so.store.action(action_id)
            if current["action_sha256"] != row["action_sha256"]:
                raise Conflict("the action changed while approving", code="hash_mismatch")
            approvals = [*current["approvals"], stored]
            db.execute("UPDATE actions SET approvals=?, updated_at=? WHERE id=?",
                       (encode(approvals), self.so.now(), action_id))
            counted, _ = self.valid_approvals({**current, "approvals": approvals})
            if len(counted) >= self.so.settings.action_policy.min_signatures and current["status"] == "prepared":
                db.execute("UPDATE actions SET status='approved' WHERE id=?", (action_id,))
        return self.show(action_id)

    def reject(self, action_id: str, expected_hash: str, reason: str, *, signer_id: str | None = None) -> dict:
        row = self.get(action_id)
        signer = self.so.signer_entry(signer_id)
        who = self.so.signer_actor(signer)
        self.so.require_human("reject", who)
        if not reason or not reason.strip():
            raise UsageError("a rejection needs a reason")
        self._decision_checks(row, expected_hash, signer, who, "reject")
        key = self.so.unlock(signer, f"reject action {action_id}")
        record = self.so.signed_record(
            "signoff.action.rejected", "reject", signer=signer, key=key, meaning="rejected", reason=reason,
            subject=make_subject("action", action_id, sha256=row["action_sha256"]),
            links=[{"rel": "action", "ref": row["prepared_record"]}],
            data={"action_id": action_id, "version": row["version"], "action_sha256": row["action_sha256"]})
        stored = self.so.emit(record, key)
        with self.so.store.transaction() as db:
            db.execute("UPDATE actions SET status='rejected', rejection=?, updated_at=? WHERE id=? AND action_sha256=?",
                       (encode({"record": stored["id"], "signer": signer.id, "reason": reason}), self.so.now(),
                        action_id, row["action_sha256"]))
        return self.show(action_id)

    # ---- execution -----------------------------------------------------------------------------
    def claim(self, action_id: str, expected_hash: str, *, payload: bytes | None = None,
              who: dict | None = None) -> Claim:
        """Claim an approved action before running it. At most one claim ever succeeds per version."""
        row = self.get(action_id)
        who = who or self.so.caller()
        subject = make_subject("action", action_id, sha256=row["action_sha256"])
        if expected_hash != row["action_sha256"]:
            raise Conflict("the hash does not match the approved action", code="hash_mismatch")
        view = self.view(row)
        if row["status"] in ("claimed", "succeeded", "failed", "unknown"):
            raise AlreadyClaimed(f"{action_id} was already claimed ({view['status']}); it is never run twice",
                                 details={"claim_id": row["claim_id"], "status": view["status"]})
        counted, expired = self.valid_approvals(row)
        if len(counted) < self.so.settings.action_policy.min_signatures:
            why = "approval expired" if expired else "no valid approval for this exact action"
            raise self.so.refuse("claim", who, "not_approved", f"{action_id}: {why}", subject=subject)
        spec = row["spec"]
        payload_checked = False
        if payload is not None:
            if spec.get("payload_sha256") != bytes_hash(payload):
                raise self.so.refuse("claim", who, "payload_mismatch",
                                     "the presented payload differs from the approved payload hash", subject=subject)
            payload_checked = True
        claim_id, now = "clm_" + secrets.token_hex(8), self.so.now()
        with self.so.store.transaction() as db:
            changed = db.execute("UPDATE actions SET status='claimed', claim_id=?, claimed_at=?, updated_at=? "
                                 "WHERE id=? AND status='approved' AND action_sha256=?",
                                 (claim_id, now, now, action_id, row["action_sha256"])).rowcount
        if changed != 1:
            current = self.get(action_id)
            raise AlreadyClaimed(f"{action_id} was claimed by someone else; it is never run twice",
                                 details={"claim_id": current["claim_id"], "status": current["status"]})
        record = self.so.record("signoff.action.claimed", who, "claim", subject=subject,
                                links=[{"rel": "approval", "ref": s.record_id} for s in counted],
                                data={"action_id": action_id, "action_sha256": row["action_sha256"],
                                      "claim_id": claim_id, "approvals": [s.record_id for s in counted],
                                      "payload_checked": payload_checked})
        try:
            stored = self.so.emit(record)
        except SinkError:
            with self.so.store.transaction() as db:   # nothing has run yet, so the claim can be released
                db.execute("UPDATE actions SET status='approved', claim_id=NULL, claimed_at=NULL WHERE id=? AND claim_id=?",
                           (action_id, claim_id))
            raise
        self.so.store.db.execute("UPDATE actions SET claim_record=? WHERE id=?", (stored["id"], action_id))
        return Claim(self, action_id, claim_id, stored)

    def report_outcome(self, action_id: str, claim_id: str, outcome: str, *, basis: str = "executor-report",
                       extra: dict | None = None, who: dict | None = None) -> dict:
        """Record what happened. Stored locally first; if the sink is down the record waits for ``sync``."""
        if outcome not in ("succeeded", "failed", "unknown"):
            raise UsageError("outcome must be succeeded, failed or unknown")
        row = self.get(action_id)
        who = who or self.so.caller()
        data = {"action_id": action_id, "claim_id": claim_id, "outcome": outcome, "basis": basis,
                **{k: v for k, v in (extra or {}).items() if v is not None}}
        record = self.so.record("signoff.action.outcome", who, "outcome",
                                subject=make_subject("action", action_id, sha256=row["action_sha256"]),
                                links=[{"rel": "claim", "ref": row["claim_record"]}] if row["claim_record"] else None,
                                data=data)
        with self.so.store.transaction() as db:
            changed = db.execute("UPDATE actions SET status=?, outcome=?, updated_at=? WHERE id=? AND status='claimed' "
                                 "AND claim_id=?", (outcome, encode({**data, "record": record["id"]}), self.so.now(),
                                                    action_id, claim_id)).rowcount
        if changed != 1:
            raise Conflict(f"{action_id} is not claimed under {claim_id}; only a human can resolve it now",
                           code="not_claimed")
        return self._deliver(record)

    def _deliver(self, record: dict) -> dict:
        try:
            stored = self.so.emit(record)
            return {**stored, "_delivered": True}
        except SinkError as error:
            self.so.store.add_pending(record, str(error), self.so.now())
            return {**record, "_delivered": False, "_error": str(error)}

    def run(self, action_id: str, *, timeout_ms: int | None = None, payload: bytes | None = None) -> dict:
        """Claim a command action, run its approved argv once (no shell) and record the outcome."""
        row = self.get(action_id)
        if row["spec"]["kind"] != "command":
            raise UsageError("only command actions can be run by aqt-signoff; claim others and report the outcome")
        claim = self.claim(action_id, row["action_sha256"], payload=payload)
        argv = row["spec"]["spec"]["argv"]
        timeout = (timeout_ms or self.so.settings.run_timeout_ms) / 1000
        started = time.monotonic()
        extra: dict = {}
        try:
            done = subprocess.run(argv, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL,
                                  env=os.environ.copy())
        except subprocess.TimeoutExpired as error:
            outcome, basis = "unknown", "timeout"
            extra = {"stdout_sha256": bytes_hash(error.stdout or b""), "stderr_sha256": bytes_hash(error.stderr or b""),
                     "excerpt": _tail(error.stdout, error.stderr)}
        except OSError as error:   # exec failed: the command did not start
            outcome, basis, extra = "failed", "exec-error", {"error": f"{type(error).__name__}: {error}"}
        except BaseException as error:
            claim.outcome = self.report_outcome(action_id, claim.claim_id, "unknown", basis="executor-exception",
                                                extra={"error": type(error).__name__})
            raise
        else:
            extra = {"exit_code": done.returncode, "stdout_sha256": bytes_hash(done.stdout),
                     "stderr_sha256": bytes_hash(done.stderr), "excerpt": _tail(done.stdout, done.stderr)}
            if done.returncode == 0:
                outcome, basis = "succeeded", "exit-code"
            elif done.returncode < 0:
                outcome, basis = "unknown", "signal"
            else:
                outcome, basis = "failed", "exit-code"
        extra["duration_ms"] = int((time.monotonic() - started) * 1000)
        return self.report_outcome(action_id, claim.claim_id, outcome, basis=basis, extra=extra)

    def resolve(self, action_id: str, as_: str, reason: str, *, signer_id: str | None = None) -> dict:
        """A human closes an unknown outcome after checking the external state."""
        if as_ not in ("succeeded", "not-applied"):
            raise UsageError("resolve as 'succeeded' or 'not-applied'")
        row = self.get(action_id)
        signer = self.so.signer_entry(signer_id)
        who = self.so.signer_actor(signer)
        self.so.require_human("resolve", who)
        if not reason or not reason.strip():
            raise UsageError("a resolution needs a reason")
        view = self.view(row)
        subject = make_subject("action", action_id, sha256=row["action_sha256"])
        if view["status"] == "claimed":
            raise self.so.refuse("resolve", who, "claim_in_progress",
                                 "this action may still be running; wait for the grace period, then check the "
                                 "external state", subject=subject)
        if view["status"] != "unknown":
            raise Conflict(f"{action_id} is {view['status']}; only an unknown outcome can be resolved",
                           code="not_unknown")
        outcome = "succeeded" if as_ == "succeeded" else "failed"
        key = self.so.unlock(signer, f"resolve action {action_id}")
        record = self.so.signed_record(
            "signoff.action.outcome", "resolve", signer=signer, key=key, meaning="verified", reason=reason,
            subject=subject, links=[{"rel": "resolves", "ref": (row["outcome"] or {}).get("record") or
                                     row["claim_record"] or row["prepared_record"]}],
            data={"action_id": action_id, "claim_id": row["claim_id"], "outcome": outcome,
                  "resolution": "applied" if as_ == "succeeded" else "not-applied", "basis": "human-resolution",
                  "previous": view["detail"] or "unknown"},
            outcome=outcome)
        stored = self.so.emit(record, key)
        with self.so.store.transaction() as db:
            db.execute("UPDATE actions SET status=?, outcome=?, updated_at=? WHERE id=? AND status IN ('claimed','unknown')",
                       (outcome, encode({**record["data"], "record": stored["id"], "resolved_by": signer.id,
                                         "signature": None}), self.so.now(), action_id))
        return self.show(action_id)


__all__ = ["Actions", "Claim", "action_id_for", "Refused"]
