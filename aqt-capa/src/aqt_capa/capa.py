"""The CAPA workflow: every state change is an evidence record first, then an index update."""

from __future__ import annotations

import difflib
import json
import os
from datetime import timedelta
from pathlib import Path
from typing import Callable

from aqt_evidence import (AgentContext, HumanCheckError, SinkError, actor, bytes_hash, detect_agent_context,
                          evidence_sources, iter_evidence, new_record, open_sink, record_content_hash, require_human, subject)

from . import sources
from .config import Config
from .similarity import similar
from .store import Store
from .util import excerpt, file_hash, fmt_time, now as utc_now, parse_time, type_matches

KINDS = ("corrective", "preventive")
FACTOR_CATEGORIES = ("method", "machine", "material", "measurement", "people", "environment")
SERVICE = actor("service", "service:aqt-capa")


class CapaError(Exception):
    """Usage or runtime problem (exit 2)."""


class Blocked(Exception):
    """A precondition is not met (exit 1). Nothing was recorded."""


class Refused(Exception):
    """A human-only command was refused because the caller looks like an agent (exit 1). Recorded."""


def default_guard() -> AgentContext:
    return require_human()


class Capa:
    def __init__(self, config: Config, *, store: Store | None = None, sink=None,
                 evidence: list[Path] | None = None, guard: Callable[[], AgentContext] | None = None,
                 context: Callable[[], AgentContext] | None = None):
        self.cfg = config
        self.store = store or Store(config.db_path)
        self.sink = sink or open_sink()
        self.evidence_paths = evidence if evidence is not None else config.evidence_paths
        self.guard = guard or default_guard
        self.context = context or detect_agent_context
        self.missing_paths: list[Path] = []
        if self.store.is_empty() and self._has_capa_records():
            self.store.rebuild(self.readable_paths())

    # ------------------------------------------------------------- plumbing
    def evidence(self) -> list[dict]:
        """All readable evidence records. A configured file that does not exist yet counts as empty
        and is listed in ``missing_paths`` (the CLI warns about it)."""
        paths = self.readable_paths()
        try:
            return [r for r in iter_evidence(paths) if isinstance(r, dict)]
        except SinkError as error:
            raise CapaError(str(error)) from error

    def readable_paths(self) -> list[Path]:
        """Configured (or default, aqt-spec spec §10.5) evidence files that exist; resolved on every read."""
        configured = [Path(p) for p in (self.evidence_paths if self.evidence_paths is not None
                                        else evidence_sources())]
        self.missing_paths = [p for p in configured if not p.exists()]
        return [p for p in configured if p.exists()]

    def _has_capa_records(self) -> bool:
        return any(str(r.get("type", "")).startswith("capa.") for r in self.evidence())

    def human_actor(self) -> dict:
        ident = os.environ.get("AQT_ACTOR") or self.cfg.identity_id
        kind = ident.split(":", 1)[0] if ident.split(":", 1)[0] in ("human", "agent", "service") else "human"
        return actor(kind, ident, role=self.cfg.identity_role, display=self.cfg.identity_display)

    def caller_actor(self) -> dict:
        """Who is calling: an agent when the agent check fires, otherwise the configured identity."""
        claimed = self.human_actor()
        if claimed["kind"] == "agent":
            return claimed
        ctx = self.context()
        if ctx.is_agent:
            harness = ctx.harness or "unknown"
            session = os.environ.get("AQT_AGENT_SESSION") or "unknown"
            return actor("agent", f"agent:{harness}:{session}", harness=harness,
                         session=None if session == "unknown" else session)
        return claimed

    def require_human(self, attempted: str) -> dict:
        """Run the shared human check; record and raise a refusal when it fails."""
        claimed = self.human_actor()
        try:
            if claimed["kind"] != "human":
                raise HumanCheckError(AgentContext(True, None, [f"actor:{claimed['id']}"]),
                                      f"refused: {claimed['id']} is not a human actor")
            self.guard()
        except HumanCheckError as error:
            ctx = error.context
            self.write(new_record("capa.refused", claimed, "refused", reason=str(error), tz=self.cfg.tz, data={
                "attempted_action": attempted,
                "reason_code": "agent-context" if ctx.is_agent else "no-tty",
                "agent_markers": list(ctx.markers)}))
            raise Refused(str(error)) from error
        return claimed

    def write(self, record: dict) -> dict:
        try:
            stored = self.sink.append(record)
        except SinkError as error:
            raise CapaError(f"evidence sink refused the record: {error}") from error
        self.store.apply(stored)
        return stored

    def _dev(self, dev_id: str):
        row = self.store.deviation(dev_id)
        if row is None:
            raise CapaError(f"unknown deviation {dev_id}")
        return row

    def _act(self, action_id: str):
        row = self.store.action(action_id)
        if row is None:
            raise CapaError(f"unknown action {action_id}")
        return row

    @staticmethod
    def _check_choice(value: str, choices, name: str) -> None:
        if value not in choices:
            raise CapaError(f"{name} must be one of {', '.join(choices)}")

    # ----------------------------------------------------------------- scan
    def scan(self) -> list[dict]:
        """Store new candidates from the evidence and git; return them."""
        cands = sources.from_records(self.evidence(), self.cfg.disabled_rules)
        if "git-revert" not in self.cfg.disabled_rules:
            for repo in self.cfg.repos:
                cands.extend(sources.from_git(repo, self.cfg.agent_commit_patterns))
        new = []
        for cand in cands:
            if self.store.upsert_candidate(cand.as_dict() | {"key": cand.key}):
                new.append(cand.as_dict())
        return new

    def candidates(self, status: str | None = "open") -> list[dict]:
        sql = "SELECT * FROM candidates" + (" WHERE status = ?" if status else "") + " ORDER BY time, key"
        return [dict(r) for r in self.store.q(sql, *([status] if status else []))]

    def _candidate(self, candidate_id: str) -> dict:
        row = self.store.candidate(candidate_id)
        if row is None:
            raise CapaError(f"unknown candidate {candidate_id} (run scan first)")
        if row["status"] != "open":
            raise Blocked(f"candidate {candidate_id} is already {row['status']}")
        cand = {k: row[k] for k in ("candidate_id", "key", "rule", "source_type", "source_ref", "time", "title",
                                    "severity", "category", "session") if row[k] is not None}
        return cand

    def accept(self, candidate_id: str, *, reason: str, severity: str | None = None,
               category: str | None = None, title: str | None = None, description: str | None = None) -> dict:
        who = self.require_human("candidate.accept")
        cand = self._candidate(candidate_id)
        return self._open(who, "accepted", title=title or cand["title"], description=description,
                          severity=severity or cand["severity"], category=category or cand["category"],
                          reason=reason, candidate=cand,
                          source={"type": cand["source_type"], "ref": cand["source_ref"], "rule": cand["rule"]})

    def dismiss(self, candidate_id: str, *, reason: str) -> dict:
        who = self.require_human("candidate.dismiss")
        cand = self._candidate(candidate_id)
        kind = "git-commit" if cand["source_ref"].startswith("git:") else "record"
        return self.write(new_record("capa.deviation", who, "dismissed", reason=reason, tz=self.cfg.tz,
                                     subject=subject(kind, cand["source_ref"]),
                                     links=[{"rel": "source", "ref": cand["source_ref"]}],
                                     data={"candidate": cand}))

    def new_deviation(self, *, title: str, description: str | None, severity: str, category: str,
                      subject_ref: str | None = None, links: list[dict] | None = None, reason: str | None = None) -> dict:
        return self._open(self.caller_actor(), "opened", title=title, description=description, severity=severity,
                          category=category, reason=reason, subject_ref=subject_ref, extra_links=links or [])

    def _open(self, who: dict, verb: str, *, title: str, description: str | None, severity: str, category: str,
              reason: str | None, candidate: dict | None = None, source: dict | None = None,
              subject_ref: str | None = None, extra_links: list[dict] = ()) -> dict:
        self._check_choice(severity, sources.SEVERITIES, "severity")
        self._check_choice(category, sources.CATEGORIES, "category")
        if not title.strip():
            raise CapaError("title must not be empty")
        dev_id = f"DEV-{self.store.next_dev_num():04d}"
        opened = utc_now()
        probe = {"dev_id": dev_id, "title": title, "description": description, "category": category,
                 "source_type": (source or {}).get("type"), "subject_ref": subject_ref}
        past = [dict(r) for r in self.store.q("SELECT * FROM deviations")]
        sims = similar(probe, past, self.cfg.similarity_threshold_ppm)
        data = {"dev_id": dev_id, "title": title, "severity": severity, "category": category,
                "due": fmt_time(opened + timedelta(days=int(self.cfg.due_days.get(severity, 30)))),
                "similar": sims}
        if description:
            data["description"] = description[:2000]
            data["description_sha256"] = bytes_hash(description.encode("utf-8"))
        if source:
            data["source"] = source
        if candidate:
            data["candidate"] = candidate
        if subject_ref:
            data["subject_ref"] = subject_ref
        recent = [s for s in sims if self._opened_within(s["dev_id"], opened, days=30)]
        if severity == "minor" and len(recent) >= 2:
            data["suggested_severity"] = "major"
        links = list(extra_links)
        if source:
            links.append({"rel": "source", "ref": source["ref"]})
        return self.write(new_record("capa.deviation", who, verb, subject=subject("deviation", dev_id), reason=reason,
                                     links=links or None, data=data, tz=self.cfg.tz, time=fmt_time(opened)))

    def _opened_within(self, dev_id: str, ref, *, days: int) -> bool:
        row = self.store.deviation(dev_id)
        return bool(row) and ref - parse_time(row["opened_at"]) <= timedelta(days=days)

    def classify(self, dev_id: str, *, reason: str, severity: str | None = None, category: str | None = None,
                 recurrence_of: list[str] | None = None) -> dict:
        who = self.require_human("deviation.classify")
        dev = self._dev(dev_id)
        if dev["state"] == "closed":
            raise Blocked(f"{dev_id} is closed; open a new deviation instead")
        if severity:
            self._check_choice(severity, sources.SEVERITIES, "severity")
        if category:
            self._check_choice(category, sources.CATEGORIES, "category")
        for ref in recurrence_of or []:
            self._dev(ref)
        before = {"severity": dev["severity"], "category": dev["category"]}
        after = {"severity": severity or dev["severity"], "category": category or dev["category"]}
        data = {"dev_id": dev_id, "before": before, "after": after, "recurrence_of": list(recurrence_of or [])}
        return self.write(new_record("capa.deviation", who, "classified", subject=subject("deviation", dev_id),
                                     reason=reason, data=data, tz=self.cfg.tz,
                                     links=[{"rel": "recurrence-of", "ref": r} for r in recurrence_of or []] or None))

    # -------------------------------------------------------- investigation
    def investigate(self, dev_id: str, *, whys: list[str], factors: list[str], root_cause: str, root_category: str,
                    impact: str | None = None, evidence: list[str] | None = None, draft: bool = False,
                    reason: str | None = None) -> dict:
        dev = self._dev(dev_id)
        if dev["state"] == "closed":
            raise Blocked(f"{dev_id} is closed")
        if not 1 <= len(whys) <= 5:
            raise CapaError("give 1 to 5 --why entries")
        self._check_choice(root_category, sources.CATEGORIES, "root category")
        parsed = []
        for factor in factors:
            cat, _, text = factor.partition(":")
            self._check_choice(cat, FACTOR_CATEGORIES, "factor category")
            if not text.strip():
                raise CapaError("factor needs CATEGORY:TEXT")
            parsed.append({"category": cat, "text": text.strip()})
        if draft:
            who, verb = self.caller_actor(), "drafted"
        else:
            who = self.require_human("investigation.record")
            recorded = self.store.one("SELECT 1 FROM investigations WHERE dev_id = ? AND status = 'recorded'", dev_id)
            verb = "revised" if recorded else "recorded"
        data = {"dev_id": dev_id, "whys": whys, "factors": parsed, "root_cause": root_cause,
                "root_category": root_category}
        if impact:
            data["impact"] = impact
        return self.write(new_record("capa.investigation", who, verb, subject=subject("deviation", dev_id),
                                     reason=reason, data=data, tz=self.cfg.tz,
                                     links=[{"rel": "evidence", "ref": e} for e in evidence or []] or None))

    # --------------------------------------------------------------- actions
    def _rel_target(self, target: str) -> tuple[str, Path]:
        root = self.cfg.project_root.resolve()
        path = Path(target)
        full = (path if path.is_absolute() else root / path).resolve()
        try:
            rel = full.relative_to(root)
        except ValueError as error:
            raise CapaError(f"target {target} is outside the project root {root}") from error
        return rel.as_posix(), full

    def _snapshot_dir(self) -> Path:
        return self.cfg.db_path.parent / "snapshots"

    def plan(self, dev_id: str, *, kind: str, target: str, description: str, window_sessions: int | None = None,
             window_days: int | None = None, max_recurrences: int = 0, match_category: str | None = None,
             match_source: str | None = None) -> dict:
        dev = self._dev(dev_id)
        if dev["state"] == "closed":
            raise Blocked(f"{dev_id} is closed")
        self._check_choice(kind, KINDS, "kind")
        rel, full = self._rel_target(target)
        before = file_hash(full)
        if before and full.stat().st_size <= 1_048_576:
            snap = self._snapshot_dir() / before.split(":", 1)[1]
            snap.parent.mkdir(parents=True, exist_ok=True)
            snap.write_bytes(full.read_bytes())
        window = {k: v for k, v in (("sessions", window_sessions), ("days", window_days)) if v}
        if not window:
            window = {"sessions": 20}
        match = {"category": match_category or dev["category"]}
        if match_source:
            match["source_type"] = match_source
        criterion = {"type": "no-recurrence", "match": match, "window": window, "max": int(max_recurrences)}
        action_id = f"CAPA-{int(dev_id.split('-')[1]):04d}-{self.store.next_action_seq(dev_id)}"
        target_obj = {"path": rel, "before_sha256": before, "after_sha256": None}
        if self.cfg.project_id:
            target_obj["project"] = self.cfg.project_id
        return self.write(new_record(
            "capa.action", self.caller_actor(), "planned", subject=subject("agent-control", rel, sha256=before),
            before={"sha256": before} if before else None, tz=self.cfg.tz,
            links=[{"rel": "deviation", "ref": dev["dev_id"]}],
            data={"action_id": action_id, "dev_id": dev_id, "kind": kind, "description": description,
                  "target": target_obj, "effectiveness_criterion": criterion}))

    def implement(self, action_id: str) -> dict:
        act = self._act(action_id)
        if act["state"] == "cancelled" or self._dev(act["dev_id"])["state"] == "closed":
            raise Blocked(f"{action_id} is {act['state']}")
        _, full = self._rel_target(act["path"])
        after = file_hash(full)
        if after == act["before_sha256"]:
            raise Blocked(f"{act['path']} is unchanged since the action was planned")
        diff_text = None
        if act["before_sha256"] and after:
            snap = self._snapshot_dir() / act["before_sha256"].split(":", 1)[1]
            if snap.exists():
                old = snap.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
                new = full.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
                diff_text = "".join(difflib.unified_diff(old, new, f"a/{act['path']}", f"b/{act['path']}"))
        data = {"action_id": action_id, "dev_id": act["dev_id"],
                "target": {"path": act["path"], "before_sha256": act["before_sha256"], "after_sha256": after},
                "effectiveness_criterion": json.loads(act["criterion"])}
        if self.cfg.project_id:
            data["target"]["project"] = self.cfg.project_id
        if diff_text is not None:
            data["diff_sha256"] = bytes_hash(diff_text.encode("utf-8"))
            data["diff_excerpt"] = diff_text[:1500]
        return self.write(new_record(
            "capa.action", self.caller_actor(), "implemented", meaning="authored", tz=self.cfg.tz,
            subject=subject("agent-control", act["path"], sha256=after),
            before={"sha256": act["before_sha256"]} if act["before_sha256"] else None,
            after={"sha256": after} if after else None,
            links=[{"rel": "deviation", "ref": act["dev_id"]}, {"rel": "implements", "ref": act["planned_record"]}],
            data=data))

    def approve(self, action_id: str, *, reason: str) -> dict:
        who = self.require_human("action.approve")
        act = self._act(action_id)
        if act["state"] != "implemented":
            raise Blocked(f"{action_id} is {act['state']}; only an implemented action can be approved")
        if act["implementer"] == who["id"] and not self.cfg.allow_self_approval:
            raise Blocked(f"{who['id']} implemented {action_id}; approval needs another person "
                          "(set [approval] allow_self_approval = true to permit it)")
        _, full = self._rel_target(act["path"])
        if file_hash(full) != act["after_sha256"]:
            raise Blocked(f"{act['path']} changed after implementation; run 'action implement' again first")
        data = {"action_id": action_id, "dev_id": act["dev_id"], "approves": act["implemented_record"],
                "approves_sha256": act["implemented_hash"],
                "target": {"path": act["path"], "before_sha256": act["before_sha256"],
                           "after_sha256": act["after_sha256"]},
                "effectiveness_criterion": json.loads(act["criterion"])}
        return self.write(new_record(
            "capa.action", who, "approved", meaning="approved", reason=reason, tz=self.cfg.tz,
            subject=subject("record", act["implemented_record"], sha256=act["implemented_hash"]),
            links=[{"rel": "deviation", "ref": act["dev_id"]}, {"rel": "approves", "ref": act["implemented_record"]}],
            data=data))

    def cancel(self, action_id: str, *, reason: str) -> dict:
        who = self.require_human("action.cancel")
        act = self._act(action_id)
        if act["state"] == "cancelled":
            raise Blocked(f"{action_id} is already cancelled")
        return self.write(new_record("capa.action", who, "cancelled", reason=reason, tz=self.cfg.tz,
                                     subject=subject("agent-control", act["path"]),
                                     data={"action_id": action_id, "dev_id": act["dev_id"],
                                           "target": {"path": act["path"], "before_sha256": act["before_sha256"],
                                                      "after_sha256": act["after_sha256"]},
                                           "effectiveness_criterion": json.loads(act["criterion"])}))

    def verify(self, action_id: str | None = None) -> list[dict]:
        rows = [self._act(action_id)] if action_id else self.store.q(
            "SELECT * FROM actions WHERE state IN ('implemented', 'approved') ORDER BY action_id")
        out = []
        for act in rows:
            _, full = self._rel_target(act["path"])
            current = file_hash(full)
            expected = act["after_sha256"]
            status = ("not-implemented" if not expected else "ok" if current == expected
                      else "missing" if current is None else "changed-since-approval")
            out.append({"action_id": act["action_id"], "path": act["path"], "expected": expected,
                        "current": current, "status": status})
        return out

    # -------------------------------------------------------------- approval
    def approval(self, act, records: list[dict] | None = None) -> dict:
        """How (and whether) the implemented change was approved. See aqt-spec spec §6.3 and the aqt-signoff Python API."""
        if act["state"] in ("planned", "cancelled") or not act["implemented_hash"]:
            return {"approved": False, "status": "not-implemented"}
        if act["approved_record"]:
            return {"approved": True, "status": "recorded-unsigned", "at": act["approved_at"], "by": act["approver"]}
        wanted = act["implemented_hash"]
        sigs = []
        for r in records if records is not None else self.evidence():
            if r.get("type") != "signoff.signature":
                continue
            data = r.get("data") or {}
            sig = data.get("signature") or {}
            statement = sig.get("statement") or data.get("statement") or {}
            hashes = {(r.get("subject") or {}).get("sha256"), (statement.get("subject") or {}).get("sha256")}
            meaning = statement.get("meaning") or data.get("meaning") or r.get("meaning")
            signer = (statement.get("signer") or {}).get("id") or (r.get("actor") or {}).get("id")
            if wanted in hashes and meaning == "approved":
                if signer == act["implementer"] and not self.cfg.allow_self_approval:
                    continue
                sigs.append((r["time"], signer, r["id"]))
        if not sigs:
            return {"approved": False, "status": "awaiting-approval"}
        sigs.sort()
        at, by, rec = sigs[0]
        try:
            import aqt_signoff  # optional
        except ImportError:
            return {"approved": True, "status": "signed-unverified", "at": at, "by": by, "record": rec,
                    "note": "aqt-signoff not installed; signature not verified"}
        try:
            ok = bool(aqt_signoff.is_approved(wanted, meaning="approved",
                                              sources=self.readable_paths()))
        except Exception as error:  # noqa: BLE001 - report, never pretend
            return {"approved": True, "status": "signed-unverified", "at": at, "by": by, "record": rec,
                    "note": f"aqt-signoff verification failed: {error}"}
        if ok:
            return {"approved": True, "status": "signed-verified", "at": at, "by": by, "record": rec}
        return {"approved": False, "status": "signature-not-valid", "by": by, "record": rec}

    # ---------------------------------------------------------- effectiveness
    def criterion(self, act) -> dict:
        crit = json.loads(act["criterion"])
        for ext in self.store.extensions(act["action_id"]):
            crit["window"] = ext["window"]
        return crit

    def evaluate(self, action_id: str, *, records: list[dict] | None = None, now=None) -> dict:
        act = self._act(action_id)
        records = records if records is not None else self.evidence()
        now = now or utc_now()
        crit = self.criterion(act)
        appr = self.approval(act, records)
        result = {"action_id": action_id, "dev_id": act["dev_id"], "criterion": crit, "approval": appr["status"]}
        if not appr["approved"]:
            return result | {"result": "pending", "reasons": [f"not approved ({appr['status']})"],
                             "counts": {}, "target_hash_ok": None}
        start = parse_time(appr["at"])
        match = crit.get("match") or {}

        def matches(category, source_type):
            return ((not match.get("category") or match["category"] == category)
                    and type_matches(match.get("source_type"), source_type))

        recurrences = [r["dev_id"] for r in self.store.q("SELECT * FROM deviations WHERE dev_id != ?", act["dev_id"])
                       if parse_time(r["occurred_at"]) > start and matches(r["category"], r["source_type"])]
        undecided = [c["candidate_id"] for c in self.store.q("SELECT * FROM candidates WHERE status = 'open'")
                     if parse_time(c["time"]) > start and matches(c["category"], c["source_type"])]
        later = [r for r in records if r.get("time") and parse_time(r["time"]) > start]
        sessions = {((r.get("actor") or {}).get("agent") or {}).get("session") for r in later} - {None}
        gaps = [r["id"] for r in later if r.get("type") == "trail.gap"]
        days = (now - start).days
        _, full = self._rel_target(act["path"])
        target_ok = file_hash(full) == act["after_sha256"]
        window = crit.get("window") or {}
        counts = {"recurrences": len(recurrences), "undecided": len(undecided), "sessions": len(sessions),
                  "days": days, "gaps": len(gaps)}
        reasons = []
        if len(recurrences) > int(crit.get("max", 0)):
            outcome = "not-effective"
            reasons.append(f"{len(recurrences)} recurrence(s): {', '.join(recurrences)}")
        else:
            if not target_ok:
                reasons.append(f"{act['path']} changed since approval")
            if undecided:
                reasons.append(f"{len(undecided)} undecided matching candidate(s): {', '.join(undecided)}")
            if gaps:
                reasons.append(f"{len(gaps)} trail gap(s) in the window")
            if window.get("sessions") and len(sessions) < window["sessions"]:
                reasons.append(f"{len(sessions)}/{window['sessions']} agent sessions observed")
            if window.get("days") and days < window["days"]:
                reasons.append(f"{days}/{window['days']} days elapsed")
            outcome = "pending" if reasons else "effective"
            if outcome == "effective":
                reasons.append("no recurrence in a complete window")
        return result | {"result": outcome, "reasons": reasons, "counts": counts, "start": fmt_time(start),
                         "window": window, "target_hash_ok": target_ok, "recurrences": recurrences,
                         "undecided": undecided}

    def effectiveness(self, target: str | None = None, *, now=None, record: bool = True) -> list[dict]:
        """Evaluate running checks (after a fresh scan); record results that changed."""
        self.scan()
        if target and target.startswith("CAPA-"):
            rows = [self._act(target)]
        else:
            sql = ("SELECT a.* FROM actions a JOIN deviations d ON d.dev_id = a.dev_id WHERE a.state != 'cancelled'"
                   " AND d.state != 'closed'" + (" AND a.dev_id = ?" if target else "") + " ORDER BY a.dev_id, a.seq")
            rows = self.store.q(sql, *([target] if target else []))
        records = self.evidence()
        results = []
        for act in rows:
            ev = self.evaluate(act["action_id"], records=records, now=now)
            if record:
                self._record_evaluation(ev)
            results.append(ev)
        return results

    def _record_evaluation(self, ev: dict) -> None:
        last = self.store.latest_evaluation(ev["action_id"])
        if last and last.get("result") == ev["result"] and last.get("reasons") == ev["reasons"]:
            return
        data = {k: ev[k] for k in ("action_id", "dev_id", "result", "reasons", "counts", "approval")}
        for key in ("window", "start", "target_hash_ok", "recurrences", "undecided"):
            if key in ev and ev[key] is not None:
                data[key] = ev[key]
        self.write(new_record("capa.effectiveness", SERVICE, "evaluated", tz=self.cfg.tz,
                              subject=subject("capa-action", ev["action_id"]),
                              links=[{"rel": "deviation", "ref": ev["dev_id"]}], data=data))

    def extend(self, action_id: str, *, reason: str, window_sessions: int | None = None,
               window_days: int | None = None) -> dict:
        who = self.require_human("effectiveness.extend")
        act = self._act(action_id)
        window = {k: v for k, v in (("sessions", window_sessions), ("days", window_days)) if v}
        if not window:
            raise CapaError("give --window-sessions and/or --window-days")
        return self.write(new_record("capa.effectiveness", who, "extended", reason=reason, tz=self.cfg.tz,
                                     subject=subject("capa-action", action_id),
                                     links=[{"rel": "deviation", "ref": act["dev_id"]}],
                                     data={"action_id": action_id, "dev_id": act["dev_id"], "window": window,
                                           "previous_window": self.criterion(act).get("window")}))

    # ---------------------------------------------------------------- closure
    def close(self, dev_id: str, *, reason: str, no_action: bool = False, now=None) -> dict:
        who = self.require_human("deviation.close")
        dev = self._dev(dev_id)
        if dev["state"] == "closed":
            raise Blocked(f"{dev_id} is already closed")
        if not self.store.one("SELECT 1 FROM investigations WHERE dev_id = ? AND status = 'recorded'", dev_id):
            raise Blocked(f"{dev_id} has no recorded investigation")
        acts = self.store.q("SELECT * FROM actions WHERE dev_id = ? AND state != 'cancelled' ORDER BY seq", dev_id)
        if no_action:
            if dev["severity"] == "critical":
                raise Blocked("a critical deviation needs a CAPA; --no-action is not allowed")
            if acts:
                raise Blocked(f"{dev_id} has actions; close it on their effectiveness instead")
            basis, summary = "no-action", []
        else:
            if not acts:
                raise Blocked(f"{dev_id} has no actions; plan one, or use --no-action with a justification")
            evals = self.effectiveness(dev_id, now=now)
            summary = [{"action_id": e["action_id"], "result": e["result"]} for e in evals]
            undecided = [e for e in evals if e["result"] == "pending"]
            if undecided:
                raise Blocked("effectiveness still pending: " + "; ".join(
                    f"{e['action_id']}: {', '.join(e['reasons'])}" for e in undecided))
            if evals[-1]["result"] != "effective":
                raise Blocked(f"the latest action {evals[-1]['action_id']} is not effective; plan a further action")
            basis = "effective"
        return self.write(new_record("capa.closure", who, "closed", meaning="approved", reason=reason, tz=self.cfg.tz,
                                     subject=subject("deviation", dev_id),
                                     links=[{"rel": "action", "ref": s["action_id"]} for s in summary] or None,
                                     data={"dev_id": dev_id, "basis": basis, "actions": summary}))

    # ------------------------------------------------------------------ views
    def list(self, *, open_only: bool = False, overdue_only: bool = False, now=None) -> list[dict]:
        now = now or utc_now()
        rows = [dict(r) for r in self.store.q("SELECT * FROM deviations ORDER BY num")]
        out = []
        for r in rows:
            investigated = self.store.one("SELECT 1 FROM investigations WHERE dev_id = ? AND status = 'recorded'",
                                          r["dev_id"]) is not None
            r["overdue"] = bool(r["state"] != "closed" and not investigated and r["due"]
                                and parse_time(r["due"]) < now)
            if open_only and r["state"] == "closed":
                continue
            if overdue_only and not r["overdue"]:
                continue
            out.append(r)
        return out

    def show(self, dev_id: str) -> dict:
        dev = dict(self._dev(dev_id))
        records = self.evidence()
        acts = []
        for act in self.store.q("SELECT * FROM actions WHERE dev_id = ? ORDER BY seq", dev_id):
            item = {k: act[k] for k in ("action_id", "kind", "description", "path", "state", "before_sha256",
                                        "after_sha256")}
            item["criterion"] = self.criterion(act)
            item["approval"] = self.approval(act, records)
            item["verify"] = self.verify(act["action_id"])[0]["status"] if act["after_sha256"] else "not-implemented"
            item["last_evaluation"] = self.store.latest_evaluation(act["action_id"])
            acts.append(item)
        inv = self.store.one("SELECT json FROM investigations WHERE dev_id = ? ORDER BY "
                             "CASE status WHEN 'recorded' THEN 0 ELSE 1 END, time DESC LIMIT 1", dev_id)
        timeline = [{"time": r["time"], "type": r["type"], "action": r["action"], "id": r["id"],
                     "actor": json.loads(r["json"])["actor"]["id"], "reason": json.loads(r["json"]).get("reason")}
                    for r in self.store.q("SELECT * FROM records WHERE dev_id = ? ORDER BY time, id", dev_id)]
        links = [dict(r) for r in self.store.q("SELECT rel, ref FROM links WHERE dev_id = ?", dev_id)]
        opened = self.store.one("SELECT json FROM records WHERE dev_id = ? AND type = 'capa.deviation' AND action IN"
                                " ('opened', 'accepted')", dev_id)
        similar_ = json.loads(opened["json"])["data"].get("similar", []) if opened else []
        return {"deviation": dev, "links": links, "similar": similar_,
                "investigation": json.loads(inv["json"]) if inv else None, "actions": acts, "timeline": timeline}

    def rebuild(self) -> int:
        return self.store.rebuild(self.readable_paths())
