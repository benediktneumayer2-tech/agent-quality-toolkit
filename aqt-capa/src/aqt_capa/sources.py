"""Source rules: evidence records and git history -> deviation candidates.

Field names follow the aqt-spec record-type registry (spec §11). Each candidate has a deterministic key
(source record id, finding index or ``git:<sha>``) so a repeated scan never
duplicates it. A candidate is only a suggestion; a human decides.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from aqt_evidence import Text

from .util import excerpt, fmt_time, parse_time

SEVERITIES = ("minor", "major", "critical")
CATEGORIES = ("instructions", "missing-context", "tool", "model", "task-specification", "environment",
              "security", "unclassified")
RULES = ("quarantine-held", "quarantine-threat", "receipt-failed", "finish-not-go", "review-fail",
         "refused", "trail-review-finding", "git-revert", "action-outcome-unknown")

_FINDING_SEVERITY = {"critical": "critical", "high": "major", "major": "major"}
UNKNOWN_SOURCE = Text("capa.candidate.unknown_source", "unknown source")


@dataclass
class Candidate:
    key: str
    rule: str
    source_type: str
    source_ref: str
    time: str
    title: str
    severity: str
    category: str
    session: str | None = None

    @property
    def candidate_id(self) -> str:
        return "C-" + hashlib.sha256(self.key.encode()).hexdigest()[:8]

    def as_dict(self) -> dict:
        value = {k: v for k, v in self.__dict__.items() if v is not None}
        value["candidate_id"] = self.candidate_id
        return value


def _session(record: dict) -> str | None:
    return ((record.get("actor") or {}).get("agent") or {}).get("session")


def _cand(record: dict, rule: str, title: str, severity: str, category: str, *, key: str | None = None) -> Candidate:
    return Candidate(key=key or record["id"], rule=rule, source_type=record["type"], source_ref=record["id"],
                     time=record["time"], title=_excerpt(title, 160), severity=severity, category=category,
                     session=_session(record))


def _excerpt(title: str, limit: int) -> str:
    """``excerpt``, keeping the message code of a title that fits as it is."""
    short = excerpt(title, limit)
    return title if short == title else short


def from_records(records: Iterable[dict], disabled: Iterable[str] = ()) -> list[Candidate]:
    """Apply the evidence rules. Needs the whole list: some rules look at later records."""
    records = [r for r in records if isinstance(r, dict) and r.get("type") and r.get("id") and r.get("time")]
    off = set(disabled)
    finished_receipts = {rid for r in records if r["type"] == "change.finish"
                         for rid in (r.get("data") or {}).get("receipts", [])}
    declared_cases = {(r.get("data") or {}).get("case_id") for r in records if r["type"] == "quarantine.threat.declared"}
    out: list[Candidate] = []
    for r in records:
        t, d = r["type"], r.get("data") or {}
        if t == "quarantine.held" and "quarantine-held" not in off and d.get("case_id") not in declared_cases:
            src = (d.get("source") or {})
            out.append(_cand(r, "quarantine-held", Text(
                "capa.candidate.quarantine_held", "Input held in quarantine: case {case} ({source}, band {band})",
                case=d.get("case_id"), source=src.get("domain") or src.get("ref") or UNKNOWN_SOURCE,
                band=d.get("band")), "minor", "security"))
        elif t == "quarantine.threat.declared" and "quarantine-threat" not in off:
            src = (d.get("source") or {})
            out.append(_cand(r, "quarantine-threat", Text(
                "capa.candidate.quarantine_threat", "Threat declared: case {case} ({source})", case=d.get("case_id"),
                source=src.get("domain") or src.get("ref") or UNKNOWN_SOURCE), "major", "security"))
        elif t == "change.receipt" and "receipt-failed" not in off and (
                d.get("passed") is False or (isinstance(d.get("exit_code"), int) and d["exit_code"] != 0)):
            command = " ".join(str(a) for a in d.get("argv", [])) or "command"
            hidden = r["id"] in finished_receipts
            title = Text("capa.candidate.receipt_failed_finish", "Failed verification receipt: {command} (exit "
                         "{exit}) — referenced by a finish", command=command, exit=d.get("exit_code")) if hidden else \
                Text("capa.candidate.receipt_failed", "Failed verification receipt: {command} (exit {exit})",
                     command=command, exit=d.get("exit_code"))
            out.append(_cand(r, "receipt-failed", title, "major" if hidden else "minor", "tool"))
        elif t == "change.finish" and "finish-not-go" not in off and (
                d.get("gate") not in (None, "GO") or d.get("waivers")):
            out.append(_cand(r, "finish-not-go", Text(
                "capa.candidate.finish_not_go", "Change finished with gate {gate} and {n} waiver(s): {plan}",
                gate=d.get("gate"), n=len(d.get("waivers") or []), plan=d.get("plan_ref", "")),
                "major" if d.get("gate") == "NO-GO" else "minor", "task-specification"))
        elif t == "change.review" and "review-fail" not in off and d.get("verdict") == "FAIL":
            out.append(_cand(r, "review-fail", Text(
                "capa.candidate.review_fail", "Review verdict FAIL ({independence}, {n} finding(s))",
                independence=d.get("independence", "unknown independence"), n=len(d.get("findings") or [])),
                "major", "model"))
        elif t.endswith(".refused") and "refused" not in off:
            who = (r.get("actor") or {}).get("id", "?")
            out.append(_cand(r, "refused", Text(
                "capa.candidate.refused", "Refused attempt: {action} by {who} ({code})",
                action=d.get("attempted_action", r.get("action")), who=who, code=d.get("reason_code", "refused")),
                "minor", "instructions"))
        elif t == "trail.review" and "trail-review-finding" not in off:
            for index, finding in enumerate(d.get("findings") or []):
                if isinstance(finding, dict) and finding.get("disposition") == "deviation":
                    out.append(_cand(r, "trail-review-finding", Text(
                                     "capa.candidate.trail_review_finding", "Audit-trail review finding: {query} ({n} "
                                     "record(s))", query=finding.get("query", "finding"),
                                     n=len(finding.get("record_ids") or [])),
                                     _FINDING_SEVERITY.get(str(finding.get("severity", "")).lower(), "minor"),
                                     "unclassified", key=f"{r['id']}#{index}"))
        elif t == "signoff.action.outcome" and "action-outcome-unknown" not in off and d.get("outcome") == "unknown":
            out.append(_cand(r, "action-outcome-unknown", Text(
                "capa.candidate.action_outcome_unknown", "Approved action {action} ended with unknown outcome",
                action=d.get("action_id")), "minor", "environment"))
    return out


_REVERTS = re.compile(r"This reverts commit ([0-9a-f]{7,40})")


def from_git(repo: Path, agent_patterns: Iterable[str] = ()) -> list[Candidate]:
    """Reverted commits. With ``agent_patterns`` only reverts of commits whose message matches one count."""
    try:
        out = subprocess.run(["git", "-C", str(repo), "log", "--format=%H%x00%s%x00%b%x00%cI%x1e"],
                             capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return []
    messages: dict[str, str] = {}
    entries = []
    for chunk in out.split("\x1e"):
        parts = chunk.strip("\n").split("\x00")
        if len(parts) < 4:
            continue
        sha, subject, body, when = parts[0].strip(), parts[1], parts[2], parts[3].strip()
        messages[sha] = subject + "\n" + body
        entries.append((sha, subject, body, when))
    patterns = [re.compile(p) for p in agent_patterns]
    result = []
    for sha, subject, body, when in entries:
        match = _REVERTS.search(body) or _REVERTS.search(subject)
        if not match and not subject.startswith('Revert "'):
            continue
        reverted = match.group(1) if match else None
        if patterns:
            original = next((m for s, m in messages.items() if reverted and s.startswith(reverted)), "")
            if not any(p.search(original) for p in patterns):
                continue
        result.append(Candidate(key=f"git:{sha}", rule="git-revert", source_type="git.revert", source_ref=f"git:{sha}",
                                time=fmt_time(parse_time(when)),
                                title=_excerpt(Text("capa.candidate.git_revert", "Reverted commit: {subject}",
                                                    subject=subject), 160),
                                severity="major", category="unclassified"))
    return result
