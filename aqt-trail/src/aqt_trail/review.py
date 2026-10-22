"""Audit-trail review: risk queries, a worksheet, and a signed ``trail.review``.

A review covers a scope (a seq range of one log, bound to the head hash at its
end). Queries flag records a reviewer should look at; the reviewer gives each
finding a disposition (``ok`` | ``explained`` | ``deviation``)
and signs. Signing is refused when the reviewer was an actor in the scope, is
not a human identity, or the trail changed since the worksheet was made.
"""

from __future__ import annotations

import json
import os
import tomllib
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from aqt_evidence import Signer, actor, bytes_hash, content_hash, new_record, record_hash, subject, utc_now

from .signers import SignerInfo, build_statement, sign_statement

QUERIES = ("self_approval", "missing_reason", "attribution_mismatch", "gaps", "out_of_hours",
           "repeated_failures", "time_anomalies", "actor_changes", "invalidated_signatures", "unanchored_head")
DISPOSITIONS = ("ok", "explained", "deviation")
APPROVALS = {"approved", "released", "verified", "reviewed"}
DECISION_ACTIONS = {"approve", "approved", "release", "released", "reject", "rejected", "waive", "waived",
                    "sign", "signed", "declare-threat", "trust-source", "accept", "dismiss", "close", "resolve"}
# Types whose actors do not count as "involved" for reviewer independence.
NOT_ACTIVITY = {"trail.refused", "trail.review", "trail.gap", "trail.anchor"}


class ReviewRefused(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


def _time(value) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _seq(record) -> int:
    return record.get("chain", {}).get("seq", -1)


def _is_decision(record) -> bool:
    return "meaning" in record or str(record.get("action", "")).split(".")[-1] in DECISION_ACTIONS


def _signer_id(record) -> str:
    statement = ((record.get("data") or {}).get("signature") or {}).get("statement") or {}
    return (statement.get("signer") or {}).get("id") or record["actor"]["id"]


def _failed(record) -> bool:
    data = record.get("data") if isinstance(record.get("data"), dict) else {}
    if str(record.get("type", "")).endswith(".refused") or record.get("action") == "refused":
        return True
    if data.get("outcome") in ("failed", "refused", "unknown") or data.get("passed") is False:
        return True
    return type(data.get("exit_code")) is int and data["exit_code"] != 0


def _finding(query, severity, records, explanation) -> dict:
    return {"query": query, "severity": severity, "record_ids": [r["id"] for r in records],
            "explanation": explanation}


# -- queries ---------------------------------------------------------------------
def q_self_approval(scope, everything, params):
    by_id = {r["id"]: r for r in everything}
    by_subject = defaultdict(list)
    for record in everything:
        ref = (record.get("subject") or {}).get("ref")
        if ref:
            by_subject[ref].append(record)
    findings = []
    for record in scope:
        if record.get("meaning") not in APPROVALS:
            continue
        approver = _signer_id(record)
        authors = [by_id[link["ref"]] for link in record.get("links", []) if link.get("ref") in by_id]
        ref = (record.get("subject") or {}).get("ref")
        authors += [r for r in by_subject.get(ref, []) if _seq(r) < _seq(record) and r.get("meaning") not in APPROVALS]
        same = [r for r in authors if r["actor"]["id"] == approver]
        if same:
            findings.append(_finding("self_approval", "major", [record, *same[:5]],
                                     f"{approver} gave '{record['meaning']}' to work they also performed"))
    return findings


def q_missing_reason(scope, everything, params):
    hits = [r for r in scope if r["actor"].get("kind") == "human" and _is_decision(r) and not r.get("reason")]
    return [_finding("missing_reason", "major", hits, "human decisions without a recorded reason")] if hits else []


def q_attribution_mismatch(scope, everything, params):
    findings = []
    for record in scope:
        observed = record.get("observed") or {}
        if observed.get("via") != "socket":
            continue
        kind = record["actor"].get("kind")
        if kind == "human" and observed.get("harness"):
            findings.append(_finding("attribution_mismatch", "major", [record],
                                     f"claims human {record['actor']['id']} but was sent from inside "
                                     f"{observed['harness']} ({' <- '.join(observed.get('process_chain', [])[:6])})"))
        elif kind == "agent" and not observed.get("harness") and record.get("type") != "trail.import":
            findings.append(_finding("attribution_mismatch", "minor", [record],
                                     "claims an agent session but no agent harness was observed"))
    return findings


def q_gaps(scope, everything, params):
    findings = []
    for record in scope:
        if record.get("type") == "trail.gap":
            data = record.get("data", {})
            findings.append(_finding("gaps", "major", [record],
                                     f"{data.get('count')} record(s) spooled between {data.get('first_time')} and "
                                     f"{data.get('last_time')}; their attribution was not observed"))
        elif record.get("action") == "log.repaired":
            findings.append(_finding("gaps", "minor", [record], "an incomplete last line was removed at start"))
    spooled = [r for r in scope if (r.get("observed") or {}).get("via") == "spool"]
    if spooled:
        findings.append(_finding("gaps", "minor", spooled, "records delivered through the spool (claimed, not observed)"))
    starts = [r for r in everything if r.get("type") == "trail.event" and r.get("action") in ("service.start", "service.stop")]
    in_scope = {r["id"] for r in scope}
    for previous, current in zip(starts, starts[1:]):
        if current["id"] not in in_scope or current.get("action") != "service.start":
            continue
        if previous.get("action") == "service.start":
            findings.append(_finding("gaps", "minor", [previous, current],
                                     "the writer stopped without a stop record (crash or kill)"))
        else:
            findings.append(_finding("gaps", "info", [previous, current],
                                     f"writer downtime from {previous['time']} to {current['time']}"))
    return findings


def q_out_of_hours(scope, everything, params):
    zone = ZoneInfo(params.get("timezone", "UTC"))
    start, end = (datetime.strptime(params.get(k), "%H:%M").time() for k in ("work_start", "work_end"))
    days = set(params.get("workdays", [1, 2, 3, 4, 5]))
    hits = []
    for record in scope:
        if record["actor"].get("kind") != "human":
            continue
        moment = _time(record["time"])
        local = moment.astimezone(zone) if moment else None
        if local and (local.isoweekday() not in days or not start <= local.time() <= end):
            hits.append(record)
    return [_finding("out_of_hours", "minor", hits, f"human actions outside {params.get('work_start')}–"
                     f"{params.get('work_end')} on workdays ({params.get('timezone', 'UTC')})")] if hits else []


def q_repeated_failures(scope, everything, params):
    limit, window = int(params.get("repeated_failures", 3)), timedelta(minutes=int(params.get("failure_window_min", 60)))
    groups = defaultdict(list)
    for record in scope:
        if _failed(record):
            data = record.get("data") if isinstance(record.get("data"), dict) else {}
            key = (record["actor"]["id"], data.get("attempted_action") or record.get("action"),
                   (record.get("subject") or {}).get("ref"))
            groups[key].append(record)
    findings = []
    for (who, what, ref), items in groups.items():
        for index in range(len(items) - limit + 1):
            first, last = _time(items[index]["time"]), _time(items[index + limit - 1]["time"])
            if first and last and last - first <= window:
                findings.append(_finding("repeated_failures", "major", items,
                                         f"{len(items)} failed or refused '{what}' attempts by {who}"))
                break
    return findings


def q_time_anomalies(scope, everything, params):
    skew = int(params.get("skew_ms", 5000))
    findings = [_finding("time_anomalies", "major", [r], f"writer clock jump ({r.get('data', {}).get('direction')})")
                for r in scope if r.get("action") == "clock.jump"]
    skewed = []
    for record in scope:
        observed = record.get("observed") or {}
        client, service = _time(observed.get("client_time")), _time(record["time"])
        if observed.get("via") == "socket" and client and service and abs((service - client).total_seconds()) * 1000 > skew:
            skewed.append(record)
    if skewed:
        findings.append(_finding("time_anomalies", "minor", skewed, f"client time differs from writer time by more than {skew} ms"))
    previous = None
    for record in scope:
        if previous is not None and record["time"] < previous:
            findings.append(_finding("time_anomalies", "major", [record], "writer time went backwards"))
        previous = record["time"]
    return findings


def q_actor_changes(scope, everything, params):
    window = timedelta(minutes=int(params.get("actor_change_window_min", 60)))
    by_subject = defaultdict(list)
    for record in scope:
        sub = record.get("subject") or {}
        if sub.get("ref") and sub.get("kind") not in ("agent-session", "tool-call", "trail-head") \
                and record.get("type") not in NOT_ACTIVITY:
            by_subject[sub["ref"]].append(record)
    findings = []
    for ref, items in by_subject.items():
        actors = {r["actor"]["id"] for r in items}
        first, last = _time(items[0]["time"]), _time(items[-1]["time"])
        if len(actors) > 1 and first and last and last - first <= window:
            findings.append(_finding("actor_changes", "info", items,
                                     f"{ref} was acted on by {len(actors)} actors: {', '.join(sorted(actors))}"))
    return findings


def q_invalidated_signatures(scope, everything, params):
    hits = [r for r in scope if r.get("type") == "signoff.invalidation"]
    return [_finding("invalidated_signatures", "major", hits, "signatures were invalidated")] if hits else []


def q_unanchored_head(scope, everything, params):
    if not everything:
        return []
    anchors = [r for r in everything if r.get("type") == "trail.anchor"]
    last = anchors[-1] if anchors else None
    after = [r for r in everything if last is None or _seq(r) > _seq(last)]
    if not after:
        return []
    since = _time(last["time"]) if last else _time(everything[0]["time"])
    age = _time(everything[-1]["time"]) - since if since else timedelta(0)
    if age > timedelta(hours=int(params.get("unanchored_hours", 24))) or last is None:
        what = "no anchor at all" if last is None else f"last anchor {last['time']}"
        return [_finding("unanchored_head", "minor", after[-1:],
                         f"{len(after)} record(s) not covered by an anchor ({what})")]
    return []


QUERY_FUNCTIONS = {name: globals()[f"q_{name}"] for name in QUERIES}


# -- profiles and worksheets -----------------------------------------------------------
def load_profile(spec: str | None, defaults: dict) -> dict:
    """The built-in ``default`` profile, or a TOML file with ``name``, ``queries`` and ``[params]``."""
    profile = {"name": "default", "queries": list(QUERIES), "params": dict(defaults)}
    if spec and spec != "default":
        path = Path(spec)
        with open(path, "rb") as handle:
            loaded = tomllib.load(handle)
        profile["name"] = loaded.get("name", path.stem)
        profile["queries"] = [q for q in loaded.get("queries", QUERIES) if q in QUERY_FUNCTIONS]
        profile["params"].update(loaded.get("params", {}))
    return profile


def run_review(records: list[dict], profile: dict, *, log_id: str, since: str | None = None,
               until: str | None = None, trail: str | None = None) -> dict:
    scope = [r for r in records if (not since or r["time"] >= since) and (not until or r["time"] <= until)]
    if not scope:
        raise ValueError("no records in the selected period")
    findings = []
    for name in profile["queries"]:
        findings.extend(QUERY_FUNCTIONS[name](scope, records, profile["params"]))
    for number, finding in enumerate(findings, 1):
        finding["id"] = f"F{number}"
    actors = sorted({r["actor"]["id"] for r in scope
                     if r["actor"].get("kind") != "service" and r.get("type") not in NOT_ACTIVITY})
    last = scope[-1]
    return {
        "aqt_worksheet": "0.1", "id": f"rv_{os.urandom(6).hex()}", "log_id": log_id, "trail": trail,
        "generated_at": utc_now(),
        "scope": {"from_seq": _seq(scope[0]), "to_seq": _seq(last), "since": since, "until": until,
                  "count": len(scope), "head": record_hash(last), "head_id": last["id"]},
        "profile": {"name": profile["name"], "sha256": bytes_hash(json.dumps(profile, sort_keys=True).encode()), "params": profile["params"]},
        "actors_reviewed": actors, "findings": findings,
    }


def worksheet_markdown(sheet: dict) -> str:
    scope = sheet["scope"]
    lines = [f"# Audit-trail review worksheet {sheet['id']}", "",
             f"- Log: `{sheet['log_id']}`, seq {scope['from_seq']}–{scope['to_seq']} ({scope['count']} records)",
             f"- Period: {scope['since'] or 'start'} – {scope['until'] or 'now'}",
             f"- Head at end of scope: `{scope['head']}`",
             f"- Profile: {sheet['profile']['name']} (`{sheet['profile']['sha256']}`)",
             f"- Actors in scope (may not sign this review): {', '.join(sheet['actors_reviewed']) or 'none'}", "",
             "| Finding | Query | Severity | Records | Explanation |", "|---|---|---|---|---|"]
    for finding in sheet["findings"]:
        ids = ", ".join(finding["record_ids"][:5]) + (" …" if len(finding["record_ids"]) > 5 else "")
        lines.append(f"| {finding['id']} | {finding['query']} | {finding['severity']} | {ids} | "
                     f"{finding['explanation'].replace('|', '/')} |")
    if not sheet["findings"]:
        lines.append("| — | — | — | — | no findings |")
    lines += ["", "Sign with `aqt-trail review sign <worksheet.json> --reviewer human:<id> "
              "--disposition F1=ok --disposition F2=explained --note F2='…' --reason '…'`.", ""]
    return "\n".join(lines)


def save_worksheet(sheet: dict, directory: str | os.PathLike) -> Path:
    folder = Path(directory) / sheet["id"]
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "worksheet.json").write_text(json.dumps(sheet, indent=2, sort_keys=True) + "\n")
    (folder / "worksheet.md").write_text(worksheet_markdown(sheet))
    return folder / "worksheet.json"


def review_body(data: dict) -> dict:
    return {key: value for key, value in data.items() if key != "signature"}


def build_review(sheet: dict, records: list[dict], *, reviewer_id: str, signer: Signer, dispositions: dict,
                 notes: dict, reason: str, conclusion: str, registry: dict[str, SignerInfo],
                 name: str | None = None, role: str | None = None, tz: str = "UTC") -> dict:
    """The signed ``trail.review`` client record. Raises ``ReviewRefused`` or ``ValueError``."""
    if not reviewer_id.startswith("human:"):
        raise ReviewRefused("not_human", "a review is signed by a human identity (human:<id>)")
    if reviewer_id in sheet["actors_reviewed"]:
        raise ReviewRefused("not_independent", f"{reviewer_id} is an actor in the reviewed scope")
    scope = sheet["scope"]
    current = next((r for r in records if _seq(r) == scope["to_seq"]), None)
    if current is None or record_hash(current) != scope["head"]:
        raise ReviewRefused("stale_worksheet", "the trail at the end of the scope differs from the worksheet")
    info = registry.get(reviewer_id)
    if info is not None:
        if signer.key_id in info.revoked_keys:
            raise ReviewRefused("revoked_key", f"key {signer.key_id} of {reviewer_id} is revoked")
        if signer.key_id not in info.active_keys:
            raise ReviewRefused("unknown_key", f"key {signer.key_id} is not registered for {reviewer_id}")
        name, role = name or info.name, role or info.role
    findings = []
    for finding in sheet["findings"]:
        disposition = dispositions.get(finding["id"], dispositions.get("all"))
        if disposition not in DISPOSITIONS:
            raise ValueError(f"finding {finding['id']} needs a disposition ({' | '.join(DISPOSITIONS)})")
        note = notes.get(finding["id"])
        if disposition != "ok" and not note:
            raise ValueError(f"finding {finding['id']}: '{disposition}' needs a --note")
        findings.append({"id": finding["id"], "query": finding["query"], "severity": finding["severity"],
                         "record_ids": finding["record_ids"], "disposition": disposition,
                         **({"note": note} if note else {})})
    data = {"worksheet": sheet["id"], "log_id": sheet["log_id"], "scope": scope, "head": scope["head"],
            "profile": sheet["profile"]["name"], "profile_sha256": sheet["profile"]["sha256"],
            "actors_reviewed": sheet["actors_reviewed"], "findings": findings, "conclusion": conclusion,
            "signer_registered": info is not None}
    review_subject = subject("trail-review", sheet["id"], sha256=content_hash(review_body(data)))
    signer_info = {"id": reviewer_id, "name": name or reviewer_id, "role": role or "reviewer"}
    statement = build_statement(record_type="trail.review", signer=signer_info, key=signer.key_id,
                                meaning="reviewed", reason=reason, subject=review_subject, signed_at=utc_now(), tz=tz)
    data["signature"] = sign_statement(statement, signer)
    return new_record("trail.review", actor("human", reviewer_id, role=signer_info["role"], display=signer_info["name"]),
                      "review.signed", subject=review_subject, reason=reason, meaning="reviewed", data=data,
                      links=[{"rel": "reviewed-head", "ref": scope["head_id"]}], tz=tz)


def refusal_record(reviewer_id: str, code: str, message: str, markers: list[str] | None = None) -> dict:
    """``trail.refused`` (aqt-spec spec §11) for a refused review signature."""
    who = actor("human", reviewer_id) if reviewer_id.startswith("human:") else actor("agent", reviewer_id or "unknown")
    return new_record("trail.refused", who, "refused", data={
        "attempted_action": "review.sign", "reason_code": code, "message": message[:500],
        "agent_markers": markers or []})
