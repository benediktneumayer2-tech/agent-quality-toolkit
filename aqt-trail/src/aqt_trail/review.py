"""Audit-trail review: risk queries, a worksheet, and a signed ``trail.review``.

A review covers a scope (a seq range of one log, bound to the head hash at its
end). Queries flag records a reviewer should look at; the reviewer gives each
finding a disposition (``ok`` | ``explained`` | ``deviation``)
and signs. Signing is refused when the reviewer was an actor in the scope, is
not a human identity, or the trail changed since the worksheet was made.

The worksheet file is only a working copy: it can be edited by anyone who can
write the reviews folder. ``build_review`` therefore recomputes the scope, the
actors and the findings from the trail itself (the queries see the trail up to
the end of the scope, so the result is reproducible) and refuses a worksheet that
differs. A user interface that displayed a worksheet passes the digest of what it
showed (``worksheet_digest``) as ``expected_sha256``, so a worksheet swapped
between display and signing is refused too.
"""

from __future__ import annotations

import base64
import json
import os
import re
import tomllib
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from aqt_evidence import (Signer, actor, bytes_hash, content_hash, new_record, record_hash, subject, utc_now,
                          verify_chain)

from . import tsa
from .signers import SignerInfo, build_statement, key_owners, sign_statement
from .text import md

QUERIES = ("self_approval", "missing_reason", "attribution_mismatch", "gaps", "out_of_hours",
           "repeated_failures", "time_anomalies", "actor_changes", "invalidated_signatures", "unanchored_head")
DISPOSITIONS = ("ok", "explained", "deviation")
APPROVALS = {"approved", "released", "verified", "reviewed"}
DECISION_ACTIONS = {"approve", "approved", "release", "released", "reject", "rejected", "waive", "waived",
                    "sign", "signed", "declare-threat", "trust-source", "accept", "dismiss", "close", "resolve"}
# Types whose actors do not count as "involved" for reviewer independence.
NOT_ACTIVITY = {"trail.refused", "trail.review", "trail.gap", "trail.anchor"}
WRITER_ID = "service:aqt-trail"
WORKSHEET_KEYS = ("aqt_worksheet", "id", "log_id", "scope", "profile", "actors_reviewed", "findings")
_WORKSHEET_ID = re.compile(r"^rv_[0-9a-f]{12}$")


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
    chain = record.get("chain") if isinstance(record, dict) else None
    seq = chain.get("seq") if isinstance(chain, dict) else None
    return seq if type(seq) is int else -1


def _data(record) -> dict:
    return record.get("data") if isinstance(record.get("data"), dict) else {}


def _observed(record) -> dict:
    return record.get("observed") if isinstance(record.get("observed"), dict) else {}


def _actor(record) -> dict:
    return record.get("actor") if isinstance(record.get("actor"), dict) else {}


def _aid(record) -> str:
    return str(_actor(record).get("id", ""))


def _is_decision(record) -> bool:
    return "meaning" in record or str(record.get("action", "")).split(".")[-1] in DECISION_ACTIONS


def _signer_id(record) -> str:
    block = _data(record).get("signature")
    statement = block.get("statement") if isinstance(block, dict) else None
    signer = statement.get("signer") if isinstance(statement, dict) else None
    found = signer.get("id") if isinstance(signer, dict) else None
    return found if isinstance(found, str) and found else _aid(record)


def is_writer_record(record) -> bool:
    """Written by the writer itself (``observed.origin: writer``, no ``via``). Clients cannot set ``observed``,
    so a ``trail.anchor`` a client sent never passes this check."""
    observed = _observed(record)
    return observed.get("origin") == "writer" and "via" not in observed and _aid(record) == WRITER_ID


def anchored_seq(record) -> int | None:
    """For a writer-written RFC 3161 ``trail.anchor`` whose token covers its checkpoint's head (imprint and TSA
    signature; ``verify`` also checks the certificate chain), the seq the checkpoint covers; else None."""
    if record.get("type") != "trail.anchor" or record.get("action") != "rfc3161" or not is_writer_record(record):
        return None
    data = _data(record)
    point, stamp = data.get("checkpoint"), data.get("tsa")
    if not isinstance(point, dict) or type(point.get("seq")) is not int or not isinstance(point.get("head"), str) \
            or not isinstance(stamp, dict) or point["seq"] >= _seq(record):
        return None
    try:
        token = base64.b64decode(str(stamp.get("token_b64", "")), validate=True)
        digest = bytes.fromhex(point["head"].split(":", 1)[1])
    except (ValueError, IndexError):
        return None
    return point["seq"] if tsa.verify_token(token, digest).ok else None


def attribution(record) -> str | None:
    """How well a socket record that claims a human is attributed, or None for other records:
    ``agent`` (an agent harness was observed), ``unconfirmed`` (``observed.chain_status`` partial or
    unavailable: the sender's process chain could not be read completely), ``legacy`` (written before
    ``chain_status`` existed: only the absence of agent markers speaks for a human), ``human``."""
    observed = _observed(record)
    if observed.get("via") != "socket" or _actor(record).get("kind") != "human":
        return None
    if observed.get("harness"):
        return "agent"
    status = observed.get("chain_status")
    if status is None:
        return "unconfirmed" if observed.get("chain_complete") is False else "legacy"
    return "human" if status == "complete" else "unconfirmed"


def scope_actors(scope: list[dict]) -> list[str]:
    """Identities that acted in ``scope`` (they may not review it): every non-service actor, except on
    records that are not activity (refusals, reviews, gaps, anchors)."""
    return sorted({_aid(r) for r in scope if _actor(r).get("kind") != "service" and r.get("type") not in NOT_ACTIVITY})


def in_period(record, since: str | None, until: str | None) -> bool:
    moment = str(record.get("time", ""))
    return (not since or moment >= since) and (not until or moment <= until)


def _failed(record) -> bool:
    data = _data(record)
    if str(record.get("type", "")).endswith(".refused") or record.get("action") == "refused":
        return True
    if data.get("outcome") in ("failed", "refused", "unknown") or data.get("passed") is False:
        return True
    return type(data.get("exit_code")) is int and data["exit_code"] != 0


def _finding(query, severity, records, explanation) -> dict:
    return {"query": query, "severity": severity, "record_ids": [str(r.get("id")) for r in records],
            "explanation": explanation}


# -- queries ---------------------------------------------------------------------
# Each query sees ``scope`` (the reviewed records) and ``everything`` (the trail up to the end of the scope).
def q_self_approval(scope, everything, params):
    by_id = {r.get("id"): r for r in everything}
    by_subject = defaultdict(list)
    for record in everything:
        ref = (record.get("subject") or {}).get("ref") if isinstance(record.get("subject"), dict) else None
        if isinstance(ref, str) and ref:
            by_subject[ref].append(record)
    findings = []
    for record in scope:
        if record.get("meaning") not in APPROVALS:
            continue
        approver = _signer_id(record)
        links = record.get("links") if isinstance(record.get("links"), list) else []
        authors = [by_id[link["ref"]] for link in links if isinstance(link, dict) and link.get("ref") in by_id]
        ref = (record.get("subject") or {}).get("ref") if isinstance(record.get("subject"), dict) else None
        authors += [r for r in by_subject.get(ref, []) if _seq(r) < _seq(record) and r.get("meaning") not in APPROVALS]
        same = [r for r in authors if _aid(r) == approver]
        if same:
            findings.append(_finding("self_approval", "major", [record, *same[:5]],
                                     f"{approver} gave '{record['meaning']}' to work they also performed"))
    return findings


def q_missing_reason(scope, everything, params):
    hits = [r for r in scope if _actor(r).get("kind") == "human" and _is_decision(r) and not r.get("reason")]
    return [_finding("missing_reason", "major", hits, "human decisions without a recorded reason")] if hits else []


def q_attribution_mismatch(scope, everything, params):
    findings, unconfirmed, legacy = [], [], []
    for record in scope:
        observed = _observed(record)
        if observed.get("via") != "socket":
            continue
        state = attribution(record)
        if state == "agent":
            chain = observed.get("process_chain") if isinstance(observed.get("process_chain"), list) else []
            findings.append(_finding("attribution_mismatch", "major", [record],
                                     f"claims human {_aid(record)} but was sent from inside "
                                     f"{observed['harness']} ({' <- '.join(str(c) for c in chain[:6])})"))
        elif state == "unconfirmed":
            unconfirmed.append(record)
        elif state == "legacy":
            legacy.append(record)
        elif _actor(record).get("kind") == "agent" and not observed.get("harness") \
                and record.get("type") != "trail.import":
            findings.append(_finding("attribution_mismatch", "minor", [record],
                                     "claims an agent session but no agent harness was observed"))
    if unconfirmed:
        findings.append(_finding("attribution_mismatch", "minor", unconfirmed,
                                 f"{len(unconfirmed)} record(s) claim a human, but the sender's process chain was "
                                 "incomplete or unreadable (observed.chain_status): not confirmed as human"))
    if legacy:
        findings.append(_finding("attribution_mismatch", "info", legacy,
                                 f"{len(legacy)} record(s) claim a human and were written before "
                                 "observed.chain_status existed: only the absence of agent markers speaks for a human"))
    return findings


def q_gaps(scope, everything, params):
    findings = []
    for record in scope:
        if record.get("type") == "trail.gap":
            data = _data(record)
            findings.append(_finding("gaps", "major", [record],
                                     f"{data.get('count')} record(s) spooled between {data.get('first_time')} and "
                                     f"{data.get('last_time')}; their attribution was not observed"))
        elif record.get("action") == "log.repaired":
            findings.append(_finding("gaps", "minor", [record], "an incomplete last line was removed at start"))
    spooled = [r for r in scope if _observed(r).get("via") == "spool"]
    if spooled:
        findings.append(_finding("gaps", "minor", spooled, "records delivered through the spool (claimed, not observed)"))
    starts = [r for r in everything if r.get("type") == "trail.event" and r.get("action") in ("service.start", "service.stop")]
    in_scope = {r.get("id") for r in scope}
    for previous, current in zip(starts, starts[1:]):
        if current.get("id") not in in_scope or current.get("action") != "service.start":
            continue
        if previous.get("action") == "service.start":
            findings.append(_finding("gaps", "minor", [previous, current],
                                     "the writer stopped without a stop record (crash or kill)"))
        else:
            findings.append(_finding("gaps", "info", [previous, current],
                                     f"writer downtime from {previous.get('time')} to {current.get('time')}"))
    return findings


def q_out_of_hours(scope, everything, params):
    zone = ZoneInfo(params.get("timezone", "UTC"))
    start, end = (datetime.strptime(params.get(k), "%H:%M").time() for k in ("work_start", "work_end"))
    days = set(params.get("workdays", [1, 2, 3, 4, 5]))
    hits = []
    for record in scope:
        if _actor(record).get("kind") != "human":
            continue
        moment = _time(record.get("time"))
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
            sub = record.get("subject") if isinstance(record.get("subject"), dict) else {}
            key = (_aid(record), str(_data(record).get("attempted_action") or record.get("action")), str(sub.get("ref")))
            groups[key].append(record)
    findings = []
    for (who, what, ref), items in groups.items():
        for index in range(len(items) - limit + 1):
            first, last = _time(items[index].get("time")), _time(items[index + limit - 1].get("time"))
            if first and last and last - first <= window:
                findings.append(_finding("repeated_failures", "major", items,
                                         f"{len(items)} failed or refused '{what}' attempts by {who}"))
                break
    return findings


def q_time_anomalies(scope, everything, params):
    skew = int(params.get("skew_ms", 5000))
    findings = [_finding("time_anomalies", "major", [r], f"writer clock jump ({_data(r).get('direction')})")
                for r in scope if r.get("action") == "clock.jump"]
    skewed = []
    for record in scope:
        observed = _observed(record)
        client, service = _time(observed.get("client_time")), _time(record.get("time"))
        if observed.get("via") == "socket" and client and service and abs((service - client).total_seconds()) * 1000 > skew:
            skewed.append(record)
    if skewed:
        findings.append(_finding("time_anomalies", "minor", skewed, f"client time differs from writer time by more than {skew} ms"))
    previous = None
    for record in scope:
        moment = str(record.get("time", ""))
        if previous is not None and moment < previous:
            findings.append(_finding("time_anomalies", "major", [record], "writer time went backwards"))
        previous = moment
    return findings


def q_actor_changes(scope, everything, params):
    window = timedelta(minutes=int(params.get("actor_change_window_min", 60)))
    by_subject = defaultdict(list)
    for record in scope:
        sub = record.get("subject") if isinstance(record.get("subject"), dict) else {}
        if isinstance(sub.get("ref"), str) and sub.get("kind") not in ("agent-session", "tool-call", "trail-head") \
                and record.get("type") not in NOT_ACTIVITY:
            by_subject[sub["ref"]].append(record)
    findings = []
    for ref, items in by_subject.items():
        actors = {_aid(r) for r in items}
        first, last = _time(items[0].get("time")), _time(items[-1].get("time"))
        if len(actors) > 1 and first and last and last - first <= window:
            findings.append(_finding("actor_changes", "info", items,
                                     f"{ref} was acted on by {len(actors)} actors: {', '.join(sorted(actors))}"))
    return findings


def q_invalidated_signatures(scope, everything, params):
    hits = [r for r in scope if r.get("type") == "signoff.invalidation"]
    return [_finding("invalidated_signatures", "major", hits, "signatures were invalidated")] if hits else []


def q_unanchored_head(scope, everything, params):
    """Records after the last RFC 3161 anchor the writer wrote. Exported heads are not counted: the trail
    cannot see whether a copy was really kept elsewhere."""
    if not everything:
        return []
    last, covered = None, -1
    for record in everything:
        seq = anchored_seq(record)
        if seq is not None:
            last, covered = record, max(covered, seq)
    after = [r for r in everything
             if _seq(r) > covered and not (r.get("type") == "trail.anchor" and is_writer_record(r))]
    if not after:
        return []
    since = _time(last.get("time")) if last else _time(everything[0].get("time"))
    newest = _time(after[-1].get("time"))
    age = newest - since if since and newest else timedelta(0)
    if last is None or age > timedelta(hours=int(params.get("unanchored_hours", 24))):
        what = "no RFC 3161 anchor" if last is None else f"last RFC 3161 anchor {last.get('time')}"
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
        if profile["name"] == "default" and profile["queries"] != list(QUERIES):
            raise ValueError(f"{path}: a profile that leaves out queries may not be named 'default'")
    return profile


def _profile_entry(name: str, queries: list[str], params: dict) -> dict:
    sha = bytes_hash(json.dumps({"name": name, "queries": queries, "params": params}, sort_keys=True).encode())
    return {"name": name, "sha256": sha, "params": params, "queries": list(queries)}


def _evaluate(records: list[dict], profile: dict, *, since: str | None, until: str | None) -> dict:
    """Scope, profile, actors and findings: a pure function of the trail up to the end of the scope."""
    scope = [r for r in records if in_period(r, since, until)]
    if not scope:
        raise ValueError("no records in the selected period")
    last = scope[-1]
    everything = [r for r in records if _seq(r) <= _seq(last)]   # the trail as it was at the end of the scope
    findings = []
    for name in profile["queries"]:
        findings.extend(QUERY_FUNCTIONS[name](scope, everything, profile["params"]))
    for number, finding in enumerate(findings, 1):
        finding["id"] = f"F{number}"
    return {
        "scope": {"from_seq": _seq(scope[0]), "to_seq": _seq(last), "since": since, "until": until,
                  "count": len(scope), "head": record_hash(last), "head_id": last.get("id")},
        "profile": _profile_entry(profile["name"], profile["queries"], profile["params"]),
        "actors_reviewed": scope_actors(scope), "findings": findings,
    }


def run_review(records: list[dict], profile: dict, *, log_id: str, since: str | None = None,
               until: str | None = None, trail: str | None = None) -> dict:
    result = _evaluate(records, profile, since=since, until=until)
    return {"aqt_worksheet": "0.1", "id": f"rv_{os.urandom(6).hex()}", "log_id": log_id, "trail": trail,
            "generated_at": utc_now(), **result}


def worksheet_digest(sheet: dict) -> str:
    """``sha256:`` over what a reviewer is shown and signs (``WORKSHEET_KEYS``); ``trail`` and
    ``generated_at`` are left out. A UI keeps this for the worksheet it displayed and passes it to
    ``build_review(..., expected_sha256=...)``."""
    shown = {key: sheet.get(key) for key in WORKSHEET_KEYS}
    return bytes_hash(json.dumps(shown, sort_keys=True, separators=(",", ":")).encode())


def worksheet_markdown(sheet: dict) -> str:
    scope = sheet["scope"]
    queries = sheet["profile"].get("queries")
    lines = [f"# Audit-trail review worksheet {md(sheet['id'])}", "",
             f"- Log: {md(sheet['log_id'])}, seq {md(scope['from_seq'])}–{md(scope['to_seq'])} "
             f"({md(scope['count'])} records)",
             f"- Period: {md(scope['since'] or 'start')} – {md(scope['until'] or 'now')}",
             f"- Head at end of scope: {md(scope['head'])}",
             f"- Profile: {md(sheet['profile']['name'])} ({md(sheet['profile']['sha256'])})"
             + (f", queries: {md(', '.join(queries))}" if queries is not None and list(queries) != list(QUERIES) else ""),
             f"- Actors in scope (may not sign this review): {md(', '.join(sheet['actors_reviewed'])) or 'none'}", "",
             "| Finding | Query | Severity | Records | Explanation |", "|---|---|---|---|---|"]
    for finding in sheet["findings"]:
        ids = ", ".join(finding["record_ids"][:5]) + (" …" if len(finding["record_ids"]) > 5 else "")
        lines.append(f"| {md(finding['id'])} | {md(finding['query'])} | {md(finding['severity'])} | {md(ids)} | "
                     f"{md(finding['explanation'])} |")
    if not sheet["findings"]:
        lines.append("| — | — | — | — | no findings |")
    lines += ["", "Sign with `aqt-trail review sign <worksheet.json> --reviewer human:<id> "
              "--disposition F1=ok --disposition F2=explained --note F2='…' --reason '…'`.",
              "Signing recomputes this worksheet from the trail and refuses it if it was changed.", ""]
    return "\n".join(lines)


def save_worksheet(sheet: dict, directory: str | os.PathLike) -> Path:
    folder = Path(directory) / sheet["id"]
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "worksheet.json").write_text(json.dumps(sheet, indent=2, sort_keys=True) + "\n")
    (folder / "worksheet.md").write_text(worksheet_markdown(sheet))
    return folder / "worksheet.json"


def review_body(data: dict) -> dict:
    return {key: value for key, value in data.items() if key != "signature"}


def _mismatch(what: str) -> ReviewRefused:
    return ReviewRefused("worksheet_mismatch", f"the worksheet's {what} differ(s) from the trail; it was changed or "
                                               "made by another version. Run 'aqt-trail review run' again")


def check_worksheet(sheet: dict, records: list[dict], *, log_id: str | None = None, keys: dict | None = None,
                    expected_sha256: str | None = None) -> dict:
    """Recompute ``sheet`` from ``records`` (the trail) and return the recomputed worksheet.

    Refuses (``ReviewRefused``) when the worksheet is not the one shown (``expected_sha256``), belongs to another
    log, no longer matches the trail at the end of its scope (``stale_worksheet``), the trail does not verify up
    to there (``trail_broken``; with ``keys`` also the service signatures), or its scope, profile, actors or
    findings differ from what the trail gives (``worksheet_mismatch``)."""
    if not isinstance(sheet, dict) or not isinstance(sheet.get("scope"), dict) or not isinstance(sheet.get("profile"), dict):
        raise _mismatch("structure")
    if expected_sha256 is not None and worksheet_digest(sheet) != expected_sha256:
        raise ReviewRefused("worksheet_changed", "the worksheet differs from the one shown; nothing was signed. "
                                                 "Reload the review")
    if not isinstance(sheet.get("id"), str) or not _WORKSHEET_ID.match(sheet["id"]):
        raise _mismatch("id")
    if log_id is not None and sheet.get("log_id") != log_id:
        raise ReviewRefused("worksheet_mismatch", f"the worksheet is for log {sheet.get('log_id')!r}, not {log_id!r}")
    scope, profile = sheet["scope"], sheet["profile"]
    to_seq = scope.get("to_seq")
    current = next((r for r in records if _seq(r) == to_seq), None) if type(to_seq) is int else None
    if current is None or record_hash(current) != scope.get("head"):
        raise ReviewRefused("stale_worksheet", "the trail at the end of the scope differs from the worksheet")
    upto = [r for r in records if 0 <= _seq(r) <= to_seq]
    try:
        chain = verify_chain(upto, keys=keys or None, require_signature=bool(keys))
    except (TypeError, AttributeError, ValueError) as error:
        raise ReviewRefused("trail_broken", f"the trail is malformed up to seq {to_seq} ({error}); "
                                            "run 'aqt-trail verify'") from error
    if not chain.ok or chain.count != to_seq + 1:
        reason = chain.summary() if not chain.ok else "records are missing"
        raise ReviewRefused("trail_broken", f"the trail does not verify up to seq {to_seq} ({reason}); "
                                            "run 'aqt-trail verify'")
    queries = profile.get("queries")
    if queries is None and profile.get("name") == "default":
        queries = list(QUERIES)                     # worksheets written before the queries were listed
    params = profile.get("params")
    if not isinstance(queries, list) or any(q not in QUERY_FUNCTIONS for q in queries) or not isinstance(params, dict) \
            or not isinstance(profile.get("name"), str):
        raise _mismatch("profile")
    if profile["name"] == "default" and queries != list(QUERIES):
        raise _mismatch("profile (a profile named 'default' runs every query)")
    if _profile_entry(profile["name"], queries, params)["sha256"] != profile.get("sha256"):
        raise _mismatch("profile hash")
    try:
        fresh = _evaluate(upto, {"name": profile["name"], "queries": queries, "params": params},
                          since=scope.get("since"), until=scope.get("until"))
    except (ValueError, TypeError, KeyError) as error:
        raise _mismatch(f"scope or profile ({error})") from error
    for key, label in (("scope", "scope"), ("actors_reviewed", "actors in scope"), ("findings", "findings")):
        if fresh[key] != sheet.get(key):
            raise _mismatch(label)
    return {"aqt_worksheet": sheet.get("aqt_worksheet"), "id": sheet["id"], "log_id": sheet.get("log_id"), **fresh}


def build_review(sheet: dict, records: list[dict], *, reviewer_id: str, signer: Signer, dispositions: dict,
                 notes: dict, reason: str, conclusion: str, registry: dict[str, SignerInfo],
                 name: str | None = None, role: str | None = None, tz: str = "UTC", log_id: str | None = None,
                 keys: dict | None = None, expected_sha256: str | None = None) -> dict:
    """The signed ``trail.review`` client record. Raises ``ReviewRefused`` or ``ValueError``.

    ``records`` must be the trail itself, not a copy that came with the worksheet: the worksheet is recomputed from
    them (``check_worksheet``) and only the recomputed scope, actors and findings are signed. With a non-empty
    ``registry`` the reviewer must be registered and sign with one of their active keys; a key registered to
    someone else is always refused."""
    if not reviewer_id.startswith("human:"):
        raise ReviewRefused("not_human", "a review is signed by a human identity (human:<id>)")
    fresh = check_worksheet(sheet, records, log_id=log_id, keys=keys, expected_sha256=expected_sha256)
    if reviewer_id in fresh["actors_reviewed"]:
        raise ReviewRefused("not_independent", f"{reviewer_id} is an actor in the reviewed scope")
    others = sorted({owner.id for owner, _key in key_owners(registry, signer.key_id) if owner.id != reviewer_id})
    if others:
        raise ReviewRefused("key_mismatch", f"key {signer.key_id} is registered to {', '.join(others)}, "
                                            f"not to {reviewer_id}")
    info = registry.get(reviewer_id)
    if info is not None:
        if signer.key_id in info.revoked_keys:
            raise ReviewRefused("revoked_key", f"key {signer.key_id} of {reviewer_id} is revoked")
        if signer.key_id not in info.active_keys:
            raise ReviewRefused("unknown_key", f"key {signer.key_id} is not registered for {reviewer_id}")
        name, role = name or info.name, role or info.role
    elif registry:
        raise ReviewRefused("unknown_signer", f"{reviewer_id} is not in the signer registry; enrol the reviewer "
                                              "with aqt-signoff first")
    scope = fresh["scope"]
    findings = []
    for finding in fresh["findings"]:
        disposition = dispositions.get(finding["id"], dispositions.get("all"))
        if disposition not in DISPOSITIONS:
            raise ValueError(f"finding {finding['id']} needs a disposition ({' | '.join(DISPOSITIONS)})")
        note = notes.get(finding["id"])
        if disposition != "ok" and not note:
            raise ValueError(f"finding {finding['id']}: '{disposition}' needs a --note")
        findings.append({"id": finding["id"], "query": finding["query"], "severity": finding["severity"],
                         "record_ids": finding["record_ids"], "disposition": disposition,
                         **({"note": note} if note else {})})
    data = {"worksheet": fresh["id"], "log_id": fresh["log_id"], "scope": scope, "head": scope["head"],
            "profile": fresh["profile"]["name"], "profile_sha256": fresh["profile"]["sha256"],
            "profile_queries": fresh["profile"]["queries"], "worksheet_sha256": worksheet_digest(sheet),
            "actors_reviewed": fresh["actors_reviewed"], "findings": findings, "conclusion": conclusion,
            "signer_registered": info is not None}
    review_subject = subject("trail-review", fresh["id"], sha256=content_hash(review_body(data)))
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
