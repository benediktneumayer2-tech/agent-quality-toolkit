"""The AQT evidence record envelope (spec version 0.1).

A record says who did what to which subject, when and why. Tools put their
type-specific payload in ``data``. The record hash covers everything except
``sig``, so signatures can be added without changing the hash.
"""

from __future__ import annotations

import os
import re
import time
from datetime import UTC, date, datetime
from typing import Any

from .canonical import CanonicalError, canonical_json, content_hash

SPEC_VERSION = "0.1"
ACTOR_KINDS = frozenset({"human", "agent", "service"})
MEANINGS = frozenset({
    "authored", "reviewed", "approved", "released", "rejected", "verified", "waived", "acknowledged",
})
TOP_LEVEL = frozenset({
    "aqt", "id", "type", "time", "tz", "actor", "observed", "action", "subject", "before", "after",
    "reason", "meaning", "links", "data", "chain", "sig",
})
# Used with fullmatch (``$`` would also match before a final newline) and ASCII digits only.
_TYPE = re.compile(r"[a-z0-9-]+\.[a-z0-9_.-]+")
_ID = re.compile(r"rec_[0-9a-f]{28}")
_HASH = re.compile(r"sha256:[0-9a-f]{64}")
_KEY_ID = re.compile(r"ed25519:[0-9a-f]{16}")
_TIME = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]{1,6})?Z")


def new_id() -> str:
    """Time-ordered record ID: milliseconds since the epoch, then 64 random bits."""
    return f"rec_{int(time.time() * 1000):012x}{os.urandom(8).hex()}"


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def actor(kind: str, id: str, *, role: str | None = None, display: str | None = None,
          harness: str | None = None, model: str | None = None, version: str | None = None,
          session: str | None = None) -> dict:
    """Build an ``actor`` object. Agent details go into ``actor.agent``."""
    value: dict[str, Any] = {"kind": kind, "id": id}
    if role:
        value["role"] = role
    if display:
        value["display"] = display
    agent = {k: v for k, v in (("harness", harness), ("model", model), ("version", version),
                               ("session", session)) if v}
    if agent:
        value["agent"] = agent
    return value


def subject(kind: str, ref: str, *, sha256: str | None = None) -> dict:
    value = {"kind": kind, "ref": ref}
    if sha256:
        value["sha256"] = sha256
    return value


def new_record(type: str, actor: dict, action: str, *, subject: dict | None = None,
               reason: str | None = None, meaning: str | None = None, before: dict | None = None,
               after: dict | None = None, links: list[dict] | None = None, data: dict | None = None,
               tz: str | None = None, time: str | None = None) -> dict:
    """Create a record. ``time`` defaults to now; an audit-trail writer may restamp it."""
    record: dict[str, Any] = {
        "aqt": SPEC_VERSION, "id": new_id(), "type": type, "time": time or utc_now(),
        "actor": actor, "action": action,
    }
    for key, value in (("tz", tz), ("subject", subject), ("before", before), ("after", after),
                       ("reason", reason), ("meaning", meaning), ("links", links), ("data", data)):
        if value is not None:
            record[key] = value
    errors = validate_record(record)
    if errors:
        raise ValueError("; ".join(errors))
    return record


def unsigned(record: dict) -> dict:
    return {key: value for key, value in record.items() if key != "sig"}


WRITER_FIELDS = ("sig", "chain", "observed", "time")


def record_content_hash(record: dict) -> str:
    """Identity of what a record says, independent of where it is stored.

    Excludes ``sig``, ``chain``, ``observed`` and ``time`` (an audit-trail writer
    sets or restamps those). Use it as ``subject.sha256`` when signing a record.
    """
    return content_hash({key: value for key, value in record.items() if key not in WRITER_FIELDS})


def record_hash(record: dict) -> str:
    """``sha256:<hex>`` over the canonical record without ``sig``."""
    return content_hash(unsigned(record))


def is_time(value: Any) -> bool:
    """True for an RFC 3339 UTC time as records use it (``Z``, up to 6 fractional digits)."""
    match = _TIME.fullmatch(value) if isinstance(value, str) else None
    if not match:
        return False
    year, month, day, hour, minute, second = (int(part) for part in match.groups()[:6])
    try:
        date(year, month, day)
    except ValueError:
        return False
    return hour < 24 and minute < 60 and second <= 60  # 60: leap second


def is_hash(value: Any) -> bool:
    """True for ``sha256:`` plus 64 lower-case hex digits."""
    return isinstance(value, str) and _HASH.fullmatch(value) is not None


def _text(value: Any) -> bool:
    return isinstance(value, str) and value != ""


def _strings(value: Any, names: tuple[str, ...]) -> bool:
    return all(isinstance(value[name], str) for name in names if name in value)


def _actor_ok(who: Any) -> bool:
    if not isinstance(who, dict) or not isinstance(who.get("kind"), str) or who["kind"] not in ACTOR_KINDS:
        return False
    agent = who.get("agent", {})
    return (_text(who.get("id")) and _strings(who, ("role", "display")) and isinstance(agent, dict)
            and _strings(agent, ("harness", "model", "version", "session")))


def _integer(value: Any) -> bool:
    return type(value) is int  # bool is not an integer here


def _observed_ok(seen: Any) -> bool:
    if not isinstance(seen, dict):
        return False
    chain, processes = seen.get("process_chain", []), seen.get("processes", [])
    return (all(_integer(seen[name]) for name in ("pid", "uid", "gid") if name in seen)
            and isinstance(chain, list) and all(isinstance(item, str) for item in chain)
            and isinstance(processes, list)
            and all(isinstance(p, dict) and _integer(p.get("pid")) and _strings(p, ("comm",))
                    and ("start_time" not in p or _integer(p["start_time"])) for p in processes)
            and (seen.get("harness") is None or isinstance(seen["harness"], str))
            and ("client_time" not in seen or is_time(seen["client_time"]))
            and seen.get("via", "socket") in ("socket", "spool"))


def validate_record(record: Any) -> list[str]:
    """Check the envelope (spec §3; the same rules as ``schemas/envelope.schema.json``, plus
    real calendar dates and the canonical-JSON rules). Returns a list of problems; empty means
    valid. Optional members are left out when absent: ``null`` is not a value for any of them."""
    if not isinstance(record, dict):
        return ["record must be a JSON object"]
    errors = []
    unknown = set(record) - TOP_LEVEL
    if unknown:
        errors.append(f"unknown top-level fields: {', '.join(sorted(map(str, unknown)))}")
    if record.get("aqt") != SPEC_VERSION:
        errors.append(f"aqt must be {SPEC_VERSION!r}")
    if not isinstance(record.get("id"), str) or not _ID.fullmatch(record["id"]):
        errors.append("id must look like rec_<28 hex>")
    if not isinstance(record.get("type"), str) or not _TYPE.fullmatch(record["type"]):
        errors.append("type must be '<tool>.<kind>' in lower case")
    if not is_time(record.get("time")):
        errors.append("time must be RFC 3339 UTC with a Z suffix")
    if "tz" in record and not _text(record["tz"]):
        errors.append("tz, when present, must be a non-empty string")
    if not _text(record.get("action")):
        errors.append("action must be a non-empty string")
    if not _actor_ok(record.get("actor")):
        errors.append("actor needs kind (human|agent|service) and id (strings; role, display and agent.* "
                      "are strings too)")
    if "observed" in record and not _observed_ok(record["observed"]):
        errors.append("observed does not match its schema (pid, uid, gid integers; via socket|spool; ...)")
    what = record.get("subject")
    if "subject" in record and (not isinstance(what, dict) or not _text(what.get("kind"))
                                or not _text(what.get("ref"))):
        errors.append("subject needs kind and ref")
    for key in ("before", "after"):
        if key in record and not isinstance(record[key], dict):
            errors.append(f"{key}, when present, must be an object")
    for key in ("subject", "before", "after"):
        value = record.get(key)
        if isinstance(value, dict) and "sha256" in value and not is_hash(value["sha256"]):
            errors.append(f"{key}.sha256 must be sha256:<64 hex>")
    if "meaning" in record and (not isinstance(record["meaning"], str) or record["meaning"] not in MEANINGS):
        errors.append(f"meaning must be one of {', '.join(sorted(MEANINGS))}")
    if "reason" in record and (not isinstance(record["reason"], str) or not record["reason"].strip()):
        errors.append("reason, when present, must be a non-empty string")
    links = record.get("links")
    if "links" in record and (not isinstance(links, list) or any(
            not isinstance(link, dict) or not _text(link.get("rel")) or not _text(link.get("ref")) for link in links)):
        errors.append("links must be a list of {rel, ref}")
    if "data" in record and not isinstance(record["data"], dict):
        errors.append("data must be an object")
    chain = record.get("chain")
    if "chain" in record and (not isinstance(chain, dict) or type(chain.get("seq")) is not int
                              or chain["seq"] < 0 or not is_hash(chain.get("prev"))):
        errors.append("chain needs integer seq >= 0 and prev sha256:<64 hex>")
    sig = record.get("sig")
    if "sig" in record and (not isinstance(sig, list) or any(
            not isinstance(s, dict) or s.get("alg") != "ed25519" or not isinstance(s.get("key"), str)
            or not _KEY_ID.fullmatch(s["key"]) or not _text(s.get("value")) for s in sig)):
        errors.append("sig must be a list of {alg: ed25519, key: ed25519:<16 hex>, value}")
    try:
        canonical_json(record)
    except CanonicalError as error:
        errors.append(str(error))
    return errors
