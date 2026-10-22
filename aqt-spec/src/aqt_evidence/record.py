"""The AQT evidence record envelope (spec version 0.1).

A record says who did what to which subject, when and why. Tools put their
type-specific payload in ``data``. The record hash covers everything except
``sig``, so signatures can be added without changing the hash.
"""

from __future__ import annotations

import os
import re
import time
from datetime import UTC, datetime
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
_TYPE = re.compile(r"^[a-z0-9-]+\.[a-z0-9_.-]+$")
_ID = re.compile(r"^rec_[0-9a-f]{12}[0-9a-f]{16}$")
_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$")


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


def validate_record(record: Any) -> list[str]:
    """Structural check of the envelope. Returns a list of problems; empty means valid."""
    if not isinstance(record, dict):
        return ["record must be a JSON object"]
    errors = []
    unknown = set(record) - TOP_LEVEL
    if unknown:
        errors.append(f"unknown top-level fields: {', '.join(sorted(unknown))}")
    if record.get("aqt") != SPEC_VERSION:
        errors.append(f"aqt must be {SPEC_VERSION!r}")
    if not isinstance(record.get("id"), str) or not _ID.match(record["id"]):
        errors.append("id must look like rec_<28 hex>")
    if not isinstance(record.get("type"), str) or not _TYPE.match(record["type"]):
        errors.append("type must be '<tool>.<kind>' in lower case")
    if not isinstance(record.get("time"), str) or not _TIME.match(record["time"]):
        errors.append("time must be RFC 3339 UTC with a Z suffix")
    if not isinstance(record.get("action"), str) or not record["action"]:
        errors.append("action must be a non-empty string")
    who = record.get("actor")
    if not isinstance(who, dict) or who.get("kind") not in ACTOR_KINDS or not who.get("id"):
        errors.append("actor needs kind (human|agent|service) and id")
    what = record.get("subject")
    if what is not None and (not isinstance(what, dict) or not what.get("kind") or not what.get("ref")):
        errors.append("subject needs kind and ref")
    for key in ("subject", "before", "after"):
        value = record.get(key)
        if isinstance(value, dict) and "sha256" in value and not _HASH.match(str(value["sha256"])):
            errors.append(f"{key}.sha256 must be sha256:<64 hex>")
    if "meaning" in record and record["meaning"] not in MEANINGS:
        errors.append(f"meaning must be one of {', '.join(sorted(MEANINGS))}")
    if "reason" in record and (not isinstance(record["reason"], str) or not record["reason"].strip()):
        errors.append("reason, when present, must be a non-empty string")
    links = record.get("links")
    if links is not None and (not isinstance(links, list) or any(
            not isinstance(link, dict) or not link.get("rel") or not link.get("ref") for link in links)):
        errors.append("links must be a list of {rel, ref}")
    chain = record.get("chain")
    if chain is not None and (not isinstance(chain, dict) or type(chain.get("seq")) is not int
                              or not _HASH.match(str(chain.get("prev", "")))):
        errors.append("chain needs integer seq and prev sha256:<64 hex>")
    sig = record.get("sig")
    if sig is not None and (not isinstance(sig, list) or any(
            not isinstance(s, dict) or s.get("alg") != "ed25519" or not s.get("key") or not s.get("value")
            for s in sig)):
        errors.append("sig must be a list of {alg: ed25519, key, value}")
    try:
        canonical_json(record)
    except CanonicalError as error:
        errors.append(str(error))
    return errors
