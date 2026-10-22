"""Writing and finding aqt-validate evidence records."""

from __future__ import annotations

from aqt_evidence import new_record

RUN, REPORT, QUALIFICATION, REQUALIFICATION, REFUSED = (
    "validate.run", "validate.report", "validate.qualification", "validate.requalification", "validate.refused")


def emit(sink, type: str, actor: dict, action: str, **fields) -> dict:
    """Create a record and append it; returns the stored record (a trail may restamp time)."""
    stored = sink.append(new_record(type, actor, action, **fields))
    return stored if isinstance(stored, dict) else fields


def find_lock(records: list[dict], protocol_sha256: str) -> dict | None:
    for record in records:
        if record.get("type") == RUN and record.get("action") == "protocol-locked" \
                and (record.get("data") or {}).get("protocol", {}).get("sha256") == protocol_sha256:
            return record
    return None


def test_readouts(records: list[dict], data_sha256: str) -> int:
    """How often the test split of this exact data has been read before (Annex 22 draft §6.3)."""
    return sum(1 for r in records if r.get("type") == RUN and r.get("action") == "completed"
               and (r.get("data") or {}).get("split_read") == "test"
               and (r.get("data") or {}).get("data_sha256") == data_sha256)


def by_id(records: list[dict], record_id: str) -> dict | None:
    return next((r for r in records if r.get("id") == record_id), None)


def last_qualification(records: list[dict], subject_id: str, kind: str) -> dict | None:
    matches = [(r.get("time", ""), n, r) for n, r in enumerate(records)
               if r.get("type") == QUALIFICATION and r.get("action") in ("approve", "reject")
               and (r.get("data") or {}).get("subject_id") == subject_id and (r.get("data") or {}).get("kind") == kind]
    return max(matches, key=lambda m: m[:2])[2] if matches else None  # latest; ties: later in the log


def requalifications_for(records: list[dict], qualification_id: str) -> list[dict]:
    return [r for r in records if r.get("type") == REQUALIFICATION
            and (r.get("data") or {}).get("qualification") == qualification_id]
