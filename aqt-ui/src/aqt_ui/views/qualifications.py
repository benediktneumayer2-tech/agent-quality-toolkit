"""Qualifications view, read-only: the latest ``validate.qualification`` per detector or AI
reviewer, its expiry, requalification triggers already recorded, and the quarantine
thresholds in use. Nothing is re-checked here (``aqt-validate check`` would write
``validate.requalification`` records); expiry is computed from the recorded dates."""

from __future__ import annotations

from datetime import UTC, datetime

from aqt_evidence import SinkError, iter_evidence

from . import evidence_fingerprint, installed
from .trail import parse_time

_CACHE: dict = {}


def _records() -> list[dict]:
    """``validate.*`` records, re-read only when an evidence file changed (large trails)."""
    key = evidence_fingerprint()
    if _CACHE.get("key") == key:
        return _CACHE["records"]
    try:
        records = [r for r in iter_evidence() if isinstance(r, dict) and str(r.get("type", "")).startswith("validate.")]
    except (SinkError, OSError):
        return []
    _CACHE.update(key=key, records=records)
    return records


def thresholds_in_use() -> dict | None:
    if not installed("aqt_quarantine"):
        return None
    from aqt_quarantine import thresholds as thresholds_mod
    from aqt_quarantine.config import load_config
    config = load_config()
    try:
        info = thresholds_mod.load(config.thresholds).summary()
    except thresholds_mod.ThresholdsError as error:
        return {"error": str(error), "path": config.thresholds}
    return {**info, "path": config.thresholds or str(thresholds_mod.default_path())}


def qualifications(warn_days: int = 30, *, now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    records = _records()
    latest: dict[tuple, dict] = {}
    for record in records:
        if record.get("type") != "validate.qualification" or record.get("action") not in ("approve", "reject"):
            continue
        data = record.get("data") or {}
        key = (data.get("subject_id"), data.get("kind"))
        if key not in latest or str(record.get("time", "")) >= str(latest[key].get("time", "")):
            latest[key] = record
    thresholds = thresholds_in_use()
    rows = []
    for (subject_id, kind), record in sorted(latest.items(), key=lambda item: str(item[0])):
        data = record.get("data") or {}
        until = parse_time(data.get("valid_until"))
        days_left = int((until - now).total_seconds() // 86400) if until else None
        triggers = [r for r in records if r.get("type") == "validate.requalification"
                    and (r.get("data") or {}).get("qualification") == record.get("id")]
        fired = sorted({f.get("trigger") for t in triggers for f in ((t.get("data") or {}).get("fired") or [])
                        if isinstance(f, dict)} | {(t.get("data") or {}).get("trigger") for t in triggers} - {None})
        if data.get("decision") == "reject":
            state = "rejected"
        elif fired:
            state = "triggered"
        elif days_left is None or days_left < 0:
            state = "expired"
        elif days_left <= warn_days:
            state = "expiring"
        else:
            state = "valid"
        same_thresholds = None
        if thresholds and data.get("thresholds_sha256") and thresholds.get("sha256"):
            same_thresholds = thresholds["sha256"] == data["thresholds_sha256"]
        rows.append({"subject_id": subject_id, "kind": kind, "state": state, "decision": data.get("decision"),
                     "conclusion": data.get("conclusion"), "valid_until": data.get("valid_until"),
                     "days_left": days_left, "approver": (record.get("actor") or {}).get("id"),
                     "approver_name": (record.get("actor") or {}).get("display"), "record": record.get("id"),
                     "time": record.get("time"), "reason": record.get("reason"), "triggers": fired,
                     "report": data.get("report"), "band": data.get("band"),
                     "expected_fpr_upper_ppm": data.get("expected_fpr_upper_ppm"),
                     "thresholds_sha256": data.get("thresholds_sha256"), "same_thresholds": same_thresholds,
                     "protocol": data.get("protocol")})
    order = {"triggered": 0, "expired": 1, "rejected": 2, "expiring": 3, "valid": 4}
    rows.sort(key=lambda r: order.get(r["state"], 9))
    reports = {r.get("id"): r for r in records if r.get("type") == "validate.report"}
    for row in rows:
        report = reports.get(row["report"]) or {}
        row["report_summary"] = {"time": report.get("time"), "reason": report.get("reason"),
                                 "subject": (report.get("subject") or {}).get("ref"),
                                 "data": {k: v for k, v in (report.get("data") or {}).items()
                                          if k in ("conclusion", "criteria", "bands", "subject_id", "kind",
                                                   "thresholds_sha256", "confidence_ppm")}} if report else None
    return {"installed": installed("aqt_validate"), "qualifications": rows, "thresholds": thresholds,
            "warn_days": warn_days}
