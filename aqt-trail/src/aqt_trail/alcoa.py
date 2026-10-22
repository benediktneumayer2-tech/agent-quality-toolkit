"""ALCOA++ report: what the trail demonstrates per attribute, and where it falls short.

Each result cites catalogue IDs (aqt-spec spec §13: ``alcoa:<attribute>`` plus
related clauses). ``pass`` means the check found nothing; it does not mean any
process is compliant.
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timedelta
from pathlib import Path

from aqt_evidence import validate_record

from .review import q_attribution_mismatch
from .verify import TrailReport

RELATED = {
    "attributable": ["annex11-2025d:12.2", "annex11-2011:12.4", "ch4-2025d:4.63"],
    "legible": ["annex11-2025d:12.4", "ch4-2025d:4.63"],
    "contemporaneous": ["annex11-2025d:12.2", "ch4-2025d:4.63"],
    "original": ["annex11-2025d:12.3", "part11:11.10(e)"],
    "accurate": ["ch4-2025d:4.63", "part11:11.70"],
    "complete": ["annex11-2025d:12.1", "ch4-2025d:4.63"],
    "consistent": ["ch4-2025d:4.63"],
    "enduring": ["annex11-2025d:16", "part11:11.10(c)"],
    "available": ["annex11-2025d:12.9", "part11:11.10(b)"],
    "traceable": ["ch4-2025d:4.63"],
}


def _time(value) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _result(attribute, status, detail):
    return {"attribute": attribute, "id": f"alcoa:{attribute}", "related": RELATED[attribute],
            "status": status, "detail": detail}


def alcoa_report(records: list[dict], report: TrailReport, *, skew_ms: int = 5000, unanchored_hours: int = 24,
                 export_check=None, now: datetime | None = None) -> list[dict]:
    results = []
    socket_records = [r for r in records if (r.get("observed") or {}).get("via") == "socket"]
    spooled = [r for r in records if (r.get("observed") or {}).get("via") == "spool"]
    mismatches = [f for f in q_attribution_mismatch(records, records, {}) if f["severity"] == "major"]
    if mismatches:
        results.append(_result("attributable", "fail", f"{len(mismatches)} record(s) claim a human but came from an "
                                                      "agent harness"))
    elif spooled:
        results.append(_result("attributable", "warn", f"{len(spooled)} record(s) arrived via the spool; their "
                                                      "sender was not observed"))
    else:
        results.append(_result("attributable", "pass", f"every record has an actor; {len(socket_records)} of "
                                                      f"{len(records)} carry observed peer attribution"))

    invalid = [r for r in records if validate_record(r)]
    results.append(_result("legible", "fail" if invalid else "pass",
                           f"{len(invalid)} record(s) fail the envelope check" if invalid else
                           "all records are canonical JSON with a valid envelope and render in the report"))

    skewed = []
    for record in socket_records:
        client, service = _time(record["observed"].get("client_time")), _time(record["time"])
        if client and service and abs((service - client).total_seconds()) * 1000 > skew_ms:
            skewed.append(record)
    imported = [r for r in records if r.get("type") == "trail.import" and "source_time" in (r.get("data") or {})]
    jumps = [r for r in records if r.get("action") == "clock.jump"]
    status = "warn" if skewed or jumps else "pass"
    results.append(_result("contemporaneous", status,
                           f"writer time on every record; {len(skewed)} with client skew > {skew_ms} ms, "
                           f"{len(jumps)} clock jump(s); {len(imported)} retrospective import(s) keep their "
                           f"source time in data.source_time"))

    chain_ok = report.first_bad_seq is None and report.count == len(records)
    results.append(_result("original", "pass" if chain_ok else "fail",
                           f"hash chain and service signatures {'intact' if chain_ok else 'broken: ' + str(report.reason)}"))

    signature_problems = [p for p in report.problems if "detached signature" in p]
    unknown = [w for w in report.warnings if "detached signature" in w]
    results.append(_result("accurate", "fail" if signature_problems else ("warn" if unknown else "pass"),
                           "; ".join(signature_problems or unknown) or
                           f"{report.signatures} detached signature(s) verified; verification re-computes every hash"))

    gaps = [r for r in records if r.get("type") == "trail.gap" or r.get("action") == "log.repaired"]
    results.append(_result("complete", "fail" if not chain_ok else ("warn" if gaps or spooled else "pass"),
                           f"sequence {'continuous' if chain_ok else 'broken'}; {len(gaps)} gap marker(s), "
                           f"{len(spooled)} spooled record(s)"))

    keys = {s.get("key") for r in records for s in r.get("sig", [])}
    backwards = sum(1 for a, b in zip(records, records[1:]) if b["time"] < a["time"])
    results.append(_result("consistent", "warn" if backwards or len(keys) > 1 else "pass",
                           f"{len(keys)} service key(s); writer time went backwards {backwards} time(s)"))

    anchors = [r for r in records if r.get("type") == "trail.anchor"]
    if not anchors:
        results.append(_result("enduring", "fail", "no anchor: a rewrite of the whole trail would go unnoticed"))
    else:
        last = _time(anchors[-1]["time"])
        newest = _time(records[-1]["time"]) if records else last
        age = (newest - last) if last and newest else timedelta(0)
        verified = report.anchors_verified
        stale = age > timedelta(hours=unanchored_hours)
        results.append(_result("enduring", "warn" if stale or not verified else "pass",
                               f"{len(anchors)} anchor(s), {verified} RFC 3161 token(s) verified to a CA; newest "
                               f"record is {int(age.total_seconds() // 3600)} h after the last anchor"))

    if export_check is None:
        results.append(_result("available", "warn", "export not checked"))
    else:
        ok, detail = export_check()
        results.append(_result("available", "pass" if ok else "fail", detail))

    ids = {r["id"] for r in records}
    unresolved = [link["ref"] for r in records for link in r.get("links", [])
                  if str(link.get("ref", "")).startswith("rec_") and link["ref"] not in ids]
    external = [link["ref"] for r in records for link in r.get("links", [])
                if not str(link.get("ref", "")).startswith("rec_")]
    results.append(_result("traceable", "warn" if unresolved else "pass",
                           f"{len(unresolved)} record link(s) point outside this trail; {len(external)} external "
                           "reference(s)"))
    return results


def export_dry_run(config) -> tuple[bool, str]:
    from .export import export_bundle, verify_bundle

    with tempfile.TemporaryDirectory() as tmp:
        try:
            bundle = export_bundle(config, Path(tmp) / "bundle")
            result = verify_bundle(bundle)
        except Exception as error:  # report, do not crash the report
            return False, f"export failed: {error}"
    return result.first_bad_seq is None, f"export bundle re-verifies: {result.summary()}"


def render(results: list[dict], fmt: str = "text") -> str:
    if fmt == "md":
        lines = ["| Attribute | Catalogue | Status | Detail |", "|---|---|---|---|"]
        lines += [f"| {r['attribute']} | `{r['id']}` | {r['status']} | {r['detail']} |" for r in results]
        return "\n".join(lines) + "\n"
    return "\n".join(f"{r['status'].upper():5} {r['id']:24} {r['detail']}" for r in results) + "\n"
