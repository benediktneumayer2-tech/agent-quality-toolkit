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

from .review import anchored_seq, attribution, is_writer_record
from .text import md
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
    """``records`` may be a selection (``--since``/``--until``); ``report`` is the verification of the whole trail."""
    results = []
    socket_records = [r for r in records if _observed(r).get("via") == "socket"]
    spooled = [r for r in records if _observed(r).get("via") == "spool"]
    states = [attribution(r) for r in records]
    agent, unconfirmed, legacy = (states.count(state) for state in ("agent", "unconfirmed", "legacy"))
    note = (f"; {legacy} human-claimed record(s) predate observed.chain_status and rest on the absence of agent "
            "markers" if legacy else "")
    if agent:
        results.append(_result("attributable", "fail", f"{agent} record(s) claim a human but came from an "
                                                      f"agent harness{note}"))
    elif unconfirmed or spooled:
        parts = ([f"{unconfirmed} record(s) claim a human but the sender's process chain was incomplete or "
                  "unreadable"] if unconfirmed else []) + \
                ([f"{len(spooled)} record(s) arrived via the spool; their sender was not observed"] if spooled else [])
        results.append(_result("attributable", "warn", "; ".join(parts) + note))
    else:
        results.append(_result("attributable", "pass", f"every record has an actor; {len(socket_records)} of "
                                                      f"{len(records)} carry observed peer attribution{note}"))

    invalid = [r for r in records if validate_record(r)]
    results.append(_result("legible", "fail" if invalid else "pass",
                           f"{len(invalid)} record(s) fail the envelope check" if invalid else
                           "all records are canonical JSON with a valid envelope and render in the report"))

    skewed = []
    for record in socket_records:
        client, service = _time(_observed(record).get("client_time")), _time(record.get("time"))
        if client and service and abs((service - client).total_seconds()) * 1000 > skew_ms:
            skewed.append(record)
    imported = [r for r in records if r.get("type") == "trail.import" and isinstance(r.get("data"), dict)
                and "source_time" in r["data"]]
    jumps = [r for r in records if r.get("action") == "clock.jump"]
    status = "warn" if skewed or jumps else "pass"
    results.append(_result("contemporaneous", status,
                           f"writer time on every record; {len(skewed)} with client skew > {skew_ms} ms, "
                           f"{len(jumps)} clock jump(s); {len(imported)} retrospective import(s) keep their "
                           f"source time in data.source_time"))

    # verification problems that are not about detached signatures: checkpoints, heads, anchors, payloads
    integrity = [p for p in report.problems if p not in report.signature_problems]
    truncated = [p for p in integrity if "truncated" in p]
    chain_ok = report.first_bad_seq is None and not integrity
    results.append(_result("original", "pass" if chain_ok else "fail",
                           "hash chain, service signatures, checkpoints, heads and anchors intact" if chain_ok else
                           "broken: " + "; ".join(([str(report.reason)] if report.first_bad_seq is not None else [])
                                                  + integrity[:3])))

    unknown = [w for w in report.warnings if "signature" in w and ("registry" in w or "not checked" in w)]
    results.append(_result("accurate", "fail" if report.signature_problems else ("warn" if unknown else "pass"),
                           "; ".join(report.signature_problems[:3] or unknown) or
                           f"{report.signatures} detached signature(s) verified; verification re-computes every hash"))

    gaps = [r for r in records if r.get("type") == "trail.gap" or r.get("action") == "log.repaired"]
    complete_ok = report.first_bad_seq is None and not truncated
    results.append(_result("complete", "fail" if not complete_ok else ("warn" if gaps or spooled else "pass"),
                           f"sequence {'continuous' if complete_ok else 'broken or truncated'}; {len(gaps)} gap "
                           f"marker(s), {len(spooled)} spooled record(s)"))

    keys = {s.get("key") for r in records for s in (r.get("sig") if isinstance(r.get("sig"), list) else [])
            if isinstance(s, dict)}
    backwards = sum(1 for a, b in zip(records, records[1:]) if str(b.get("time")) < str(a.get("time")))
    results.append(_result("consistent", "warn" if backwards or len(keys) > 1 else "pass",
                           f"{len(keys)} service key(s); writer time went backwards {backwards} time(s)"))

    anchors = [r for r in records if anchored_seq(r) is not None]
    exported = [r for r in records if r.get("type") == "trail.anchor" and r.get("action") == "external-head"
                and is_writer_record(r)]
    forged = [r for r in records if r.get("type") == "trail.anchor" and not is_writer_record(r)]
    ignored = f"; {len(forged)} trail.anchor record(s) not written by the writer were ignored" if forged else ""
    if not anchors:
        results.append(_result("enduring", "warn" if exported else "fail",
                               (f"no RFC 3161 anchor; {len(exported)} exported head(s) noted (they count only where "
                                "you keep them: verify --heads)" if exported else
                                "no anchor: a rewrite of the whole trail would go unnoticed") + ignored))
    else:
        last = _time(anchors[-1].get("time"))
        newest = _time(records[-1].get("time")) if records else last
        age = (newest - last) if last and newest else timedelta(0)
        verified = report.anchors_verified
        stale = age > timedelta(hours=unanchored_hours)
        results.append(_result("enduring", "warn" if stale or not verified or forged else "pass",
                               f"{len(anchors)} anchor(s), {verified} RFC 3161 token(s) verified to a CA; newest "
                               f"record is {int(age.total_seconds() // 3600)} h after the last anchor{ignored}"))

    if export_check is None:
        results.append(_result("available", "warn", "export not checked"))
    else:
        ok, detail = export_check()
        results.append(_result("available", "pass" if ok else "fail", detail))

    ids = {r.get("id") for r in records}
    links = [link for r in records for link in (r.get("links") if isinstance(r.get("links"), list) else [])
             if isinstance(link, dict)]
    unresolved = [link["ref"] for link in links if str(link.get("ref", "")).startswith("rec_") and link["ref"] not in ids]
    external = [link.get("ref") for link in links if not str(link.get("ref", "")).startswith("rec_")]
    results.append(_result("traceable", "warn" if unresolved else "pass",
                           f"{len(unresolved)} record link(s) point outside this trail; {len(external)} external "
                           "reference(s)"))
    return results


def _observed(record) -> dict:
    return record.get("observed") if isinstance(record.get("observed"), dict) else {}


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
        lines += [f"| {r['attribute']} | `{r['id']}` | {r['status']} | {md(r['detail'])} |" for r in results]
        return "\n".join(lines) + "\n"
    return "\n".join(f"{r['status'].upper():5} {r['id']:24} {r['detail']}" for r in results) + "\n"
