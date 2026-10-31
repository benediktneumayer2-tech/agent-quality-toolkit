"""ALCOA++ report: what the trail demonstrates per attribute, and where it falls short.

Each result cites catalogue IDs (aqt-spec spec §13: ``alcoa:<attribute>`` plus
related clauses). ``pass`` means the check found nothing; it does not mean any
process is compliant.
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timedelta
from pathlib import Path

from aqt_evidence import Text, text_join, validate_record

from .review import anchored_seq, attribution, is_test_anchor, is_writer_record
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
                 export_check=None, now: datetime | None = None, test_tsa: bool = False) -> list[dict]:
    """``records`` may be a selection (``--since``/``--until``); ``report`` is the verification of the whole trail.
    TEST ONLY anchors count for ``enduring`` only with ``test_tsa``; exported-head notes never do (only head copies
    that ``verify --heads`` matched, ``report.covered_seq``)."""
    results = []
    socket_records = [r for r in records if _observed(r).get("via") == "socket"]
    spooled = [r for r in records if _observed(r).get("via") == "spool"]
    states = [attribution(r) for r in records]
    agent, unconfirmed, legacy = (states.count(state) for state in ("agent", "unconfirmed", "legacy"))
    note = [Text("trail.alcoa.legacy", "{n} human-claimed record(s) predate observed.chain_status and rest on the "
                 "absence of agent markers", n=legacy)] if legacy else []
    if agent:
        results.append(_result("attributable", "fail", text_join("; ", [Text(
            "trail.alcoa.agent", "{n} record(s) claim a human but came from an agent harness", n=agent), *note])))
    elif unconfirmed or spooled:
        parts = ([Text("trail.alcoa.unconfirmed", "{n} record(s) claim a human but the sender's process chain was "
                       "incomplete or unreadable", n=unconfirmed)] if unconfirmed else []) + \
                ([Text("trail.alcoa.spooled", "{n} record(s) arrived via the spool; their sender was not observed",
                       n=len(spooled))] if spooled else [])
        results.append(_result("attributable", "warn", text_join("; ", parts + note)))
    else:
        results.append(_result("attributable", "pass", text_join("; ", [Text(
            "trail.alcoa.attributed", "every record has an actor; {observed} of {n} carry observed peer attribution",
            observed=len(socket_records), n=len(records)), *note])))

    invalid = [r for r in records if validate_record(r)]
    results.append(_result("legible", "fail" if invalid else "pass",
                           Text("trail.alcoa.envelope_fail", "{n} record(s) fail the envelope check", n=len(invalid))
                           if invalid else Text("trail.alcoa.legible", "all records are canonical JSON with a valid "
                                                "envelope and render in the report")))

    skewed = []
    for record in socket_records:
        client, service = _time(_observed(record).get("client_time")), _time(record.get("time"))
        if client and service and abs((service - client).total_seconds()) * 1000 > skew_ms:
            skewed.append(record)
    imported = [r for r in records if r.get("type") == "trail.import" and isinstance(r.get("data"), dict)
                and "source_time" in r["data"]]
    jumps = [r for r in records if r.get("action") == "clock.jump"]
    status = "warn" if skewed or jumps else "pass"
    results.append(_result("contemporaneous", status, Text(
        "trail.alcoa.contemporaneous", "writer time on every record; {skewed} with client skew > {skew_ms} ms, "
        "{jumps} clock jump(s); {imported} retrospective import(s) keep their source time in data.source_time",
        skewed=len(skewed), skew_ms=skew_ms, jumps=len(jumps), imported=len(imported))))

    # verification problems that are not about detached signatures: checkpoints, heads, anchors, payloads
    integrity = [p for p in report.problems if p not in report.signature_problems]
    truncated = [p for p in integrity if "truncated" in p]
    chain_ok = report.first_bad_seq is None and not integrity
    reason = report.reason if isinstance(report.reason, str) else str(report.reason)
    results.append(_result("original", "pass" if chain_ok else "fail",
                           Text("trail.alcoa.original", "hash chain, service signatures, checkpoints, heads and "
                                "anchors intact") if chain_ok else
                           Text("trail.alcoa.original_broken", "broken: {problems}", problems=text_join(
                               "; ", ([reason] if report.first_bad_seq is not None else []) + integrity[:3]))))

    unknown = [w for w in report.warnings if "signature" in w and ("registry" in w or "not checked" in w)]
    results.append(_result("accurate", "fail" if report.signature_problems else ("warn" if unknown else "pass"),
                           text_join("; ", report.signature_problems[:3] or unknown) or
                           Text("trail.alcoa.accurate", "{n} detached signature(s) verified; verification re-computes "
                                "every hash", n=report.signatures)))

    gaps = [r for r in records if r.get("type") == "trail.gap" or r.get("action") == "log.repaired"]
    complete_ok = report.first_bad_seq is None and not truncated
    counts = {"gaps": len(gaps), "spooled": len(spooled)}
    results.append(_result("complete", "fail" if not complete_ok else ("warn" if gaps or spooled else "pass"),
                           Text("trail.alcoa.complete", "sequence continuous; {gaps} gap marker(s), {spooled} spooled "
                                "record(s)", **counts) if complete_ok else
                           Text("trail.alcoa.incomplete", "sequence broken or truncated; {gaps} gap marker(s), "
                                "{spooled} spooled record(s)", **counts)))

    keys = {s.get("key") for r in records for s in (r.get("sig") if isinstance(r.get("sig"), list) else [])
            if isinstance(s, dict)}
    backwards = sum(1 for a, b in zip(records, records[1:]) if str(b.get("time")) < str(a.get("time")))
    results.append(_result("consistent", "warn" if backwards or len(keys) > 1 else "pass", Text(
        "trail.alcoa.consistent", "{keys} service key(s); writer time went backwards {n} time(s)", keys=len(keys),
        n=backwards)))

    anchors = [r for r in records if anchored_seq(r, test_tsa=test_tsa) is not None]
    exported = [r for r in records if r.get("type") == "trail.anchor" and r.get("action") == "external-head"
                and is_writer_record(r)]
    forged = [r for r in records if r.get("type") == "trail.anchor" and not is_writer_record(r)]
    tests = [] if test_tsa else [r for r in records if r.get("type") == "trail.anchor" and is_writer_record(r)
                                 and r.get("action") == "rfc3161" and is_test_anchor(r)]
    ignored = ([Text("trail.alcoa.forged_anchors", "{n} trail.anchor record(s) not written by the writer were "
                     "ignored", n=len(forged))] if forged else []) + \
              ([Text("trail.alcoa.test_anchors", "{n} TEST ONLY anchor(s) not counted (--test-tsa)", n=len(tests))]
               if tests else [])
    if not anchors:
        noted = [Text("trail.alcoa.exported_heads", "{n} exported head(s) noted (they count only where you keep "
                      "them: verify --heads)", n=len(exported))] if exported else []
        if report.covered_seq is not None:
            results.append(_result("enduring", "warn", text_join("; ", [Text(
                "trail.alcoa.heads_cover", "no RFC 3161 anchor counted; head copies matched by verify --heads or "
                "CA-verified anchors cover seq {seq}", seq=report.covered_seq), *noted, *ignored])))
        else:
            results.append(_result("enduring", "fail", text_join("; ", [Text(
                "trail.alcoa.no_anchor", "no anchor: a rewrite of the whole trail would go unnoticed"),
                *noted, *ignored])))
    else:
        last = _time(anchors[-1].get("time"))
        newest = _time(records[-1].get("time")) if records else last
        age = (newest - last) if last and newest else timedelta(0)
        verified = report.anchors_verified
        stale = age > timedelta(hours=unanchored_hours)
        results.append(_result("enduring", "warn" if stale or not verified or forged else "pass", text_join("; ", [
            Text("trail.alcoa.anchors", "{n} anchor(s), {verified} RFC 3161 token(s) verified to a CA; newest record "
                 "is {hours} h after the last anchor", n=len(anchors), verified=verified,
                 hours=int(age.total_seconds() // 3600)), *ignored])))

    if export_check is None:
        results.append(_result("available", "warn", Text("trail.alcoa.export_unchecked", "export not checked")))
    else:
        ok, detail = export_check()
        results.append(_result("available", "pass" if ok else "fail", detail))

    ids = {r.get("id") for r in records}
    links = [link for r in records for link in (r.get("links") if isinstance(r.get("links"), list) else [])
             if isinstance(link, dict)]
    unresolved = [link["ref"] for link in links if str(link.get("ref", "")).startswith("rec_") and link["ref"] not in ids]
    external = [link.get("ref") for link in links if not str(link.get("ref", "")).startswith("rec_")]
    results.append(_result("traceable", "warn" if unresolved else "pass", Text(
        "trail.alcoa.traceable", "{n} record link(s) point outside this trail; {external} external reference(s)",
        n=len(unresolved), external=len(external))))
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
            return False, Text("trail.alcoa.export_failed", "export failed: {error}", error=str(error))
    return result.first_bad_seq is None, Text("trail.alcoa.export_verifies", "export bundle re-verifies: {summary}",
                                              summary=result.summary())


def render(results: list[dict], fmt: str = "text") -> str:
    if fmt == "md":
        lines = ["| Attribute | Catalogue | Status | Detail |", "|---|---|---|---|"]
        lines += [f"| {r['attribute']} | `{r['id']}` | {r['status']} | {md(r['detail'])} |" for r in results]
        return "\n".join(lines) + "\n"
    return "\n".join(f"{r['status'].upper():5} {r['id']:24} {r['detail']}" for r in results) + "\n"
