"""Trend review: a management-review style summary of deviations and CAPA."""

from __future__ import annotations

import json
from collections import Counter

from .util import fmt_time, now as utc_now, parse_time


def _period(when, by: str) -> str:
    if by == "week":
        year, week, _ = when.isocalendar()
        return f"{year}-W{week:02d}"
    return when.strftime("%Y-%m")


def trends(capa, *, since=None, by: str = "month", now=None) -> dict:
    now = now or utc_now()
    store = capa.store
    devs = [dict(r) for r in store.q("SELECT * FROM deviations ORDER BY num")]
    in_range = [d for d in devs if since is None or parse_time(d["opened_at"]) >= since]
    periods: dict[str, dict] = {}
    for d in in_range:
        key = _period(parse_time(d["opened_at"]), by)
        bucket = periods.setdefault(key, {"total": 0, "by_category": Counter(), "by_severity": Counter(),
                                          "by_source": Counter()})
        bucket["total"] += 1
        bucket["by_category"][d["category"]] += 1
        bucket["by_severity"][d["severity"]] += 1
        bucket["by_source"][d["source_type"] or "manual"] += 1
    listed = {d["dev_id"]: d for d in capa.list(now=now)}
    open_devs = [{"dev_id": d["dev_id"], "severity": d["severity"], "category": d["category"], "state": d["state"],
                  "age_days": (now - parse_time(d["opened_at"])).days, "overdue": listed[d["dev_id"]]["overdue"]}
                 for d in devs if d["state"] != "closed"]
    open_actions, overdue_checks = [], []
    results = Counter()
    for act in store.q("SELECT a.*, d.state AS dev_state FROM actions a JOIN deviations d ON d.dev_id = a.dev_id"
                       " WHERE a.state != 'cancelled' ORDER BY a.dev_id, a.seq"):
        last = store.latest_evaluation(act["action_id"])
        if last and last.get("result") in ("effective", "not-effective"):
            results[last["result"]] += 1
        if act["dev_state"] == "closed":
            continue
        open_actions.append({"action_id": act["action_id"], "state": act["state"],
                             "result": (last or {}).get("result", "not evaluated")})
        if last and last.get("result") == "pending" and last.get("start"):
            window = last.get("window") or {}
            elapsed = (now - parse_time(last["start"])).days
            if elapsed >= (window.get("days") or 60):
                overdue_checks.append({"action_id": act["action_id"], "elapsed_days": elapsed,
                                       "reasons": last.get("reasons", [])})
    decided = results["effective"] + results["not-effective"]
    recurrence = Counter(r["ref"] for r in store.q("SELECT ref FROM links WHERE rel = 'recurrence-of'"))
    candidates = Counter(r["status"] for r in store.q("SELECT status FROM candidates"))
    return {
        "generated": fmt_time(now), "since": fmt_time(since) if since else None, "by": by,
        "deviations_in_range": len(in_range),
        "totals": {
            "by_category": dict(Counter(d["category"] for d in in_range)),
            "by_severity": dict(Counter(d["severity"] for d in in_range)),
            "by_source": dict(Counter(d["source_type"] or "manual" for d in in_range)),
        },
        "periods": {k: {"total": v["total"], "by_category": dict(v["by_category"]),
                        "by_severity": dict(v["by_severity"]), "by_source": dict(v["by_source"])}
                    for k, v in sorted(periods.items())},
        "open_deviations": open_devs,
        "open_actions": open_actions,
        "overdue_investigations": [d["dev_id"] for d in open_devs if d["overdue"]],
        "overdue_effectiveness_checks": overdue_checks,
        "effectiveness": {"effective": results["effective"], "not_effective": results["not-effective"],
                          "rate_ppm": (results["effective"] * 1_000_000) // decided if decided else None},
        "top_recurrences": [{"dev_id": k, "recurrences": v} for k, v in recurrence.most_common(5)],
        "candidates": {"undecided": candidates.get("open", 0), "accepted": candidates.get("accepted", 0),
                       "dismissed": candidates.get("dismissed", 0)},
        "evidence_sources": [str(p) for p in capa.evidence_paths] if capa.evidence_paths else "default (AQT_EVIDENCE or sink + trail log)",
    }


def _table(counter: dict) -> str:
    return ", ".join(f"{k} {v}" for k, v in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))) or "none"


def render_markdown(report: dict) -> str:
    eff = report["effectiveness"]
    rate = f"{eff['rate_ppm'] / 10_000:.1f} %" if eff["rate_ppm"] is not None else "n/a"
    lines = [
        "# CAPA trend review",
        "",
        f"Generated {report['generated']}; deviations opened since {report['since'] or 'the beginning'}: "
        f"**{report['deviations_in_range']}**. Evidence: {json.dumps(report['evidence_sources'])}.",
        "",
        "## Deviations",
        "",
        f"- By category: {_table(report['totals']['by_category'])}",
        f"- By severity: {_table(report['totals']['by_severity'])}",
        f"- By source: {_table(report['totals']['by_source'])}",
        "",
        f"| {report['by'].capitalize()} | Total | Categories | Severities |",
        "|---|---|---|---|",
    ]
    for key, value in report["periods"].items():
        lines.append(f"| {key} | {value['total']} | {_table(value['by_category'])} | {_table(value['by_severity'])} |")
    lines += ["", "## Open work", "",
              f"- Open deviations: {len(report['open_deviations'])}"
              + "".join(f"\n  - {d['dev_id']} ({d['severity']}, {d['category']}, {d['state']}, {d['age_days']} d"
                        + (", investigation overdue" if d["overdue"] else "") + ")" for d in report["open_deviations"]),
              f"- Open actions: {len(report['open_actions'])}"
              + "".join(f"\n  - {a['action_id']} ({a['state']}, {a['result']})" for a in report["open_actions"]),
              f"- Overdue effectiveness checks: {len(report['overdue_effectiveness_checks'])}"
              + "".join(f"\n  - {c['action_id']} ({c['elapsed_days']} d: {'; '.join(c['reasons'])})"
                        for c in report["overdue_effectiveness_checks"]),
              f"- Undecided candidates: {report['candidates']['undecided']} "
              f"(accepted {report['candidates']['accepted']}, dismissed {report['candidates']['dismissed']})",
              "", "## Effectiveness", "",
              f"- Effective {eff['effective']}, not effective {eff['not_effective']}; effectiveness rate {rate}",
              "- Top recurrences: " + (", ".join(f"{r['dev_id']} ({r['recurrences']})"
                                                for r in report["top_recurrences"]) or "none"),
              ""]
    return "\n".join(lines)
