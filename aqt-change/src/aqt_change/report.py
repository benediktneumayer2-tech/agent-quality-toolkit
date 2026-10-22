"""Trace report: task -> commits -> receipts -> reviews -> sign-offs, deviations, waivers, gate."""

from __future__ import annotations

import html
from pathlib import Path

from aqt_evidence import iter_evidence, record_content_hash

from .gate import evaluate_gate, latest_finish
from .gitio import trailers
from .ledger import Ledger
from .plan import EVENT_SECTIONS, Plan
from .plans import read_plan, require_valid, status

STATEMENT = ("Agent Quality Toolkit supports quality-management practices; it is not a validated system and "
             "does not by itself make any process compliant with GMP, GDP, 21 CFR Part 11 or EU Annex 11.")


def _task_commits(ledger: Ledger, plan: Plan, base: str | None) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    if not ledger.git:
        return found
    for sha, body in ledger.git.log(base):
        pairs = trailers(body)
        if not any(k == "AQT-Plan" and v.split(" ")[0] == plan.id for k, v in pairs):
            continue
        for key, value in pairs:
            if key == "AQT-Task":
                found.setdefault(value, []).append(sha[:12])
    return found


def _signoffs(ledger: Ledger, plan_id: str, sources: list[Path] | None) -> list[dict]:
    mine = {record_content_hash(r): r["id"] for r in ledger.records(plan_id=plan_id)}
    found = []
    try:
        for record in iter_evidence(sources):
            subj = record.get("subject") or {}
            if record.get("type") == "signoff.signature" and subj.get("sha256") in mine:
                found.append({"signature": record.get("id"), "record": mine[subj["sha256"]],
                              "meaning": record.get("meaning"), "signer": (record.get("actor") or {}).get("id"),
                              "time": record.get("time")})
    except Exception:
        pass
    return found


def build(ledger: Ledger, plan_path: str, sources: list[Path] | None = None) -> dict:
    rel, plan = read_plan(ledger, plan_path)
    require_valid(plan, rel)
    gate = evaluate_gate(ledger, rel, plan, sources=sources)
    state = ledger.plan_state(plan.id) or {}
    commits = _task_commits(ledger, plan, gate["scope"]["base_commit"])
    reviews = [r for r in ledger.records("change.review", plan.id)]
    history = [r for r in ledger.records("change.plan.reconciled", plan.id)]
    finish = latest_finish(ledger, plan.id)
    deviations = [e for e in plan.events if e.category in ("deviation", "failure", "blocker")]
    return {"plan": plan, "rel": rel, "gate": gate, "status": status(ledger, rel, ratchet=False),
            "state": state, "commits": commits, "reviews": reviews, "history": history, "finish": finish,
            "deviations": deviations, "signoffs": _signoffs(ledger, plan.id, sources)}


def _tables(info: dict) -> list[tuple[str, list[str] | None, list[list[str]], str | None]]:
    plan, gate = info["plan"], info["gate"]
    sections = []
    meta = [["Plan", f"{plan.id} — {plan.title}"], ["File", info["rel"]], ["Status", str(plan.status)],
            ["Ledger state", info["status"]["state"]], ["Accepted version", info["state"].get("accepted_raw", "-")],
            ["Base commit", str(gate["scope"]["base_commit"])],
            ["Approval", f"{gate['approval']['state']} ({gate['approval'].get('record') or '-'})"],
            ["Gate", gate["decision"]]]
    sections.append(("Summary", None, meta, None))
    sections.append(("Gate reasons", ["Code", "Item", "Detail"],
                     [[r["code"], r.get("item", ""), r.get("detail", "")] for r in gate["reasons"]],
                     "No open reasons." if not gate["reasons"] else None))
    sections.append(("Tasks", ["ID", "Done", "Task", "Commits"],
                     [[t.id, "x" if t.checked else "", t.text, ", ".join(info["commits"].get(t.id, []))]
                      for t in plan.tasks], None))
    rows = []
    for item_id, entry in gate["items"].items():
        if entry["manual"]:
            rows.append([item_id, entry["text"], "manual", entry["state"],
                         f"attested by {entry.get('attested_by')}" if entry.get("receipt") else "", entry.get("receipt") or ""])
        for command in entry["commands"]:
            counts = command.get("counts") or {}
            rows.append([item_id, entry["text"], command["command"], command["state"],
                         f"{counts.get('passed', 0)}/{counts.get('total', 0)} passed" if counts else (command.get("outcome") or ""),
                         command.get("receipt") or ""])
    sections.append(("Verification", ["ID", "Item", "Command", "State", "Result", "Receipt"], rows, None))
    sections.append(("Reviews", ["Record", "Reviewer", "Independence", "Verdict", "Findings", "Summary"],
                     [[r["id"], r["data"]["reviewer"].get("id", ""), r["data"]["independence"], r["data"]["verdict"],
                       str(len(r["data"].get("findings", []))), r.get("reason", "")] for r in info["reviews"]],
                     "No reviews recorded." if not info["reviews"] else None))
    sections.append(("Sign-offs", ["Signature", "Signs record", "Meaning", "Signer", "Time"],
                     [[s["signature"], s["record"], str(s["meaning"]), str(s["signer"]), str(s["time"])]
                      for s in info["signoffs"]], "No sign-offs found." if not info["signoffs"] else None))
    sections.append(("Plan history", ["Record", "Action", "Kind", "Actor", "Reason", "Items changed"],
                     [[r["id"], r["action"], r["data"].get("kind", ""), r["actor"]["id"], r.get("reason", ""),
                       _items(r["data"].get("items"))] for r in info["history"]], None))
    scope = gate["scope"]
    sections.append(("Approved scope versus actual diff", ["Path", "Change", "Approved"],
                     [[c["path"], c["status"], "no" if c["path"] in scope["unapproved"] else "yes"]
                      for c in scope["changed"]],
                     f"Declared paths: {', '.join(scope['declared_paths']) or 'none'}. Result: {scope['result']}."))
    sections.append(("Deviations, failures and blockers", ["Time", "Kind", "Title"],
                     [[e.timestamp, e.category, e.title] for e in info["deviations"]],
                     "None recorded in the plan." if not info["deviations"] else None))
    sections.append(("Waivers", ["Item", "Reason"], [[w["item"], w["reason"]] for w in gate["waivers"]],
                     "No waivers." if not gate["waivers"] else None))
    sections.append(("Anti-gaming warnings", ["Code", "Path", "Detail"],
                     [[w["code"], w.get("path", ""), w.get("detail", "")] for w in gate["warnings"]],
                     "No warnings." if not gate["warnings"] else None))
    finish = info["finish"]
    sections.append(("Finish", None, [["Record", finish["id"]], ["Commit", str(finish["data"].get("commit"))],
                                      ["Gate at finish", finish["data"]["gate"]]] if finish else [],
                     "Not finished." if not finish else None))
    return sections


def _items(items: dict | None) -> str:
    if not items:
        return ""
    parts = [f"{k}: {', '.join(v)}" for k, v in items.items() if v]
    return "; ".join(parts)


def _md_cell(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_markdown(info: dict) -> str:
    plan = info["plan"]
    out = [f"# Change report: {plan.id}", ""]
    for title, header, rows, note in _tables(info):
        out += [f"## {title}", ""]
        if header is None:
            out += [f"- **{_md_cell(k)}:** {_md_cell(v)}" for k, v in rows]
        elif rows:
            out.append("| " + " | ".join(header) + " |")
            out.append("|" + "---|" * len(header))
            out += ["| " + " | ".join(_md_cell(c) for c in row) + " |" for row in rows]
        if note:
            out += ["", note] if rows else [note]
        out.append("")
    out += ["---", "", f"*{STATEMENT}*", ""]
    return "\n".join(out)


def render_html(info: dict) -> str:
    plan = info["plan"]
    esc = html.escape
    body = [f"<h1>Change report: {esc(plan.id)}</h1>"]
    for title, header, rows, note in _tables(info):
        body.append(f"<h2>{esc(title)}</h2>")
        if header is None:
            body.append("<dl>" + "".join(f"<dt>{esc(str(k))}</dt><dd>{esc(str(v))}</dd>" for k, v in rows) + "</dl>")
        elif rows:
            body.append("<table><thead><tr>" + "".join(f"<th>{esc(h)}</th>" for h in header) + "</tr></thead><tbody>"
                        + "".join("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in row) + "</tr>" for row in rows)
                        + "</tbody></table>")
        if note:
            body.append(f"<p>{esc(note)}</p>")
    body.append(f"<hr><p><em>{esc(STATEMENT)}</em></p>")
    style = ("body{font-family:system-ui,sans-serif;max-width:72rem;margin:2rem auto;padding:0 1rem;color:#1d1d1f;"
             "background:#fff}table{border-collapse:collapse;width:100%;margin:.5rem 0 1rem}th,td{border:1px solid "
             "#ccc;padding:.3rem .5rem;text-align:left;vertical-align:top;font-size:.9rem}th{background:#f2f2f2}"
             "dt{font-weight:600}dd{margin:0 0 .4rem 0}@media (prefers-color-scheme:dark){body{background:#151515;"
             "color:#eee}th{background:#262626}th,td{border-color:#444}}")
    return ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" "
            "content=\"width=device-width,initial-scale=1\"><title>Change report " + esc(plan.id) + "</title><style>"
            + style + "</style></head><body>" + "".join(body) + "</body></html>\n")
