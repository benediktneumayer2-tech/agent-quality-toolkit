"""Signature manifestation: a readable signature block (Markdown or HTML).

Shows printed name, signer id, role, meaning, local date/time with zone (and UTC),
reason and current status for each signature, plus the content hash, so a printed
copy can be matched to the electronic record. The block is rendered separately:
appending it to the signed file would change the file and invalidate the signatures.
"""

from __future__ import annotations

import html
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .core import VerifyReport
from .registry import parse_time


def local_time(utc: str | None, tz: str | None) -> str:
    if not utc:
        return "?"
    moment = parse_time(utc)
    try:
        zone = ZoneInfo(tz or "UTC")
    except (ZoneInfoNotFoundError, ValueError):
        zone, tz = ZoneInfo("UTC"), "UTC"
    local = moment.astimezone(zone)
    return f"{local:%Y-%m-%d %H:%M:%S} {local.tzname()} ({tz or 'UTC'})"


def rows(report: VerifyReport) -> list[dict]:
    out = []
    for s in sorted(report.signatures, key=lambda s: s.signed_at or ""):
        out.append({"name": s.name or "?", "id": s.signer_id or "?", "role": s.role or "?",
                    "meaning": s.meaning or "?", "local": local_time(s.signed_at, s.tz),
                    "utc": s.signed_at or "?", "reason": s.reason or "", "status": s.status,
                    "detail": s.detail, "record": s.record_id or ""})
    return out


def _md(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def render_markdown(report: VerifyReport) -> str:
    subject = report.subject
    lines = ["## Electronic signatures", "",
             f"**Content:** `{_md(subject.get('ref', ''))}`  ",
             f"**SHA-256:** `{subject.get('sha256', '')}`  ",
             f"**Verification:** {report.summary()}", "",
             "| Printed name | Signer ID | Role | Meaning | Date and time | Reason | Status |",
             "|---|---|---|---|---|---|---|"]
    for r in rows(report):
        status = r["status"] + (f" ({r['detail']})" if r["detail"] and r["status"] != "valid" else "")
        lines.append(f"| {_md(r['name'])} | {_md(r['id'])} | {_md(r['role'])} | {r['meaning']} | "
                     f"{r['local']}<br>{r['utc']} | {_md(r['reason'])} | {_md(status)} |")
    if not report.signatures:
        lines.append("| — | — | — | — | — | — | unsigned |")
    for meaning, result in report.policies.items():
        lines.append("")
        lines.append(f"Policy `{meaning}`: {'met' if result.met else 'NOT met'} "
                     f"({result.count} of {result.policy.min_signatures}){' — ' + result.note if result.note else ''}")
    lines += ["", "_Verify with `aqt-signoff verify`. A signature applies only to content with the SHA-256 above._", ""]
    return "\n".join(lines)


def render_html(report: VerifyReport) -> str:
    esc = html.escape
    subject = report.subject
    body = []
    for r in rows(report):
        status = r["status"] + (f" ({r['detail']})" if r["detail"] and r["status"] != "valid" else "")
        body.append(f"<tr class=\"{esc(r['status'])}\"><td>{esc(r['name'])}</td><td>{esc(r['id'])}</td>"
                    f"<td>{esc(r['role'])}</td><td>{esc(r['meaning'])}</td>"
                    f"<td>{esc(r['local'])}<br><small>{esc(r['utc'])}</small></td><td>{esc(r['reason'])}</td>"
                    f"<td>{esc(status)}</td></tr>")
    if not body:
        body.append("<tr><td colspan=\"7\">unsigned</td></tr>")
    policies = "".join(f"<li>Policy <code>{esc(m)}</code>: {'met' if p.met else 'NOT met'} "
                       f"({p.count} of {p.policy.min_signatures}) {esc(p.note)}</li>"
                       for m, p in report.policies.items())
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Electronic signatures</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #111; background: #fff; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #999; padding: .4rem .6rem; text-align: left; vertical-align: top; }}
tr.valid td:last-child {{ color: #0a5d1e; font-weight: 600; }}
tr.invalidated td:last-child, tr.invalid td:last-child, tr.revoked td:last-child,
tr.unknown-signer td:last-child {{ color: #a01010; font-weight: 600; }}
code {{ word-break: break-all; }}
</style></head><body>
<h2>Electronic signatures</h2>
<p><strong>Content:</strong> <code>{esc(subject.get('ref', ''))}</code><br>
<strong>SHA-256:</strong> <code>{esc(subject.get('sha256', ''))}</code><br>
<strong>Verification:</strong> {esc(report.summary())}</p>
<table><thead><tr><th>Printed name</th><th>Signer ID</th><th>Role</th><th>Meaning</th><th>Date and time</th>
<th>Reason</th><th>Status</th></tr></thead><tbody>
{''.join(body)}
</tbody></table>
<ul>{policies}</ul>
<p><small>Verify with <code>aqt-signoff verify</code>. A signature applies only to content with the SHA-256 above.</small></p>
</body></html>
"""


def render(report: VerifyReport, fmt: str = "md") -> str:
    if fmt == "html":
        return render_html(report)
    return render_markdown(report)
