"""Case views for a human reviewer: terminal (ANSI) and static HTML.

Case content is attacker-controlled. Control characters are shown as
``<U+XXXX>`` so the content cannot drive the terminal, and the HTML is fully
escaped, without scripts.
"""

from __future__ import annotations

import html

from .store import Case

INVISIBLE_SHOWN = {0x00AD, 0x180E, 0xFEFF} | set(range(0x200B, 0x2010)) | set(range(0x202A, 0x202F)) \
    | set(range(0x2060, 0x2065)) | set(range(0x2066, 0x206A))
CONTEXT = 300


def visible(text: str) -> str:
    out = []
    for char in text:
        code = ord(char)
        if char in "\n\t":
            out.append(char)
        elif code < 0x20 or 0x7F <= code < 0xA0 or code in INVISIBLE_SHOWN or 0xE0000 <= code <= 0xE007F:
            out.append(f"<U+{code:04X}>")
        else:
            out.append(char)
    return out and "".join(out) or ""


def _merged(evidence: list[dict], length: int) -> list[tuple[int, int, str]]:
    spans = sorted((max(0, e["start"]), min(length, e["end"]), e.get("reason") or e["label"]) for e in evidence
                   if e.get("end", 0) > e.get("start", 0))
    merged: list[list] = []
    for start, end, reason in spans:
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
            if reason not in merged[-1][2]:
                merged[-1][2] += "; " + reason
        else:
            merged.append([start, end, reason])
    return [tuple(item) for item in merged]


def _windows(spans, length: int, full: bool) -> list[tuple[int, int]]:
    if full or not spans:
        return [(0, length if full else min(length, 2 * CONTEXT))]
    windows: list[list[int]] = []
    for start, end, _ in spans:
        a, b = max(0, start - CONTEXT), min(length, end + CONTEXT)
        if windows and a <= windows[-1][1]:
            windows[-1][1] = max(windows[-1][1], b)
        else:
            windows.append([a, b])
    return [tuple(item) for item in windows]


def summary_lines(case: Case) -> list[str]:
    data = case.data
    source = data.get("source") or {}
    thresholds = data.get("thresholds") or {}
    lines = [
        f"case {case.case_id}   state {case.state}   band {case.band}   score {data.get('score_ppm', 0)} ppm",
        f"opened {case.opened.get('time')}   record {case.opened.get('id')}",
        f"source {source.get('tool')}  {source.get('ref') or ''}  (harness {source.get('harness') or '-'}, "
        f"session {source.get('session') or '-'})",
        "detectors " + ", ".join(f"{d['id']} {d['version']} = {data.get('scores', {}).get(d['id'], 'error')} ppm"
                                 for d in data.get("detectors", [])),
        f"thresholds {thresholds.get('version')} sha256 {thresholds.get('sha256')} "
        f"calibrated {'yes' if thresholds.get('calibrated') else 'NO (uncalibrated defaults)'}",
        f"reason code {data.get('reason_code')}   content {data.get('content_sha256')} ({data.get('chars')} chars)",
    ]
    for error in data.get("errors", []):
        lines.append(f"detector error: {error.get('detector')}: {error.get('error')}")
    if data.get("trusted_source"):
        lines.append(f"trusted source {data['trusted_source'].get('domain')} (band lowered)")
    lines.append("decisions:" if case.decisions else "decisions: none")
    for decision in case.decisions:
        record = decision.record
        who = record.get("actor", {})
        lines.append(f"  {record.get('time')} {record.get('action')} by {who.get('display') or ''} {who.get('id')} "
                     f"- signature {decision.status}{'' if decision.honoured else ' (NOT honoured)'}"
                     f"{' - ' + decision.note if decision.note else ''}")
        lines.append(f"    reason: {visible(record.get('reason', ''))}")
    for item in case.refused:
        data_r = item.get("data", {})
        lines.append(f"  {item.get('time')} REFUSED {data_r.get('attempted_action')} ({data_r.get('reason_code')}; "
                     f"{', '.join(data_r.get('agent_markers', [])) or 'no agent markers'})")
    for item in case.delivered:
        data_d = item.get("data", {})
        lines.append(f"  {item.get('time')} delivered {data_d.get('kind')} to session {data_d.get('session')} "
                     f"({data_d.get('mode')})")
    return lines


def terminal(case: Case, text: str | None, *, color: bool, full: bool = False) -> str:
    lines = summary_lines(case)
    evidence = case.data.get("evidence", [])
    lines.append("evidence:" if evidence else "evidence: none recorded")
    for item in evidence:
        lines.append(f"  [{item['start']}:{item['end']}] {item['label']} ({item['detector']}): {item['reason']}: "
                     f"{visible(item.get('excerpt', ''))!r}")
    if text is None:
        lines.append("content: not available")
        return "\n".join(lines) + "\n"
    spans = _merged(evidence, len(text))
    on, off = ("\x1b[7m", "\x1b[0m") if color else ("[[", "]]")
    lines.append("content (untrusted; highlighted = evidence):")
    for a, b in _windows(spans, len(text), full):
        pieces, cursor = [], a
        for start, end, _ in spans:
            if end <= a or start >= b:
                continue
            start, end = max(start, a), min(end, b)
            pieces.append(visible(text[cursor:start]))
            pieces.append(on + visible(text[start:end]) + off)
            cursor = end
        pieces.append(visible(text[cursor:b]))
        lines.append(("... " if a > 0 else "") + "".join(pieces) + (" ..." if b < len(text) else ""))
        lines.append("")
    return "\n".join(lines) + "\n"


def html_page(case: Case, text: str | None) -> str:
    evidence = case.data.get("evidence", [])
    body = ""
    if text is not None:
        spans = _merged(evidence, len(text))
        pieces, cursor = [], 0
        for start, end, reason in spans:
            pieces.append(html.escape(visible(text[cursor:start])))
            pieces.append(f'<mark title="{html.escape(reason, quote=True)}">{html.escape(visible(text[start:end]))}</mark>')
            cursor = end
        pieces.append(html.escape(visible(text[cursor:])))
        body = "".join(pieces)
    rows = "".join(f"<tr><td>{item['start']}–{item['end']}</td><td>{html.escape(item['label'])}</td>"
                   f"<td>{html.escape(item['detector'])}</td><td>{html.escape(item['reason'])}</td>"
                   f"<td><code>{html.escape(visible(item.get('excerpt', '')))}</code></td></tr>" for item in evidence)
    summary = html.escape("\n".join(summary_lines(case)))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Case {case.case_id}</title>
<style>
:root {{ --bg:#fbfaf7; --fg:#1d1d1b; --muted:#5d5a52; --mark:#ffd8a8; --line:#ddd8cc; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#191917; --fg:#ecebe6; --muted:#a8a498; --mark:#7a4a12;
  --line:#3a3833; }} }}
body {{ background:var(--bg); color:var(--fg); font:15px/1.5 system-ui, sans-serif; margin:0 auto; max-width:60rem;
  padding:1rem; }}
pre {{ white-space:pre-wrap; word-break:break-word; border:1px solid var(--line); padding:.75rem; }}
mark {{ background:var(--mark); color:inherit; }}
table {{ border-collapse:collapse; width:100%; font-size:13px; }} td {{ border-top:1px solid var(--line);
  padding:.25rem .4rem; vertical-align:top; }}
.warn {{ color:var(--muted); }}
</style></head><body>
<h1>Quarantine case {case.case_id}</h1>
<p class="warn">The content below is untrusted third-party data. Highlighted passages are detector evidence.</p>
<pre>{summary}</pre>
<h2>Evidence</h2><table>{rows or '<tr><td>none recorded</td></tr>'}</table>
<h2>Content</h2><pre>{body or 'not available'}</pre>
</body></html>
"""
