"""Validation reports: one block model rendered as Markdown and HTML."""

from __future__ import annotations

import html

NON_COMPLIANCE = ("Agent Quality Toolkit supports quality-management practices; it is not a validated system and "
                  "does not by itself make any process compliant with GMP, GDP, 21 CFR Part 11 or EU Annex 11.")


def pct(ppm: int | None, digits: int = 1) -> str:
    return "–" if ppm is None else f"{ppm / 10_000:.{digits}f} %"


def fmt_rate(r: dict | None) -> str:
    if not r or not r.get("n"):
        return "n = 0"
    return f"{r['k']}/{r['n']} = {pct(r['rate_ppm'])} [{pct(r['lo_ppm'])}, {pct(r['hi_ppm'])}]"


def fmt_bound(r: dict | None, which: str) -> str:
    if not r or not r.get("n"):
        return "–"
    return pct(r["lower1_ppm" if which == "lower" else "upper1_ppm"], 2)


class Report:
    def __init__(self):
        self.blocks: list[tuple] = []

    def h(self, level: int, text: str):
        self.blocks.append(("h", level, text))

    def p(self, text: str):
        self.blocks.append(("p", text))

    def items(self, values: list[str]):
        if values:
            self.blocks.append(("ul", values))

    def table(self, headers: list[str], rows: list[list]):
        self.blocks.append(("table", headers, [[("" if c is None else str(c)) for c in row] for row in rows]))

    # ------------------------------------------------------------------ renderers

    def markdown(self) -> str:
        out = []
        for block in self.blocks:
            if block[0] == "h":
                out.append("#" * block[1] + " " + block[2])
            elif block[0] == "p":
                out.append(block[1])
            elif block[0] == "ul":
                out.append("\n".join(f"- {v}" for v in block[1]))
            else:
                headers, rows = block[1], block[2]
                esc = lambda c: c.replace("|", "\\|").replace("\n", " ")  # noqa: E731
                lines = ["| " + " | ".join(map(esc, headers)) + " |", "|" + "---|" * len(headers)]
                lines += ["| " + " | ".join(map(esc, row)) + " |" for row in rows]
                out.append("\n".join(lines))
        return "\n\n".join(out) + "\n"

    def html(self, title: str) -> str:
        body = []
        for block in self.blocks:
            if block[0] == "h":
                body.append(f"<h{block[1]}>{html.escape(block[2])}</h{block[1]}>")
            elif block[0] == "p":
                body.append(f"<p>{html.escape(block[1])}</p>")
            elif block[0] == "ul":
                body.append("<ul>" + "".join(f"<li>{html.escape(v)}</li>" for v in block[1]) + "</ul>")
            else:
                head = "".join(f"<th>{html.escape(h)}</th>" for h in block[1])
                rows = "".join("<tr>" + "".join(f"<td>{html.escape(c)}</td>" for c in row) + "</tr>" for row in block[2])
                body.append(f"<table><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>")
        style = ("body{font-family:system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;"
                 "line-height:1.45;color:#1b1b1b;background:#fff}table{border-collapse:collapse;margin:.5rem 0}"
                 "td,th{border:1px solid #ccc;padding:.25rem .5rem;text-align:left;vertical-align:top}"
                 "th{background:#f3f3f3}@media(prefers-color-scheme:dark){body{color:#e8e8e8;background:#161616}"
                 "td,th{border-color:#444}th{background:#262626}}")
        return (f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" "
                f"content=\"width=device-width,initial-scale=1\"><title>{html.escape(title)}</title>"
                f"<style>{style}</style></head><body>{''.join(body)}</body></html>\n")


def criteria_rows(criteria: list[dict]) -> list[list]:
    rows = []
    for c in criteria:
        scope = ", ".join(f"{k}={c[k]}" for k in ("band", "split", "family", "category", "detector", "period") if k in c)
        target = pct(c["target_ppm"], 2) if "target_ppm" in c else c.get("target")
        if isinstance(c.get("observed"), dict):
            obs = c["observed"]
            observed = fmt_rate(obs)
            value = fmt_bound(obs, c["bound"]) if c["bound"] != "point" else pct(obs.get("rate_ppm"), 2)
        elif "observed_ppm" in c:
            observed = value = f"{c['observed_ppm'] / 1_000_000:.3f}"
            target = f"{c['target_ppm'] / 1_000_000:.3f}"
        else:
            observed = value = c.get("observed", "–")
        status = c["status"].upper() + (f" ({c['note']})" if c.get("note") else "")
        rows.append([c["id"], c["metric"], scope or "–", c["bound"], f"{c['op']} {target}", value, observed, status])
    return rows


CRITERIA_HEADERS = ["ID", "Metric", "Scope", "Bound", "Target", "Value used", "Observed (95 % CI)", "Result"]
