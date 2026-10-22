"""``aqt-capa`` command line. Exit codes: 0 ok, 1 check failed / refused / precondition unmet, 2 usage or runtime error."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import sources
from .capa import FACTOR_CATEGORIES, KINDS, Blocked, Capa, CapaError, Refused
from .config import load_config
from .store import Store
from .trends import render_markdown, trends
from .util import parse_since


def _parser() -> argparse.ArgumentParser:
    def options(suppress: bool) -> argparse.ArgumentParser:
        # Accepted before or after the subcommand; sub-level copies must not reset the top-level values.
        default = {"default": argparse.SUPPRESS} if suppress else {}
        group = argparse.ArgumentParser(add_help=False)
        group.add_argument("--config", help="TOML config (default $XDG_CONFIG_HOME/aqt/capa.toml)", **default)
        group.add_argument("--db", help="SQLite working index (default $XDG_STATE_HOME/aqt/capa/capa.db)", **default)
        group.add_argument("--evidence", action="append", metavar="PATH", **default,
                           help="evidence JSONL to read (repeatable; default AQT_EVIDENCE or sink file + trail log)")
        group.add_argument("--root", help="project root for action targets (default: config or current directory)",
                           **default)
        group.add_argument("--repo", action="append", metavar="PATH", **default,
                           help="git repository to scan for reverts (repeatable)")
        group.add_argument("--json", action="store_true", help="machine-readable output", **default)
        return group

    common = [options(True)]
    p = argparse.ArgumentParser(prog="aqt-capa", description="Deviations and CAPA for AI coding agent work.",
                                parents=[options(False)])
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("scan", parents=common, help="find deviation candidates in the evidence and git")

    cand = sub.add_parser("candidate", parents=common, help="list, accept or dismiss candidates").add_subparsers(
        dest="sub", required=True)
    cl = cand.add_parser("list", parents=common)
    cl.add_argument("--all", action="store_true", help="include decided candidates")
    ca = cand.add_parser("accept", parents=common)
    ca.add_argument("candidate")
    ca.add_argument("--reason", required=True)
    ca.add_argument("--severity", choices=sources.SEVERITIES)
    ca.add_argument("--category", choices=sources.CATEGORIES)
    ca.add_argument("--title")
    ca.add_argument("--description")
    cd = cand.add_parser("dismiss", parents=common)
    cd.add_argument("candidate")
    cd.add_argument("--reason", required=True)

    dev = sub.add_parser("deviation", parents=common, help="open or classify a deviation").add_subparsers(
        dest="sub", required=True)
    dn = dev.add_parser("new", parents=common)
    dn.add_argument("--title", required=True)
    dn.add_argument("--description")
    dn.add_argument("--severity", required=True, choices=sources.SEVERITIES)
    dn.add_argument("--category", default="unclassified", choices=sources.CATEGORIES)
    dn.add_argument("--subject", dest="subject_ref", help="what the deviation is about (path, session, record id)")
    dn.add_argument("--link", action="append", default=[], metavar="REL=REF")
    dn.add_argument("--reason")
    dc = dev.add_parser("classify", parents=common)
    dc.add_argument("dev")
    dc.add_argument("--reason", required=True)
    dc.add_argument("--severity", choices=sources.SEVERITIES)
    dc.add_argument("--category", choices=sources.CATEGORIES)
    dc.add_argument("--recurrence-of", action="append", default=[], metavar="DEV")

    inv = sub.add_parser("investigate", parents=common,
                         help="record the investigation (5-Whys, 6M factors, root cause)")
    inv.add_argument("dev")
    inv.add_argument("--why", action="append", required=True, default=[])
    inv.add_argument("--factor", action="append", default=[], metavar="CATEGORY:TEXT",
                     help=f"Ishikawa factor; categories {', '.join(FACTOR_CATEGORIES)}")
    inv.add_argument("--root-cause", required=True)
    inv.add_argument("--root-category", required=True, choices=sources.CATEGORIES)
    inv.add_argument("--impact")
    inv.add_argument("--evidence-ref", action="append", default=[], metavar="REC")
    inv.add_argument("--draft", action="store_true", help="record as a draft (allowed for agents)")
    inv.add_argument("--reason")

    act = sub.add_parser("action", parents=common,
                         help="corrective/preventive actions on agent controls").add_subparsers(dest="sub", required=True)
    ap = act.add_parser("plan", parents=common)
    ap.add_argument("dev")
    ap.add_argument("--kind", required=True, choices=KINDS)
    ap.add_argument("--target", required=True, help="agent control file, e.g. AGENTS.md (inside the project root)")
    ap.add_argument("--description", required=True)
    ap.add_argument("--criterion", default="no-recurrence", choices=["no-recurrence"])
    ap.add_argument("--window-sessions", type=int)
    ap.add_argument("--window-days", type=int)
    ap.add_argument("--max", type=int, default=0, help="allowed recurrences in the window (default 0)")
    ap.add_argument("--match-category", choices=sources.CATEGORIES)
    ap.add_argument("--match-source", metavar="TYPE", help="record type pattern, e.g. 'change.*'")
    ai = act.add_parser("implement", parents=common)
    ai.add_argument("action")
    aa = act.add_parser("approve", parents=common)
    aa.add_argument("action")
    aa.add_argument("--reason", required=True)
    ax = act.add_parser("cancel", parents=common)
    ax.add_argument("action")
    ax.add_argument("--reason", required=True)
    av = act.add_parser("verify", parents=common)
    av.add_argument("action", nargs="?")

    eff = sub.add_parser("effectiveness", parents=common, help="evaluate effectiveness checks, or extend a window")
    eff.add_argument("target", nargs="?", help="DEV-… or CAPA-… (default: all running checks)")
    eff.add_argument("--check", action="store_true", help="exit 1 unless every evaluated check is effective")
    eff.add_argument("--extend", metavar="ACTION", help="extend the window of ACTION (human, with --reason)")
    eff.add_argument("--window-sessions", type=int)
    eff.add_argument("--window-days", type=int)
    eff.add_argument("--reason")

    cl = sub.add_parser("close", parents=common,
                        help="close a deviation (effective CAPA, or --no-action with justification)")
    cl.add_argument("dev")
    cl.add_argument("--reason", required=True)
    cl.add_argument("--no-action", action="store_true")

    ls = sub.add_parser("list", parents=common, help="list deviations")
    ls.add_argument("--open", action="store_true")
    ls.add_argument("--overdue", action="store_true")
    sh = sub.add_parser("show", parents=common, help="show one deviation with its timeline")
    sh.add_argument("dev")
    sh.add_argument("--markdown", action="store_true")

    tr = sub.add_parser("trends", parents=common, help="management-review style trend summary")
    tr.add_argument("--since", help="e.g. 90d, 12w or 2026-01-01")
    tr.add_argument("--by", choices=["month", "week"], default="month")
    tr.add_argument("--format", choices=["md", "json"], default="md")

    sub.add_parser("rebuild", parents=common, help="rebuild the working index from capa.* evidence records")
    return p


def _emit(args, value, text: str | None = None) -> None:
    if args.json or text is None:
        print(json.dumps(value, indent=2, sort_keys=True, default=str))
    else:
        print(text)


def _show_markdown(view: dict) -> str:
    d = view["deviation"]
    lines = [f"# {d['dev_id']}: {d['title']}", "",
             f"- State: **{d['state']}**; severity {d['severity']}; category {d['category']}",
             f"- Source: {d['source_type'] or 'manual'} {d['source_ref'] or ''}".rstrip(),
             f"- Opened {d['opened_at']} by {d['opened_by']}; investigation due {d['due']}"]
    if d.get("closed_at"):
        lines.append(f"- Closed {d['closed_at']} (basis: {d['basis']})")
    if view["similar"]:
        lines.append("- Similar: " + ", ".join(f"{s['dev_id']} ({s['score_ppm'] // 10_000} %)" for s in view["similar"]))
    if d.get("description"):
        lines += ["", d["description"]]
    inv = view["investigation"]
    if inv:
        lines += ["", "## Investigation", ""] + [f"{i}. {w}" for i, w in enumerate(inv["whys"], 1)]
        lines += [f"- {f['category']}: {f['text']}" for f in inv["factors"]]
        lines += ["", f"**Root cause** ({inv['root_category']}): {inv['root_cause']}"]
    if view["actions"]:
        lines += ["", "## Actions", "", "| Action | Kind | Target | State | Approval | File | Effectiveness |",
                  "|---|---|---|---|---|---|---|"]
        for a in view["actions"]:
            last = a["last_evaluation"] or {}
            lines.append(f"| {a['action_id']} | {a['kind']} | `{a['path']}` | {a['state']} | {a['approval']['status']}"
                         f" | {a['verify']} | {last.get('result', 'not evaluated')} |")
    lines += ["", "## Timeline", ""]
    lines += [f"- {t['time']} `{t['type']}` {t['action']} by {t['actor']}" + (f": {t['reason']}" if t["reason"] else "")
              for t in view["timeline"]]
    return "\n".join(lines)


def run(args) -> int:
    cfg = load_config(args.config)
    if args.db:
        cfg.db_path = Path(args.db)
    if args.root:
        cfg.project_root = Path(args.root)
    if args.repo:
        cfg.repos = [Path(r) for r in args.repo]
    evidence = [Path(e) for e in args.evidence] if args.evidence else cfg.evidence_paths
    capa = Capa(cfg, store=Store(cfg.db_path), evidence=evidence)
    cmd, sub = args.cmd, getattr(args, "sub", None)

    if cmd == "scan":
        new = capa.scan()
        _emit(args, new, "\n".join(f"{c['candidate_id']}  {c['severity']:<8} {c['category']:<18} {c['title']}"
                                   for c in new) or "no new candidates")
    elif cmd == "candidate" and sub == "list":
        rows = capa.candidates(None if args.all else "open")
        _emit(args, rows, "\n".join(f"{c['candidate_id']}  {c['status']:<9} {c['severity']:<8} {c['title']}"
                                    for c in rows) or "no candidates")
    elif cmd == "candidate" and sub == "accept":
        rec = capa.accept(args.candidate, reason=args.reason, severity=args.severity, category=args.category,
                          title=args.title, description=args.description)
        _emit(args, rec, _opened_text(rec))
    elif cmd == "candidate" and sub == "dismiss":
        rec = capa.dismiss(args.candidate, reason=args.reason)
        _emit(args, rec, f"dismissed {args.candidate} ({rec['id']})")
    elif cmd == "deviation" and sub == "new":
        links = []
        for item in args.link:
            rel, _, ref = item.partition("=")
            if not ref:
                raise CapaError("--link needs REL=REF")
            links.append({"rel": rel, "ref": ref})
        rec = capa.new_deviation(title=args.title, description=args.description, severity=args.severity,
                                 category=args.category, subject_ref=args.subject_ref, links=links, reason=args.reason)
        _emit(args, rec, _opened_text(rec))
    elif cmd == "deviation" and sub == "classify":
        rec = capa.classify(args.dev, reason=args.reason, severity=args.severity, category=args.category,
                            recurrence_of=args.recurrence_of)
        _emit(args, rec, f"{args.dev}: {rec['data']['before']} -> {rec['data']['after']}")
    elif cmd == "investigate":
        rec = capa.investigate(args.dev, whys=args.why, factors=args.factor, root_cause=args.root_cause,
                               root_category=args.root_category, impact=args.impact, evidence=args.evidence_ref,
                               draft=args.draft, reason=args.reason)
        _emit(args, rec, f"{args.dev}: investigation {rec['action']} ({rec['id']})")
    elif cmd == "action" and sub == "plan":
        rec = capa.plan(args.dev, kind=args.kind, target=args.target, description=args.description,
                        window_sessions=args.window_sessions, window_days=args.window_days, max_recurrences=args.max,
                        match_category=args.match_category, match_source=args.match_source)
        d = rec["data"]
        _emit(args, rec, f"planned {d['action_id']} on {d['target']['path']} (before {d['target']['before_sha256']}); "
                         f"criterion {json.dumps(d['effectiveness_criterion'], sort_keys=True)}")
    elif cmd == "action" and sub == "implement":
        rec = capa.implement(args.action)
        _emit(args, rec, f"implemented {args.action}: {rec['data']['target']['after_sha256']}\n"
                         f"approve with: aqt-capa action approve {args.action} --reason …  or  "
                         f"aqt-signoff sign --record {rec['id']} --meaning approved")
    elif cmd == "action" and sub == "approve":
        rec = capa.approve(args.action, reason=args.reason)
        _emit(args, rec, f"approved {args.action} ({rec['id']}, recorded, unsigned)")
    elif cmd == "action" and sub == "cancel":
        rec = capa.cancel(args.action, reason=args.reason)
        _emit(args, rec, f"cancelled {args.action}")
    elif cmd == "action" and sub == "verify":
        rows = capa.verify(args.action)
        _emit(args, rows, "\n".join(f"{r['action_id']}  {r['status']:<24} {r['path']}" for r in rows) or "no actions")
        if any(r["status"] != "ok" for r in rows):
            return 1
    elif cmd == "effectiveness":
        if args.extend:
            if not args.reason:
                raise CapaError("--extend needs --reason")
            rec = capa.extend(args.extend, reason=args.reason, window_sessions=args.window_sessions,
                              window_days=args.window_days)
            _emit(args, rec, f"extended {args.extend}: window {rec['data']['window']}")
            return 0
        rows = capa.effectiveness(args.target)
        _emit(args, rows, "\n".join(f"{r['action_id']}  {r['result']:<14} {'; '.join(r['reasons'])}" for r in rows)
              or "no running effectiveness checks")
        if args.check and any(r["result"] != "effective" for r in rows):
            return 1
    elif cmd == "close":
        rec = capa.close(args.dev, reason=args.reason, no_action=args.no_action)
        _emit(args, rec, f"closed {args.dev} (basis: {rec['data']['basis']})")
    elif cmd == "list":
        rows = capa.list(open_only=args.open, overdue_only=args.overdue)
        _emit(args, rows, "\n".join(f"{r['dev_id']}  {r['state']:<12} {r['severity']:<8} {r['category']:<18} "
                                    f"{r['title']}" + ("  [overdue]" if r["overdue"] else "") for r in rows)
              or "no deviations")
    elif cmd == "show":
        view = capa.show(args.dev)
        _emit(args, view, _show_markdown(view))
    elif cmd == "trends":
        report = trends(capa, since=parse_since(args.since), by=args.by)
        if args.json or args.format == "json":
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print(render_markdown(report))
    elif cmd == "rebuild":
        count = capa.rebuild()
        _emit(args, {"replayed": count}, f"rebuilt index from {count} capa record(s)")
    for path in capa.missing_paths:
        print(f"aqt-capa: note: evidence file {path} does not exist (read as empty)", file=sys.stderr)
    return 0


def _opened_text(rec: dict) -> str:
    d = rec["data"]
    text = f"opened {d['dev_id']} ({d['severity']}, {d['category']}): {d['title']}"
    if d.get("similar"):
        text += "\nsimilar: " + ", ".join(f"{s['dev_id']} ({s['score_ppm'] // 10_000} %)" for s in d["similar"])
    if d.get("suggested_severity"):
        text += f"\nsuggestion: recurring minor deviation; consider severity {d['suggested_severity']}"
    return text


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exit_:
        return int(exit_.code or 0) and 2
    try:
        return run(args)
    except Refused as error:
        print(f"aqt-capa: {error} (refusal recorded)", file=sys.stderr)
        return 1
    except Blocked as error:
        print(f"aqt-capa: {error}", file=sys.stderr)
        return 1
    except (CapaError, FileNotFoundError, ValueError) as error:
        print(f"aqt-capa: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
