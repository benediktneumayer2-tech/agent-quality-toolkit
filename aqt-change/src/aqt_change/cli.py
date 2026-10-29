"""``aqt-change``: change control and verification receipts for agent work.

Exit codes: 0 ok, 1 check failed or refused, 2 usage or runtime error.
``hook claude-code`` follows the Claude Code protocol instead (2 blocks).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, finish as finish_mod, gate as gate_mod, hooks, plans, receipts, report, review, scope
from .errors import ChangeError, usage
from .ledger import Ledger


def _common() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--root", help="project root (default: Git top level of the current directory)")
    common.add_argument("--state", help="ledger directory (default: <git-dir>/aqt-change)")
    common.add_argument("--json", action="store_true", help="machine-readable output")
    return common


def _evidence(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--evidence", action="append", default=None, metavar="PATH",
                        help="evidence JSONL to read sign-offs from (repeatable; default AQT_EVIDENCE / sink / trail)")


def build_parser() -> argparse.ArgumentParser:
    common = _common()
    parser = argparse.ArgumentParser(prog="aqt-change", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"aqt-change {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    plan = sub.add_parser("plan", help="create, register and inspect plans")
    plan_sub = plan.add_subparsers(dest="plan_command", required=True)
    p = plan_sub.add_parser("new", parents=[common], help="write a plan from the template and register it")
    p.add_argument("path")
    p.add_argument("--id", required=True)
    p.add_argument("--title", required=True)
    p.add_argument("--implementation")
    p.add_argument("--follows", help="plan id this one follows up")
    p = plan_sub.add_parser("add", parents=[common], help="register an existing plan (baseline record)")
    p.add_argument("path")
    p = plan_sub.add_parser("status", parents=[common], help="reconciliation state of plans")
    p.add_argument("paths", nargs="*")

    p = sub.add_parser("reconcile", parents=[common], help="accept the current plan version")
    p.add_argument("path")
    p.add_argument("--kind", required=True, choices=["editorial", "semantic"])
    p.add_argument("--reason")
    p.add_argument("--expect", help="raw sha256 of the version you edited")

    p = sub.add_parser("begin", parents=[common], help="start the plan: baseline and Git base commit")
    p.add_argument("path")
    p.add_argument("--reason")

    p = sub.add_parser("run", parents=[common], help="run a command and record a receipt")
    p.add_argument("--plan")
    p.add_argument("--item")
    p.add_argument("--all", action="store_true", help="run every declared verification command")
    p.add_argument("--junit", help="JUnit XML file written by the command")
    p.add_argument("--timeout", type=int)
    p.add_argument("--quiet", action="store_true", help="do not echo the command output")
    p.add_argument("cmd", nargs=argparse.REMAINDER, help="-- command and arguments")

    p = sub.add_parser("attest", parents=[common], help="record evidence for a manual verification item")
    p.add_argument("path")
    p.add_argument("--item", required=True)
    p.add_argument("--evidence", action="append", default=[], dest="files")
    p.add_argument("--reason", required=True)

    p = sub.add_parser("review", help="review records")
    review_sub = p.add_subparsers(dest="review_command", required=True)
    p = review_sub.add_parser("add", parents=[common], help="record a review bound to the current diff")
    p.add_argument("path")
    p.add_argument("--reviewer", required=True)
    p.add_argument("--harness")
    p.add_argument("--model")
    p.add_argument("--independence", required=True,
                   choices=["same-session", "fresh-context", "different-model", "human"])
    p.add_argument("--verdict", required=True, type=str.upper, choices=["PASS", "CONCERNS", "FAIL", "WAIVED"])
    p.add_argument("--findings", help="JSON file: list of {severity, title, path, line}")
    p.add_argument("--reason", required=True, help="review summary")
    p.add_argument("--base", help="diff base (default: plan base commit)")
    p.add_argument("--qualification", help="validate.qualification record id of the reviewer")

    p = sub.add_parser("reconcile-diff", parents=[common], help="approved scope versus actual diff")
    p.add_argument("path")
    _evidence(p)

    p = sub.add_parser("finish", parents=[common], help="checked, idempotent completion with a scoped commit")
    p.add_argument("path")
    p.add_argument("--key", required=True, help="idempotency key")
    p.add_argument("--summary", required=True)
    p.add_argument("--path", dest="paths", action="append", default=[], metavar="FILE",
                   help="task-owned file to commit (repeatable)")
    p.add_argument("--message", help="commit subject/body (trailers are added)")
    p.add_argument("--waive", action="append", default=[], metavar="ID=REASON")
    p.add_argument("--ack-warnings", metavar="REASON")
    p.add_argument("--remaining")
    p.add_argument("--no-commit", action="store_true")
    _evidence(p)

    p = sub.add_parser("report", parents=[common], help="trace report (Markdown or HTML) and gate file")
    p.add_argument("path")
    p.add_argument("--format", choices=["md", "html"], default="md")
    p.add_argument("--out")
    p.add_argument("--gate", dest="gate_file", help="also write the gate JSON here")
    p.add_argument("--rerun", action="store_true")
    _evidence(p)

    p = sub.add_parser("gate", parents=[common], help="print the gate decision JSON (exit 1 unless GO)")
    p.add_argument("path")
    p.add_argument("--rerun", action="store_true", help="re-execute declared commands first")
    _evidence(p)

    p = sub.add_parser("hook", help="hook entry points")
    hook_sub = p.add_subparsers(dest="hook_command", required=True)
    hook_sub.add_parser("claude-code", parents=[common], help="read a Claude Code hook event on stdin")
    p = hook_sub.add_parser("commit-msg", parents=[common], help="check AQT-* trailers of a commit message file")
    p.add_argument("file")
    p.add_argument("--require", action="store_true", help="require AQT-Plan while a plan is in progress")

    p = sub.add_parser("hooks", help="hook setup")
    hooks_sub = p.add_subparsers(dest="hooks_command", required=True)
    hooks_sub.add_parser("print", parents=[common], help="print the Claude Code settings snippet")
    hooks_sub.add_parser("install-git", parents=[common], help="install the git commit-msg shim")
    return parser


def _out(args, payload, text: str | None = None) -> None:
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    elif text is not None:
        print(text)


def _sources(args) -> list[Path] | None:
    return [Path(p) for p in args.evidence] if getattr(args, "evidence", None) else None


def _waivers(values: list[str]) -> dict[str, str]:
    result = {}
    for value in values:
        if "=" not in value:
            raise usage("waiver_invalid", f"--waive needs ID=REASON, got {value!r}")
        item, reason = value.split("=", 1)
        result[item.strip()] = reason.strip()
    return result


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return _dispatch(args)
    except ChangeError as error:
        if getattr(args, "json", False):
            print(json.dumps(error.as_dict(), indent=2, sort_keys=True, default=str))
        else:
            print(f"aqt-change: {error.code}: {error.message}", file=sys.stderr)
        return error.exit_code


def _dispatch(args) -> int:
    if args.command == "hook" and args.hook_command == "claude-code":
        try:
            payload = json.loads(sys.stdin.read() or "{}")
        except ValueError:
            payload = {}
        ledger = None
        if args.root or args.state:
            ledger = Ledger.open(args.root or payload.get("cwd"), args.state)
        code, message = hooks.claude_code(payload, ledger)
        if message:
            print(message, file=sys.stderr)
        return code
    ledger = Ledger.open(args.root, args.state)
    if args.command == "plan":
        if args.plan_command == "new":
            result = plans.new(ledger, args.path, args.id, args.title, args.implementation, args.follows)
            _out(args, result, f"created {result['path']} ({result['plan_id']}), record {result['record']}")
            return 0
        if args.plan_command == "add":
            result = plans.add(ledger, args.path)
            _out(args, result, f"{result['result']}: {result['path']} ({result['plan_id']})")
            return 0
        paths = args.paths or [s["path"] for s in ledger.plan_states()]
        results = [plans.status(ledger, path) for path in paths]
        bad = [r for r in results if r["state"] not in plans.STATES_OK]
        lines = []
        for r in results:
            lines.append(f"{r['state']:<18} {r['path']} ({r['plan_id']})")
            for key, values in r.get("items", {}).items():
                if values:
                    lines.append(f"    {key}: {', '.join(values)}")
            for error in r.get("errors", [])[:5]:
                lines.append(f"    error: {error}")
        _out(args, {"plans": results, "ok": not bad}, "\n".join(lines) or "no registered plans")
        return 1 if bad else 0
    if args.command == "reconcile":
        result = plans.reconcile(ledger, args.path, args.kind, args.reason, args.expect)
        _out(args, result, f"{result['result']}: {result['plan_id']}" + (f" ({result['kind']}, record {result['record']})"
                                                                     if result.get("record") else ""))
        return 0
    if args.command == "begin":
        result = plans.begin(ledger, args.path, args.reason)
        _out(args, result, f"{result['result']}: {result['plan_id']} base {result.get('base_commit')}")
        return 0
    if args.command == "run":
        cmd = list(args.cmd)
        if cmd and cmd[0] == "--":
            cmd = cmd[1:]
        records = receipts.run(ledger, cmd, plan_path=args.plan, item=args.item, all_items=args.all,
                               junit=args.junit, timeout=args.timeout, echo=not (args.quiet or args.json))
        failed = [r for r in records if not r["data"]["passed"]]
        lines = [f"{'PASS' if r['data']['passed'] else 'FAIL'} {r['data'].get('item') or '-'} "
                 f"{r['data']['command']} -> {r['data']['outcome']} (exit {r['data']['exit_code']}) receipt {r['id']}"
                 + "".join(f"\n    warning: {w['code']} {w.get('path', '')} {w.get('detail', '')}".rstrip()
                           for w in r["data"].get("warnings", []))
                 for r in records]
        _out(args, {"receipts": records, "passed": not failed}, "\n".join(lines))
        return 1 if failed else 0
    if args.command == "attest":
        record = receipts.attest(ledger, args.path, args.item, args.files, args.reason)
        _out(args, record, f"attested {args.item} by {record['actor']['id']}: receipt {record['id']}")
        return 0
    if args.command == "review":
        record = review.add_review(ledger, args.path, reviewer=args.reviewer, independence=args.independence,
                                   verdict=args.verdict, reason=args.reason, harness=args.harness, model=args.model,
                                   findings_file=args.findings, base=args.base, qualification=args.qualification)
        _out(args, record, f"review {record['data']['verdict']} ({record['data']['independence']}) recorded: {record['id']}")
        return 0
    if args.command == "reconcile-diff":
        record = scope.reconcile_diff(ledger, args.path, _sources(args))
        data = record["data"]
        lines = [f"result: {data['result']} (base {data['base_commit']}, approval {data['approval']['state']})"]
        lines += [f"  unapproved: {p}" for p in data["unapproved"]]
        lines += [f"  missing evidence: {i}" for i in data["missing_evidence"]]
        lines += [f"  project settings changed: {p}" for p in data.get("settings_changed", [])]
        _out(args, record, "\n".join(lines))
        return 0 if data["result"] == "clean" else 1
    if args.command == "finish":
        result = finish_mod.finish(ledger, args.path, key=args.key, summary=args.summary, paths=args.paths,
                                   message=args.message, waivers=_waivers(args.waive),
                                   ack_warnings=args.ack_warnings, no_commit=args.no_commit,
                                   remaining=args.remaining, sources=_sources(args))
        _out(args, result, f"{result['result']}{' (replayed)' if result.get('replayed') else ''}: "
                           f"{result['plan_id']} record {result['record']} commit {result['commit']} "
                           f"gate {result['gate']}")
        return 0
    if args.command == "report":
        if args.rerun:
            gate_mod.gate(ledger, args.path, sources=_sources(args), rerun=True)
        info = report.build(ledger, args.path, _sources(args))
        text = report.render_html(info) if args.format == "html" else report.render_markdown(info)
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
        if args.gate_file:
            Path(args.gate_file).write_text(json.dumps(gate_mod.public(info["gate"]), indent=2, sort_keys=True,
                                                       default=str) + "\n", encoding="utf-8")
        if args.json:
            print(json.dumps({"gate": gate_mod.public(info["gate"]), "out": args.out}, indent=2, default=str))
        elif not args.out:
            print(text)
        else:
            print(f"wrote {args.out} (gate {info['gate']['decision']})")
        return 0
    if args.command == "gate":
        result = gate_mod.public(gate_mod.gate(ledger, args.path, sources=_sources(args), rerun=args.rerun))
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
        return 0 if result["decision"] == "GO" else 1
    if args.command == "hook":
        code, message = hooks.commit_msg(ledger, args.file, args.require)
        if message:
            print(message, file=sys.stderr)
        return code
    if args.command == "hooks":
        if args.hooks_command == "print":
            print(hooks.snippet())
            return 0
        target = hooks.install_git_hook(ledger)
        _out(args, {"installed": str(target)}, f"installed {target}")
        return 0
    raise usage("command_unknown", f"unknown command {args.command}")


if __name__ == "__main__":
    sys.exit(main())
