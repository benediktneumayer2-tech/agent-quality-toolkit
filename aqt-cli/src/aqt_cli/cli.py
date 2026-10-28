"""``aqt``: one command for the Agent Quality Toolkit.

  aqt status [--json] [--verify]     is everything in order? one verdict, and the fix for each problem
  aqt setup [--yes] [--id ID --name NAME --role ROLE]
                                     first-time setup, step by step; safe to rerun
  aqt <tool> ARGS...                 run a tool with these arguments: trail, signoff, change, sensei,
                                     quarantine, validate, capa, ui, spec (or evidence)

Exit codes: 0 ok (warnings allowed), 1 a check failed, 2 usage or runtime error.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .checks import CHECKS, FAIL, Context, StepSkipped, needs_step, run_check, run_checks, verdict
from .tools import TOOLS, run_tool


def _exit(results) -> int:
    return 1 if verdict(results) == FAIL else 0


def print_status(results, say=print) -> None:
    counts = {kind: sum(1 for r in results if r.result == kind) for kind in ("fail", "warn")}
    detail = ", ".join(f"{n} {'failed' if kind == 'fail' else 'warning(s)'}" for kind, n in counts.items() if n)
    say(f"aqt status: {verdict(results).upper()}" + (f" ({detail})" if detail else ""))
    for result in results:
        say(f"  {result.result:<5} {result.id:<15} {result.explanation}")
        if result.fix and result.result != "ok":
            say(f"  {'':<5} {'':<15} fix: {result.fix}")


def cmd_status(args) -> int:
    results = run_checks(Context(verify=args.verify))
    if args.json:
        print(json.dumps({"verdict": verdict(results), "checks": [r.as_dict() for r in results]}, indent=2))
    else:
        print_status(results)
    return _exit(results)


def _capital(text: str) -> str:
    return text[:1].upper() + text[1:]


def setup(ctx: Context) -> int:
    """Show what is missing, apply each step (after confirmation unless --yes), then show the status."""
    initial = dict(zip((check.id for check in CHECKS), run_checks(ctx)))
    todo = [check for check in CHECKS if needs_step(check, initial[check.id])]
    if todo:
        ctx.say(f"aqt setup: {len(todo)} step(s) to do")
        for check in todo:
            ctx.say(f"  - {check.does}" + ("  [needs you]" if check.personal else ""))
    else:
        ctx.say("aqt setup: nothing to do")
    for check in CHECKS:
        if check.step is None:
            continue
        result = run_check(ctx, check)      # fresh: an earlier step may have done this one already
        if result.result in ("warn", "fail") and not result.can_apply and result.fix:
            ctx.say(f"{check.id}: yours to do: {result.fix}")
        if not needs_step(check, result):
            continue
        question = f"{_capital(result.explanation)}. {_capital(check.does)}?"
        if not check.personal and not ctx.yes and not ctx.confirm(question):
            ctx.say(f"{check.id}: skipped")
            continue
        try:
            check.step(ctx)
        except StepSkipped as skipped:
            ctx.say(f"{check.id}: skipped: {skipped}")
        except Exception as error:  # noqa: BLE001 - report it and go on with the next step
            ctx.say(f"{check.id}: FAILED: {error}")
        else:
            ctx.say(f"{check.id}: done")
    ctx.say("")
    results = run_checks(ctx)
    print_status(results, ctx.say)
    return _exit(results)


def cmd_setup(args) -> int:
    ctx = Context(yes=args.yes, interactive=sys.stdin.isatty(), signer_id=args.id, name=args.name,
                  role=args.role)
    return setup(ctx)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aqt", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"aqt (agent-quality-toolkit) {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="{status,setup,<tool>}")
    p = sub.add_parser("status", help="one verdict for the whole setup, with the fix for each problem")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--verify", action="store_true", help="verify the whole trail (slower on large trails)")
    p.set_defaults(func=cmd_status)
    p = sub.add_parser("setup", help="first-time setup, step by step; safe to rerun")
    p.add_argument("--yes", action="store_true",
                   help="apply every step that does not need you without asking (enrolling always asks)")
    p.add_argument("--id", help="your signer ID, e.g. human:alice")
    p.add_argument("--name", help="your printed name")
    p.add_argument("--role", help="your role, e.g. quality-manager or developer")
    p.set_defaults(func=cmd_setup)
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv and argv[0] in TOOLS:
        return run_tool(argv[0], argv[1:])
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exit_:
        return 0 if exit_.code in (0, None) else 2
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\naqt: interrupted", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
