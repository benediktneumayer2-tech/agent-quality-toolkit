"""``aqt``: one command for the Agent Quality Toolkit.

  aqt status [--json] [--verify]     is everything in order? one verdict, and the fix for each problem
  aqt setup [--yes] [--id ID --name NAME --role ROLE]
                                     first-time setup, step by step; safe to rerun
  aqt project status [DIR] [--json]  what AQT needs in this repository, and the fix for each gap
  aqt project init [DIR] [--yes] [--local]
                                     set this repository up (hooks, deny rules, agent instructions,
                                     aqt-change settings); safe to rerun, never commits
  aqt <tool> ARGS...                 run a tool with these arguments: trail, signoff, change, sensei,
                                     quarantine, validate, capa, ui, spec (or evidence)

Exit codes: 0 ok (warnings allowed), 1 a check failed, 2 usage or runtime error.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__, project
from .checks import CHECKS, FAIL, Context, StepSkipped, needs_step, run_check, run_checks, verdict
from .tools import TOOLS, run_tool


def _exit(results) -> int:
    return 1 if verdict(results) == FAIL else 0


def print_status(results, say=print, title: str = "aqt status") -> None:
    counts = {kind: sum(1 for r in results if r.result == kind) for kind in ("fail", "warn")}
    detail = ", ".join(f"{n} {'failed' if kind == 'fail' else 'warning(s)'}" for kind, n in counts.items() if n)
    say(f"{title}: {verdict(results).upper()}" + (f" ({detail})" if detail else ""))
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


def apply_steps(ctx: Context, checks, name: str, title: str) -> int:
    """Show what is missing, apply each step (after confirmation unless --yes), then show the status."""
    initial = dict(zip((check.id for check in checks), run_checks(ctx, checks)))
    todo = [check for check in checks if needs_step(check, initial[check.id])]
    listed = [check for check in todo if not any(other.id == check.part_of for other in todo)]
    if listed:
        ctx.say(f"{name}: {len(listed)} step(s) to do")
        for check in listed:
            ctx.say(f"  - {check.describe(ctx)}" + ("  [needs you]" if check.personal else ""))
        if not ctx.yes and not ctx.interactive and any(not check.personal for check in listed):
            ctx.say("no terminal to confirm the steps: they are skipped; rerun with --yes to apply them")
    else:
        ctx.say(f"{name}: nothing to do")
    skipped: set[str] = set()
    for check in checks:
        if check.step is None:
            continue
        result = run_check(ctx, check)      # fresh: an earlier step may have done this one already
        if result.result in ("warn", "fail") and not result.can_apply and result.fix:
            ctx.say(f"{check.id}: yours to do: {result.fix}")
        if not needs_step(check, result):
            continue
        if not check.personal and not ctx.yes:
            if not ctx.interactive:
                if check.part_of not in skipped:      # its step was skipped as part of that one already
                    ctx.say(f"{check.id}: skipped (no terminal; --yes applies it)")
                skipped.add(check.id)
                continue
            if not ctx.confirm(f"{_capital(result.explanation)}. {_capital(check.describe(ctx))}?"):
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
    results = run_checks(ctx, checks)
    print_status(results, ctx.say, title)
    return _exit(results)


def setup(ctx: Context) -> int:
    return apply_steps(ctx, CHECKS, "aqt setup", "aqt status")


def cmd_setup(args) -> int:
    ctx = Context(yes=args.yes, interactive=sys.stdin.isatty(), signer_id=args.id, name=args.name,
                  role=args.role)
    return setup(ctx)


def project_init(ctx: project.ProjectContext) -> int:
    return apply_steps(ctx, project.PROJECT_CHECKS, "aqt project init", "aqt project status")


def _project_context(args, **kw) -> project.ProjectContext:
    root, git = project.resolve_root(args.dir)
    return project.ProjectContext(root=root, git=git, interactive=sys.stdin.isatty(), **kw)


def cmd_project(args) -> int:
    try:
        if args.project_command == "init":
            return project_init(_project_context(args, yes=args.yes, local=args.local))
        ctx = _project_context(args)
    except (OSError, ValueError) as error:
        print(f"aqt project: {error}", file=sys.stderr)
        return 2
    results = run_checks(ctx, project.PROJECT_CHECKS)
    if args.json:
        print(json.dumps({"verdict": verdict(results), "project": str(ctx.root),
                          "checks": [r.as_dict() for r in results]}, indent=2))
    else:
        print_status(results, title="aqt project status")
    return _exit(results)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aqt", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"aqt (agent-quality-toolkit) {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="{status,setup,project,<tool>}")
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
    p = sub.add_parser("project", help="what AQT needs in one repository: status, or init to set it up")
    project_sub = p.add_subparsers(dest="project_command", required=True, metavar="{status,init}")
    p = project_sub.add_parser("status", help="what is in place in this repository, and the fix for each gap")
    p.add_argument("dir", nargs="?", help="the repository (default: the current directory)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.set_defaults(func=cmd_project)
    p = project_sub.add_parser("init", help="set this repository up, step by step; safe to rerun; never commits")
    p.add_argument("dir", nargs="?", help="the repository (default: the current directory)")
    p.add_argument("--yes", action="store_true", help="apply every step without asking")
    p.add_argument("--local", action="store_true",
                   help="write the Claude Code hooks and deny rules into .claude/settings.local.json")
    p.set_defaults(func=cmd_project)
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
