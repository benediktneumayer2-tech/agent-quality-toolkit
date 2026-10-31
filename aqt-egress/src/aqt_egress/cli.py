"""``aqt-egress`` (also ``aqt egress``): the outbound checkpoint.

  aqt egress run [--project DIR] [--store excerpt|full] [--excerpt-chars N] [--local-endpoint HOST:PORT]
                 [--private-tmp] -- COMMAND [ARGS...]
        run COMMAND in a box whose only way out is the proxy; every request is recorded with
        the process that sent it (observe only: nothing is blocked)
  aqt egress report [--session ID] [--since 7d|DATE] [--json] [--evidence PATH]
        who talked to whom: sessions, destinations, processes, name lookups without a request
  aqt egress prune [--retention-days N|forever] [--dry-run]
        delete stored bodies (full mode) older than the retention period; recorded
  aqt egress status [--json]
        installed, CA, box support, last session
  aqt egress drain
        move records waiting in aqt-egress's own spool into the trail (also done at each session)

Settings: $XDG_CONFIG_HOME/aqt/egress.toml (store, retention_days, excerpt_chars, passthrough, llm_hosts,
local_endpoints).
Exit codes: run returns the command's exit code; otherwise 0 ok, 1 problem, 2 usage or runtime error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .settings import (SettingsError, check_excerpt, check_store, egress_state, load_settings, parse_endpoint,
                       parse_retention)


def cmd_run(args) -> int:
    from .box import BoxUnavailable
    from .run import run
    settings = load_settings()
    if args.store:
        settings.store = check_store(args.store)
    if args.excerpt_chars is not None:
        settings.excerpt_chars = check_excerpt(args.excerpt_chars)
    for endpoint in args.local_endpoint or []:
        if parse_endpoint(endpoint) not in settings.local_endpoints:
            settings.local_endpoints.append(parse_endpoint(endpoint))
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    try:
        return run(command, project=Path(args.project or "."), settings=settings, private_tmp=args.private_tmp)
    except (BoxUnavailable, OSError) as error:
        print(f"aqt-egress: {error}", file=sys.stderr)
        return 2


def cmd_report(args) -> int:
    from .report import build, load, parse_since, render
    records = load([Path(path) for path in args.evidence] if args.evidence else None)
    report = build(records, session=args.session, since=parse_since(args.since) if args.since else None)
    print(json.dumps(report, indent=2) if args.json else render(report))
    return 0


def cmd_prune(args) -> int:
    from .records import RecordWriter
    from .store import BodyStore
    settings = load_settings()
    days = parse_retention(args.retention_days) if args.retention_days is not None else settings.retention_days
    store = BodyStore(egress_state() / "bodies")
    result = store.prune(days, dry_run=args.dry_run)
    retention = days if days is not None else "forever"
    if args.dry_run:
        print(f"would remove {result['removed']} stored object(s) ({result['bytes']} bytes); "
              f"{result['kept']} kept (retention {retention})")
        return 0
    data = {"removed": result["removed"], "bytes": result["bytes"], "kept": result["kept"], "retention_days": retention}
    if result["cutoff"] is not None:
        from datetime import UTC, datetime
        data["cutoff"] = datetime.fromtimestamp(result["cutoff"], UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    writer = RecordWriter()
    writer.emit("egress.pruned", "pruned", data, subject={"kind": "egress.store", "ref": "bodies"})
    writer.close()
    print(f"removed {result['removed']} stored object(s) ({result['bytes']} bytes); {result['kept']} kept "
          f"(retention {retention})")
    return 1 if writer.failed else 0


def cmd_drain(args) -> int:
    from .records import drain_spool
    result = drain_spool()
    if result.get("error"):
        print(f"aqt-egress: {result.get('waiting', 0)} record(s) still waiting: {result['error']}", file=sys.stderr)
        return 1
    print(f"drained {result['drained']} record(s) into the trail")
    return 0


def status() -> dict:
    """What ``aqt status`` shows: version, CA, box support, last session."""
    from .box import available
    state = egress_state()
    ok, why = available()
    value = {"version": __version__, "ca": (state / "ca" / "mitmproxy-ca-cert.pem").exists(),
             "box": ok, "box_detail": why, "last_session": None}
    try:
        value["last_session"] = json.loads((state / "last-session.json").read_text())
    except (OSError, ValueError):
        pass
    return value


def cmd_status(args) -> int:
    value = status()
    if args.json:
        print(json.dumps(value, indent=2))
        return 0 if value["box"] else 1
    last = value["last_session"]
    print(f"aqt-egress {value['version']}: box {'ok' if value['box'] else 'NOT AVAILABLE'} ({value['box_detail']})")
    print(f"  CA: {'present' if value['ca'] else 'not created yet (the first run creates it)'}")
    print("  last session: " + (f"{last['session']} {last.get('ended', '?')} {last.get('requests', 0)} request(s), "
                                 f"exit {last.get('exit_code')}" if last else "none"))
    return 0 if value["box"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aqt-egress", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"aqt-egress {__version__}")
    sub = parser.add_subparsers(dest="command_name", required=True, metavar="{run,report,prune,status,drain}")
    p = sub.add_parser("run", help="run a command in the box; every outbound request is recorded")
    p.add_argument("--project", help="the project folder (default: the current folder)")
    p.add_argument("--store", choices=("excerpt", "full"), help="for this session (default from egress.toml)")
    p.add_argument("--excerpt-chars", type=int, help="length of the masked excerpts (0 to 4096; default 280)")
    p.add_argument("--local-endpoint", action="append", metavar="HOST:PORT",
                   help="an inference server on this host's loopback the box may reach (repeatable)")
    p.add_argument("--private-tmp", action="store_true",
                   help="give the box a fresh /tmp (closes other programs' sockets there)")
    p.add_argument("command", nargs=argparse.REMAINDER, help="-- COMMAND [ARGS...]")
    p.set_defaults(func=cmd_run)
    p = sub.add_parser("report", help="who talked to whom")
    p.add_argument("--session", help="one session (id or prefix)")
    p.add_argument("--since", help="sessions started since: 7d, 24h, 30m or a date")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--evidence", action="append", help="read records from this file (repeatable)")
    p.set_defaults(func=cmd_report)
    p = sub.add_parser("prune", help="delete stored bodies older than the retention period")
    p.add_argument("--retention-days", help="days (7 or more) or 'forever' (default from egress.toml)")
    p.add_argument("--dry-run", action="store_true", help="only count what would be removed")
    p.set_defaults(func=cmd_prune)
    p = sub.add_parser("drain", help="move records from aqt-egress's own spool into the trail")
    p.set_defaults(func=cmd_drain)
    p = sub.add_parser("status", help="installed, CA, box support, last session")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.set_defaults(func=cmd_status)
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exit_:
        return 0 if exit_.code in (0, None) else 2
    if args.command_name == "run" and not [part for part in args.command if part != "--"]:
        print("aqt-egress run: no command given (aqt egress run -- COMMAND ...)", file=sys.stderr)
        return 2
    try:
        return args.func(args)
    except (SettingsError, ValueError) as error:
        print(f"aqt-egress: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
