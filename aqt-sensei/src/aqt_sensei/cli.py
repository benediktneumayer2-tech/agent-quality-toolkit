"""`aqt-sensei`: owner, worker, launcher and hook commands.

Exit codes: 0 ok, 1 refused or a check failed, 2 usage or runtime error (including the bridge being offline).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from . import __version__
from .agent import Unavailable, call
from .agent import run as agent_run
from .config import EXAMPLE_CONFIG, Paths, create_token, load_config, read_token

OWNER_COMMANDS = ("pair", "list", "show", "approve", "discard", "forward", "mode", "budget", "pause", "resume", "end")


def _out(data, args, text: str | None = None) -> None:
    if getattr(args, "json", False):
        print(json.dumps(data, ensure_ascii=False, indent=1))
    elif text is not None:
        print(text)


def _owner_call(paths: Paths, payload: dict) -> dict:
    token = read_token(paths.token_file)
    if not token:
        raise SystemExit("aqt-sensei: no owner token; run `aqt-sensei init` first")
    return call(paths.owner_socket, {**payload, "token": token})


def _backend(config) -> str:
    if config.backend:
        return config.backend
    if os.environ.get("HERDR_ENV") == "1" and not os.environ.get("TMUX"):
        return "herdr"
    return "tmux"


def _limits(args) -> dict:
    return {"max_messages": args.max_messages, "max_exchanges": args.max_exchanges, "max_cost": args.max_cost}


def _read_text(args) -> str | None:
    if getattr(args, "edit_file", None):
        return Path(args.edit_file).read_text()
    return getattr(args, "text", None)


def _summary(reply: dict) -> str:
    lines = []
    for pair in reply.get("pairs", []):
        used, budget = pair["used"], pair["budget"]
        limits = ", ".join(f"{k.removeprefix('max_')} {used[k.removeprefix('max_')]}/{v}"
                           for k, v in budget.items() if v) or "no limits"
        lines.append(f"{pair['id']}  {pair['state']:<8} {pair['mode']:<7} {pair['name']}  "
                     f"worker {pair['worker']['pane_id']} · sensei {pair['advisor']['pane_id']} "
                     f"({pair['advisor'].get('profile')}) · {limits} · {pair.get('independence')}")
        if pair.get("note"):
            lines.append(f"    note: {pair['note']}")
        for message in (m for m in reply.get("messages", []) if m["pair_id"] == pair["id"]):
            first = " ".join(message["text"].split())[:90]
            lines.append(f"    {message['id']}  #{message['seq']:<3} {message['from']:>7} → {message['to']:<7} "
                         f"{message['kind']:<6} {message['state']:<17} {first}")
    if reply.get("ledger_pending"):
        lines.append(f"ledger: {reply['ledger_pending']} records waiting for the evidence sink")
    return "\n".join(lines) or "no pairs"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aqt-sensei", description=(
        "Independent advisor for a coding agent: any vendor, read-only enforced by the OS, "
        "owner modes and budgets, advice ledger."))
    parser.add_argument("--version", action="version", version=f"aqt-sensei {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    def sub(name, help_text, json_flag=True):
        command = commands.add_parser(name, help=help_text)
        if json_flag:
            command.add_argument("--json", action="store_true", help="machine-readable output")
        return command

    init = sub("init", "write an example config (if missing) and create the owner token")
    init.add_argument("--owner-id")
    init.add_argument("--display")

    serve = sub("serve", "run the bridge daemon in the foreground", json_flag=False)
    serve.add_argument("--backend", choices=("tmux", "herdr"))

    pair = sub("pair", "pair a worker pane with a sandboxed advisor")
    pair.add_argument("--worker", required=True, metavar="PANE", help="worker pane id (tmux %%N, Herdr wN:pN)")
    pair.add_argument("--advisor", required=True, help="claude | codex | pi | a configured profile | a command")
    pair.add_argument("--project", required=True, help="project folder the advisor may read")
    pair.add_argument("--backend", choices=("tmux", "herdr"))
    pair.add_argument("--mode", choices=("manual", "confirm", "auto"))
    pair.add_argument("--max-exchanges", type=int)
    pair.add_argument("--max-messages", type=int)
    pair.add_argument("--max-cost", type=int, help="integer minor units (declared, not metered)")
    pair.add_argument("--model", help="advisor model")
    pair.add_argument("--worker-platform", help="claude | codex | pi | other (for the record and prompt detection)")
    pair.add_argument("--worker-model")
    pair.add_argument("--name")
    pair.add_argument("--network", choices=("share", "none"))
    pair.add_argument("--first-prompt")
    pair.add_argument("--start-with", choices=("worker", "advisor"), default="worker")
    pair.add_argument("--reason", required=True)

    listing = sub("list", "pairs with pending and recent messages")
    listing.add_argument("--pair")
    show = sub("show", "a message exactly as it will be typed, with its versions")
    show.add_argument("message")

    for name, help_text in (("approve", "approve a waiting message (optionally edited)"),
                            ("discard", "discard a pending message"),
                            ("forward", "forward a held message (manual mode)")):
        command = sub(name, help_text)
        command.add_argument("message")
        command.add_argument("--reason", required=True)
        if name == "approve":
            edit = command.add_mutually_exclusive_group()
            edit.add_argument("--text", help="replace the text before approving")
            edit.add_argument("--edit-file", help="read the replacement text from a file")

    mode = sub("mode", "set a pair's mode")
    mode.add_argument("pair")
    mode.add_argument("mode", choices=("manual", "confirm", "auto"))
    mode.add_argument("--reason", required=True)

    budget = sub("budget", "set, clear or add to a pair's budget")
    budget.add_argument("pair")
    budget.add_argument("--max-exchanges", type=int)
    budget.add_argument("--max-messages", type=int)
    budget.add_argument("--max-cost", type=int)
    budget.add_argument("--clear", action="store_true", help="remove all limits first")
    budget.add_argument("--add-cost", type=int, help="record a cost in minor units")
    budget.add_argument("--reason", required=True)

    for name in ("pause", "resume"):
        command = sub(name, f"{name} deliveries of a pair")
        command.add_argument("pair")
        command.add_argument("--reason")
    end = sub("end", "end a pair and close the sensei pane")
    end.add_argument("pair")
    end.add_argument("--reason", required=True)

    doctor = sub("doctor", "check the host and prove the advisor sandbox")
    target = doctor.add_mutually_exclusive_group(required=True)
    target.add_argument("--pair")
    target.add_argument("--profile", help="profile or advisor command, with --project")
    doctor.add_argument("--project")
    doctor.add_argument("--backend", choices=("tmux", "herdr"))

    login = sub("login", "sign the private advisor home of a platform in (once)", json_flag=False)
    login.add_argument("platform", choices=("claude", "codex", "pi"))

    launch = commands.add_parser("launch", help="(bridge) start the advisor in its sandbox")
    launch.add_argument("--pair", required=True)
    launch.add_argument("--resume", action="store_true", help="accepted; resuming follows the stored session")
    launch.add_argument("cmd", nargs=argparse.REMAINDER, help="-- CMD runs CMD in the sandbox instead")

    ask = commands.add_parser("ask", help="(worker) ask the sensei, then end your turn")
    ask.add_argument("text")
    ask.add_argument("--file", action="append", default=[], metavar="PATH")
    commands.add_parser("status", help="(worker) show the pair")

    hook = commands.add_parser("hook-state", help="(agent hooks, tmux) report this pane's state")
    hook.add_argument("state", choices=("working", "idle", "blocked", "done"))
    hook.add_argument("--pane", help="default: $TMUX_PANE")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as error:
        return 2 if error.code not in (0, None) else 0
    paths = Paths.default()
    try:
        config = load_config(paths.config_file)
    except (ValueError, OSError) as error:
        print(f"aqt-sensei: config: {error}", file=sys.stderr)
        return 2
    command = args.command
    try:
        if command == "init":
            return _init(args, paths)
        if command == "serve":
            return _serve(args, paths, config)
        if command in ("ask", "status"):
            return agent_run(command, getattr(args, "text", None), getattr(args, "file", ()),
                             socket_path=paths.agent_socket, prog="aqt-sensei")
        if command == "hook-state":
            from .hosts import write_pane_state
            pane = args.pane or os.environ.get("TMUX_PANE")
            if not pane:
                return 0  # not in tmux: nothing to report, never break the agent's hook
            write_pane_state(paths.pane_state, pane, args.state)
            return 0
        if command == "launch":
            from .launch import launch
            cmd = args.cmd[1:] if args.cmd[:1] == ["--"] else args.cmd
            return launch(args.pair, paths=paths, config=config, command=cmd or None)
        if command == "doctor":
            return _doctor(args, paths, config)
        if command == "login":
            return _login(args, paths, config)
        return _owner(args, paths)
    except Unavailable:
        print("aqt-sensei: the bridge is offline (run `aqt-sensei serve`)", file=sys.stderr)
        return 2
    except Exception as error:  # report, never a traceback for ordinary failures
        from .sandbox import SandboxError
        if isinstance(error, (SandboxError, OSError, ValueError)):
            print(f"aqt-sensei: {error}", file=sys.stderr)
            return 2
        raise


def _init(args, paths: Paths) -> int:
    if not paths.config_file.exists():
        paths.config_file.parent.mkdir(parents=True, exist_ok=True)
        text = EXAMPLE_CONFIG
        if args.owner_id:
            text = text.replace('id = "owner"', f'id = {json.dumps(args.owner_id)}')
        if args.display:
            text = text.replace('# display = "Your Name"', f"display = {json.dumps(args.display)}")
        paths.config_file.write_text(text)
        print(f"wrote {paths.config_file}")
    created = create_token(paths.token_file)
    print(f"{'created' if created else 'kept'} owner token {paths.token_file} (0600; never share it with agents)")
    paths.ensure()
    return 0


def _serve(args, paths: Paths, config) -> int:
    from .bridge import Bridge
    from .hosts import make_host
    from .ledger import Ledger
    from .server import Server
    if not read_token(paths.token_file):
        print("aqt-sensei: no owner token; run `aqt-sensei init` first", file=sys.stderr)
        return 2
    backend = args.backend or _backend(config)
    host = make_host(backend, tmux_socket=config.tmux_socket, state_dir=paths.pane_state,
                     quiet_seconds=config.quiet_seconds)
    ledger = Ledger(sink_spec=config.sink, spool=paths.state / "ledger-spool.jsonl",
                    owner_id=config.owner_actor_id, owner_display=config.owner_display)
    bridge = Bridge(paths=paths, config=config, host=host, ledger=ledger)
    server = Server(bridge, paths)
    try:
        server.start()
    except RuntimeError as error:
        print(f"aqt-sensei: {error}", file=sys.stderr)
        return 1
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    print(f"aqt-sensei: {backend} bridge listening in {paths.runtime}", flush=True)
    try:
        server.run(stop, config.poll_seconds)
    finally:
        server.shutdown()
    return 0


def _owner(args, paths: Paths) -> int:
    command = args.command
    payload: dict = {"op": command}
    if command == "pair":
        payload.update(worker=args.worker, advisor=args.advisor, project=os.path.abspath(args.project),
                       backend=args.backend, mode=args.mode, model=args.model, worker_platform=args.worker_platform,
                       worker_model=args.worker_model, name=args.name, network=args.network,
                       first_prompt=args.first_prompt, start_with=args.start_with, reason=args.reason, **_limits(args))
    elif command == "list":
        payload["pair_id"] = args.pair
    elif command in ("show", "approve", "discard", "forward"):
        payload["message_id"] = args.message
        if command != "show":
            payload["reason"] = args.reason
        if command == "approve":
            payload["text"] = _read_text(args)
    elif command == "mode":
        payload.update(pair_id=args.pair, mode=args.mode, reason=args.reason)
    elif command == "budget":
        payload.update(pair_id=args.pair, clear=args.clear, add_cost=args.add_cost, reason=args.reason, **_limits(args))
    else:  # pause, resume, end
        payload.update(pair_id=args.pair, reason=args.reason)
    reply = _owner_call(paths, payload)
    if reply.get("status") != "available":
        print(f"aqt-sensei: {reply.get('message') or 'refused'}", file=sys.stderr)
        return 1
    if command == "list":
        _out(reply, args, _summary(reply))
    elif command == "show":
        versions = reply.get("versions") or []
        text = reply["rendered"]
        if len(versions) > 1:
            text += "\n\n--- original text ---\n" + versions[0]
        _out(reply, args, text)
    elif command == "pair":
        _out(reply, args, f"paired {reply['pair_id']}: sensei pane {reply['pair']['advisor']['pane_id']} "
                          f"({reply['pair']['mode']} mode)")
    elif "message" in reply:
        _out(reply, args, f"{reply['message']['id']}: {reply['message']['state']}")
    else:
        pair = reply.get("pair") or {}
        _out(reply, args, f"{pair.get('id')}: {pair.get('state')}, mode {pair.get('mode')}, "
                          f"budget {pair.get('budget')}")
    return 0


def _doctor(args, paths: Paths, config) -> int:
    from .doctor import doctor_pair, doctor_profile, print_checks
    if args.pair:
        result = doctor_pair(args.pair, paths=paths, config=config)
        try:
            _owner_call(paths, {"op": "record_doctor", "pair_id": args.pair, "doctor": result})
        except (Unavailable, SystemExit):
            result["recorded"] = False
    else:
        if not args.project:
            print("aqt-sensei: --profile needs --project", file=sys.stderr)
            return 2
        result = doctor_profile(args.profile, args.project, paths=paths, config=config,
                                backend=args.backend or _backend(config))
    _out(result, args) if args.json else print_checks(result)
    return 0 if result["passed"] else 1


def _login(args, paths: Paths, config) -> int:
    """Run the platform CLI inside a sandbox where only its private home is writable.

    Claude Code: sign in with /login, then quit. Codex: device sign-in. pi: configure, then quit.
    """
    from .launch import prepare
    from .sandbox import resolve_cli, resolve_profile
    profile = resolve_profile(args.platform, config.profiles)
    login = {"claude": [], "codex": ["login", "--device-auth"], "pi": []}[args.platform]
    with tempfile.TemporaryDirectory(prefix="aqt-sensei-login-") as scratch:
        pair = {"id": "login-" + os.urandom(3).hex(), "backend": "none", "project_root": scratch,
                "scratch_dir": scratch, "mode": "confirm", "budget": {}, "network": "share", "name": "login",
                "worker": {"pane_id": None}, "advisor": {"pane_id": "login", "platform": args.platform,
                                                         "model": None, "session": None},
                "profile": profile.as_dict()}
        cli = resolve_cli(profile.command[0])[0]
        argv = prepare(pair, paths=paths, config=config, command=[cli, *login], proxy=False)
        try:
            return subprocess.call(argv)
        finally:
            shutil.rmtree(paths.pair_runtime(pair["id"]), ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
