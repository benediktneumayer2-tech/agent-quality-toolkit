"""Agent side of aqt-sensei: `ask` (worker) and `reply` / `send` / `status` / `worker-log` (advisor).

Standard library only: this file is also copied into each advisor sandbox as
the `sensei` command. Exit codes: 0 done, 1 refused, 2 usage error or bridge
offline (or the caller's own shell sandbox blocks the socket).
"""

import argparse
import json
import os
import socket
import sys
from pathlib import Path

MAX_TEXT = 64 * 1024


class Unavailable(Exception):
    pass


class Blocked(Unavailable):
    """The caller's own shell sandbox forbids connecting to the socket."""


def call(path, payload, timeout=60.0):
    """Send one JSON line to a bridge socket and return the JSON reply."""
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout)
    try:
        try:
            client.connect(str(path))
        except (FileNotFoundError, ConnectionRefusedError) as error:
            raise Unavailable(str(error)) from error
        except PermissionError as error:
            raise Blocked(str(error)) from error
        client.sendall(json.dumps(payload, ensure_ascii=False).encode() + b"\n")
        chunks = []
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            if chunk.endswith(b"\n"):
                break
    finally:
        client.close()
    reply = json.loads(b"".join(chunks) or b"{}")
    return reply if isinstance(reply, dict) else {"status": "error", "message": "invalid bridge reply"}


def default_agent_socket():
    if os.environ.get("AQT_SENSEI_SOCKET"):
        return Path(os.environ["AQT_SENSEI_SOCKET"])
    if os.environ.get("AQT_SENSEI_RUNTIME"):
        return Path(os.environ["AQT_SENSEI_RUNTIME"]) / "agent.sock"
    base = os.environ.get("XDG_RUNTIME_DIR")
    if base:
        return Path(base) / "aqt-sensei" / "agent.sock"
    state = os.environ.get("AQT_SENSEI_STATE") or str(
        Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state") / "aqt" / "sensei")
    return Path(state) / "run" / "agent.sock"


def pane_hint():
    return os.environ.get("TMUX_PANE") or os.environ.get("HERDR_PANE_ID") or None


def build_payload(command, text=None, files=(), last=None):
    payload = {"op": command.replace("-", "_"), "pane_hint": pane_hint()}
    if command in ("ask", "reply", "send"):
        if not text or not text.strip():
            raise ValueError("the message text is empty")
        if len(text.encode()) > MAX_TEXT:
            raise ValueError("the message is too long; write it to a file and add --file PATH")
        resolved = []
        for name in files:
            path = Path(name).expanduser().absolute()
            if not path.exists():
                raise ValueError(f"file not found: {name}")
            resolved.append(str(path))
        payload.update(text=text, files=resolved)
    elif command == "worker-log":
        payload["last"] = max(1, min(int(last or 200), 2000))
    return payload


def run(command, text=None, files=(), last=None, socket_path=None, out=None, err=None, prog="sensei"):
    out, err = out or sys.stdout, err or sys.stderr
    try:
        payload = build_payload(command, text, files, last)
    except ValueError as error:
        print(f"{prog}: {error}", file=err)
        return 2
    try:
        reply = call(socket_path or default_agent_socket(), payload)
    except Blocked:
        print(f"{prog}: your shell sandbox blocks the bridge socket; rerun this command with escalated "
              "permissions (outside your tool's sandbox).", file=err)
        return 2
    except Unavailable:
        print(f"{prog}: the aqt-sensei bridge is offline (aqt-sensei serve is not running).", file=err)
        return 2
    except (OSError, ValueError) as error:
        print(f"{prog}: the bridge did not answer ({error.__class__.__name__}).", file=err)
        return 2
    if reply.get("status") != "available":
        print(f"{prog}: {reply.get('message') or 'request refused'}", file=err)
        return 1
    print(reply.get("output", ""), file=out)
    return 0


def advisor_main(argv=None):
    """The in-sandbox `sensei` command."""
    parser = argparse.ArgumentParser(prog="sensei", description="Talk to your worker through the aqt-sensei bridge.")
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (("reply", "answer the worker's open question"),
                            ("send", "send the worker an unsolicited plan, review or warning")):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("text")
        command.add_argument("--file", action="append", default=[], metavar="PATH")
    commands.add_parser("status", help="show the pair, mode, budget and pending messages")
    log = commands.add_parser("worker-log", help="the worker pane's recent output")
    log.add_argument("--last", type=int, default=200, metavar="LINES")
    args = parser.parse_args(argv)
    return run(args.command, getattr(args, "text", None), getattr(args, "file", ()), getattr(args, "last", None))


if __name__ == "__main__":
    raise SystemExit(advisor_main())
