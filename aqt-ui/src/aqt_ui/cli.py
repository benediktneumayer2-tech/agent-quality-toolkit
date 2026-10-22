"""``aqt-ui``: start the local web UI.

    aqt-ui [--port N] [--read-only] [--no-browser] [--config PATH]

Prints a one-time login link. Press Enter for a fresh link; Ctrl+C stops the server and
ends every session. Exit codes: 0 stopped normally, 2 usage or start-up error.
"""

from __future__ import annotations

import argparse
import sys
import threading
import webbrowser

from . import __version__
from .config import load_config
from .guard import Guard, startup_mode
from .server import App, make_server


def _fresh_links(app: App) -> None:
    for _line in sys.stdin:
        print(f"login link: {app.new_login_link()}", flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aqt-ui", description="Local web UI of the Agent Quality Toolkit "
                                     "(127.0.0.1 only).")
    parser.add_argument("--port", type=int, default=None, help="TCP port (default: ui.toml or a free port)")
    parser.add_argument("--read-only", action="store_true", help="never allow decisions from this server")
    parser.add_argument("--no-browser", action="store_true", help="do not open the browser")
    parser.add_argument("--config", help="ui.toml to use (default: $XDG_CONFIG_HOME/aqt/ui.toml)")
    parser.add_argument("--version", action="version", version=f"aqt-ui {__version__}")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
    except (OSError, ValueError) as error:
        print(f"aqt-ui: {error}", file=sys.stderr)
        return 2
    mode = startup_mode(args.read_only)
    app = App(config, mode, Guard(mode))
    try:
        server = make_server(app, config.port if args.port is None else args.port)
    except OSError as error:
        print(f"aqt-ui: cannot listen on 127.0.0.1: {error}", file=sys.stderr)
        return 2
    app.trail.verify_now()          # full verification once at start, in the background
    link = app.new_login_link()
    if mode.decisions:
        print("aqt-ui: decisions are on (each one asks for your passphrase)")
    else:
        print(f"aqt-ui: READ-ONLY. {mode.reason}")
    print(f"aqt-ui {__version__} on http://127.0.0.1:{app.port}/")
    print(f"login link (works once): {link}")
    print("Press Enter for a fresh login link, Ctrl+C to stop.", flush=True)
    if sys.stdin and sys.stdin.isatty():
        threading.Thread(target=_fresh_links, args=(app,), daemon=True).start()
    if config.open_browser and not args.no_browser:
        threading.Thread(target=webbrowser.open, args=(link,), daemon=True).start()
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\naqt-ui: stopped; all sessions ended")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
