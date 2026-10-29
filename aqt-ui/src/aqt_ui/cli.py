"""``aqt-ui``: start the local web UI.

    aqt-ui [--port N] [--read-only] [--no-browser] [--config PATH]

Prints a one-time login link. Press Enter for a fresh link; Ctrl+C stops the server and
ends every session. Exit codes: 0 stopped normally, 2 usage or start-up error.

The browser is not started with the link: a command line can be read by every local user
(``/proc/<pid>/cmdline``). It is started with a ``file://`` page that forwards to the link, in a
private folder (mode 0700, the file 0600) named ``aqt-ui-login-*`` directly in the home
directory; the page is removed as soon as a link was used and when the server stops.

The home directory, not ``$XDG_RUNTIME_DIR`` or ``/tmp``, because snap-packaged browsers (Ubuntu's
default Firefox and Chromium) can read only non-hidden files under ``$HOME`` there: ``/run/user``
is outside their confinement and their ``/tmp`` is private. Without a usable home directory the
page goes to ``$XDG_RUNTIME_DIR`` or the temporary directory as before. The printed link always
works as well.
"""

from __future__ import annotations

import argparse
import html
import os
import shutil
import sys
import tempfile
import threading
import webbrowser
from pathlib import Path

from . import __version__
from .config import load_config
from .guard import Guard, startup_mode
from .server import App, make_server


def _fresh_links(app: App) -> None:
    for _line in sys.stdin:
        print(f"login link (works once, replaces older ones): {app.new_login_link()}", flush=True)


def login_dir() -> str | None:
    """Where the forward page's folder goes: the home directory when it is a writable directory of
    this user (readable by snap browsers too), else ``$XDG_RUNTIME_DIR``, else the temp directory."""
    home = os.path.expanduser("~")
    try:
        info = os.stat(home)
        if os.path.isdir(home) and info.st_uid == os.getuid() and os.access(home, os.W_OK | os.X_OK):
            return home
    except OSError:
        pass
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    return runtime if runtime and os.path.isdir(runtime) else None


def open_browser(app: App, link: str, *, opener=webbrowser.open) -> Path:
    """Open the browser on a private page that forwards to ``link``; the token stays out of
    every command line. Returns the page; it is removed once a login link has been used."""
    folder = Path(tempfile.mkdtemp(prefix="aqt-ui-login-", dir=login_dir()))   # mode 0700, only this user
    page = folder / "login.html"
    target = html.escape(link, quote=True)
    text = ("<!doctype html><html lang=en><head><meta charset=utf-8><meta name=referrer content=no-referrer>"
            f'<meta http-equiv="refresh" content="0;url={target}"><title>aqt-ui login</title></head>'
            f'<body><p><a href="{target}">Open the AQT quality desk</a></p></body></html>\n')
    fd = os.open(page, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)

    def remove() -> None:
        shutil.rmtree(folder, ignore_errors=True)
    app.on_login = remove
    opener(page.as_uri())
    return page


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
    login_page = None
    if config.open_browser and not args.no_browser:
        try:
            login_page = open_browser(app, link, opener=lambda url: threading.Thread(
                target=webbrowser.open, args=(url,), daemon=True).start())
        except OSError as error:
            print(f"aqt-ui: could not prepare the browser page ({error}); open the link yourself")
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\naqt-ui: stopped; all sessions ended")
    finally:
        server.server_close()
        if login_page is not None:
            shutil.rmtree(login_page.parent, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
