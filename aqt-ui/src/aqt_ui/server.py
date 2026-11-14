"""The HTTP layer: one-time login, session cookie plus session key, Origin check, Host check,
strict CSP and static files around the JSON API of ``core.Core``. Standard library only; bound to 127.0.0.1.

Browsers send a cookie for 127.0.0.1 to every port of that host, so the cookie alone is not a
session: every API request must also carry the session's key in the ``X-AQT-CSRF`` header. The
key reaches the page once, in the answer to the login link, and stays in the tab's
``sessionStorage`` (which is separated by port). No answer to a cookie-only request contains it.

Request logging records method, path without query, status and duration only, and for each
decision request the process that sent it. Request bodies (which carry the passphrase of a
decision) are never logged or echoed. Each connection has a read and write timeout, and the
number of connections handled at once is limited.
"""

from __future__ import annotations

import hmac
import json
import re
import secrets
import threading
import time
import traceback
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, unquote, urlsplit

from .config import UiConfig
from .core import Core, Response
from .guard import Guard, Mode
from .views import UsageProblem

STATIC = Path(__file__).parent / "static"
STATIC_TYPES = {".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
                ".svg": "image/svg+xml", ".html": "text/html; charset=utf-8"}
# the areas (Needs you, Changes, Projects, Evidence, Settings), the first-run setup, and the views of 0.2 whose
# addresses the page redirects to their new place (old bookmarks keep working)
PAGES = {"/", "/changes", "/projects", "/evidence", "/settings", "/welcome",
         "/health", "/trail", "/quarantine", "/signatures", "/capa", "/qualifications"}
EVIDENCE_ROUTE = re.compile(r"/evidence/(trail|signatures|quarantine|capa|qualifications|export)")
# a case page (/case/<case id>) and a change page (/change/<project>/<plan id>): the same page shell
CASE_ROUTE = re.compile(r"/case/([A-Za-z0-9._~:%@+-]{1,300})")
CHANGE_ROUTE = re.compile(r"/change/[0-9]{1,4}/(?!\.\.?$)[A-Za-z0-9._-]{1,200}")
# what a decoded case id never holds: a query, a fragment, a backslash, control characters, a .. part
UNSAFE_CASE_ID = re.compile(r"[?#\\\x00-\x1f\x7f]|(^|[:/])\.\.?([:/]|$)")


def page_route(path: str) -> bool:
    """A case, change or evidence page the shell is served for."""
    found = CASE_ROUTE.fullmatch(path)
    if found:
        return not UNSAFE_CASE_ID.search(unquote(found.group(1)))
    return bool(CHANGE_ROUTE.fullmatch(path) or EVIDENCE_ROUTE.fullmatch(path))
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; "
       "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
MAX_BODY = 64 * 1024
BIND = "127.0.0.1"
KEY_HEADER = "X-AQT-CSRF"     # the session key; required on every API request
REQUEST_TIMEOUT = 20.0        # seconds for each read or write on a connection
MAX_CONNECTIONS = 32          # connections handled at once; more are closed at once


@dataclass
class Session:
    csrf: str
    created: float = field(default_factory=time.time)
    shown: dict = field(default_factory=dict)      # (case id, content hash) -> quarantine pages sent


class App(Core):
    """Server state: the core (settings, decision mode, view adapters, the API) plus login and sessions."""

    kind = "aqt-ui server"

    def __init__(self, config: UiConfig, mode: Mode, guard: Guard | None = None, *, log=None):
        super().__init__(config, mode, guard or Guard(mode), log=log)    # the guard looks up the TCP peer
        self.sessions: dict[str, Session] = {}
        self.tokens: set[str] = set()
        self.lock = threading.Lock()
        self.port = 0
        self.on_login: Callable[[], None] | None = None     # called after a login link was used

    # -- login and sessions --------------------------------------------------------------------------
    @property
    def cookie_name(self) -> str:
        return f"aqt_ui_{self.port}"     # names the server; the session key, not the cookie, guards the session

    def new_login_link(self) -> str:
        """A fresh one-time link. Links handed out before it and not used yet stop working."""
        token = secrets.token_urlsafe(32)
        with self.lock:
            self.tokens = {token}
        return f"http://{BIND}:{self.port}/login?t={token}"

    def redeem(self, token: str) -> str | None:
        """Exchange a one-time login token for a new session id. Each use is logged, so a
        session that someone else started with the link shows up in the terminal."""
        with self.lock:
            match = next((known for known in self.tokens if hmac.compare_digest(known.encode(), token.encode())),
                         None)
            if match is None:
                return None
            self.tokens.discard(match)
            session_id = secrets.token_urlsafe(32)
            self.sessions[session_id] = Session(secrets.token_urlsafe(32))
            count = len(self.sessions)
        self.log(f"aqt-ui: a login link was used; browser session {count} started. If that was not you, "
                 "stop aqt-ui with Ctrl+C.")
        if self.on_login:
            try:
                self.on_login()
            except Exception:  # noqa: BLE001 - clean-up after login never breaks the login
                pass
        return session_id

    def session(self, session_id: str | None) -> Session | None:
        if not session_id:
            return None
        with self.lock:
            return self.sessions.get(session_id)


class UiServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, app: App, port: int = 0, *, max_connections: int = MAX_CONNECTIONS,
                 request_timeout: float = REQUEST_TIMEOUT):
        self.app = app
        self.request_timeout = request_timeout
        self._slots = threading.BoundedSemaphore(max_connections)
        super().__init__((BIND, port), Handler)
        app.port = self.server_address[1]

    def process_request(self, request, client_address) -> None:
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)          # too many connections at once: close this one
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class Handler(BaseHTTPRequestHandler):
    server: UiServer
    server_version = "aqt-ui"
    sys_version = ""

    def setup(self) -> None:
        self.timeout = self.server.request_timeout    # applied to the socket by StreamRequestHandler
        super().setup()

    # -- logging: method, path without query, status, duration; nothing else --------------------------
    def log_request(self, code="-", size="-") -> None:
        status = code.value if isinstance(code, HTTPStatus) else code
        duration = (time.monotonic() - getattr(self, "_started", time.monotonic())) * 1000
        path = urlsplit(getattr(self, "path", "") or "").path
        self.server.app.log(f"aqt-ui {self.command or '-'} {path} {status} {duration:.0f}ms")

    def log_error(self, format, *args) -> None:  # noqa: A002 - BaseHTTPRequestHandler signature
        pass   # send_error is followed by log_request; never repeat request lines (they carry tokens)

    def log_message(self, format, *args) -> None:  # noqa: A002
        pass

    # -- plumbing --------------------------------------------------------------------------------------
    @property
    def app(self) -> App:
        return self.server.app

    def _headers(self, status: int, content_type: str, length: int, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()

    def send_bytes(self, status: int, body: bytes, content_type: str, extra: dict | None = None) -> None:
        self._headers(status, content_type, len(body), extra)
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_json(self, status: int, value) -> None:
        self.respond(Response(status, value))

    def respond(self, response: Response) -> None:
        extra = {"Content-Disposition": f'attachment; filename="{response.filename}"'} if response.filename else None
        self.send_bytes(response.status, response.payload(), response.content_type, extra)

    def send_page(self, status: int, title: str, text: str) -> None:
        body = (f"<!doctype html><html lang=en><head><meta charset=utf-8><title>{title}</title>"
                f"<link rel=stylesheet href=/static/app.css></head><body class=plain><main class=plain-page>"
                f"<h1>{title}</h1><p>{text}</p></main></body></html>").encode("utf-8")
        self.send_bytes(status, body, "text/html; charset=utf-8")

    def problem(self, status: int, message: str, **extra) -> None:
        self.send_json(status, {"ok": False, "message": message, **extra})

    # -- checks ----------------------------------------------------------------------------------------
    def host_ok(self) -> bool:
        host = self.headers.get("Host", "")
        port = self.app.port
        return host in (f"{BIND}:{port}", f"localhost:{port}")

    def cookie_values(self) -> list[str]:
        """Every value sent under this server's cookie name. Parsed by hand: other pages on
        127.0.0.1 may set cookies that ``http.cookies`` rejects together with all the others."""
        name = self.app.cookie_name
        values = []
        for header in self.headers.get_all("Cookie") or []:
            for part in header.split(";"):
                key, sep, value = part.partition("=")
                if sep and key.strip() == name:
                    values.append(value.strip().strip('"'))
        return values

    def current_session(self) -> Session | None:
        for value in self.cookie_values():
            session = self.app.session(value)
            if session is not None:
                return session
        return None

    def key_ok(self, session: Session) -> bool:
        token = self.headers.get(KEY_HEADER, "")
        return bool(token) and hmac.compare_digest(token.encode(), session.csrf.encode())

    def state_change_ok(self) -> str | None:
        """None when Origin and content type are right, else the reason."""
        origin = self.headers.get("Origin", "")
        if origin != f"http://{self.headers.get('Host', '')}":
            return "bad or missing Origin"
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            return "JSON body required"
        return None

    def body(self) -> dict:
        text = str(self.headers.get("Content-Length") or "0").strip()
        if not re.fullmatch(r"[0-9]{1,9}", text):
            raise UsageProblem("bad Content-Length")
        length = int(text)
        if length > MAX_BODY:
            raise UsageProblem("request body too large")
        raw = b"{}"
        if length:
            try:
                raw = self.rfile.read(length)              # exactly the announced bytes, never "until EOF"
            except TimeoutError:
                self.close_connection = True
                raise UsageProblem("the request body did not arrive in time") from None
            if len(raw) != length:
                raise UsageProblem("the request body is shorter than its Content-Length")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise UsageProblem("the request body is not valid JSON") from None
        if not isinstance(value, dict):
            raise UsageProblem("the request body must be a JSON object")
        return value

    # -- dispatch --------------------------------------------------------------------------------------
    def do_HEAD(self):  # noqa: N802
        self.do_GET()

    def do_GET(self):  # noqa: N802
        self._dispatch("GET")

    def do_POST(self):  # noqa: N802
        self._dispatch("POST")

    def _dispatch(self, method: str) -> None:
        self._started = time.monotonic()
        try:
            if not self.host_ok():
                self.send_page(403, "Host not allowed", "aqt-ui answers only to 127.0.0.1 and localhost.")
                return
            url = urlsplit(self.path)
            query = {key: values[-1] for key, values in parse_qs(url.query).items()}
            path = url.path
            if method == "GET" and path == "/login":
                if self.command != "GET":          # a HEAD request would spend the token without the key
                    self.problem(405, "open the login link with GET")
                    return
                self.login(query.get("t", ""))
                return
            if method == "GET" and path.startswith("/static/"):
                self.static(path[len("/static/"):])
                return
            if method == "GET" and (path in PAGES or page_route(path)):
                self.static("index.html")         # the page shell holds no data; the API needs the session
                return
            if not path.startswith("/api/"):
                self.problem(404, "not found")
                return
            session = self.current_session()
            if session is None:
                self.problem(401, "not logged in: open the login link printed by aqt-ui in its terminal "
                             "(press Enter there for a fresh link)")
                return
            if not self.key_ok(session):
                self.problem(403, "refused: bad or missing CSRF token (the session key of this browser tab). "
                             "Open a fresh login link: press Enter in the aqt-ui terminal.")
                return
            if method == "POST":
                reason = self.state_change_ok()
                if reason:
                    self.problem(403, f"refused: {reason}")
                    return
            # the body is read only by routes that use one; the guard looks up the process on the other end
            self.respond(self.app.handle(method, path, query, self.body, shown=session.shown,
                                         human_check=lambda: self.app.guard.human_check(
                                             self.client_address, self.server.server_address)))
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as error:  # noqa: BLE001 - never crash the server; never echo the request
            self.app.log(f"aqt-ui internal error: {traceback.format_exc()}")
            try:
                self.problem(500, f"internal error: {type(error).__name__}")
            except OSError:
                pass

    def login(self, token: str) -> None:
        """A used link answers with the page itself, which carries the session key once in a
        meta tag; the page moves it to ``sessionStorage`` and its address to ``/``."""
        session_id = self.app.redeem(token) if token else None
        session = self.app.session(session_id)
        if session is None:
            self.send_page(403, "Login link not valid", "This login link was already used, was replaced by a "
                           "fresher one or does not belong to this server. Press Enter in the aqt-ui terminal to "
                           "print a fresh link.")
            return
        cookie = f"{self.app.cookie_name}={session_id}; HttpOnly; SameSite=Strict; Path=/"
        page = (STATIC / "index.html").read_text(encoding="utf-8")
        page = page.replace("<head>\n", f'<head>\n<meta name="aqt-csrf" content="{session.csrf}">\n', 1)
        self.send_bytes(200, page.encode("utf-8"), STATIC_TYPES[".html"], {"Set-Cookie": cookie})

    def static(self, name: str) -> None:
        if not re.fullmatch(r"[a-z0-9_-]+\.(js|css|svg|html)", name):
            self.problem(404, "not found")
            return
        path = STATIC / name
        if not path.is_file():
            self.problem(404, "not found")
            return
        self.send_bytes(200, path.read_bytes(), STATIC_TYPES[path.suffix])


def make_server(app: App, port: int = 0) -> UiServer:
    return UiServer(app, port)
