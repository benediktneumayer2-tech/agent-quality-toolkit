"""The HTTP layer: one-time login, session cookie, CSRF and Origin checks, Host check, strict
CSP, static files and the JSON API. Standard library only; bound to 127.0.0.1.

Request logging records method, path without query, status and duration only. Request
bodies (which carry the passphrase of a decision) are never logged or echoed.
"""

from __future__ import annotations

import hmac
import json
import re
import secrets
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .config import UiConfig
from .guard import Guard, Mode
from .views import NotInstalled, UsageProblem, ViewProblem, installed
from .views.trail import PAGE

STATIC = Path(__file__).parent / "static"
STATIC_TYPES = {".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
                ".svg": "image/svg+xml", ".html": "text/html; charset=utf-8"}
PAGES = {"/", "/trail", "/quarantine", "/changes", "/signatures", "/capa", "/qualifications"}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; "
       "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
MAX_BODY = 64 * 1024
BIND = "127.0.0.1"


@dataclass
class Session:
    csrf: str
    created: float = field(default_factory=time.time)


class App:
    """Server state: settings, decision mode, sessions and the view adapters."""

    def __init__(self, config: UiConfig, mode: Mode, guard: Guard | None = None, *, log=None):
        from .views.changes import ChangesView
        from .views.trail import TrailView
        self.config, self.mode = config, mode
        self.guard = guard or Guard(mode)
        self.sessions: dict[str, Session] = {}
        self.tokens: set[str] = set()
        self.lock = threading.Lock()
        self.port = 0
        self.log = log or (lambda line: print(line, file=sys.stderr, flush=True))
        self.trail = TrailView()
        self.changes = ChangesView(config.projects)

    # fresh adapters per request: they read the tools' configuration each time
    def quarantine(self):
        from .views.quarantine import QuarantineView
        return QuarantineView()

    def capa(self):
        from .views.capa import CapaView
        return CapaView()

    def signatures(self):
        from .views.signatures import SignaturesView
        return SignaturesView()

    # -- login and sessions --------------------------------------------------------------------------
    @property
    def cookie_name(self) -> str:
        return f"aqt_ui_{self.port}"     # cookies are not separated by port; the name is

    def new_login_link(self) -> str:
        token = secrets.token_urlsafe(32)
        with self.lock:
            self.tokens.add(token)
        return f"http://{BIND}:{self.port}/login?t={token}"

    def redeem(self, token: str) -> str | None:
        """Exchange a one-time login token for a new session id."""
        with self.lock:
            match = next((known for known in self.tokens if hmac.compare_digest(known, token)), None)
            if match is None:
                return None
            self.tokens.discard(match)
            session_id = secrets.token_urlsafe(32)
            self.sessions[session_id] = Session(secrets.token_urlsafe(32))
            return session_id

    def session(self, session_id: str | None) -> Session | None:
        if not session_id:
            return None
        with self.lock:
            return self.sessions.get(session_id)


class UiServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, app: App, port: int = 0):
        self.app = app
        super().__init__((BIND, port), Handler)
        app.port = self.server_address[1]


class Handler(BaseHTTPRequestHandler):
    server: UiServer
    server_version = "aqt-ui"
    sys_version = ""

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
        body = json.dumps(value, default=str, ensure_ascii=False).encode("utf-8")
        body = self._scrub(body)
        self.send_bytes(status, body, "application/json; charset=utf-8")

    def send_page(self, status: int, title: str, text: str) -> None:
        body = (f"<!doctype html><html lang=en><head><meta charset=utf-8><title>{title}</title>"
                f"<link rel=stylesheet href=/static/app.css></head><body class=plain><main class=plain-page>"
                f"<h1>{title}</h1><p>{text}</p></main></body></html>").encode("utf-8")
        self.send_bytes(status, body, "text/html; charset=utf-8")

    def _scrub(self, body: bytes) -> bytes:
        """Safety net only: no code path echoes the passphrase. Very short values are not
        scrubbed because replacing them would garble ordinary words in the response."""
        secret = getattr(self, "_secret", None)
        if secret and len(secret) >= 8:
            body = body.replace(secret.encode("utf-8"), b"[passphrase removed]")
            body = body.replace(json.dumps(secret)[1:-1].encode("utf-8"), b"[passphrase removed]")
        return body

    def problem(self, status: int, message: str, **extra) -> None:
        self.send_json(status, {"ok": False, "message": message, **extra})

    # -- checks ----------------------------------------------------------------------------------------
    def host_ok(self) -> bool:
        host = self.headers.get("Host", "")
        port = self.app.port
        return host in (f"{BIND}:{port}", f"localhost:{port}")

    def current_session(self) -> Session | None:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        try:
            cookie = SimpleCookie(raw)
        except Exception:  # noqa: BLE001 - a malformed cookie is no cookie
            return None
        morsel = cookie.get(self.app.cookie_name)
        return self.app.session(morsel.value if morsel else None)

    def state_change_ok(self, session: Session) -> str | None:
        """None when Origin, CSRF header and content type are right, else the reason."""
        origin = self.headers.get("Origin", "")
        if origin != f"http://{self.headers.get('Host', '')}":
            return "bad or missing Origin"
        token = self.headers.get("X-AQT-CSRF", "")
        if not token or not hmac.compare_digest(token, session.csrf):
            return "bad or missing CSRF token"
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            return "JSON body required"
        return None

    def body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise UsageProblem("bad Content-Length") from None
        if length > MAX_BODY:
            raise UsageProblem("request body too large")
        raw = self.rfile.read(length) if length else b"{}"
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
        self._secret = None
        try:
            if not self.host_ok():
                self.send_page(403, "Host not allowed", "aqt-ui answers only to 127.0.0.1 and localhost.")
                return
            url = urlsplit(self.path)
            query = {key: values[-1] for key, values in parse_qs(url.query).items()}
            path = url.path
            if method == "GET" and path == "/login":
                self.login(query.get("t", ""))
                return
            if method == "GET" and path.startswith("/static/"):
                self.static(path[len("/static/"):])
                return
            session = self.current_session()
            if session is None:
                if path.startswith("/api/"):
                    self.problem(401, "not logged in: open the login link printed by aqt-ui in its terminal")
                else:
                    self.send_page(401, "Login needed", "Open the login link that aqt-ui printed in its terminal. "
                                   "Press Enter there to print a fresh link.")
                return
            if method == "GET" and path in PAGES:
                self.static("index.html")
                return
            if not path.startswith("/api/"):
                self.problem(404, "not found")
                return
            if method == "POST":
                reason = self.state_change_ok(session)
                if reason:
                    self.problem(403, f"refused: {reason}")
                    return
            self.api(method, path, query, session)
        except ViewProblem as error:
            self.problem(error.status, str(error), **({"install": error.package} if isinstance(error, NotInstalled)
                                                      else {}))
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as error:  # noqa: BLE001 - never crash the server; never echo the request
            detail = traceback.format_exc()
            if self._secret:
                detail = detail.replace(self._secret, "[passphrase removed]")
            self.app.log(f"aqt-ui internal error: {detail}")
            try:
                self.problem(500, f"internal error: {type(error).__name__}")
            except OSError:
                pass
        finally:
            self._secret = None

    def login(self, token: str) -> None:
        session_id = self.app.redeem(token) if token else None
        if session_id is None:
            self.send_page(403, "Login link not valid", "This login link was already used or does not belong to "
                           "this server. Press Enter in the aqt-ui terminal to print a fresh link.")
            return
        cookie = f"{self.app.cookie_name}={session_id}; HttpOnly; SameSite=Strict; Path=/"
        self.send_bytes(303, b"", "text/plain; charset=utf-8", {"Set-Cookie": cookie, "Location": "/"})

    def static(self, name: str) -> None:
        if not re.fullmatch(r"[a-z0-9_-]+\.(js|css|svg|html)", name):
            self.problem(404, "not found")
            return
        path = STATIC / name
        if not path.is_file():
            self.problem(404, "not found")
            return
        self.send_bytes(200, path.read_bytes(), STATIC_TYPES[path.suffix])

    # -- API -------------------------------------------------------------------------------------------
    def api(self, method: str, path: str, query: dict, session: Session) -> None:
        app = self.app
        parts = [part for part in path.split("/")[2:] if part]
        route = (method, *parts)
        if route == ("GET", "session"):
            self.send_json(200, {"csrf": session.csrf, "mode": app.mode.as_dict(), "version": __version__,
                                 "installed": {name: installed(name) for name in
                                               ("aqt_quarantine", "aqt_signoff", "aqt_change", "aqt_capa",
                                                "aqt_validate")},
                                 "projects": [str(p) for p in app.config.projects]})
        elif route == ("GET", "overview"):
            from .views.overview import build
            self.send_json(200, build(app))
        elif route == ("POST", "trail", "verify"):
            started = app.trail.verify_now()
            self.send_json(202, {"ok": True, "started": started})
        elif route == ("GET", "trail", "status"):
            self.send_json(200, {"status": app.trail.status(), "alcoa": app.trail.alcoa()})
        elif route == ("GET", "trail", "records"):
            before, offset, limit = query.get("before"), query.get("offset"), query.get("limit")
            self.send_json(200, app.trail.records(
                since=query.get("since"), until=query.get("until"), type=query.get("type"),
                actor=query.get("actor"), action=query.get("action"), subject=query.get("subject"),
                session=query.get("session"), before=int(before) if before and before.isdigit() else None,
                offset=int(offset) if offset and offset.isdigit() else 0,
                limit=int(limit) if limit and limit.isdigit() else PAGE))
        elif route == ("POST", "trail", "review", "run"):
            body = self.body()
            self.send_json(200, {"ok": True, **app.trail.review_run(since=str(body.get("since") or "") or None,
                                                                    until=str(body.get("until") or "") or None),
                                 "signers": signer_list()})
        elif len(route) == 5 and route[:3] == ("POST", "trail", "review") and route[4] == "sign":
            self.decide(lambda body, check: app.trail.review_sign(
                route[3], shown_head=str(body.get("head") or ""), dispositions=body.get("dispositions") or {},
                notes=body.get("notes") or {}, reason=str(body.get("reason") or ""),
                conclusion=str(body.get("conclusion") or ""), passphrase=self._secret or "",
                signer_id=str(body.get("signer_id") or ""), human_check=check))
        elif route == ("GET", "trail", "export"):
            name, data = app.trail.export()
            self.send_bytes(200, data, "application/gzip", {"Content-Disposition": f'attachment; filename="{name}"'})
        elif len(route) == 4 and route[:3] == ("GET", "trail", "record"):
            found = app.trail.record(route[3])
            if found is None:
                self.problem(404, f"no record {route[3]}")
            else:
                self.send_json(200, found)
        elif route == ("GET", "quarantine"):
            self.send_json(200, app.quarantine().cases(query.get("state")))
        elif len(route) == 3 and route[:2] == ("GET", "quarantine"):
            self.send_json(200, app.quarantine().case(route[2], full=query.get("full") == "1"))
        elif len(route) == 4 and route[:3] == ("POST", "quarantine", "sources") and route[3] in ("trust", "revoke"):
            self.decide(lambda body, check: app.quarantine().trust(
                str(body.get("domain") or ""), reason=str(body.get("reason") or ""), passphrase=self._secret or "",
                signer_id=body.get("signer_id"), human_check=check, expires=str(body.get("expires") or "") or None,
                subdomains=bool(body.get("subdomains")), revoke=route[3] == "revoke",
                shown_record=str(body.get("record") or "") or None))
        elif len(route) == 4 and route[:2] == ("POST", "quarantine") and route[3] in ("release", "threat"):
            self.decide(lambda body, check: app.quarantine().decide(
                route[2], route[3], reason=str(body.get("reason") or ""), passphrase=self._secret or "",
                shown_sha256=str(body.get("content_sha256") or ""), signer_id=body.get("signer_id"),
                human_check=check, overrule_threat=bool(body.get("overrule_threat"))))
        elif route == ("GET", "changes"):
            self.send_json(200, app.changes.summary())
        elif len(route) == 4 and route[:3] == ("GET", "changes", "actions"):
            self.send_json(200, app.changes.action(route[3]))
        elif len(route) == 5 and route[:3] == ("POST", "changes", "actions") and route[4] in ("approve", "reject"):
            self.decide(lambda body, check: app.changes.decide_action(
                route[3], route[4], expected_hash=str(body.get("expected_hash") or ""),
                reason=str(body.get("reason") or ""), passphrase=self._secret or "",
                signer_id=body.get("signer_id"), human_check=check))
        elif route == ("POST", "changes", "plans", "approve"):
            self.decide(lambda body, check: app.changes.approve_plan(
                str(body.get("root") or ""), str(body.get("plan_id") or ""),
                shown_record=str(body.get("record") or ""), shown_sha256=str(body.get("sha256") or ""),
                reason=str(body.get("reason") or ""), passphrase=self._secret or "",
                signer_id=body.get("signer_id"), human_check=check))
        elif route == ("GET", "signatures"):
            self.send_json(200, app.signatures().registry())
        elif route == ("GET", "signatures", "verify"):
            self.send_json(200, app.signatures().verify(file=query.get("file"), record=query.get("record"),
                                                        sha256=query.get("sha256")))
        elif route == ("GET", "signatures", "manifest"):
            result = app.signatures().verify(file=query.get("file"), record=query.get("record"),
                                             sha256=query.get("sha256"))
            html_format = query.get("format") == "html"
            body = (result["manifest_html"] if html_format else result["manifest_md"]).encode("utf-8")
            name = "signature-manifest." + ("html" if html_format else "md")
            # an attachment, never rendered as a page of this origin
            self.send_bytes(200, body, "text/markdown; charset=utf-8" if not html_format else "application/octet-stream",
                            {"Content-Disposition": f'attachment; filename="{name}"'})
        elif route == ("GET", "capa"):
            self.send_json(200, app.capa().summary())
        elif route == ("GET", "capa", "trends"):
            self.send_bytes(200, app.capa().trends().encode("utf-8"), "text/markdown; charset=utf-8",
                            {"Content-Disposition": 'attachment; filename="capa-trends.md"'})
        elif len(route) == 3 and route[:2] == ("GET", "capa"):
            self.send_json(200, app.capa().deviation(route[2]))
        elif len(route) == 5 and route[:3] == ("POST", "capa", "candidates") and route[4] in ("accept", "dismiss"):
            self.decide(lambda body, check: app.capa().decide(
                route[4], route[3], reason=str(body.get("reason") or ""), passphrase=self._secret or "",
                signer_id=body.get("signer_id"), human_check=check))
        elif len(route) == 5 and route[:3] == ("POST", "capa", "actions") and route[4] == "approve":
            self.decide(lambda body, check: app.capa().approve_action(
                route[3], expected_hash=str(body.get("expected_hash") or ""), reason=str(body.get("reason") or ""),
                passphrase=self._secret or "", signer_id=body.get("signer_id"), human_check=check))
        elif len(route) == 4 and route[:2] == ("POST", "capa") and route[3] == "close":
            self.decide(lambda body, check: app.capa().decide(
                "close", route[2], reason=str(body.get("reason") or ""), passphrase=self._secret or "",
                signer_id=body.get("signer_id"), human_check=check, shown_version=str(body.get("version") or ""),
                no_action=bool(body.get("no_action"))))
        elif route == ("GET", "qualifications"):
            from .views.qualifications import qualifications
            self.send_json(200, qualifications(app.config.qualification_warn_days))
        else:
            self.problem(404, "not found")

    def decide(self, call) -> None:
        """A human-only request. The package runs the guard first and records a refusal itself;
        the passphrase is used once to unlock the key and dropped with the request."""
        body = self.body()
        passphrase = body.pop("passphrase", None)
        self._secret = passphrase if isinstance(passphrase, str) and passphrase else None
        if self.app.mode.explicit:
            self.problem(403, "refused: this aqt-ui server was started with --read-only")
            return
        check = self.app.guard.human_check(self.client_address, self.server.server_address)
        result = call(body, check)
        self.send_json(200 if result.get("ok") else 403, result)


def signer_list() -> list[dict]:
    from .views import installed as has
    if not has("aqt_signoff"):
        return []
    from .views.changes import _signers
    return _signers()


def make_server(app: App, port: int = 0) -> UiServer:
    return UiServer(app, port)
