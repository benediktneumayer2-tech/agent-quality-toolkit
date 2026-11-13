"""The core of aqt-ui without a transport: the JSON API (``Core.handle``) and ``aqt core --stdio``.

The same ``Core.handle(method, path, query, body)`` answers the browser through the HTTP server
(``aqt-ui``, which keeps login, session, CSRF and Host checks to itself) and a desktop app through
stdin and stdout (``aqt core --stdio``, also ``aqt-ui core --stdio``). The app starts the core as its
child process; nothing listens on a port.

Protocol 1 of ``--stdio``: newline-delimited UTF-8 JSON, one object per line.

- At start the core writes ``{"event": "ready", "body": {...}}``: what ``GET /api/session`` answers
  (``mode``, ``version``, ``installed``, ``install``, ``projects``) plus ``"protocol": 1``.
- A request is ``{"id": "<string>", "method": "GET" | "POST", "path": "/api/...?...", "body": <object|null>}``;
  the query string is part of ``path``, ``body`` is what the browser POSTs as JSON.
- Each response is ``{"id": "<same>", "status": <int>, "content_type": "<mime>", ...}`` with one of
  ``"body"`` (a JSON answer), ``"text"`` (a text download, UTF-8) or ``"base64"`` (a binary download), and
  ``"filename"`` where the HTTP API sends ``Content-Disposition``. Status codes, content types and problem
  JSON (``{"ok": false, "message": ...}``) are the HTTP API's. A line that is not a request object is
  answered with status 400 (405 for another method) and the ``id`` it carried, ``null`` if none.
- Requests may overlap: a small thread pool answers them, each response is written as one line under a
  lock, so responses can arrive in another order than the requests; match them by ``id``.
- Lines with ``"event"`` are messages the core sends unasked: ``ready``, then ``queue`` whenever the "Needs
  you" queue changes: ``{"event": "queue", "body": {"count": n, "new": [{"id", "title", "kind", "key",
  "args"}, ...], "removed": ["<id>", ...]}}``. ``id`` is the case id (its page is ``/case/<id>``), ``kind`` the
  area (``quarantine``, ``changes``, ``trail``, ``capa``, ``qualifications``), ``title`` one English line,
  ``key`` and ``args`` what the page needs to say it in its language (as in the overview's entries). The core
  looks every few seconds (``AQT_CORE_QUEUE_SECONDS``, default 5; 0 turns it off) with the overview's own
  data, which the trail's state answers without verifying the trail again. The first ``queue`` event after
  the start carries the count with ``new`` and ``removed`` empty, so a restart announces nothing.
- End of input (stdin closed) lets running requests finish, then the core exits with code 0.

Stdout carries protocol lines only: at start the real stdout is kept for them and file descriptor 1 is
pointed at stderr, so a stray ``print`` or a child process cannot corrupt the stream; stdin likewise
becomes ``/dev/null`` for child processes. Logs and tracebacks go to stderr. Request bodies, which carry
the passphrase of a decision, are never logged; the passphrase is dropped with the request.

Decisions are on only when the core runs for a person: no agent markers in its own environment and
no agent among its ancestors (its parent is the desktop app; the check walks on above it). No terminal
is needed, the app's window is the person's place to decide. Each decision request checks the parent
process, its ancestry and markers again, as the HTTP server checks the peer of a request. With
``--read-only`` decisions are refused as the read-only HTTP server refuses them.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import parse_qs, unquote, urlsplit

from aqt_evidence import HumanCheckError

from . import __version__
from .config import UiConfig, load_config
from .guard import Guard, Mode, parent_peer, startup_mode
from .views import (NotInstalled, UsageProblem, ViewProblem, coded_fields, install_command, installed, message,
                    refusal_text)
from .views.trail import PAGE

JSON_TYPE = "application/json; charset=utf-8"
PROTOCOL = 1
WORKERS = 4                    # stdio requests answered at once
QUEUE_SECONDS = 5.0            # how often the core looks at the "Needs you" queue
REMOVED = "[passphrase removed]"


@dataclass
class Response:
    """One API answer: a JSON ``body``, or a download as ``text`` or binary ``data``."""
    status: int
    body: Any = None
    content_type: str = JSON_TYPE
    text: str | None = None
    data: bytes | None = None
    filename: str | None = None          # sent as Content-Disposition: attachment

    def payload(self) -> bytes:
        """The bytes of an HTTP answer."""
        if self.text is not None:
            return self.text.encode("utf-8")
        if self.data is not None:
            return self.data
        return json.dumps(self.body, default=str, ensure_ascii=False).encode("utf-8")

    def message(self, request_id) -> dict:
        """The stdio response object for request ``request_id``."""
        out: dict = {"id": request_id, "status": self.status, "content_type": self.content_type}
        if self.text is not None:
            out["text"] = self.text
        elif self.data is not None:
            out["base64"] = base64.b64encode(self.data).decode("ascii")
        else:
            out["body"] = self.body
        if self.filename:
            out["filename"] = self.filename
        return out


def problem(status: int, message: str, **extra) -> Response:
    return Response(status, {"ok": False, "message": message, **extra})


def scrub(value, secret: str | None):
    """Safety net only: no code path echoes the passphrase. Very short values are not scrubbed
    because replacing them would garble ordinary words in the response."""
    if not secret or len(secret) < 8:
        return value
    if isinstance(value, str):
        return value.replace(secret, REMOVED)
    if isinstance(value, dict):
        return {scrub(key, secret): scrub(item, secret) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub(item, secret) for item in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return scrub(str(value), secret)          # what the JSON encoder writes for other values


@dataclass
class Request:
    """One API request while it is answered. ``secret`` holds a decision's passphrase until the
    answer is made, then it is dropped."""
    method: str
    path: str
    query: dict
    body: Any                                   # the JSON object, None, or a callable that reads it
    human_check: Callable[[], Callable]         # makes the package's human check of a decision
    shown: dict
    secret: str | None = field(default=None, repr=False)

    def read_body(self) -> dict:
        value = self.body() if callable(self.body) else self.body
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise UsageProblem("the request body must be a JSON object")
        return value


class Core:
    """Settings, decision mode, guard and view adapters, and the JSON API on top of them."""

    kind = "aqt core"           # names this process in refusals

    def __init__(self, config: UiConfig, mode: Mode, guard: Guard | None = None, *, log=None):
        from .views.changes import ChangesView
        from .views.trail import TrailView
        self.config, self.mode = config, mode
        self.guard = guard or Guard(mode, peer_lookup=parent_peer)     # the HTTP server passes its own
        self.log = log or (lambda line: print(line, file=sys.stderr, flush=True))
        self.trail = TrailView()
        self.changes = ChangesView(config.projects)
        self.shown: dict = {}       # quarantine pages sent; the core has one session, the HTTP server one per browser

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

    def session_info(self) -> dict:
        views = ("aqt_quarantine", "aqt_signoff", "aqt_change", "aqt_capa", "aqt_validate")
        return {"mode": self.mode.as_dict(), "version": __version__,
                "installed": {name: installed(name) for name in views},
                "install": {name.replace("_", "-"): install_command(name.replace("_", "-"))
                            for name in views if not installed(name)},
                "projects": [str(p) for p in self.config.projects]}

    def handle(self, method: str, path: str, query: dict, body=None, *,
               human_check: Callable[[], Callable] | None = None, shown: dict | None = None) -> Response:
        """Answer one API request (``path`` starts with ``/api/``). ``body`` is the JSON object sent, or a
        callable that reads it (the HTTP server reads a body only for routes that use one).
        ``human_check`` makes the human check of a decision (default: the guard's check, which in the
        core looks at this process's parent); ``shown`` is the session's record of quarantine pages sent. Never raises."""
        request = Request(method, path, query, body,
                          human_check or (lambda: self.guard.human_check(None, None)),
                          self.shown if shown is None else shown)
        try:
            response = self._route(request)
        except ViewProblem as error:
            response = problem(error.status, str(error),
                               **({"install": error.install} if isinstance(error, NotInstalled) else {}),
                               **coded_fields("message", error))
        except Exception as error:  # noqa: BLE001 - never crash the core; never echo the request
            detail = traceback.format_exc()
            if request.secret:
                detail = detail.replace(request.secret, REMOVED)
            self.log(f"aqt-ui internal error: {detail}")
            response = problem(500, f"internal error: {type(error).__name__}")
        if request.secret and response.text is None and response.data is None:
            response.body = scrub(response.body, request.secret)
        request.secret = None
        return response

    def _route(self, req: Request) -> Response:
        query = req.query
        parts = [part for part in req.path.split("/")[2:] if part]
        route = (req.method, *parts)
        if route == ("GET", "session"):
            return Response(200, self.session_info())
        if route == ("GET", "overview"):
            from .views.overview import build
            return Response(200, build(self))
        if route == ("POST", "trail", "verify"):
            started = self.trail.verify_now()
            return Response(202, {"ok": True, "started": started})
        if route == ("GET", "trail", "status"):
            return Response(200, {"status": self.trail.status(), "alcoa": self.trail.alcoa()})
        if route == ("GET", "trail", "records"):
            before, offset, limit = query.get("before"), query.get("offset"), query.get("limit")
            return Response(200, self.trail.records(
                since=query.get("since"), until=query.get("until"), type=query.get("type"),
                actor=query.get("actor"), action=query.get("action"), subject=query.get("subject"),
                session=query.get("session"), before=int(before) if before and before.isdigit() else None,
                offset=int(offset) if offset and offset.isdigit() else 0,
                limit=int(limit) if limit and limit.isdigit() else PAGE))
        if route == ("POST", "trail", "review", "run"):
            body = req.read_body()
            return Response(200, {"ok": True, **self.trail.review_run(since=str(body.get("since") or "") or None,
                                                                      until=str(body.get("until") or "") or None),
                                  "signers": signer_list()})
        if len(route) == 5 and route[:3] == ("POST", "trail", "review") and route[4] == "sign":
            return self._decide(req, lambda body, check: self.trail.review_sign(
                route[3], shown_head=str(body.get("head") or ""),
                shown_sha256=str(body.get("worksheet_sha256") or ""), dispositions=body.get("dispositions") or {},
                notes=body.get("notes") or {}, reason=str(body.get("reason") or ""),
                conclusion=str(body.get("conclusion") or ""), passphrase=req.secret or "",
                signer_id=str(body.get("signer_id") or ""), human_check=check))
        if route == ("GET", "trail", "export"):
            name, data = self.trail.export()
            return Response(200, content_type="application/gzip", data=data, filename=name)
        if len(route) == 4 and route[:3] == ("GET", "trail", "record"):
            found = self.trail.record(route[3])
            return problem(404, f"no record {route[3]}") if found is None else Response(200, found)
        if route == ("GET", "quarantine"):
            return Response(200, self.quarantine().cases(query.get("state")))
        if len(route) == 3 and route[:2] == ("GET", "quarantine"):
            page = query.get("page") or "0"
            return Response(200, self.quarantine().case(route[2], full=query.get("full") == "1",
                                                        page=int(page) if page.isdigit() else 0, shown=req.shown))
        if len(route) == 4 and route[:3] == ("POST", "quarantine", "sources") and route[3] in ("trust", "revoke"):
            return self._decide(req, lambda body, check: self.quarantine().trust(
                str(body.get("domain") or ""), reason=str(body.get("reason") or ""), passphrase=req.secret or "",
                signer_id=body.get("signer_id"), human_check=check, expires=str(body.get("expires") or "") or None,
                subdomains=bool(body.get("subdomains")), revoke=route[3] == "revoke",
                shown_record=str(body.get("record") or "") or None))
        if len(route) == 4 and route[:2] == ("POST", "quarantine") and route[3] in ("release", "threat"):
            return self._decide(req, lambda body, check: self.quarantine().decide(
                route[2], route[3], reason=str(body.get("reason") or ""), passphrase=req.secret or "",
                shown_sha256=str(body.get("content_sha256") or ""), signer_id=body.get("signer_id"),
                human_check=check, overrule_threat=bool(body.get("overrule_threat")), shown=req.shown))
        if route == ("GET", "changes"):
            return Response(200, self.changes.summary())
        if len(route) == 4 and route[:3] == ("GET", "changes", "actions"):
            return Response(200, self.changes.action(route[3]))
        if len(route) == 5 and route[:3] == ("POST", "changes", "actions") and route[4] in ("approve", "reject"):
            return self._decide(req, lambda body, check: self.changes.decide_action(
                route[3], route[4], expected_hash=str(body.get("expected_hash") or ""),
                reason=str(body.get("reason") or ""), passphrase=req.secret or "",
                signer_id=body.get("signer_id"), human_check=check))
        if route == ("POST", "changes", "plans", "approve"):
            return self._decide(req, lambda body, check: self.changes.approve_plan(
                str(body.get("root") or ""), str(body.get("plan_id") or ""),
                shown_record=str(body.get("record") or ""), shown_sha256=str(body.get("sha256") or ""),
                reason=str(body.get("reason") or ""), passphrase=req.secret or "",
                signer_id=body.get("signer_id"), human_check=check))
        if len(route) == 4 and route[:2] == ("GET", "change"):
            return Response(200, self.changes.change(route[2], unquote(route[3]), fresh=query.get("fresh") == "1"))
        if len(route) == 5 and route[:2] == ("POST", "change") and route[4] == "release":
            return self._decide(req, lambda body, check: self.changes.sign_release(
                route[2], unquote(route[3]), shown_record=str(body.get("record") or ""),
                shown_sha256=str(body.get("sha256") or ""), shown_path=str(body.get("path") or ""),
                reason=str(body.get("reason") or ""),
                passphrase=req.secret or "", signer_id=body.get("signer_id"), human_check=check))
        if route == ("GET", "signatures"):
            return Response(200, self.signatures().registry())
        if route == ("GET", "signatures", "verify"):
            return Response(200, self.signatures().verify(file=query.get("file"), record=query.get("record"),
                                                          sha256=query.get("sha256")))
        if route == ("GET", "signatures", "manifest"):
            result = self.signatures().verify(file=query.get("file"), record=query.get("record"),
                                              sha256=query.get("sha256"))
            html_format = query.get("format") == "html"
            # an attachment, never rendered as a page of this origin
            return Response(200, text=result["manifest_html"] if html_format else result["manifest_md"],
                            content_type="application/octet-stream" if html_format else "text/markdown; charset=utf-8",
                            filename="signature-manifest." + ("html" if html_format else "md"))
        if route == ("GET", "capa"):
            return Response(200, self.capa().summary())
        if route == ("GET", "capa", "trends"):
            return Response(200, text=self.capa().trends(), content_type="text/markdown; charset=utf-8",
                            filename="capa-trends.md")
        if len(route) == 3 and route[:2] == ("GET", "capa"):
            return Response(200, self.capa().deviation(route[2]))
        if len(route) == 5 and route[:3] == ("POST", "capa", "candidates") and route[4] in ("accept", "dismiss"):
            return self._decide(req, lambda body, check: self.capa().decide(
                route[4], route[3], reason=str(body.get("reason") or ""), passphrase=req.secret or "",
                signer_id=body.get("signer_id"), human_check=check))
        if len(route) == 5 and route[:3] == ("POST", "capa", "actions") and route[4] == "approve":
            return self._decide(req, lambda body, check: self.capa().approve_action(
                route[3], expected_hash=str(body.get("expected_hash") or ""), reason=str(body.get("reason") or ""),
                passphrase=req.secret or "", signer_id=body.get("signer_id"), human_check=check))
        if len(route) == 4 and route[:2] == ("POST", "capa") and route[3] == "close":
            return self._decide(req, lambda body, check: self.capa().decide(
                "close", route[2], reason=str(body.get("reason") or ""), passphrase=req.secret or "",
                signer_id=body.get("signer_id"), human_check=check, shown_version=str(body.get("version") or ""),
                no_action=bool(body.get("no_action"))))
        if route == ("GET", "qualifications"):
            from .views.qualifications import qualifications
            return Response(200, qualifications(self.config.qualification_warn_days))
        if route[1:2] in (("setup",), ("projects",)):
            return self._setup_route(req, route)
        return problem(404, "not found")

    # -- first-run setup, Settings and Projects: aqt-cli's checks and steps (views/setup.py) ---------------
    def _setup_route(self, req: Request, route: tuple) -> Response:
        from .views import setup
        query = req.query
        if route == ("GET", "setup"):
            return Response(200, setup.status())
        if route == ("GET", "setup", "signer-id"):
            return Response(200, setup.signer_id(str(query.get("name") or ""), str(query.get("id") or "")))
        if route == ("POST", "setup", "apply"):
            return self._setup_step(req, lambda body: setup.apply(str(body.get("check") or "")))
        if route == ("POST", "setup", "enrol"):
            return self._decide(req, lambda body, check: setup.enrol(
                name=str(body.get("name") or ""), role=str(body.get("role") or ""),
                signer=str(body.get("signer_id") or ""), passphrase=req.secret or "", human_check=check))
        if route == ("GET", "projects"):
            self.reload_config()
            return Response(200, setup.projects(self.config.projects))
        if route == ("GET", "projects", "preview"):
            return Response(200, setup.project_preview(str(query.get("path") or "")))
        if route == ("POST", "projects", "connect"):
            def connect(body):
                items = body.get("items")
                result = setup.project_connect(str(body.get("path") or ""), items if isinstance(items, list) else [])
                self.reload_config()                 # ui.toml may list the project now
                return result
            return self._setup_step(req, connect)
        return problem(404, "not found")

    def reload_config(self) -> None:
        """Read ui.toml again (the Projects area and project init change it); keep the old one if it is broken."""
        from .views.changes import ChangesView
        try:
            fresh = load_config(self.config.path)
        except (OSError, ValueError) as error:
            self.log(f"aqt-ui: ui.toml cannot be read again: {error}")
            return
        if fresh.projects != self.config.projects:
            self.changes = ChangesView(fresh.projects)
        self.config = fresh

    def _setup_step(self, req: Request, call) -> Response:
        """A setup step that changes files or services (no signature): refused in read-only mode and checked by
        the same human check as a decision, before anything is done."""
        body = req.read_body()
        if self.mode.explicit:
            return problem(403, f"refused: this {self.kind} was started with --read-only")
        check = req.human_check()
        peer = getattr(check, "peer", None)
        outcome = "failed"
        try:
            try:
                check()
            except HumanCheckError as error:
                code = "agent_context" if error.context.is_agent else "no_tty"
                outcome = f"refused ({code})"
                return Response(403, {"ok": False, "message": message(error), "reason_code": code,
                                      "reason_text": refusal_text(code)})
            result = call(body)
            outcome = "done" if result.get("ok") else "not done"
            return Response(200, result)
        finally:
            who = peer.describe() if peer is not None else "an unidentified process"
            self.log(f"aqt-ui setup {req.path} from {who}: {outcome}")

    def _decide(self, req: Request, call) -> Response:
        """A human-only request. The package runs the guard first and records a refusal itself;
        the passphrase is used once to unlock the key and dropped with the request."""
        body = req.read_body()
        passphrase = body.pop("passphrase", None)
        req.secret = passphrase if isinstance(passphrase, str) and passphrase else None
        if self.mode.explicit:
            return problem(403, f"refused: this {self.kind} was started with --read-only")
        check = req.human_check()
        peer = getattr(check, "peer", None)
        outcome = "failed"
        try:
            result = call(body, check)
            outcome = ("recorded " if result.get("ok") else "refused ") + str(result.get("record_id") or "-")
            return Response(200 if result.get("ok") else 403, result)
        except ViewProblem as error:
            outcome = f"not signed ({error.status})"
            raise
        finally:
            who = peer.describe() if peer is not None else "an unidentified process"
            self.log(f"aqt-ui decision {req.path} from {who}: {outcome}")


def signer_list() -> list[dict]:
    from .views import installed as has
    if not has("aqt_signoff"):
        return []
    from .views.changes import _signers
    return _signers()


# -- the queue event -------------------------------------------------------------------------------------
def notice_title(entry: dict) -> str:
    """One line for a system notification about a queue entry."""
    args = entry.get("args") or {}
    if entry.get("view") == "quarantine" and entry.get("code") in ("held", "warned"):
        verb = "holds" if entry["code"] == "held" else "warns about"
        return f"Quarantine {verb} content from {args.get('source') or 'an unknown source'}"
    return str(entry.get("title") or entry.get("id"))


class QueueWatch:
    """What changed in the "Needs you" queue since the last look (``poll``). The queue comes from the
    overview, which reads the tools' stored state; the trail is not verified for it."""

    def __init__(self, core: Core):
        self.core = core
        self.known: dict[str, dict] | None = None

    def poll(self) -> dict | None:
        """The body of a ``queue`` event, or None when nothing changed. The first look reports only the count."""
        from .views.overview import build
        current = {entry["id"]: {"id": entry["id"], "title": notice_title(entry), "kind": entry["view"],
                                 "key": entry["key"], "args": entry["args"]}
                   for entry in build(self.core)["needs"]}
        known, self.known = self.known, current
        if known is None:
            return {"count": len(current), "new": [], "removed": []}
        new = [entry for key, entry in current.items() if key not in known]
        removed = [key for key in known if key not in current]
        return {"count": len(current), "new": new, "removed": removed} if new or removed else None


def watch_queue(core: Core, write: Callable[[dict], None], stop: threading.Event, seconds: float) -> None:
    """Every ``seconds`` until ``stop`` is set: a ``queue`` event when the queue changed."""
    watch = QueueWatch(core)
    while True:
        try:
            body = watch.poll()
        except Exception:  # noqa: BLE001 - the next look tries again; the requests go on
            core.log(f"aqt core: the queue could not be read: {traceback.format_exc()}")
            body = None
        if body is not None:
            write({"event": "queue", "body": body})
        if stop.wait(seconds):
            return


def queue_seconds(environ=os.environ) -> float:
    try:
        return max(0.0, float(environ.get("AQT_CORE_QUEUE_SECONDS", QUEUE_SECONDS)))
    except ValueError:
        return QUEUE_SECONDS


# -- stdio -----------------------------------------------------------------------------------------------
def _line(message: dict) -> bytes:
    return json.dumps(message, default=str, ensure_ascii=False).encode("utf-8") + b"\n"


def serve(core: Core, stdin, stdout, *, workers: int = WORKERS, queue_seconds: float = 0) -> int:
    """Answer protocol lines from ``stdin`` (bytes) on ``stdout`` (bytes) until end of input; returns 0.
    With ``queue_seconds`` > 0 a ``queue`` event follows the ready event, and again on every change."""
    lock = threading.Lock()
    stop = threading.Event()

    def write(message: dict) -> None:
        try:
            line = _line(message)
        except (TypeError, ValueError, UnicodeError) as error:   # an answer that cannot be encoded
            line = _line(problem(500, f"internal error: {type(error).__name__}").message(message.get("id")))
        with lock:
            try:
                stdout.write(line)
                stdout.flush()
            except OSError as error:      # the app is gone; its end of input follows
                core.log(f"aqt core: cannot write a response: {error}")

    def answer(request_id, method: str, path: str, body) -> None:
        started = time.monotonic()
        try:
            url = urlsplit(path)
            query = {key: values[-1] for key, values in parse_qs(url.query).items()}
            response = core.handle(method, url.path, query, body)
            core.log(f"aqt core {method} {url.path} {response.status} {(time.monotonic() - started) * 1000:.0f}ms")
        except Exception as error:  # noqa: BLE001 - every request gets an answer
            core.log(f"aqt core internal error: {traceback.format_exc()}")
            response = problem(500, f"internal error: {type(error).__name__}")
        write(response.message(request_id))

    write({"event": "ready", "body": {**core.session_info(), "protocol": PROTOCOL}})
    if queue_seconds > 0:
        threading.Thread(target=watch_queue, args=(core, write, stop, queue_seconds), daemon=True,
                         name="aqt-core-queue").start()
    try:
        _answer_lines(stdin, write, answer, workers)
    finally:
        stop.set()
    return 0


def _answer_lines(stdin, write, answer, workers: int) -> None:
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="aqt-core") as pool:
        for raw in stdin:
            if not raw.strip():
                continue
            request_id = None
            try:
                request = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                write(problem(400, "the request line is not valid JSON").message(None))
                continue
            if not isinstance(request, dict):
                write(problem(400, "a request must be a JSON object").message(None))
                continue
            request_id = request.get("id")
            method, path = request.get("method"), request.get("path")
            if not isinstance(request_id, str):
                write(problem(400, "a request needs a string id").message(request_id))
            elif method not in ("GET", "POST"):
                write(problem(405, "the method must be GET or POST").message(request_id))
            elif not isinstance(path, str) or not path.startswith("/api/"):
                write(problem(404, "not found").message(request_id))
            else:
                pool.submit(answer, request_id, method, path, request.get("body"))


def _protocol_streams():
    """The real stdin and stdout, kept for the protocol; file descriptors 0 and 1 then point at
    ``/dev/null`` and stderr, so neither a stray ``print`` nor a child process can touch the stream."""
    sys.stdout.flush()
    stdin = os.fdopen(os.dup(0), "rb")
    stdout = os.fdopen(os.dup(1), "wb")
    null = os.open(os.devnull, os.O_RDONLY)
    os.dup2(null, 0)
    os.close(null)
    try:
        os.dup2(2, 1)
    except OSError:                  # no stderr: drop such output
        sink = os.open(os.devnull, os.O_WRONLY)
        os.dup2(sink, 1)
        os.close(sink)
    return stdin, stdout


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aqt core", description="The AQT core for a desktop app: the JSON API "
                                     "of aqt-ui over stdin and stdout (JSON lines, protocol 1), no network.")
    parser.add_argument("--stdio", action="store_true", help="speak the protocol on stdin and stdout (required)")
    parser.add_argument("--read-only", action="store_true", help="never allow decisions from this core")
    parser.add_argument("--config", help="ui.toml to use (default: $XDG_CONFIG_HOME/aqt/ui.toml)")
    args = parser.parse_args(argv)
    if not args.stdio:
        parser.error("--stdio is required (the only transport)")
    try:
        config = load_config(args.config)
    except (OSError, ValueError) as error:
        print(f"aqt core: {error}", file=sys.stderr)
        return 2
    mode = startup_mode(args.read_only, terminal=False)
    core = Core(config, mode)
    print("aqt core: decisions are on (each one asks for your passphrase)" if mode.decisions
          else f"aqt core: READ-ONLY. {mode.reason}", file=sys.stderr, flush=True)
    stdin, stdout = _protocol_streams()
    core.trail.verify_now()          # full verification once at start, in the background
    try:
        return serve(core, stdin, stdout, queue_seconds=queue_seconds())
    except KeyboardInterrupt:
        return 0
