"""The daemon's sockets. Rights follow the socket and the observed caller:

- ``owner.sock``  every owner operation; uid + token + not a paired pane + terminal;
- ``agent.sock``  ``ask`` and ``status`` for workers; the pair comes from the caller's ancestry;
- ``pairs/<id>/advisor.sock``  ``reply``, ``send``, ``status``, ``worker_log`` for that pair's advisor only.

Every refusal is recorded as ``sensei.refused``.
"""

from __future__ import annotations

import json
import os
import socketserver
import threading
from pathlib import Path

from aqt_evidence import actor

from .agent import Unavailable, call
from .bridge import Bridge, BridgeError, Refused
from .config import Paths, read_token
from .ledger import LedgerError, agent_actor
from .peer import PROC, describe_pid, owner_refusal, peer_credentials, token_matches

MAX_LINE = 2 * 64 * 1024 + 65536
WORKER_OPS = ("ask", "status")
ADVISOR_OPS = ("reply", "send", "status", "worker_log")
OWNER_MESSAGES = {
    "uid": "refused: the caller runs as another user",
    "token": "refused: missing or wrong owner token",
    "paired-pane": "refused: owner operations cannot come from a paired agent pane",
    "agent-session": "refused: owner operations cannot come from an agent session",
    "no-terminal": "refused: owner operations need an interactive terminal",
    "paired-terminal": "refused: owner operations cannot come from a paired pane's terminal",
}


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline(MAX_LINE)
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise ValueError
        except ValueError:
            reply = {"status": "error", "message": "expected one JSON object"}
        else:
            try:
                creds = peer_credentials(self.connection)
                reply = self.server.owner.dispatch(self.server.kind, self.server.pair_id, request, creds)
            except Exception as error:  # keep the daemon alive
                reply = {"status": "error", "message": f"bridge failure: {error.__class__.__name__}"}
        self.wfile.write(json.dumps(reply, ensure_ascii=False).encode() + b"\n")


class _UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class Server:
    def __init__(self, bridge: Bridge, paths: Paths, *, proc: Path = PROC, daemon_uid: int | None = None,
                 describe=describe_pid):
        self.bridge, self.paths = bridge, paths
        self.proc = proc
        self.daemon_uid = os.getuid() if daemon_uid is None else daemon_uid
        self.describe = describe
        self.servers: dict[str, _UnixServer] = {}
        self.lock = threading.Lock()
        bridge.on_pair = self.open_advisor
        bridge.on_end = self.close_advisor

    # -- sockets
    def _listen(self, key: str, path: Path, kind: str, pair_id: str | None = None) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.unlink(missing_ok=True)
        previous = os.umask(0o177)
        try:
            server = _UnixServer(str(path), _Handler)
        finally:
            os.umask(previous)
        os.chmod(path, 0o600)
        server.owner, server.kind, server.pair_id = self, kind, pair_id
        threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True,
                         name=f"aqt-sensei-{key}").start()
        with self.lock:
            self.servers[key] = server

    def start(self) -> None:
        self.paths.ensure()
        if self.paths.owner_socket.exists():
            try:
                call(self.paths.owner_socket, {"op": "ping"}, timeout=2)
                raise RuntimeError("another aqt-sensei bridge is already running")
            except (Unavailable, OSError, ValueError):
                pass
        self._listen("owner", self.paths.owner_socket, "owner")
        self._listen("agent", self.paths.agent_socket, "agent")
        for pair in self.bridge.live_pairs():
            self.open_advisor(pair["id"])

    def open_advisor(self, pair_id: str) -> None:
        self._listen(f"advisor:{pair_id}", self.paths.advisor_socket(pair_id), "advisor", pair_id)

    def close_advisor(self, pair_id: str) -> None:
        with self.lock:
            server = self.servers.pop(f"advisor:{pair_id}", None)
        if server:
            threading.Thread(target=server.shutdown, daemon=True).start()
            server.server_close()
        self.paths.advisor_socket(pair_id).unlink(missing_ok=True)

    def shutdown(self) -> None:
        with self.lock:
            servers = list(self.servers.items())
            self.servers.clear()
        for key, server in servers:
            server.shutdown()
            server.server_close()
        for path in (self.paths.owner_socket, self.paths.agent_socket):
            path.unlink(missing_ok=True)

    def run(self, stop: threading.Event, poll_seconds: float) -> None:
        while not stop.is_set():
            try:
                self.bridge.tick()
            except Exception as error:  # log and keep polling
                print(f"aqt-sensei: poll failed: {error!r}", flush=True)
            stop.wait(poll_seconds)

    # -- requests
    def dispatch(self, kind: str, pair_id: str | None, request: dict, creds: tuple[int, int, int]) -> dict:
        pid, uid, gid = creds
        peer = self.describe(pid, uid, gid, proc=self.proc)
        described = peer.describe()
        op = request.get("op")
        claimed = self.bridge.ledger.owner
        try:
            if kind == "owner":
                if op == "ping":
                    return {"status": "available", "output": "pong"}
                token_ok = token_matches(request.get("token"), self._token())
                code = owner_refusal(peer, token_ok=token_ok, daemon_uid=self.daemon_uid,
                                     paired=self.bridge.paired_panes())
                if code:
                    raise Refused(OWNER_MESSAGES[code], code)
                return {"status": "available", **self.bridge.owner_op(request, described)}
            if kind == "agent":
                claimed = actor("agent", f"agent:{peer.harness or 'unknown'}:pid-{pid}", role="worker")
                if op not in WORKER_OPS:
                    raise Refused(f"refused: workers may use {', '.join(WORKER_OPS)} only", "op-not-allowed")
                with self.bridge.lock:
                    pair = self.bridge.worker_for(peer.chain, request.get("pane_hint"))
                claimed = agent_actor(pair, "worker")
                pair_id = pair["id"]
                return {"status": "available", **self.bridge.agent_op("worker", pair, request, described)}
            pair = self.bridge.pair(pair_id)
            claimed = agent_actor(pair, "advisor")
            if op not in ADVISOR_OPS:
                raise Refused(f"refused: the sensei may use {', '.join(ADVISOR_OPS)} only", "op-not-allowed")
            return {"status": "available", **self.bridge.agent_op("advisor", pair, request, described)}
        except Refused as refusal:
            self.bridge.ledger.write_or_spool(self.bridge.ledger.refused_record(
                claimed, str(op), refusal.code, peer=described, markers=peer.agent_markers,
                pair_id=pair_id, message=str(refusal)))
            return {"status": "error", "code": refusal.code, "message": str(refusal)}
        except (BridgeError, LedgerError) as error:
            return {"status": "error", "message": str(error)}

    def _token(self) -> str | None:
        return read_token(self.paths.token_file)
