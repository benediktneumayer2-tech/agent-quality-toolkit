"""Shared fixtures: isolated folders, local upstream test servers (HTTP and HTTPS with a test CA),
the proxy in this process, and records read back from a JSONL sink.

Nothing here reaches the internet: upstream servers listen on 127.0.0.1 with port 0, and the
proxy's own test listener does too.
"""

from __future__ import annotations

import asyncio
import gzip
import http.server
import ipaddress
import json
import os
import shutil
import socket
import ssl
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from aqt_evidence import JsonlSink, read_jsonl

_HOME: str | None = None


def pytest_configure(config):
    """Throw-away HOME and XDG folders for the whole run (never the real ~/.local/state/aqt)."""
    global _HOME
    _HOME = tempfile.mkdtemp(prefix="aqt-egress-home-")
    os.environ["HOME"] = _HOME
    if os.name == "nt":   # Windows takes the home and the AQT folders from these
        for name, sub in (("USERPROFILE", ""), ("APPDATA", "appdata"), ("LOCALAPPDATA", "localappdata")):
            os.environ[name] = os.path.join(_HOME, sub)
    for name, sub in (("XDG_STATE_HOME", "state"), ("XDG_CONFIG_HOME", "config")):
        os.environ[name] = os.path.join(_HOME, sub)
    os.environ.pop("XDG_RUNTIME_DIR", None)


def pytest_unconfigure(config):
    if _HOME:
        shutil.rmtree(_HOME, ignore_errors=True)


@pytest.fixture
def env(tmp_path, monkeypatch):
    runtime = Path(tempfile.mkdtemp(prefix="aqte", dir="/tmp" if os.name == "posix" else None))      # AF_UNIX paths are short
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    if os.name == "nt":
        monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    for name in ("AQT_SINK", "AQT_TRAIL_STATE", "AQT_EVIDENCE", "AQT_EGRESS_TEST", "AQT_QUARANTINE_STATE"):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "home").mkdir()
    yield tmp_path
    shutil.rmtree(runtime, ignore_errors=True)


# -- upstream test servers -----------------------------------------------------------------------
STREAM_CHUNKS = [b"data: one\n\n", b"data: two\n\n", b"data: three\n\n"]
STREAM_PAUSE = 0.4


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    seen: list[str] = []                      # paths the upstream received (N2: nothing on a closed connection)

    def parse_request(self):
        ok = super().parse_request()
        if ok:
            Handler.seen.append(self.path)
        return ok

    def log_message(self, *args):
        pass

    def _send(self, body: bytes, *, status=200, content_type="text/plain", headers=()):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for chunk in STREAM_CHUNKS:
                self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                self.wfile.flush()
                time.sleep(STREAM_PAUSE)
            self.wfile.write(b"0\r\n\r\n")
            return
        if self.path.startswith("/gzip"):
            self._send(gzip.compress(b"compressed hello, token=abcdefgh1234"), headers=[("Content-Encoding", "gzip")])
            return
        self._send(b"hello from upstream " + self.path.encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        if self.path.startswith("/slow"):
            time.sleep(1.0)
        if self.path.startswith("/upgrade"):        # a non-WebSocket upgrade, then an echo
            self.send_response(101)
            self.send_header("Upgrade", "x-test")
            self.send_header("Connection", "Upgrade")
            self.end_headers()
            self.wfile.flush()
            data = self.connection.recv(100)
            self.connection.sendall(b"echo:" + data)
            self.close_connection = True
            return
        self._send(json.dumps({"received": len(body)}).encode(), content_type="application/json")


class Upstream:
    def __init__(self, folder: Path):
        from mitmproxy.certs import CertStore
        CertStore.create_store(folder, "testca", 2048, organization="test upstream", cn="test upstream CA")
        store = CertStore.from_store(folder, "testca", 2048)
        entry = store.get_cert("upstream.test", [x509.DNSName("upstream.test"), x509.DNSName("localhost"),
                                                 x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                                                 x509.IPAddress(ipaddress.ip_address("203.0.113.10"))])
        self.ca = str(folder / "testca-ca-cert.pem")
        (folder / "server.pem").write_bytes(entry.cert.to_pem() + entry.privatekey.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        self.http = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.https = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(folder / "server.pem")
        self.https.socket = context.wrap_socket(self.https.socket, server_side=True)
        self.http_port = self.http.server_address[1]
        self.https_port = self.https.server_address[1]
        self.threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (self.http, self.https)]
        for thread in self.threads:
            thread.start()

    def close(self):
        for server in (self.http, self.https):
            server.shutdown()
            server.server_close()


@pytest.fixture
def upstream(tmp_path):
    server = Upstream(tmp_path / "upstream")
    yield server
    server.close()


# -- the proxy in this process --------------------------------------------------------------------
class InProcessProxy:
    """mitmproxy with the Egress add-on on a 127.0.0.1:0 listener, in a background thread."""

    def __init__(self, tmp: Path, upstream: Upstream, *, settings, test_hosts: dict, allow_loopback=False,
                 own_addresses=None):
        from aqt_egress.mask import load_key
        from aqt_egress.proxy import Egress, ensure_ca
        from aqt_egress.records import RecordWriter
        from aqt_egress.resolver import Lookups
        from aqt_egress.store import BodyStore
        self.records_path = tmp / "records.jsonl"
        self.ca_dir = tmp / "ca"
        self.ca_dir.mkdir(mode=0o700)
        self.ca_cert, self.fingerprint = ensure_ca(self.ca_dir)
        (tmp / "ca.pem").write_bytes(self.ca_cert)
        self.ca_file = str(tmp / "ca.pem")
        self.writer = RecordWriter(sink=JsonlSink(self.records_path))
        self.store = BodyStore(tmp / "bodies").ensure() if settings.store == "full" else None
        self.lookups = Lookups()
        self.addon = Egress(session="egs_test", session_record=None, writer=self.writer, settings=settings,
                            key=load_key(tmp / "key"), lookups=self.lookups, store=self.store,
                            attribute=lambda kind, peer, remote=None: {"chain": [{"pid": 1, "comm": "test-client"}],
                                                          "chain_status": "complete"},
                            test_hosts=test_hosts, allow_loopback=allow_loopback, own_addresses=own_addresses)
        self.upstream_ca = upstream.ca
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        self.ready = threading.Event()
        self.thread = threading.Thread(target=lambda: asyncio.run(self._main()), daemon=True)
        self.thread.start()
        assert self.ready.wait(20), "proxy did not start"

    async def _main(self):
        from aqt_egress.proxy import make_master, serve_listeners
        self.loop = asyncio.get_running_loop()
        self.stop = asyncio.Event()
        master = make_master(self.ca_dir, self.addon, upstream_ca=self.upstream_ca)
        running = asyncio.create_task(master.run())
        await asyncio.sleep(0)
        servers = await serve_listeners(master, self.addon, {"proxy": self.sock})
        self.ready.set()
        await self.stop.wait()
        for server in servers:
            server.close()
        master.shutdown()
        await asyncio.wait_for(running, 10)

    def opener(self):
        context = ssl.create_default_context(cafile=self.ca_file)
        proxy = f"http://127.0.0.1:{self.port}"
        return urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}),
                                           urllib.request.HTTPSHandler(context=context))

    def records(self, *, settle: float = 0.3) -> list[dict]:
        time.sleep(settle)                       # hooks of the requests that just finished
        deadline = time.monotonic() + 5
        while not self.writer.queue.empty() and time.monotonic() < deadline:
            time.sleep(0.05)
        time.sleep(0.1)
        if not self.records_path.exists():
            return []
        return list(read_jsonl(self.records_path))

    def close(self):
        self.loop.call_soon_threadsafe(self.stop.set)
        self.thread.join(15)
        self.writer.close()


@pytest.fixture
def make_proxy(tmp_path, upstream, env):
    from aqt_egress.settings import Settings
    made = []

    def make(**kw):
        settings = kw.pop("settings", None) or Settings()
        hosts = kw.pop("test_hosts", {"upstream.test": f"127.0.0.1:{upstream.https_port}",
                                      "plain.test": f"127.0.0.1:{upstream.http_port}"})
        proxy = InProcessProxy(tmp_path / f"p{len(made)}", upstream, settings=settings, test_hosts=hosts, **kw)
        made.append(proxy)
        return proxy

    for index in range(4):
        (tmp_path / f"p{index}").mkdir()
    yield make
    for proxy in made:
        proxy.close()


def requests_of(records, action="observed"):
    return [record for record in records if record["type"] == "egress.request" and record["action"] == action]
