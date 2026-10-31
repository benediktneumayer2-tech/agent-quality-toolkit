"""The proxy: mitmproxy in this process, serving the listeners opened inside the box.

mitmproxy runs without listeners of its own (``server = false``). Its server instances' connection
handlers serve the sockets that ``netns`` created in the box's network namespace:

- ``proxy`` (``127.0.0.1:3128`` in the box): an HTTP proxy for ``HTTP(S)_PROXY`` clients;
- ``redirect``: transparent mode; nftables sends every other TCP connection here and the
  original destination comes from the kernel (``SO_ORIGINAL_DST``);
- ``direct80`` / ``direct443``: clients that ignore the proxy variables and connect to the address
  the box resolver gave them; the destination is taken from the TLS server name or the Host header.

The ``Egress`` add-on attributes each connection to the box process that opened it, lets bodies
stream through (hashing, counting and, in full mode, spooling them as they pass), and writes one
``egress.request`` record per request, WebSocket or TCP connection. This stage only observes:
nothing is held or changed, with one exception that is the box's boundary, not a policy: the
proxy never connects to the host's own loopback addresses for the box.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import socket
import time
import zlib
from datetime import UTC, datetime
from pathlib import Path

from mitmproxy import ctx, options
from mitmproxy.addons import default_addons
from mitmproxy.certs import CertStore
from mitmproxy.master import Master
from mitmproxy.proxy.mode_servers import ProxyConnectionHandler, ServerInstance

from .attribution import normal_ip, unattributed
from .mask import excerpt, headers_summary, mask_text
from .store import decode_body

PLACEHOLDER = "no-destination.aqt-egress.invalid"
CA_BASENAME = "mitmproxy"
HEAD_BYTES = 64 * 1024
TLS_PINNING_HINTS = ("certificate", "unknown ca", "trust")
LOOPBACK_REFUSED = "aqt-egress: the host's own loopback is outside the box"
logger = logging.getLogger("aqt_egress")


# -- CA ------------------------------------------------------------------------------------------
def ensure_ca(folder: Path) -> tuple[bytes, str]:
    """Create the private CA once (mitmproxy's own files, 0600 in a 0700 folder); (certificate PEM,
    SHA-256 fingerprint of the certificate)."""
    if not (folder / f"{CA_BASENAME}-ca.pem").exists():
        CertStore.create_store(folder, CA_BASENAME, 2048, organization="aqt-egress", cn="aqt-egress local CA")
    for path in folder.iterdir():
        path.chmod(0o600)
    folder.chmod(0o700)
    store = CertStore.from_store(folder, CA_BASENAME, 2048)
    return (folder / f"{CA_BASENAME}-ca-cert.pem").read_bytes(), "sha256:" + store.default_ca.fingerprint().hex()


def make_master(confdir: Path, addon, *, upstream_ca: str | None = None) -> Master:
    opts = options.Options(confdir=str(confdir))
    master = Master(opts)
    master.addons.add(*default_addons())
    master.addons.add(addon)
    update = dict(server=False, onboarding=False, connection_strategy="eager", block_global=False,
                  ssl_insecure=False, http3=False)
    if upstream_ca:
        update["ssl_verify_upstream_trusted_ca"] = upstream_ca
    opts.update(**update)
    return master


# -- listeners -----------------------------------------------------------------------------------
class _Lazy:
    """The options as the direct listeners' connections see them: server connections open lazily,
    because the destination is known only from the TLS server name or the Host header. (Everywhere
    else they open eagerly, so that protocols in which the server speaks first work.)"""

    def __init__(self, options):
        self._options = options

    def __getattr__(self, name):
        return "lazy" if name == "connection_strategy" else getattr(self._options, name)


async def serve_listeners(master: Master, addon: "Egress", sockets: dict) -> list[asyncio.Server]:
    """Start serving the box's listeners (``proxy``, ``redirect``, ``direct80``, ``direct443``)."""
    manager = master.addons.get("proxyserver")
    regular = ServerInstance.make("regular", manager)
    transparent = ServerInstance.make("transparent", manager)

    def via(name, handle):
        async def accept(reader, writer):
            peer = writer.get_extra_info("peername")
            addon.via_by_peer[(normal_ip(peer[0]), peer[1])] = name
            await handle(reader, writer)
        return accept

    def direct(port):
        async def handle(reader, writer):
            handler = ProxyConnectionHandler(ctx.master, reader, writer, _Lazy(ctx.options), transparent.mode)
            handler.layer = transparent.make_top_layer(handler.layer.context)
            handler.layer.context.server.address = (PLACEHOLDER, port)
            with manager.register_connection(handler.layer.context.client.id, handler):
                await handler.handle_client()
        return handle

    handlers = {"proxy": regular.handle_stream, "redirect": transparent.handle_stream,
                "direct80": direct(80), "direct443": direct(443)}
    return [await asyncio.start_server(via(name, handle), sock=sockets[name])
            for name, handle in handlers.items() if name in sockets]


# -- body taps -----------------------------------------------------------------------------------
class Tap:
    """A body passing through: hashed, counted, its head kept for the excerpt, spooled in full mode."""

    def __init__(self, store=None):
        self.sha = hashlib.sha256()
        self.size = 0
        self.head = bytearray()
        self.file = self.path = None
        if store is not None:
            self.file, self.path = store.spool()

    def __call__(self, chunk: bytes) -> bytes:
        if chunk:
            self.sha.update(chunk)
            self.size += len(chunk)
            if len(self.head) < HEAD_BYTES:
                self.head += chunk[:HEAD_BYTES - len(self.head)]
            if self.file is not None:
                self.file.write(chunk)
        return chunk

    def summary(self) -> dict:
        value = {"bytes": self.size}
        if self.size:
            value["body_sha256"] = "sha256:" + self.sha.hexdigest()
        return value

    def take(self) -> bytes | None:
        """The spooled body (full mode), removed from the spool."""
        if self.file is None:
            return None
        self.file.close()
        self.file = None
        try:
            return self.path.read_bytes()
        finally:
            self.path.unlink(missing_ok=True)


def _excerpt(tap: Tap, encoding: str | None, chars: int) -> str | None:
    head = bytes(tap.head)
    if encoding and encoding.lower() != "identity":
        if tap.size > len(head):
            if encoding.lower() not in ("gzip", "deflate"):
                return None
            try:
                head = zlib.decompressobj(wbits=47).decompress(head)   # gzip or zlib, a prefix is enough
            except zlib.error:
                return None
        else:
            head, decoded = decode_body(head, encoding)
            if not decoded:
                return None
    return excerpt(head, chars)


def _iso(timestamp: float | None) -> str | None:
    if not timestamp:
        return None
    return datetime.fromtimestamp(timestamp, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _ms(start: float | None, end: float | None) -> int | None:
    if not start or not end or end < start:
        return None
    return int((end - start) * 1000)


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _loopback(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(normal_ip(ip))
    except ValueError:
        return False
    return address.is_loopback or address.is_unspecified


def _clean(value):
    """Drop None values (records carry no nulls in this tool)."""
    if isinstance(value, dict):
        return {key: _clean(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [_clean(item) for item in value]
    return value


# -- the add-on ----------------------------------------------------------------------------------
class Egress:
    def __init__(self, *, session: str, session_record: str | None, writer, settings, key: bytes,
                 attribute=None, lookups=None, store=None, test_hosts: dict | None = None,
                 allow_loopback: bool = False):
        self.session = session
        self.session_record = session_record
        self.writer = writer
        self.settings = settings
        self.key = key
        self.attribute = attribute or (lambda kind, peer: unattributed("not in a box"))
        self.lookups = lookups
        self.store = store                            # BodyStore in full mode, else None
        self.test_hosts = test_hosts or {}            # tests only: name[:port] -> host[:port]
        self.allow_loopback = allow_loopback or bool(self.test_hosts)   # tests only: a local test server
        self.asked: dict[str, tuple] = {}             # server connection id -> destination before a test mapping
        self.via_by_peer: dict[tuple, str] = {}
        self.conns: dict[str, dict] = {}
        self.passthrough = {host: "configured" for host in settings.passthrough}
        self.seq = 0
        self.counts = {"requests": 0, "bytes_up": 0, "bytes_down": 0, "refused": 0}

    # -- connections -------------------------------------------------------------------------
    def client_connected(self, client):
        peer = (normal_ip(client.peername[0]), client.peername[1])
        via = self.via_by_peer.pop(peer, "proxy")
        self.conns[client.id] = {"via": via, "process": self.attribute("tcp", peer), "recorded": False,
                                 "tls": None}

    def client_disconnected(self, client):
        info = self.conns.pop(client.id, None)
        if info and not info["recorded"]:
            self._emit_connection(client, None, info, error=client.error)

    def tls_clienthello(self, data):
        info = self.conns.get(data.context.client.id)
        sni = (data.client_hello.sni or "").lower().rstrip(".") or None
        server = data.context.server
        if info and info["via"].startswith("direct") and sni:
            server.address = (sni, server.address[1])
        if info is not None:
            info["server"] = server
        host = sni or (server.address[0] if server.address else None)
        reason = self.passthrough.get(host or "")
        if info is not None:
            info["tls"] = {"mode": "passthrough", "reason": reason} if reason else {"mode": "intercepted"}
        if reason:
            data.ignore_connection = True

    def tls_failed_client(self, data):
        info = self.conns.get(data.context.client.id)
        error = data.conn.error or "TLS handshake with the client failed"
        host = data.conn.sni
        if host and any(hint in error.lower() for hint in TLS_PINNING_HINTS):
            self.passthrough.setdefault(host.lower(), "client-rejected-certificate")
        if info is not None:
            info["tls"] = {"mode": "intercepted", "client_failed": True}
            self._emit_connection(data.context.client, data.context.server, info, error=error)

    async def server_connect(self, data):
        server = data.server
        host, port = server.address[0], server.address[1]
        info = self.conns.get(data.client.id)
        if info is not None:
            info["server"] = server
        if host == PLACEHOLDER:
            server.error = "aqt-egress: no destination (no TLS server name and no Host header)"
            return
        mapped = self.test_hosts.get(f"{host}:{port}") or self.test_hosts.get(host)
        if mapped:
            self.asked[server.id] = (host, port)
            mapped_host, _, mapped_port = mapped.rpartition(":") if mapped.count(":") == 1 else (mapped, "", "")
            server.address = (mapped_host, int(mapped_port) if mapped_port else port)
            if not _is_ip(host):
                server.sni = server.sni or host
            return
        # The address is left as it is (mitmproxy reuses connections by it); what it resolves to is
        # checked here and the connected peer again in server_connected.
        if _is_ip(host):
            addresses = [host]
        else:
            try:
                found = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
            except OSError as error:
                server.error = f"cannot resolve {host}: {error}"
                return
            addresses = [item[4][0] for item in found]
        if not self.allow_loopback and any(_loopback(address) for address in addresses):
            server.error = LOOPBACK_REFUSED
            if info is not None:
                info["refused"] = "host-loopback"

    def server_connected(self, data):
        """A name that resolved differently a moment later (DNS rebinding) must not reach the host's
        loopback either: close such a connection before anything is sent on it."""
        peer = data.server.peername
        if self.allow_loopback or not peer or not _loopback(peer[0]):
            return
        info = self.conns.get(data.client.id)
        if info is not None:
            info["refused"] = "host-loopback"
            self._emit_connection(data.client, data.server, info, error=LOOPBACK_REFUSED)
        handler = ctx.master.addons.get("proxyserver").connections.get(data.client.id)
        for connection in (data.server, data.client):       # nothing is sent; the client sees a reset
            transport = handler.transports.get(connection) if handler else None
            if transport is not None and transport.writer is not None:
                transport.writer.close()

    # -- HTTP --------------------------------------------------------------------------------
    def requestheaders(self, flow):
        info = self.conns.get(flow.client_conn.id)
        if info and info["via"] == "direct80" and flow.request.host == PLACEHOLDER:
            host = flow.request.host_header
            if host:
                name, _, port = host.rpartition(":") if host.count(":") == 1 else (host, "", "")
                flow.request.host = (name or host).lower()
                flow.request.port = int(port) if port.isdigit() else 80
        tap = Tap(self.store)
        flow.metadata["aqt.request"] = tap
        flow.metadata["aqt.start"] = time.time()
        flow.request.stream = tap

    def responseheaders(self, flow):
        tap = Tap(self.store)
        flow.metadata["aqt.response"] = tap
        flow.response.stream = tap

    def response(self, flow):
        if flow.response.status_code == 101:      # WebSocket: recorded at its end, with its traffic
            flow.metadata["aqt.ws"] = {"up": 0, "down": 0, "messages": 0}
            return
        self._emit_http(flow)

    def error(self, flow):
        self._emit_http(flow, error=flow.error.msg if flow.error else "error")

    def websocket_message(self, flow):
        counts = flow.metadata.setdefault("aqt.ws", {"up": 0, "down": 0, "messages": 0})
        message = flow.websocket.messages[-1]
        counts["up" if message.from_client else "down"] += len(message.content)
        counts["messages"] += 1
        flow.websocket.messages.clear()

    def websocket_end(self, flow):
        self._emit_http(flow, protocol="websocket")

    # -- TCP ---------------------------------------------------------------------------------
    def tcp_start(self, flow):
        flow.metadata["aqt.up"], flow.metadata["aqt.down"] = Tap(self.store), Tap(self.store)
        flow.metadata["aqt.start"] = time.time()

    def tcp_message(self, flow):
        message = flow.messages[-1]
        flow.metadata["aqt.up" if message.from_client else "aqt.down"](message.content)
        flow.messages.clear()

    def tcp_end(self, flow):
        self._emit_tcp(flow)

    def tcp_error(self, flow):
        self._emit_tcp(flow, error=flow.error.msg if flow.error else "error")

    # -- lookups -----------------------------------------------------------------------------
    def on_lookup(self, name: str, qtype: int, peer) -> None:
        if self.lookups is not None:
            self.lookups.add(name, qtype, self.attribute("udp", (normal_ip(peer[0]), peer[1])))

    def flush_lookups(self, older_than: float) -> None:
        if self.lookups is None:
            return
        for entry in self.lookups.unclaimed(older_than):
            data = {"session": self.session, "name": entry["name"], "types": entry["types"],
                    "count": entry["count"], "first_time": _iso(entry["first"]), "last_time": _iso(entry["last"]),
                    "process": entry.get("process")}
            self.writer.emit("egress.lookup", "observed", _clean(data),
                             subject={"kind": "egress.name", "ref": entry["name"]}, links=self._links())

    # -- records -----------------------------------------------------------------------------
    def _links(self):
        return [{"rel": "session", "ref": self.session_record}] if self.session_record else None

    def _base(self, info, host, port, *, ip=None, sni=None) -> dict:
        self.seq += 1
        refused = info.get("refused") if info else None
        if refused:
            self.counts["refused"] += 1
        data = {
            "session": self.session, "seq": self.seq, "mode": "observe",
            "decision": "refused" if refused else "allowed",
            "process": info["process"] if info else unattributed("connection not seen from its start"),
            "destination": {"host": host or "", "port": port or 0, "ip": normal_ip(ip) if ip else None,
                            "sni": sni, "via": info["via"] if info else None},
        }
        if refused:
            data["reason_code"] = refused
        if self.lookups is not None and host:
            claimed = self.lookups.claim(host, data["process"])
            if claimed:
                data["lookups"] = [{"name": entry["name"], "types": entry["types"], "count": entry["count"]}
                                   for entry in claimed]
        return data

    def _submit(self, data: dict, host, port, store_work=None) -> None:
        def build():
            if store_work is not None:
                store_work(data)
            return "egress.request", "observed", _clean(data), {"kind": "egress.destination",
                                                                "ref": f"{host}:{port}"}, self._links()
        self.writer.submit(build)

    def _tls(self, info, client) -> dict:
        if info and info.get("tls"):
            return info["tls"]
        return {"mode": "intercepted"} if client is not None and client.tls_established else {"mode": "none"}

    def _emit_http(self, flow, *, error: str | None = None, protocol: str | None = None) -> None:
        if flow.metadata.get("aqt.recorded"):
            return
        flow.metadata["aqt.recorded"] = True
        info = self.conns.get(flow.client_conn.id)
        if info is not None:
            info["recorded"] = True
        request, response, server = flow.request, flow.response, flow.server_conn
        asked = self.asked.get(server.id) if server is not None else None
        host, port = request.pretty_host, asked[1] if asked else request.port
        tls = server is not None and server.tls or flow.client_conn.tls_established
        data = self._base(info, host, port, ip=server.peername[0] if server and server.peername else None,
                          sni=((server.sni if server else None) or flow.client_conn.sni) if tls else None)
        path, _, query = request.path.partition("?")
        req_tap: Tap | None = flow.metadata.get("aqt.request")
        resp_tap: Tap | None = flow.metadata.get("aqt.response")
        names, credentials = headers_summary(request.headers.items(multi=True), self.key)
        chars = self.settings.excerpt_chars
        data.update(protocol=protocol or request.http_version, tls=self._tls(info, flow.client_conn),
                    method=request.method, path=mask_text(path)[:2048],
                    query_sha256=("sha256:" + hashlib.sha256(query.encode("utf-8", "surrogateescape")).hexdigest())
                    if query else None)
        req_encoding = request.headers.get("content-encoding")
        data["request"] = {"headers": names, "credentials": credentials or None,
                           "content_type": request.headers.get("content-type"),
                           **(req_tap.summary() if req_tap else {"bytes": len(request.raw_content or b"")}),
                           "excerpt": _excerpt(req_tap, req_encoding, chars) if req_tap else None}
        if response is not None:
            resp_names, _ = headers_summary(response.headers.items(multi=True), self.key)
            resp_encoding = response.headers.get("content-encoding")
            data["response"] = {"status": response.status_code, "headers": resp_names,
                                "content_type": response.headers.get("content-type"),
                                **(resp_tap.summary() if resp_tap else {"bytes": len(response.raw_content or b"")}),
                                "excerpt": _excerpt(resp_tap, resp_encoding, chars) if resp_tap else None}
        websocket = flow.metadata.get("aqt.ws")
        if protocol == "websocket" and websocket:
            data["websocket"] = websocket
        start = flow.metadata.get("aqt.start") or request.timestamp_start
        end = (response.timestamp_end if response else None) or time.time()
        data["timing"] = {"start": _iso(start), "total_ms": _ms(start, end),
                          "connect_ms": _ms(server.timestamp_start, server.timestamp_tcp_setup) if server else None,
                          "tls_ms": _ms(server.timestamp_tcp_setup, server.timestamp_tls_setup) if server else None,
                          "ttfb_ms": _ms(request.timestamp_end, response.timestamp_start) if response else None}
        if error:
            data["error"] = mask_text(error)[:500]
        up = (req_tap.size if req_tap else 0) + (websocket or {}).get("up", 0)
        down = (resp_tap.size if resp_tap else 0) + (websocket or {}).get("down", 0)
        self.counts["requests"] += 1
        self.counts["bytes_up"] += up
        self.counts["bytes_down"] += down
        store_work = None
        if self.store is not None:
            req_raw = req_tap.take() if req_tap else None
            resp_raw = resp_tap.take() if resp_tap else None
            req_fields = list(request.headers.items(multi=True))
            resp_fields = list(response.headers.items(multi=True)) if response is not None else None

            def store_work(data, store=self.store):
                refs = {"headers": store.put_headers(req_fields, resp_fields)}
                if req_raw:
                    refs["request_body"] = store.put_body(req_raw, req_encoding)
                if resp_raw:
                    refs["response_body"] = store.put_body(resp_raw, response.headers.get("content-encoding"))
                data["store"] = refs
        self._submit(data, host, port, store_work)

    def _emit_tcp(self, flow, *, error: str | None = None) -> None:
        info = self.conns.get(flow.client_conn.id)
        if info is not None:
            info["recorded"] = True
        server = flow.server_conn
        host, port = self.asked.get(server.id) or (server.address or (None, None))[:2]
        data = self._base(info, host, port, ip=server.peername[0] if server.peername else None, sni=server.sni)
        up, down = flow.metadata.get("aqt.up"), flow.metadata.get("aqt.down")
        start = flow.metadata.get("aqt.start")
        data.update(protocol="tcp", tls=self._tls(info, flow.client_conn),
                    request={**up.summary(), "excerpt": _excerpt(up, None, self.settings.excerpt_chars)},
                    response={**down.summary(), "excerpt": _excerpt(down, None, self.settings.excerpt_chars)},
                    timing={"start": _iso(start), "total_ms": _ms(start, time.time()),
                            "connect_ms": _ms(server.timestamp_start, server.timestamp_tcp_setup)})
        if error:
            data["error"] = mask_text(error)[:500]
        self.counts["requests"] += 1
        self.counts["bytes_up"] += up.size
        self.counts["bytes_down"] += down.size
        store_work = None
        if self.store is not None:
            up_raw, down_raw = up.take(), down.take()

            def store_work(data, store=self.store):
                data["store"] = {key: store.put_body(raw, None) for key, raw in
                                 (("request_body", up_raw), ("response_body", down_raw)) if raw}
        self._submit(data, host, port, store_work)

    def _emit_connection(self, client, server, info, *, error: str | None) -> None:
        """A connection that carried no request we saw: TLS passed through or failed, refused, or closed early."""
        info["recorded"] = True
        server = server or info.get("server")
        address = (self.asked.get(server.id) if server is not None else None) or \
            (server.address if server is not None and server.address else (None, None))
        host = client.sni or (address[0] if address[0] != PLACEHOLDER else None)
        port = address[1] or (client.sockname[1] if client.sockname else None)
        data = self._base(info, host, port,
                          ip=server.peername[0] if server is not None and server.peername else None, sni=client.sni)
        data.update(protocol="tls" if info.get("tls") else "tcp", tls=self._tls(info, client),
                    timing={"start": _iso(client.timestamp_start),
                            "total_ms": _ms(client.timestamp_start, client.timestamp_end or time.time())})
        if error:
            data["error"] = mask_text(str(error))[:500]
        elif data["tls"].get("mode") != "passthrough":
            data["error"] = "closed before a request"
        self.counts["requests"] += 1
        self._submit(data, host, port)
