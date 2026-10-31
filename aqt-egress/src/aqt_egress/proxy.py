"""The proxy: mitmproxy in this process, serving the listeners opened inside the box.

mitmproxy runs without listeners of its own (``server = false``). Its server instances' connection
handlers serve the sockets that ``netns`` created in the box's network namespace:

- ``proxy`` (``127.0.0.1:3128`` in the box): an HTTP proxy for ``HTTP(S)_PROXY`` clients;
- ``redirect``: transparent mode; nftables sends every other TCP connection here and the
  original destination comes from the kernel (``SO_ORIGINAL_DST``);
- ``direct80`` / ``direct443``: clients that ignore the proxy variables and connect to the address
  the box resolver gave them; the destination is taken from the TLS server name or the Host header;
- ``local4:PORT`` / ``local6:PORT``: the box's own loopback at a configured local inference endpoint,
  forwarded to that endpoint on the host.

Requests to LLM API destinations (``llm``) are recorded by structure only, without text excerpts.

The ``Egress`` add-on attributes each connection to the box process that opened it, lets bodies
stream through (hashing, counting and, in full mode, spooling them as they pass), and writes one
``egress.request`` record per request, WebSocket or TCP connection. This stage only observes:
nothing is held or changed, with one exception that is the box's boundary, not a policy: the
proxy never connects to the host itself for the box (its loopback and its interface addresses), except
to configured local endpoints. Each upstream connection first gets an ``opened`` record, written
before anything is sent on it.
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

from . import llm as llm_api
from .attribution import normal_ip, unattributed
from .mask import excerpt, headers_summary, mask_text
from .store import decode_body

PLACEHOLDER = "no-destination.aqt-egress.invalid"
CA_BASENAME = "mitmproxy"
HEAD_BYTES = 64 * 1024
OUTSIDE_REFUSED = {"host-loopback": "aqt-egress: the host's own loopback is outside the box",
                   "host-local": "aqt-egress: this host's own addresses are outside the box",
                   "record-unavailable": "aqt-egress: the connection could not be recorded, so it was closed"}
LOOPBACK_REFUSED = OUTSIDE_REFUSED["host-loopback"]
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
            key = (normal_ip(peer[0]), peer[1])
            addon.via_by_peer[key] = name
            addon.io_by_peer[key] = _count(reader, writer)
            await handle(reader, writer)
        return accept

    def fixed(address, *, lazy):
        """Transparent mode with a destination fixed in advance (or found later, for ``PLACEHOLDER``)."""
        async def handle(reader, writer):
            options = _Lazy(ctx.options) if lazy else ctx.options
            handler = ProxyConnectionHandler(ctx.master, reader, writer, options, transparent.mode)
            handler.layer = transparent.make_top_layer(handler.layer.context)
            handler.layer.context.server.address = address
            with manager.register_connection(handler.layer.context.client.id, handler):
                await handler.handle_client()
        return handle

    handlers = {"proxy": regular.handle_stream, "redirect": transparent.handle_stream,
                "direct80": fixed((PLACEHOLDER, 80), lazy=True), "direct443": fixed((PLACEHOLDER, 443), lazy=True)}
    for name in sockets:
        if name.startswith("local"):
            port = int(name.rpartition(":")[2])
            handlers[name] = fixed(addon.local_by_port[port], lazy=False)
    return [await asyncio.start_server(via("local" if name.startswith("local") else name, handle), sock=sockets[name])
            for name, handle in handlers.items() if name in sockets]


def _count(reader, writer) -> dict:
    """Count the bytes between the box and the proxy on one connection (also when TLS passes through
    unread). The stream objects stay what they are; only their read and write are wrapped."""
    counts = {"up": 0, "down": 0}
    read, write = reader.read, writer.write

    async def counted_read(n=-1):
        data = await read(n)
        counts["up"] += len(data)
        return data

    def counted_write(data):
        counts["down"] += len(data)
        return write(data)

    reader.read, writer.write = counted_read, counted_write
    return counts


# -- body taps -----------------------------------------------------------------------------------
class Tap:
    """A body passing through: hashed, counted, its head kept for the excerpt, spooled in full mode."""

    def __init__(self, store=None, keep: int = HEAD_BYTES):
        self.keep = keep
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
            if len(self.head) < self.keep:
                self.head += chunk[:self.keep - len(self.head)]
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


def _without_argv(process: dict) -> dict:
    """The process chain of an LLM request without command-line arguments (they may hold the prompt)."""
    chain = [{key: value for key, value in entry.items() if key != "argv"} | ({"argc": len(entry["argv"])}
             if "argv" in entry else {}) for entry in process.get("chain", [])]
    return {**process, "chain": chain}


def _clean(value):
    """Drop None values (records carry no nulls in this tool)."""
    if isinstance(value, dict):
        return {key: _clean(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [_clean(item) for item in value]
    return value


# -- the add-on ----------------------------------------------------------------------------------
TLS_ALERTS = ("unknown ca", "bad certificate", "certificate unknown")   # a client's explicit rejection of the CA
HOOK_ERROR = "aqt-egress could not record this exchange fully"


def host_addresses() -> set[str]:
    """Every address of this host's interfaces (LAN, VPN, bridges ...): ``ip -j addr`` from a system
    folder, else /proc/net/if_inet6 plus the IPv4 address of each interface."""
    from .netns import system_tool
    found: set[str] = set()
    ip = system_tool("ip")
    if ip:
        try:
            import json as json_
            import subprocess
            for link in json_.loads(subprocess.run([ip, "-j", "addr", "show"], capture_output=True, text=True,
                                                   timeout=10).stdout or "[]"):
                for entry in link.get("addr_info", []):
                    if entry.get("local"):
                        found.add(normal_ip(entry["local"]))
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    if not found:
        import fcntl
        import struct
        try:
            for line in Path("/proc/net/if_inet6").read_text().splitlines():
                raw = line.split()[0]
                found.add(normal_ip(str(ipaddress.IPv6Address(bytes.fromhex(raw)))))
        except (OSError, ValueError, IndexError):
            pass
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            for _index, name in socket.if_nameindex():
                try:
                    raw = fcntl.ioctl(probe.fileno(), 0x8915, struct.pack("256s", name.encode()[:15]))  # SIOCGIFADDR
                    found.add(socket.inet_ntoa(raw[20:24]))
                except OSError:
                    continue
    return found


def _guarded(name: str, emits: bool):
    """A hook that fails is counted (``hook_errors`` in the ended record) and, where it was to write the
    record, still leaves a minimal one: a failing hook must not let traffic pass unrecorded."""
    def wrap(method):
        if asyncio.iscoroutinefunction(method):
            async def hook(self, *args):
                try:
                    return await method(self, *args)
                except Exception as error:  # noqa: BLE001
                    self._hook_failed(name, error, args, emits)
        else:
            def hook(self, *args):
                try:
                    return method(self, *args)
                except Exception as error:  # noqa: BLE001
                    self._hook_failed(name, error, args, emits)
        hook.__name__ = method.__name__
        return hook
    return wrap


class Egress:
    def __init__(self, *, session: str, session_record: str | None, writer, settings, key: bytes,
                 attribute=None, lookups=None, store=None, test_hosts: dict | None = None,
                 allow_loopback: bool = False, own_addresses: set[str] | None = None):
        local = list(getattr(settings, "local_endpoints", []))
        self.local = set(local)                       # (ip, port) on the host the box may reach
        self.local_by_port = {port: (ip, port) for ip, port in local}
        self.session = session
        self.session_record = session_record
        self.writer = writer
        self.settings = settings
        self.key = key
        self.attribute = attribute or (lambda kind, peer, remote=None: unattributed("not in a box"))
        self.lookups = lookups
        self.store = store                            # BodyStore in full mode, else None
        self.test_hosts = test_hosts or {}            # tests only: name[:port] -> host[:port]
        self.allow_loopback = allow_loopback or bool(self.test_hosts)   # tests only: a local test server
        self.own_addresses = set(own_addresses or ())  # this host's interface addresses (refused like loopback)
        self.asked: dict[str, tuple] = {}             # server connection id -> destination before a test mapping
        self.opened: dict[str, str] = {}              # server connection id -> its "opened" record
        self.via_by_peer: dict[tuple, str] = {}
        self.io_by_peer: dict[tuple, dict] = {}
        self.conns: dict[str, dict] = {}
        self.passthrough_hosts = set(settings.passthrough)                  # configured, by name
        self.learned: dict[tuple, str] = {}           # (server name, destination) -> reason
        self.seq = 0
        self.counts = {"requests": 0, "opened": 0, "bytes_up": 0, "bytes_down": 0, "refused": 0,
                       "store_errors": 0, "hook_errors": 0, "unrecorded_closed": 0}

    # -- boundaries ---------------------------------------------------------------------------
    def refresh_addresses(self, found: set[str]) -> None:
        """Add newly seen host addresses; an empty or failed lookup never removes the known ones."""
        self.own_addresses |= set(found or ())

    def _outside(self, address: str, port: int) -> str | None:
        """Why the box may not reach this address of the host itself, or None."""
        if self.allow_loopback or (normal_ip(address), port) in self.local:
            return None
        if _loopback(address):
            return "host-loopback"
        if normal_ip(address) in self.own_addresses:
            return "host-local"
        return None

    def _hook_failed(self, name: str, error: Exception, args, emits: bool) -> None:
        self.counts["hook_errors"] += 1
        logger.error("hook %s failed: %r", name, error, exc_info=error)
        target = args[0] if args else None
        if not emits or target is None:
            return
        flow_recorded = getattr(target, "metadata", {}).get("aqt.recorded") if hasattr(target, "metadata") else None
        if flow_recorded:
            return
        try:
            if hasattr(target, "metadata"):
                target.metadata["aqt.recorded"] = True
            client = getattr(target, "client_conn", None) or target
            info = self.conns.get(getattr(client, "id", None))
            if info is not None:
                info["recorded"] = True
            server = getattr(target, "server_conn", None) or (info or {}).get("server")
            host, port = self._address(server, getattr(target, "request", None))
            data = self._base(info, host, port)
            data["error"] = f"{HOOK_ERROR}: {type(error).__name__}"
            self.counts["requests"] += 1
            self.writer.emit("egress.request", "observed", _clean(data),
                             subject={"kind": "egress.destination", "ref": f"{host}:{port}"}, links=self._links())
        except Exception as again:  # noqa: BLE001 - the error is counted already
            logger.error("minimal record failed: %r", again)

    # -- connections -------------------------------------------------------------------------
    @_guarded("client_connected", emits=False)
    def client_connected(self, client):
        peer = (normal_ip(client.peername[0]), client.peername[1])
        via = self.via_by_peer.pop(peer, "proxy")
        remote = (normal_ip(client.sockname[0]), client.sockname[1]) if client.sockname else None
        self.conns[client.id] = {"via": via, "process": self.attribute("tcp", peer, remote), "recorded": False,
                                 "tls": None, "io": self.io_by_peer.pop(peer, None)}

    @_guarded("client_disconnected", emits=True)
    def client_disconnected(self, client):
        info = self.conns.pop(client.id, None)
        if info and not info["recorded"]:
            self._emit_connection(client, None, info, error=client.error)

    @_guarded("tls_clienthello", emits=False)
    def tls_clienthello(self, data):
        info = self.conns.get(data.context.client.id)
        sni = (data.client_hello.sni or "").lower().rstrip(".") or None
        server = data.context.server
        if info and info["via"].startswith("direct") and sni:
            server.address = (sni, server.address[1])
        if info is not None:
            info["server"] = server
        reason = "configured" if sni in self.passthrough_hosts else self.learned.get((sni, server.address))
        if info is not None:
            info["tls"] = {"mode": "passthrough", "reason": reason} if reason else {"mode": "intercepted"}
        if reason:
            data.ignore_connection = True

    @_guarded("tls_failed_client", emits=True)
    def tls_failed_client(self, data):
        info = self.conns.get(data.context.client.id)
        error = data.conn.error or "TLS handshake with the client failed"
        sni, server = data.conn.sni, data.context.server
        if info is not None:
            info["tls"] = {"mode": "intercepted", "client_failed": True}
        # only an explicit alert from the client counts, and only for this name at this destination
        if sni and server.address and any(alert in error.lower() for alert in TLS_ALERTS):
            key = (sni.lower(), server.address)
            if key not in self.learned:
                self.learned[key] = "client-rejected-certificate"
                if info is not None:
                    info["tls"]["passthrough_learned"] = True
        if info is not None:
            self._emit_connection(data.context.client, server, info, error=error)

    @_guarded("server_connect", emits=False)
    async def server_connect(self, data):
        server = data.server
        host, port = server.address[0], server.address[1]
        info = self.conns.get(data.client.id)
        if info is not None:
            info["server"] = server
        if host == PLACEHOLDER:
            server.error = "aqt-egress: no destination (no TLS server name and no Host header)"
            return
        if (host, port) in self.local:                # a configured local inference endpoint
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
        reasons = [reason for reason in (self._outside(address, port) for address in addresses) if reason]
        if reasons:
            server.error = OUTSIDE_REFUSED[reasons[0]]
            if info is not None:
                info["refused"] = reasons[0]

    @_guarded("server_connected", emits=False)
    async def server_connected(self, data):
        """Before anything is sent upstream: a name that now resolves to the host itself (DNS rebinding)
        is closed; otherwise an ``opened`` record with the destination is written first, so that a proxy
        that dies or hangs mid-exchange still leaves the destination on record."""
        peer = data.server.peername
        info = self.conns.get(data.client.id)
        reason = self._outside(peer[0], peer[1]) if peer else None
        if reason:
            if info is not None:
                info["refused"] = reason
                self._emit_connection(data.client, data.server, info, error=OUTSIDE_REFUSED[reason])
            self._close(data)
            return
        host, port = self._address(data.server, None)
        record_data = {
            "session": self.session, "mode": "observe", "decision": "allowed",
            "process": info["process"] if info else unattributed("connection not seen from its start"),
            "destination": {"host": host, "port": port, "ip": normal_ip(peer[0]) if peer else None,
                            "sni": data.server.sni, "via": info["via"] if info else None},
            "timing": {"start": _iso(data.server.timestamp_start)},
        }
        if self._llm(host, port, info):
            record_data["process"] = _without_argv(record_data["process"])
        record = self.writer.record("egress.request", "opened", _clean(record_data), links=self._links(),
                                    subject={"kind": "egress.destination", "ref": f"{host}:{port}"})
        self.opened[data.server.id] = record["id"]
        self.counts["opened"] += 1
        if not await asyncio.get_running_loop().run_in_executor(None, self.writer.append_now, record):
            # no record, no traffic: close this connection before anything is sent on it
            self.counts["unrecorded_closed"] += 1
            if info is not None:
                info["refused"] = "record-unavailable"
            self._close(data)

    def _close(self, data) -> None:
        """Close both ends of a connection that was just opened; nothing has been sent on it yet."""
        handler = ctx.master.addons.get("proxyserver").connections.get(data.client.id)
        for connection in (data.server, data.client):       # the client sees a reset
            transport = handler.transports.get(connection) if handler else None
            if transport is not None and transport.writer is not None:
                transport.writer.close()

    # -- HTTP --------------------------------------------------------------------------------
    @_guarded("requestheaders", emits=False)
    def requestheaders(self, flow):
        info = self.conns.get(flow.client_conn.id)
        if info and info["via"] == "direct80" and flow.request.host == PLACEHOLDER:
            host = flow.request.host_header
            if host:
                name, _, port = host.rpartition(":") if host.count(":") == 1 else (host, "", "")
                flow.request.host = (name or host).lower()
                flow.request.port = int(port) if port.isdigit() else 80
        provider = self._llm(*self._address(flow.server_conn, flow.request), info)   # final decision at the end
        tap = Tap(self.store, keep=llm_api.KEEP_BYTES if provider else HEAD_BYTES)
        flow.metadata["aqt.llm"] = provider
        flow.metadata["aqt.request"] = tap
        flow.metadata["aqt.start"] = time.time()
        flow.request.stream = tap

    def _llm(self, host: str | None, port, info: dict | None) -> str | None:
        """The LLM provider of the destination the proxy connects to (never of what the client claims in
        Host or SNI), or None: such requests get no text excerpts. A configured local endpoint is ``local``
        on every path (its own listener, the proxy, the redirect)."""
        if info is not None and info.get("via") == "local":
            return "local"
        if host and port and (normal_ip(host), port) in self.local:
            return "local"
        return llm_api.provider(host, self.settings.llm_hosts)

    @_guarded("responseheaders", emits=False)
    def responseheaders(self, flow):
        tap = Tap(self.store)
        flow.metadata["aqt.response"] = tap
        flow.response.stream = tap

    @_guarded("response", emits=True)
    def response(self, flow):
        upgrade = flow.request.headers.get("upgrade", "")
        if flow.response.status_code == 101 and "websocket" in upgrade.lower():
            flow.metadata["aqt.ws"] = {"up": 0, "down": 0, "messages": 0}   # recorded at its end, with its traffic
            return
        self._emit_http(flow, protocol="http-upgrade" if flow.response.status_code == 101 else None)

    @_guarded("error", emits=True)
    def error(self, flow):
        self._emit_http(flow, error=flow.error.msg if flow.error else "error")

    @_guarded("websocket_message", emits=False)
    def websocket_message(self, flow):
        counts = flow.metadata.setdefault("aqt.ws", {"up": 0, "down": 0, "messages": 0})
        message = flow.websocket.messages[-1]
        counts["up" if message.from_client else "down"] += len(message.content)
        counts["messages"] += 1
        flow.websocket.messages.clear()

    @_guarded("websocket_end", emits=True)
    def websocket_end(self, flow):
        self._emit_http(flow, protocol="websocket")

    # -- TCP ---------------------------------------------------------------------------------
    @_guarded("tcp_start", emits=False)
    def tcp_start(self, flow):
        flow.metadata["aqt.up"], flow.metadata["aqt.down"] = Tap(self.store), Tap(self.store)
        flow.metadata["aqt.start"] = time.time()

    @_guarded("tcp_message", emits=False)
    def tcp_message(self, flow):
        message = flow.messages[-1]
        flow.metadata["aqt.up" if message.from_client else "aqt.down"](message.content)
        flow.messages.clear()

    @_guarded("tcp_end", emits=True)
    def tcp_end(self, flow):
        self._emit_tcp(flow)

    @_guarded("tcp_error", emits=True)
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
    def _links(self, server=None):
        links = [{"rel": "session", "ref": self.session_record}] if self.session_record else []
        opened = self.opened.get(server.id) if server is not None else None
        if opened:
            links.append({"rel": "opened", "ref": opened})
        return links or None

    def _address(self, server, request) -> tuple:
        """Where the proxy connected (or was to connect): the name or address it used, not what the
        client claims in Host or SNI. Under a test mapping, the destination before the mapping."""
        if server is not None and server.id in self.asked:
            return self.asked[server.id]
        if server is not None and server.address and server.address[0] != PLACEHOLDER:
            return server.address[0], server.address[1]
        if request is not None:
            return request.host, request.port
        return None, None

    def _base(self, info, host, port, *, ip=None, sni=None, claimed=None) -> dict:
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
        if claimed and claimed.lower().rstrip(".") != (host or "").lower():
            data["destination"]["host_header"] = claimed       # what the client claimed, if it differs
        if refused:
            data["reason_code"] = refused
        if self.lookups is not None and host:
            claimed_lookups = self.lookups.claim(host, data["process"])
            if claimed_lookups:
                data["lookups"] = [{"name": entry["name"], "types": entry["types"], "count": entry["count"]}
                                   for entry in claimed_lookups]
        return data

    def _submit(self, data: dict, host, port, store_work=None, server=None) -> None:
        links = self._links(server)

        def build():
            if store_work is not None:
                try:
                    store_work(data)
                except Exception as error:  # noqa: BLE001 - the record stays, with the error
                    self.counts["store_errors"] += 1
                    data["store_error"] = f"{type(error).__name__}: {error}"[:300]
            return "egress.request", "observed", _clean(data), {"kind": "egress.destination",
                                                                "ref": f"{host}:{port}"}, links
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
        host, port = self._address(server, request)
        tls = server is not None and server.tls or flow.client_conn.tls_established
        claimed = request.host_header.rsplit(":", 1)[0] if request.host_header and ":" in request.host_header \
            and not request.host_header.endswith("]") else request.host_header
        data = self._base(info, host, port, ip=server.peername[0] if server and server.peername else None,
                          sni=((server.sni if server else None) or flow.client_conn.sni) if tls else None,
                          claimed=claimed)
        path, _, query = request.path.partition("?")
        req_tap: Tap | None = flow.metadata.get("aqt.request")
        resp_tap: Tap | None = flow.metadata.get("aqt.response")
        names, credentials = headers_summary(request.headers.items(multi=True), self.key)
        provider = self._llm(host, port, info)
        chars = 0 if provider else self.settings.excerpt_chars      # LLM traffic: structure, never text
        data.update(protocol=protocol or request.http_version, tls=self._tls(info, flow.client_conn),
                    method=request.method, path=mask_text(path)[:2048],
                    query_sha256=("sha256:" + hashlib.sha256(query.encode("utf-8", "surrogateescape")).hexdigest())
                    if query else None)
        if protocol == "http-upgrade":
            data["upgrade"] = request.headers.get("upgrade", "")[:100]
        req_encoding = request.headers.get("content-encoding")
        data["request"] = {"headers": names, "credentials": credentials or None,
                           "content_type": request.headers.get("content-type"),
                           **(req_tap.summary() if req_tap else {"bytes": len(request.raw_content or b"")}),
                           "excerpt": _excerpt(req_tap, req_encoding, chars) if req_tap else None}
        if provider:
            data["process"] = _without_argv(data["process"])
            data["llm"] = {"provider": provider, **(llm_api.structure(
                bytes(req_tap.head), complete=req_tap.size <= len(req_tap.head), encoding=req_encoding,
                path=path) if req_tap and req_tap.size else {})}
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
                data["store"] = refs
                if req_raw:
                    refs["request_body"] = store.put_body(req_raw, req_encoding)
                if resp_raw:
                    refs["response_body"] = store.put_body(resp_raw, response.headers.get("content-encoding"))
        self._submit(data, host, port, store_work, server)

    def _emit_tcp(self, flow, *, error: str | None = None) -> None:
        info = self.conns.get(flow.client_conn.id)
        if info is not None:
            info["recorded"] = True
        server = flow.server_conn
        host, port = self._address(server, None)
        data = self._base(info, host, port, ip=server.peername[0] if server.peername else None, sni=server.sni,
                          claimed=flow.client_conn.sni)
        up, down = flow.metadata.get("aqt.up"), flow.metadata.get("aqt.down")
        start = flow.metadata.get("aqt.start")
        provider = self._llm(host, port, info)
        chars = 0 if provider else self.settings.excerpt_chars
        if provider:
            data["process"] = _without_argv(data["process"])
            data["llm"] = {"provider": provider}
        data.update(protocol="tcp", tls=self._tls(info, flow.client_conn),
                    request={**up.summary(), "excerpt": _excerpt(up, None, chars)},
                    response={**down.summary(), "excerpt": _excerpt(down, None, chars)},
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
        self._submit(data, host, port, store_work, server)

    def _emit_connection(self, client, server, info, *, error: str | None) -> None:
        """A connection that carried no request we saw: TLS passed through or failed, refused, or closed
        early. Its sizes are the bytes that passed between the box and the proxy on this connection."""
        info["recorded"] = True
        server = server or info.get("server")
        host, port = self._address(server, None)
        if host is None:
            port = client.sockname[1] if client.sockname else None
        data = self._base(info, host, port,
                          ip=server.peername[0] if server is not None and server.peername else None, sni=client.sni,
                          claimed=client.sni)
        io = info.get("io") or {}
        data.update(protocol="tls" if info.get("tls") else "tcp", tls=self._tls(info, client),
                    request={"bytes": io.get("up", 0)}, response={"bytes": io.get("down", 0)},
                    timing={"start": _iso(client.timestamp_start),
                            "total_ms": _ms(client.timestamp_start, client.timestamp_end or time.time())})
        if self._llm(host, port, info):
            data["process"] = _without_argv(data["process"])
        if error:
            data["error"] = mask_text(str(error))[:500]
        elif data["tls"].get("mode") != "passthrough":
            data["error"] = "closed before a request"
        self.counts["requests"] += 1
        self.counts["bytes_up"] += io.get("up", 0)
        self.counts["bytes_down"] += io.get("down", 0)
        self._submit(data, host, port, None, server)
