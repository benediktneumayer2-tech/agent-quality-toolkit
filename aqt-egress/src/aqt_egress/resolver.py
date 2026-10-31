"""The box resolver: every name is answered with the listener's address, and recorded.

Inside the box ``/etc/resolv.conf`` names ``127.0.0.1``, and (where nftables works) any UDP query
to port 53 elsewhere is redirected here too. Names are never resolved upstream by the box: an A
query gets ``127.0.0.1``, an AAAA query ``::1``, every other type an empty answer. A client that
ignores the proxy variables then connects to the box's own ports 80/443, where the proxy takes
the destination from the Host header or the TLS server name and resolves it itself.

Lookups wait in ``Lookups`` until the request that followed claims them (its record then lists
them); what nobody claimed within ``UNCLAIMED_S`` becomes an ``egress.lookup`` record.
"""

from __future__ import annotations

import asyncio
import struct
import time

QTYPES = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 33: "SRV", 64: "SVCB", 65: "HTTPS", 12: "PTR",
          2: "NS", 6: "SOA", 255: "ANY"}
ANSWERS = {1: bytes([127, 0, 0, 1]), 28: bytes(15) + b"\x01"}
TTL = 1
UNCLAIMED_S = 30.0


def parse_query(packet: bytes) -> tuple[int, int, str, int, int] | None:
    """(id, flags, name, qtype, end of the question) of a standard query, or None."""
    if len(packet) < 12:
        return None
    ident, flags, qdcount = struct.unpack("!HHH", packet[:6])
    if flags & 0x8000 or (flags >> 11) & 0xF != 0 or qdcount < 1:
        return None
    labels, offset = [], 12
    while True:
        if offset >= len(packet):
            return None
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0 or offset + length > len(packet):
            return None
        labels.append(packet[offset:offset + length].decode("ascii", "replace"))
        offset += length
    if offset + 4 > len(packet):
        return None
    qtype, _qclass = struct.unpack("!HH", packet[offset:offset + 4])
    return ident, flags, ".".join(labels).lower(), qtype, offset + 4


def answer(packet: bytes) -> tuple[bytes, str, int] | None:
    """(response, name, qtype) for a query: the listener's address for A and AAAA, nothing else."""
    parsed = parse_query(packet)
    if parsed is None:
        return None
    ident, flags, name, qtype, end = parsed
    data = ANSWERS.get(qtype)
    reply_flags = 0x8000 | (flags & 0x0100) | 0x0080         # response, copy RD, RA
    header = struct.pack("!HHHHHH", ident, reply_flags, 1, 1 if data else 0, 0, 0)
    body = packet[12:end]
    if data:
        body += struct.pack("!HHHIH", 0xC00C, qtype, 1, TTL, len(data)) + data
    return header + body, name, qtype


class Lookups:
    """Lookups waiting for the request that follows them, per name and asking process."""

    def __init__(self, clock=time.time):
        self.clock = clock
        self.pending: dict[tuple[str, int | None], dict] = {}
        self.total = 0

    @staticmethod
    def _pid(process: dict | None) -> int | None:
        chain = (process or {}).get("chain") or []
        return chain[0].get("pid") if chain else None

    def add(self, name: str, qtype: int, process: dict | None) -> None:
        self.total += 1
        now = self.clock()
        key = (name, self._pid(process))
        entry = self.pending.setdefault(key, {"name": name, "types": [], "count": 0, "first": now,
                                              "process": process})
        kind = QTYPES.get(qtype, str(qtype))
        if kind not in entry["types"]:
            entry["types"].append(kind)
        entry["count"] += 1
        entry["last"] = now

    def claim(self, host: str | None, process: dict | None) -> list[dict]:
        """The lookups of ``host`` by the process that made the request (or by an unknown process)."""
        name = (host or "").lower().rstrip(".")
        pid = self._pid(process)
        return [self.pending.pop(key) for key in ((name, pid), (name, None)) if key in self.pending
                and (key[1] is None or key[1] == pid)]

    def unclaimed(self, older_than: float = UNCLAIMED_S) -> list[dict]:
        now = self.clock()
        done = [key for key, entry in self.pending.items() if now - entry["last"] >= older_than]
        return [self.pending.pop(key) for key in done]


class ResolverProtocol(asyncio.DatagramProtocol):
    def __init__(self, on_lookup):
        self.on_lookup = on_lookup        # (name, qtype, peer) -> None
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        result = answer(data)
        if result is None:
            return
        response, name, qtype = result
        try:
            self.on_lookup(name, qtype, addr)     # before the answer: the asking socket is still open
        except Exception:  # noqa: BLE001 - recording must never stop the resolver
            pass
        self.transport.sendto(response, addr)
