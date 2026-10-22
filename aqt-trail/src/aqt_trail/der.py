"""Minimal DER encoding and decoding, enough for RFC 3161 time-stamp tokens.

Only definite-length DER is supported (RFC 3161 responses are DER). The
decoder returns ``Node`` objects that keep their exact bytes, so signed parts
can be re-hashed exactly as received.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

INTEGER, BIT_STRING, OCTET_STRING, NULL, OID, UTF8, SEQUENCE, SET = 0x02, 0x03, 0x04, 0x05, 0x06, 0x0C, 0x30, 0x31
BOOLEAN, GENERALIZED_TIME = 0x01, 0x18


class DerError(ValueError):
    pass


# -- encoding ---------------------------------------------------------------
def _length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _length(len(content)) + content


def seq(*items: bytes) -> bytes:
    return tlv(SEQUENCE, b"".join(items))


def set_of(*items: bytes) -> bytes:
    return tlv(SET, b"".join(sorted(items)))  # DER: SET OF sorted by encoding


def integer(value: int) -> bytes:
    length = max(1, (value.bit_length() + 8) // 8)
    return tlv(INTEGER, value.to_bytes(length, "big", signed=True))


def octets(value: bytes) -> bytes:
    return tlv(OCTET_STRING, value)


def null() -> bytes:
    return tlv(NULL, b"")


def boolean(value: bool) -> bytes:
    return tlv(BOOLEAN, b"\xff" if value else b"\x00")


def oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    body = bytearray([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append(0x80 | (part & 0x7F))
            part >>= 7
        body.extend(reversed(chunk))
    return tlv(OID, bytes(body))


def generalized_time(moment: datetime) -> bytes:
    moment = moment.astimezone(UTC)
    text = moment.strftime("%Y%m%d%H%M%S")
    if moment.microsecond:
        text += "." + f"{moment.microsecond:06d}".rstrip("0")
    return tlv(GENERALIZED_TIME, (text + "Z").encode("ascii"))


def explicit(number: int, content: bytes) -> bytes:
    return tlv(0xA0 | number, content)


def implicit(number: int, encoded: bytes, constructed: bool = True) -> bytes:
    """Re-tag an encoded TLV as context-specific [number] IMPLICIT."""
    tag = (0xA0 if constructed else 0x80) | number
    return bytes([tag]) + encoded[1:]


# -- decoding ---------------------------------------------------------------
@dataclass
class Node:
    tag: int
    raw: bytes        # complete TLV
    content: bytes

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)

    def children(self) -> list["Node"]:
        return parse_all(self.content)

    def child(self, index: int) -> "Node":
        items = self.children()
        if index >= len(items):
            raise DerError("missing element")
        return items[index]

    def as_int(self) -> int:
        if self.tag != INTEGER:
            raise DerError("expected INTEGER")
        return int.from_bytes(self.content, "big", signed=True)

    def as_oid(self) -> str:
        if self.tag != OID or not self.content:
            raise DerError("expected OBJECT IDENTIFIER")
        first = self.content[0]
        parts, value = [first // 40 if first < 80 else 2, first % 40 if first < 80 else first - 80], 0
        for byte in self.content[1:]:
            value = (value << 7) | (byte & 0x7F)
            if not byte & 0x80:
                parts.append(value)
                value = 0
        return ".".join(str(p) for p in parts)

    def as_time(self) -> datetime:
        if self.tag != GENERALIZED_TIME:
            raise DerError("expected GeneralizedTime")
        text = self.content.decode("ascii").rstrip("Z")
        fmt = "%Y%m%d%H%M%S.%f" if "." in text else "%Y%m%d%H%M%S"
        return datetime.strptime(text, fmt).replace(tzinfo=UTC)


def parse_one(data: bytes, offset: int = 0) -> tuple[Node, int]:
    if offset + 2 > len(data):
        raise DerError("truncated DER")
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise DerError("high tag numbers are not supported")
    first = data[offset + 1]
    position = offset + 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or count > 4 or position + count > len(data):
            raise DerError("unsupported DER length")
        length = int.from_bytes(data[position:position + count], "big")
        position += count
    end = position + length
    if end > len(data):
        raise DerError("truncated DER")
    return Node(tag, data[offset:end], data[position:end]), end


def parse(data: bytes) -> Node:
    node, end = parse_one(data)
    if end != len(data):
        raise DerError("trailing bytes after DER value")
    return node


def parse_all(data: bytes) -> list[Node]:
    nodes, offset = [], 0
    while offset < len(data):
        node, offset = parse_one(data, offset)
        nodes.append(node)
    return nodes
