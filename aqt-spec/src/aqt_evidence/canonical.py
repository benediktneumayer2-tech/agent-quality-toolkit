"""AQT canonical JSON and hashing.

AQT canonical JSON is UTF-8, object keys sorted, no insignificant whitespace.
Keys must be ASCII and numbers must be integers within +/-2**53, so the output
is byte-identical to RFC 8785 (JCS) for every valid AQT document.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

MAX_SAFE_INTEGER = 2**53 - 1


class CanonicalError(ValueError):
    """The value cannot be represented in AQT canonical JSON."""


def _encodable(text: str, path: str) -> None:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError as error:
        raise CanonicalError(f"{path}: string is not valid Unicode (lone surrogate)") from error


def _check(value: Any, path: str) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        _encodable(value, path)
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalError(f"{path}: integer outside +/-2**53")
        return
    if isinstance(value, float):
        raise CanonicalError(f"{path}: floats are not allowed; use an integer or a string")
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _check(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise CanonicalError(f"{path}: object keys must be ASCII strings")
            _check(item, f"{path}.{key}")
        return
    raise CanonicalError(f"{path}: unsupported type {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    """Serialise ``value`` as AQT canonical JSON bytes."""
    try:
        _check(value, "$")
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except RecursionError as error:
        raise CanonicalError("value is nested too deeply") from error


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def content_hash(value: Any) -> str:
    """``sha256:<hex>`` of the canonical form of ``value``."""
    return "sha256:" + sha256_hex(canonical_json(value))


def bytes_hash(data: bytes) -> str:
    """``sha256:<hex>`` of raw bytes (files, artefacts, texts)."""
    return "sha256:" + sha256_hex(data)


def _reject_float(text: str) -> Any:
    raise CanonicalError(f"floats are not allowed: {text}")


def _reject_constant(text: str) -> Any:
    raise CanonicalError(f"{text} is not allowed")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalError(f"duplicate object key {key!r}")
        result[key] = value
    return result


def parse_json(text: str | bytes) -> Any:
    """Strict parse: rejects duplicate keys, floats, NaN/Infinity, lone surrogates and
    anything else that cannot be AQT canonical JSON. Raises ``CanonicalError``."""
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8")
        except UnicodeDecodeError as error:
            raise CanonicalError("input is not valid UTF-8") from error
    try:
        value = json.loads(text, object_pairs_hook=_no_duplicates, parse_float=_reject_float,
                           parse_constant=_reject_constant)
    except CanonicalError:
        raise
    except ValueError as error:
        raise CanonicalError(f"not valid JSON: {error}") from error
    except RecursionError as error:
        raise CanonicalError("JSON is nested too deeply") from error
    try:
        _check(value, "$")
    except RecursionError as error:
        raise CanonicalError("JSON is nested too deeply") from error
    return value


def parse_record(text: str | bytes) -> dict:
    """Strictly parse one record (a JSON object). Envelope rules are checked separately
    by ``validate_record``."""
    value = parse_json(text)
    if not isinstance(value, dict):
        raise CanonicalError("a record must be a JSON object")
    return value


def parse_canonical_line(line: str | bytes) -> dict:
    """Strictly parse one stored line of a JSON-lines log, for verifiers.

    The line (without one final ``\\n``) must parse with ``parse_record`` and be exactly
    the record's canonical form, so the stored bytes are the record that is hashed and
    signed. Raises ``CanonicalError``."""
    if isinstance(line, str):
        try:
            line = line.encode("utf-8")
        except UnicodeEncodeError as error:
            raise CanonicalError("line is not valid Unicode") from error
    body = line[:-1] if line.endswith(b"\n") else line
    record = parse_record(body)
    if canonical_json(record) != body:
        raise CanonicalError("line is not in canonical form (spec §4)")
    return record
