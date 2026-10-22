"""A strict YAML subset for plan front matter.

Supported: nested mappings (indented by spaces), plain / single-quoted /
double-quoted scalars, integers, ``true``/``false``/``null``, flow lists
``[a, b]`` and block lists of scalars (``- item``), full-line comments and
``...`` markers. Anything else is refused with a clear error instead of being
guessed. Floats stay strings (evidence records allow integers only).
"""

from __future__ import annotations

import json
import re
from typing import Any


class FrontMatterError(ValueError):
    pass


_KEY = re.compile(r"^(?P<indent> *)(?P<key>[A-Za-z0-9_.-]+):(?:\s+(?P<value>.*?))?\s*$")
_ITEM = re.compile(r"^(?P<indent> *)-(?:\s+(?P<value>.*?))?\s*$")
_INT = re.compile(r"^[-+]?\d+$")
_PLAIN_SAFE = re.compile(r"^[A-Za-z0-9_./@+-][A-Za-z0-9_ ./@+-]*$")


def split(text: str) -> tuple[str | None, str]:
    """Return (front matter text or None, body)."""
    if not text.startswith("---\n") and not text.startswith("---\r\n"):
        return None, text
    lines = text.splitlines(keepends=True)
    for index in range(1, len(lines)):
        if lines[index].rstrip("\r\n") == "---":
            return "".join(lines[1:index]), "".join(lines[index + 1:])
    raise FrontMatterError("front matter starts with --- but has no closing ---")


def _strip_comment(value: str) -> str:
    if value.startswith(("'", '"')):
        return value
    match = re.search(r"\s#", value)
    return value[:match.start()].rstrip() if match else value


def scalar(raw: str) -> Any:
    value = _strip_comment(raw.strip())
    if value == "" or value in ("null", "~", "Null", "NULL"):
        return None
    if value in ("true", "True", "TRUE"):
        return True
    if value in ("false", "False", "FALSE"):
        return False
    if _INT.match(value):
        return int(value)
    if value.startswith("'"):
        if not value.endswith("'") or len(value) < 2:
            raise FrontMatterError(f"unterminated single-quoted string: {value}")
        return value[1:-1].replace("''", "'")
    if value.startswith('"'):
        try:
            return json.loads(value)
        except ValueError as error:
            raise FrontMatterError(f"unsupported double-quoted string: {value}") from error
    if value.startswith("["):
        if not value.endswith("]"):
            raise FrontMatterError(f"unterminated flow list: {value}")
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [scalar(part) for part in _split_flow(inner)]
    if value.startswith(("{", "&", "*", "!", "|", ">")):
        raise FrontMatterError(f"unsupported YAML construct: {value}")
    return value


def _split_flow(inner: str) -> list[str]:
    parts, current, quote = [], "", None
    for char in inner:
        if quote:
            current += char
            if char == quote:
                quote = None
        elif char in ("'", '"'):
            quote = char
            current += char
        elif char == ",":
            parts.append(current)
            current = ""
        elif char in "[]{}":
            raise FrontMatterError("nested flow collections are not supported")
        else:
            current += char
    parts.append(current)
    return [part.strip() for part in parts]


def parse(text: str) -> dict:
    lines = [(number, line.rstrip("\r\n")) for number, line in enumerate(text.splitlines(), 1)]
    lines = [(n, l) for n, l in lines if l.strip() and not l.lstrip().startswith("#") and l.strip() != "..."]
    for number, line in lines:
        if "\t" in line[: len(line) - len(line.lstrip())]:
            raise FrontMatterError(f"line {number}: tabs are not allowed for indentation")
    value, position = _parse_block(lines, 0, 0)
    if position != len(lines):
        raise FrontMatterError(f"line {lines[position][0]}: unexpected indentation")
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise FrontMatterError("front matter must be a mapping")
    return value


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _parse_block(lines, position: int, indent: int):
    if position >= len(lines):
        return None, position
    number, line = lines[position]
    if _indent(line) != indent:
        return None, position
    if _ITEM.match(line):
        return _parse_list(lines, position, indent)
    return _parse_mapping(lines, position, indent)


def _parse_mapping(lines, position: int, indent: int):
    result: dict[str, Any] = {}
    while position < len(lines):
        number, line = lines[position]
        current = _indent(line)
        if current < indent:
            break
        if current > indent:
            raise FrontMatterError(f"line {number}: unexpected indentation")
        match = _KEY.match(line)
        if not match:
            raise FrontMatterError(f"line {number}: expected 'key: value'")
        key = match.group("key")
        if key in result:
            raise FrontMatterError(f"line {number}: duplicate key {key!r}")
        raw = match.group("value")
        position += 1
        if raw is None or raw == "" or _strip_comment(raw) == "":
            if position < len(lines) and _indent(lines[position][1]) > indent:
                child_indent = _indent(lines[position][1])
                value, position = _parse_block(lines, position, child_indent)
            elif position < len(lines) and _indent(lines[position][1]) == indent and _ITEM.match(lines[position][1]):
                value, position = _parse_list(lines, position, indent)
            else:
                value = None
            result[key] = value
        else:
            result[key] = scalar(raw)
    return result, position


def _parse_list(lines, position: int, indent: int):
    result: list[Any] = []
    while position < len(lines):
        number, line = lines[position]
        if _indent(line) != indent:
            break
        match = _ITEM.match(line)
        if not match:
            break
        raw = match.group("value") or ""
        stripped = raw.strip()
        if stripped and not stripped.startswith(("'", '"', "[")) and _KEY.match(stripped):
            raise FrontMatterError(f"line {number}: lists of mappings are not supported")
        result.append(scalar(raw))
        position += 1
    return result, position


# --- writing -----------------------------------------------------------------

def _dump_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    text = str(value)
    if (_PLAIN_SAFE.match(text) and not _INT.match(text) and text.strip() == text
            and text not in ("null", "true", "false", "~") and not text.startswith("-")):
        return text
    return "'" + text.replace("'", "''") + "'"


def dump(data: dict, indent: int = 0) -> str:
    out = []
    pad = " " * indent
    for key, value in data.items():
        if isinstance(value, dict):
            if not value:
                raise FrontMatterError(f"empty mapping {key!r} cannot be written")
            out.append(f"{pad}{key}:\n")
            out.append(dump(value, indent + 2))
        elif isinstance(value, list):
            if not value:
                out.append(f"{pad}{key}: []\n")
            else:
                out.append(f"{pad}{key}:\n")
                for item in value:
                    if isinstance(item, (dict, list)):
                        raise FrontMatterError("nested collections in lists cannot be written")
                    out.append(f"{pad}  - {_dump_scalar(item)}\n")
        else:
            out.append(f"{pad}{key}: {_dump_scalar(value)}\n")
    return "".join(out)


def join(front: dict, body: str) -> str:
    return "---\n" + dump(front) + "---\n" + body
