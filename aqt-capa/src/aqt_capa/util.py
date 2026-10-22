"""Small helpers: time parsing, hashing files, duration specs."""

from __future__ import annotations

import fnmatch
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

from aqt_evidence import bytes_hash


def parse_time(value: str) -> datetime:
    """RFC 3339 (``Z`` or offset) to an aware UTC datetime."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def fmt_time(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def now() -> datetime:
    return datetime.now(UTC)


_SINCE = re.compile(r"^(\d+)([dw])$")


def parse_since(value: str | None, *, reference: datetime | None = None) -> datetime | None:
    """``90d``, ``12w`` or an ISO date/time."""
    if not value:
        return None
    match = _SINCE.match(value.strip())
    if match:
        days = int(match.group(1)) * (7 if match.group(2) == "w" else 1)
        return (reference or now()) - timedelta(days=days)
    return parse_time(value if "T" in value else value + "T00:00:00Z")


def file_hash(path: Path) -> str | None:
    try:
        return bytes_hash(path.read_bytes())
    except FileNotFoundError:
        return None


def type_matches(pattern: str | None, value: str | None) -> bool:
    if not pattern:
        return True
    return value is not None and fnmatch.fnmatchcase(value, pattern)


def excerpt(text: str | None, limit: int = 240) -> str | None:
    if text is None:
        return None
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
