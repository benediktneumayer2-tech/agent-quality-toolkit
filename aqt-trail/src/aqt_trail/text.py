"""Showing client-controlled strings safely in a terminal and in Markdown.

Records can carry any Unicode text (canonical JSON allows control characters), so
everything a client wrote is escaped before it reaches a terminal or a Markdown
renderer: control characters (C0, C1, DEL) and invisible format characters
(bidirectional overrides, zero-width characters) become visible ``\\x..`` /
``\\u....`` escapes.
"""

from __future__ import annotations

import html
import unicodedata

_KEEP = {"\n": "\n", "\t": "\t"}


def _escape(char: str) -> str:
    code = ord(char)
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}" if code < 0x10000 else f"\\U{code:08x}"


def printable(value, *, keep_newlines: bool = False) -> str:
    """``value`` as text with control and invisible format characters escaped."""
    text = value if isinstance(value, str) else str(value)
    out = []
    for char in text:
        if keep_newlines and char in _KEEP:
            out.append(char)
        elif unicodedata.category(char) in ("Cc", "Cf", "Zl", "Zp"):
            out.append(_escape(char))
        else:
            out.append(char)
    return "".join(out)


def md(value) -> str:
    """``value`` for a Markdown table cell or list item: no raw HTML, links, code spans or line breaks."""
    text = printable(value).replace("\\", "\\\\")
    text = html.escape(text, quote=False)
    for char in "`[]|":
        text = text.replace(char, "\\" + char)
    return text
