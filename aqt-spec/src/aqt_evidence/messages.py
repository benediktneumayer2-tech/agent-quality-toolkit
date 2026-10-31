"""Message codes: an English sentence that also carries a stable code and its parameters.

``Text(code, template, **args)`` is a ``str``: printed, put into JSON or stored in a record it is exactly
``template.format(**args)``, byte for byte. The code and the parameters ride along (``.code``, ``.args``) for a
user interface that shows the sentence in another language from its own catalogue (aqt-ui
``static/messages.js``). Codes are dotted and namespaced by package (``change.gate.receipt_trust``); a template
uses only ``{name}`` placeholders, and one code has one template. Evidence content (reasons, notes, ids, paths)
goes in as a parameter and is never translated.

A ``Text`` stays one only as long as it is passed on as it is: ``+``, f-strings, ``str.join``, slicing and
``str()`` give a plain ``str``. ``text_join`` joins parts and keeps them; ``coded`` gives code and parameters as
plain JSON where the text leaves the process (a subprocess, a file, a database), for an additive sibling field.
"""

from __future__ import annotations

from typing import Iterable

JOIN = "aqt.join"


class Text(str):
    """An English sentence with ``code`` and ``args`` (the parameters it was formatted with)."""

    code: str
    args: dict

    def __new__(cls, code: str, template: str, /, **args) -> "Text":
        return _make(template.format(**args), code, args)

    def __reduce__(self):          # copy, deepcopy (dataclasses.asdict) and pickle keep code and args
        return _make, (str(self), self.code, self.args)


def _make(value: str, code: str, args: dict) -> Text:
    made = str.__new__(Text, value)
    made.code, made.args = code, args
    return made


def text_join(sep: str, parts: Iterable[str]) -> Text:
    """``sep.join(parts)`` that keeps every part: code ``aqt.join``, args ``{"sep", "items"}``."""
    items = list(parts)
    return _make(sep.join(items), JOIN, {"sep": sep, "items": items})


def coded(value) -> dict | None:
    """``{"code", "args"}`` as plain JSON for a ``Text``, or for an exception whose message is one (a ``Text``
    among the args becomes such a dict too); None for anything else."""
    if isinstance(value, BaseException):
        value = value.args[0] if value.args else None
    if not isinstance(value, Text):
        return None
    return {"code": value.code, "args": {str(key): _plain(item) for key, item in value.args.items()}}


def _plain(value):
    if isinstance(value, Text):
        return coded(value)
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)
