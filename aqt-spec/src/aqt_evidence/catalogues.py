"""GxP catalogues (packaged ``catalogues.json``, standard library only).

Reports cite catalogue item IDs such as ``alcoa:attributable``, ``part11:11.50(a)`` or
``annex11-2025d:12.2``. The YAML sources and the generated crosswalk live in the
aqt-spec source tree (``catalogues/``, ``crosswalk.md``).
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from .schemas import data_dir

ALCOA = ("attributable", "legible", "contemporaneous", "original", "accurate", "complete", "consistent",
         "enduring", "available", "traceable")


def _path() -> Path:
    packaged = data_dir("catalogues.json")
    return packaged if packaged.exists() else data_dir("catalogues") / "catalogues.json"


@lru_cache(maxsize=1)
def load() -> dict:
    """The whole catalogue set: ``{"statement", "features", "catalogues": [...]}``."""
    return json.loads(_path().read_text(encoding="utf-8"))


def catalogue_ids() -> list[str]:
    return [catalogue["catalogue"] for catalogue in load()["catalogues"]]


@lru_cache(maxsize=1)
def _items() -> dict[str, dict]:
    return {item["id"]: {**item, "catalogue": catalogue["catalogue"]}
            for catalogue in load()["catalogues"] for item in catalogue["items"]}


def item(item_id: str) -> dict:
    """One catalogue item by ID; raises ``KeyError`` for an unknown ID."""
    return _items()[item_id]


def items(catalogue: str | None = None) -> list[dict]:
    return [entry for entry in _items().values() if catalogue is None or entry["catalogue"] == catalogue]


def features() -> dict[str, dict]:
    return load()["features"]


def supporting(feature: str) -> list[str]:
    """IDs of the catalogue items a feature supports."""
    return [entry["id"] for entry in _items().values() if feature in entry["supported_by"]]
