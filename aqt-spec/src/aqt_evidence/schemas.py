"""Packaged JSON Schemas and the record-type registry.

Reading the registry and schemas needs only the standard library. Validating
against a schema needs the optional ``jsonschema`` package
(``pip install "aqt-spec[schema]"``).
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

EXTENSION_PREFIX = "x-"


def data_dir(name: str) -> Path:
    """Packaged data folder (wheel) or the source-tree folder (editable install)."""
    here = Path(__file__).resolve().parent
    packaged = here / "_data" / name
    return packaged if packaged.exists() else here.parents[1] / name


def schema_dir() -> Path:
    return data_dir("schemas")


@lru_cache(maxsize=1)
def registry() -> dict:
    """The record-type registry (``schemas/registry.json``)."""
    return json.loads((schema_dir() / "registry.json").read_text(encoding="utf-8"))


def registered_types() -> list[str]:
    return sorted(registry()["types"])


def is_registered(type_: str) -> bool:
    """True for registered types and for ``x-<org>.<kind>`` extension types."""
    return type_ in registry()["types"] or type_.startswith(EXTENSION_PREFIX)


@lru_cache(maxsize=None)
def load_schema(name: str) -> dict:
    """Load a schema by name: ``envelope``, ``observed``, ``signature``, ``checkpoint``,
    ``thresholds``, ``signers``, ``common`` or a record type such as ``change.receipt``."""
    entry = registry()["types"].get(name)
    path = schema_dir() / (entry["schema"] if entry else f"{name}.schema.json")
    if not path.exists():
        raise KeyError(f"no schema named {name!r}")
    return json.loads(path.read_text(encoding="utf-8"))


def schema_for(type_: str) -> dict | None:
    """The ``data`` schema of a registered record type, or ``None``."""
    return load_schema(type_) if type_ in registry()["types"] else None


@lru_cache(maxsize=1)
def _registry_of_resources():
    try:
        from referencing import Registry, Resource
    except ImportError as error:  # pragma: no cover - depends on the environment
        raise ImportError('schema validation needs jsonschema: pip install "aqt-spec[schema]"') from error
    resources = []
    for path in sorted(schema_dir().rglob("*.schema.json")):
        content = json.loads(path.read_text(encoding="utf-8"))
        resources.append((content["$id"], Resource.from_contents(content)))
    return Registry().with_resources(resources)


def validate_schema(instance: Any, name: str) -> list[str]:
    """Validate ``instance`` against the named schema. Returns problems; empty means valid."""
    try:
        from jsonschema import Draft202012Validator
    except ImportError as error:
        raise ImportError('schema validation needs jsonschema: pip install "aqt-spec[schema]"') from error
    validator = Draft202012Validator(load_schema(name), registry=_registry_of_resources())
    problems = []
    for error in sorted(validator.iter_errors(instance), key=lambda e: list(e.absolute_path)):
        where = "/".join(str(part) for part in error.absolute_path) or "$"
        problems.append(f"{where}: {error.message}")
    return problems


def validate_payload(record: dict) -> list[str]:
    """Validate ``record['data']`` against its type's schema (unregistered types: no check)."""
    type_ = record.get("type")
    if not isinstance(type_, str) or type_ not in registry()["types"]:
        return []
    return [f"data/{problem}" if not problem.startswith("$") else f"data{problem[1:]}"
            for problem in validate_schema(record.get("data", {}), type_)]
