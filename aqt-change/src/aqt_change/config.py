"""User configuration: ``$XDG_CONFIG_HOME/aqt/change.toml`` (or ``AQT_CHANGE_CONFIG``).

Project settings: ``.aqt/change.toml`` in the repository, committed with the code, so the agent's
environment cannot switch them off (``Ledger.project_settings()``): ``require_trail``, ``trail_keys``,
``fingerprint_exclude`` and a ``[gate]`` table. The user configuration is within the agent's reach, so its
loosening settings count less: its ``fingerprint_exclude`` leaves out only untracked files outside the plan's
paths, and a path admitted only by its ``always_allowed_paths`` gives MANUAL.
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from aqt_evidence import content_hash

from .errors import usage

PROJECT_FILE = ".aqt/change.toml"
INDEPENDENCE = ("same-session", "fresh-context", "different-model", "human")
LIFECYCLE_OWNERS = ("aqt-change", "external")
PROJECT_GATE_KEYS = ("require_signed_approval", "min_review_independence", "warnings_block", "always_allowed_paths")
KEY_ID_RE = re.compile(r"^ed25519:[0-9a-f]{16}$")


@dataclass
class GatePolicy:
    require_signed_approval: bool = False
    min_review_independence: str = "none"
    warnings_block: bool = False
    always_allowed_paths: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"require_signed_approval": self.require_signed_approval,
                "min_review_independence": self.min_review_independence,
                "warnings_block": self.warnings_block,
                "always_allowed_paths": list(self.always_allowed_paths)}

    def sha256(self) -> str:
        return content_hash(self.as_dict())


@dataclass
class Config:
    actor: str | None = None
    excerpt_lines: int = 20
    timeout_seconds: int = 1800
    fingerprint_exclude: list[str] = field(default_factory=list)
    lifecycle_owner: str = "aqt-change"
    gate: GatePolicy = field(default_factory=GatePolicy)
    source: str | None = None


def config_path() -> Path:
    if os.environ.get("AQT_CHANGE_CONFIG"):
        return Path(os.environ["AQT_CHANGE_CONFIG"])
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "aqt" / "change.toml"


def load_config(path: str | os.PathLike | None = None) -> Config:
    target = Path(path) if path else config_path()
    if not target.exists():
        return Config()
    try:
        raw = tomllib.loads(target.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise usage("config_invalid", f"cannot read config {target}: {error}") from error
    gate_raw = raw.get("gate", {}) or {}
    gate = GatePolicy(
        require_signed_approval=bool(gate_raw.get("require_signed_approval", False)),
        min_review_independence=str(gate_raw.get("min_review_independence", "none")),
        warnings_block=bool(gate_raw.get("warnings_block", False)),
        always_allowed_paths=[str(p) for p in gate_raw.get("always_allowed_paths", [])],
    )
    if gate.min_review_independence not in ("none", *INDEPENDENCE):
        raise usage("config_invalid", "gate.min_review_independence must be none or an independence class")
    config = Config(
        actor=raw.get("actor"),
        excerpt_lines=int(raw.get("excerpt_lines", 20)),
        timeout_seconds=int(raw.get("timeout_seconds", 1800)),
        fingerprint_exclude=[str(p) for p in raw.get("fingerprint_exclude", [])],
        lifecycle_owner=str(raw.get("lifecycle_owner", "aqt-change")),
        gate=gate,
        source=str(target),
    )
    if config.lifecycle_owner not in LIFECYCLE_OWNERS:
        raise usage("config_invalid", "lifecycle_owner must be 'aqt-change' or 'external'")
    return config


def parse_project_settings(text: str, where: str) -> dict:
    """The settings in one copy of ``.aqt/change.toml``: ``{"require_trail": bool, "trail_keys": [key id, ...],
    "fingerprint_exclude": [glob, ...], "gate": {key: value}}`` (``gate`` holds only the keys the copy sets). ``where`` names the copy in error
    messages. A copy that cannot be read, or has an unknown key, refuses (it must not count as "no settings")."""
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise usage("config_invalid", f"cannot read project settings {where}: {error}") from error

    def invalid(message: str):
        return usage("config_invalid", f"project settings {where}: {message}")

    unknown = sorted(set(raw) - {"require_trail", "trail_keys", "fingerprint_exclude", "gate"})
    if unknown:
        raise invalid(f"unknown key(s) {', '.join(unknown)}")
    value = raw.get("require_trail", False)
    if not isinstance(value, bool):
        raise invalid("require_trail must be true or false")
    keys = raw.get("trail_keys", [])
    if not isinstance(keys, list) or not all(isinstance(k, str) and KEY_ID_RE.match(k) for k in keys):
        raise invalid('trail_keys must be a list of service key ids such as "ed25519:0123456789abcdef"')
    globs = raw.get("fingerprint_exclude", [])
    if not isinstance(globs, list) or not all(isinstance(g, str) and g for g in globs):
        raise invalid("fingerprint_exclude must be a list of globs")
    gate = raw.get("gate", {})
    if not isinstance(gate, dict):
        raise invalid("gate must be a table")
    unknown = sorted(set(gate) - set(PROJECT_GATE_KEYS))
    if unknown:
        raise invalid(f"unknown gate key(s) {', '.join(unknown)} (allowed: {', '.join(PROJECT_GATE_KEYS)})")
    for name in ("require_signed_approval", "warnings_block"):
        if name in gate and not isinstance(gate[name], bool):
            raise invalid(f"gate.{name} must be true or false")
    if "min_review_independence" in gate and gate["min_review_independence"] not in ("none", *INDEPENDENCE):
        raise invalid("gate.min_review_independence must be none or an independence class")
    allowed = gate.get("always_allowed_paths", [])
    if not isinstance(allowed, list) or not all(isinstance(g, str) and g for g in allowed):
        raise invalid("gate.always_allowed_paths must be a list of globs")
    return {"require_trail": value, "trail_keys": sorted(set(keys)), "fingerprint_exclude": list(globs),
            "gate": dict(gate)}
