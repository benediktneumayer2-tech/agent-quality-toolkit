"""Configuration: ``$XDG_CONFIG_HOME/aqt/quarantine.toml`` (or ``AQT_QUARANTINE_CONFIG`` / ``--config``).

Every path can be overridden by flag or environment variable:
``AQT_QUARANTINE_STATE`` (state dir), ``AQT_SIGNERS`` (signer registry),
``AQT_KEYS_DIR`` (key directory), ``AQT_SINK`` (evidence sink, see aqt-spec).
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from aqt_evidence import state_dir as aqt_state_dir

DEFAULT_METADATA_KEYS = ("url", "query", "tool_use_id", "codeText", "type", "mimeType", "uri", "id", "name")


def config_home() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "aqt"


@dataclass
class Config:
    path: Path | None = None
    state_dir: Path = field(default_factory=lambda: aqt_state_dir() / "quarantine")
    registry: Path = field(default_factory=lambda: config_home() / "signers.json")
    keys_dir: Path = field(default_factory=lambda: config_home() / "keys")
    sink: str | None = None
    thresholds: str | None = None
    tz: str | None = None
    detectors: list[dict] = field(default_factory=lambda: [{"kind": "heuristics"}])
    max_scan_chars: int = 2_000_000
    record_passes: bool = True
    trusted_source_policy: str = "downgrade"     # or "pass"
    require_signed_decisions: bool = True
    responsible: list[str] = field(default_factory=list)  # signer ids allowed to decide; empty = all registered
    # Claude Code adapter
    tools: list[str] = field(default_factory=lambda: ["WebFetch", "WebSearch", "mcp__.*"])
    metadata_keys: tuple[str, ...] = DEFAULT_METADATA_KEYS
    wrap_min_chars: int = 80
    deliver_max_chars: int = 9000


def _path(value, default: Path) -> Path:
    return Path(value).expanduser() if value else default


def load_config(path: str | os.PathLike | None = None, *, state_dir: str | None = None) -> Config:
    path = path or os.environ.get("AQT_QUARANTINE_CONFIG")
    candidate = Path(path).expanduser() if path else config_home() / "quarantine.toml"
    doc: dict = {}
    if candidate.exists():
        with open(candidate, "rb") as handle:
            doc = tomllib.load(handle)
    elif path:
        raise FileNotFoundError(f"config file {candidate} not found")
    paths = doc.get("paths", {})
    policy = doc.get("policy", {})
    claude = doc.get("claude_code", {})
    config = Config(path=candidate if candidate.exists() else None)
    config.state_dir = _path(state_dir or os.environ.get("AQT_QUARANTINE_STATE") or paths.get("state_dir"),
                             config.state_dir)
    config.registry = _path(os.environ.get("AQT_SIGNERS") or paths.get("registry"), config.registry)
    config.keys_dir = _path(os.environ.get("AQT_KEYS_DIR") or paths.get("keys"), config.keys_dir)
    config.sink = os.environ.get("AQT_SINK") or paths.get("sink") or None
    config.thresholds = os.environ.get("AQT_QUARANTINE_THRESHOLDS") or paths.get("thresholds") or None
    config.tz = doc.get("tz") or os.environ.get("TZ") or None
    if doc.get("detectors"):
        config.detectors = [dict(item) for item in doc["detectors"]]
    for key in ("max_scan_chars", "record_passes", "trusted_source_policy", "require_signed_decisions",
                "responsible"):
        if key in policy:
            setattr(config, key, policy[key])
    if config.trusted_source_policy not in ("downgrade", "pass"):
        raise ValueError("policy.trusted_source_policy must be 'downgrade' or 'pass'")
    for key in ("tools", "wrap_min_chars", "deliver_max_chars"):
        if key in claude:
            setattr(config, key, claude[key])
    if "metadata_keys" in claude:
        config.metadata_keys = tuple(claude["metadata_keys"])
    return config
