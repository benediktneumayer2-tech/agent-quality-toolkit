"""Configuration: one TOML file, XDG paths, every path overridable."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from aqt_evidence import state_dir

DEFAULT_DUE_DAYS = {"critical": 2, "major": 7, "minor": 30}


def config_dir() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "aqt"


@dataclass
class Config:
    identity_id: str = "human:local"
    identity_role: str | None = None
    identity_display: str | None = None
    evidence_paths: list[Path] | None = None      # None = aqt_evidence.evidence_sources()
    project_root: Path = field(default_factory=Path.cwd)
    project_id: str | None = None
    repos: list[Path] = field(default_factory=list)
    disabled_rules: list[str] = field(default_factory=list)
    agent_commit_patterns: list[str] = field(default_factory=list)  # empty = every revert counts
    due_days: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_DUE_DAYS))
    similarity_threshold_ppm: int = 300_000
    allow_self_approval: bool = False
    tz: str | None = None
    db_path: Path = field(default_factory=lambda: state_dir() / "capa" / "capa.db")


def _paths(values, base: Path) -> list[Path]:
    return [(base / Path(v).expanduser()) if not Path(v).expanduser().is_absolute() else Path(v).expanduser()
            for v in values]


def load_config(path: str | os.PathLike | None = None) -> Config:
    """Read ``path`` or ``$XDG_CONFIG_HOME/aqt/capa.toml``; a missing default file means defaults."""
    explicit = path is not None
    path = Path(path) if path else config_dir() / "capa.toml"
    data: dict = {}
    if path.exists():
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    elif explicit:
        raise FileNotFoundError(f"config file {path} not found")
    base = path.parent if path.exists() else Path.cwd()
    cfg = Config()
    ident = data.get("identity", {})
    cfg.identity_id = ident.get("id", cfg.identity_id)
    cfg.identity_role = ident.get("role")
    cfg.identity_display = ident.get("display")
    cfg.tz = ident.get("tz") or os.environ.get("TZ") or None
    if "paths" in data.get("evidence", {}):
        cfg.evidence_paths = _paths(data["evidence"]["paths"], base)
    project = data.get("project", {})
    if "root" in project:
        cfg.project_root = _paths([project["root"]], base)[0]
    cfg.project_id = project.get("id")
    scan = data.get("scan", {})
    cfg.repos = _paths(scan.get("repos", []), base)
    cfg.disabled_rules = list(scan.get("disabled_rules", []))
    cfg.agent_commit_patterns = list(scan.get("agent_commit_patterns", []))
    cfg.due_days.update(data.get("due_days", {}))
    cfg.similarity_threshold_ppm = int(data.get("similarity", {}).get("threshold_ppm", cfg.similarity_threshold_ppm))
    cfg.allow_self_approval = bool(data.get("approval", {}).get("allow_self_approval", False))
    if os.environ.get("AQT_CAPA_DB"):
        cfg.db_path = Path(os.environ["AQT_CAPA_DB"])
    elif "db" in data.get("state", {}):
        cfg.db_path = _paths([data["state"]["db"]], base)[0]
    return cfg
