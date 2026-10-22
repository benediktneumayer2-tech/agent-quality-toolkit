"""Configuration, actors, sinks and evidence lookup."""

from __future__ import annotations

import getpass
import os
import tomllib
from pathlib import Path

from aqt_evidence import actor, detect_agent_context, evidence_sources, iter_evidence, open_sink, state_dir

TOOL = "aqt-validate"


def config_path() -> Path:
    if os.environ.get("AQT_VALIDATE_CONFIG"):
        return Path(os.environ["AQT_VALIDATE_CONFIG"])
    base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "aqt" / "validate.toml"


def load_config(path: str | Path | None = None) -> dict:
    """``actor`` (e.g. ``human:alice``), ``sink``, ``state_dir``, ``evidence`` (list of paths)."""
    path = Path(path) if path else config_path()
    config: dict = {}
    if path.exists():
        with open(path, "rb") as handle:
            config = tomllib.load(handle)
    return config


def validate_state_dir(config: dict, override: str | None = None) -> Path:
    value = override or os.environ.get("AQT_VALIDATE_STATE") or config.get("state_dir")
    return Path(value).expanduser() if value else state_dir() / "validate"


def sink_spec(config: dict, override: str | None = None) -> str | None:
    return override or os.environ.get("AQT_SINK") or config.get("sink")


def get_sink(config: dict, override: str | None = None):
    return open_sink(sink_spec(config, override))


def human_id(config: dict) -> str:
    value = os.environ.get("AQT_ACTOR") or config.get("actor")
    if value:
        return value if value.startswith("human:") else f"human:{value}"
    return f"human:{getpass.getuser()}"


def invoking_actor(config: dict, *, environ: dict | None = None, chain: list[str] | None = None) -> dict:
    """The actor that runs a command: an agent when agent markers are present, else the human."""
    context = detect_agent_context(environ, chain=chain)
    if context.is_agent:
        env = os.environ if environ is None else environ
        session = env.get("AQT_AGENT_SESSION") or env.get("CODEX_THREAD_ID") or "unknown"
        return actor("agent", f"agent:{context.harness}:{session}", harness=context.harness, session=session)
    return actor("human", human_id(config))


def evidence_paths(config: dict, explicit: list[str] | None = None, sink_override: str | None = None) -> list[Path]:
    if explicit:
        return [Path(p) for p in explicit]
    paths = [Path(p).expanduser() for p in config.get("evidence", [])] or evidence_sources()
    spec = sink_spec(config, sink_override)
    if spec and spec.startswith("file:"):
        sink_file = Path(spec[5:])
        if sink_file.exists() and sink_file not in paths:
            paths.append(sink_file)
    return [p for p in paths if p.exists()]


def records(config: dict, explicit: list[str] | None = None, sink_override: str | None = None) -> list[dict]:
    paths = evidence_paths(config, explicit, sink_override)
    return [r for r in iter_evidence(paths) if isinstance(r, dict)] if paths else []
