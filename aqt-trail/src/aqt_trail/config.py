"""Paths and configuration.

State lives in ``$AQT_TRAIL_STATE`` or ``$XDG_STATE_HOME/aqt/trail``; the
configuration file is ``$XDG_CONFIG_HOME/aqt/trail.toml``. Every value has a
default, so the tool works without a configuration file.
"""

from __future__ import annotations

import copy
import json
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from aqt_evidence import spool_file
from aqt_evidence import state_dir as aqt_state_dir

DEFAULTS: dict = {
    "writer": {
        "socket": "",              # default: $XDG_RUNTIME_DIR/aqt/trail.sock, else <state>/aqt-trail.sock
        "socket_mode": "0600",     # separate-user mode: "0660" with socket_group
        "socket_group": "",
        "log_mode": "0600",        # separate-user mode: "0640" (group may read and verify, never write)
        "allowed_uids": [],        # empty: only the uid the writer runs as
        "clock_jump_ms": 2000,
        "drain_interval_s": 30,
        "max_request_bytes": 16 * 1024 * 1024,
    },
    # test_tsa: trust the built-in TEST ONLY authority (demos and tests): its CA in verify, its anchors in
    # status, review and ALCOA++. Otherwise its anchors never count, whoever asked the writer for them.
    "anchor": {"tsa_url": "", "tsa_ca": "", "timeout_s": 10, "test_tsa": False},
    "import": {"excerpt_chars": 160},
    "review": {
        "timezone": "UTC",
        "work_start": "07:00",
        "work_end": "19:00",
        "workdays": [1, 2, 3, 4, 5],        # ISO weekdays
        "repeated_failures": 3,
        "failure_window_min": 60,
        "skew_ms": 5000,
        "unanchored_hours": 24,
        "actor_change_window_min": 60,
    },
}


def config_dir() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "aqt"


def default_state() -> Path:
    env = os.environ.get("AQT_TRAIL_STATE")
    return Path(env) if env else aqt_state_dir() / "trail"


def spool_path() -> Path:
    """The shared client spool (aqt-spec spec §10.4), the same file ``aqt_evidence.SocketSink`` uses."""
    return spool_file()


def _merge(base: dict, extra: dict) -> dict:
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = value
    return base


@dataclass
class Config:
    state: Path
    values: dict = field(default_factory=lambda: copy.deepcopy(DEFAULTS))

    def section(self, name: str) -> dict:
        return self.values[name]

    @property
    def trail_path(self) -> Path:
        return self.state / "trail.jsonl"

    @property
    def checkpoints_path(self) -> Path:
        return self.state / "checkpoints.jsonl"

    @property
    def key_path(self) -> Path:
        return self.state / "keys" / "service.key"

    @property
    def meta_path(self) -> Path:
        return self.state / "trail.json"

    @property
    def socket_path(self) -> Path:
        configured = self.values["writer"].get("socket")
        if configured:
            return Path(configured)
        sink = os.environ.get("AQT_SINK", "")
        if sink.startswith("unix:"):
            return Path(sink[5:])
        runtime = os.environ.get("XDG_RUNTIME_DIR")
        if runtime:
            return Path(runtime) / "aqt" / "trail.sock"
        return self.state / "aqt-trail.sock"

    def meta(self) -> dict:
        return json.loads(self.meta_path.read_text())


def load_config(path: str | os.PathLike | None = None, *, state: str | os.PathLike | None = None) -> Config:
    values = copy.deepcopy(DEFAULTS)
    candidate = Path(path) if path else config_dir() / "trail.toml"
    if candidate.exists():
        with open(candidate, "rb") as handle:
            _merge(values, tomllib.load(handle))
    elif path:
        raise FileNotFoundError(f"config file {candidate} not found")
    configured_state = values.get("trail", {}).get("state") if isinstance(values.get("trail"), dict) else None
    chosen = Path(state) if state else (Path(configured_state) if configured_state else default_state())
    return Config(chosen, values)
