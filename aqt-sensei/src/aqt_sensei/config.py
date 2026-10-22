"""Paths, configuration and the owner token.

Every path follows XDG and can be overridden by environment variables, so tests
and several installations never collide:

- ``AQT_SENSEI_CONFIG``  config file (default ``$XDG_CONFIG_HOME/aqt/sensei.toml``)
- ``AQT_SENSEI_STATE``   state folder (default ``$XDG_STATE_HOME/aqt/sensei``)
- ``AQT_SENSEI_RUNTIME`` sockets and pane state (default ``$XDG_RUNTIME_DIR/aqt-sensei``)
- ``AQT_SENSEI_TOKEN``   owner token file (default ``$XDG_CONFIG_HOME/aqt/sensei/owner.token``)
"""

from __future__ import annotations

import os
import secrets
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

MODES = ("manual", "confirm", "auto")
BACKENDS = ("tmux", "herdr", "fake")
PATH_ENV = ("AQT_SENSEI_CONFIG", "AQT_SENSEI_STATE", "AQT_SENSEI_RUNTIME", "AQT_SENSEI_TOKEN")


def _xdg(name: str, default: str) -> Path:
    return Path(os.environ.get(name) or Path.home() / default)


@dataclass
class Paths:
    config_file: Path
    token_file: Path
    state: Path
    runtime: Path

    @classmethod
    def default(cls) -> "Paths":
        config = _xdg("XDG_CONFIG_HOME", ".config") / "aqt"
        state = Path(os.environ.get("AQT_SENSEI_STATE") or _xdg("XDG_STATE_HOME", ".local/state") / "aqt" / "sensei")
        runtime_base = os.environ.get("XDG_RUNTIME_DIR")
        runtime = Path(os.environ.get("AQT_SENSEI_RUNTIME")
                       or (Path(runtime_base) / "aqt-sensei" if runtime_base else state / "run"))
        return cls(
            config_file=Path(os.environ.get("AQT_SENSEI_CONFIG") or config / "sensei.toml"),
            token_file=Path(os.environ.get("AQT_SENSEI_TOKEN") or config / "sensei" / "owner.token"),
            state=state, runtime=runtime)

    # sockets and folders
    @property
    def owner_socket(self) -> Path:
        return self.runtime / "owner.sock"

    @property
    def agent_socket(self) -> Path:
        return self.runtime / "agent.sock"

    def pair_runtime(self, pair_id: str) -> Path:
        return self.runtime / "pairs" / pair_id

    def advisor_socket(self, pair_id: str) -> Path:
        return self.pair_runtime(pair_id) / "advisor.sock"

    @property
    def pane_state(self) -> Path:
        return self.runtime / "panes"

    def home(self, platform: str) -> Path:
        """The private agent home of one advisor platform (never the owner's)."""
        return self.state / "homes" / platform

    def env(self) -> dict:
        """Environment that lets a child process (the launcher) find the same paths."""
        return {"AQT_SENSEI_CONFIG": str(self.config_file), "AQT_SENSEI_STATE": str(self.state),
                "AQT_SENSEI_RUNTIME": str(self.runtime), "AQT_SENSEI_TOKEN": str(self.token_file)}

    def ensure(self) -> None:
        for folder in (self.state, self.runtime, self.runtime / "pairs", self.pane_state):
            folder.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(folder, 0o700)


@dataclass
class Budget:
    max_messages: int | None = None
    max_exchanges: int | None = None
    max_cost: int | None = None

    def as_dict(self) -> dict:
        return {"max_messages": self.max_messages, "max_exchanges": self.max_exchanges,
                "max_cost": self.max_cost}


@dataclass
class Config:
    owner_id: str = "owner"
    owner_display: str | None = None
    backend: str | None = None            # None: tmux if $TMUX is set, Herdr if $HERDR_ENV, else tmux
    tmux_socket: str | None = None        # tmux -L NAME (None: the default server)
    poll_seconds: float = 1.5
    quiet_seconds: float = 3.0
    default_mode: str = "confirm"
    auto_budget: Budget = field(default_factory=lambda: Budget(max_exchanges=8))
    sink: str | None = None               # AQT_SINK syntax; None: AQT_SINK or the default file
    bwrap: str = "bwrap"
    network: str = "share"
    env_allow: list[str] = field(default_factory=list)
    extra_ro_binds: list[str] = field(default_factory=list)
    scratch_root: str = ".sensei"         # relative to the project, or absolute
    profiles: dict = field(default_factory=dict)  # overrides and custom profiles

    @property
    def owner_actor_id(self) -> str:
        return self.owner_id if self.owner_id.startswith("human:") else f"human:{self.owner_id}"


def load_config(path: Path | None = None) -> Config:
    path = path or Paths.default().config_file
    if not path.exists():
        return Config()
    data = tomllib.loads(path.read_text())
    config = Config()
    owner = data.get("owner", {})
    config.owner_id = owner.get("id", config.owner_id)
    config.owner_display = owner.get("display", config.owner_display)
    bridge = data.get("bridge", {})
    config.backend = bridge.get("backend", config.backend)
    config.tmux_socket = bridge.get("tmux_socket", config.tmux_socket)
    config.poll_seconds = float(bridge.get("poll_seconds", config.poll_seconds))
    config.quiet_seconds = float(bridge.get("quiet_seconds", config.quiet_seconds))
    config.default_mode = bridge.get("default_mode", config.default_mode)
    config.sink = bridge.get("sink", config.sink)
    auto = bridge.get("auto_budget")
    if isinstance(auto, dict):
        config.auto_budget = Budget(auto.get("max_messages"), auto.get("max_exchanges"), auto.get("max_cost"))
    sandbox = data.get("sandbox", {})
    config.bwrap = sandbox.get("bwrap", config.bwrap)
    config.network = sandbox.get("network", config.network)
    config.env_allow = list(sandbox.get("env_allow", config.env_allow))
    config.extra_ro_binds = list(sandbox.get("extra_ro_binds", config.extra_ro_binds))
    config.scratch_root = sandbox.get("scratch_root", config.scratch_root)
    config.profiles = dict(data.get("profiles", {}))
    if config.default_mode not in MODES:
        raise ValueError(f"default_mode must be one of {', '.join(MODES)}")
    if config.network not in ("share", "none"):
        raise ValueError("sandbox.network must be share or none")
    return config


def create_token(path: Path) -> bool:
    """Create the owner token (0600) if it does not exist; True if created."""
    if path.exists():
        return False
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(secrets.token_hex(32) + "\n")
    return True


def read_token(path: Path) -> str | None:
    try:
        return path.read_text().strip() or None
    except OSError:
        return None


EXAMPLE_CONFIG = """\
# aqt-sensei configuration ($XDG_CONFIG_HOME/aqt/sensei.toml)

[owner]
id = "owner"              # recorded as human:<id>
# display = "Your Name"

[bridge]
# backend = "tmux"        # tmux | herdr (default: tmux inside tmux, herdr inside Herdr)
# tmux_socket = "work"    # tmux -L NAME
poll_seconds = 1.5
quiet_seconds = 3.0       # tmux without hooks: pane unchanged this long and a prompt visible
default_mode = "confirm"  # manual | confirm | auto
# sink = "file:/path/evidence.jsonl"   # or unix:/path/trail.sock; default AQT_SINK or the AQT default file

[bridge.auto_budget]      # applied when a pair starts in auto mode without explicit limits
max_exchanges = 8

[sandbox]
bwrap = "bwrap"
network = "share"         # share (model API and web search) | none
env_allow = []            # e.g. ["ANTHROPIC_API_KEY"] for a pi advisor; the advisor can read these
extra_ro_binds = []       # e.g. ["~/.agents/skills"]
scratch_root = ".sensei"  # scratch folders: <project>/.sensei/<pair>/

# Override a built-in profile or add a custom one:
# [profiles.myagent]
# command = ["myagent", "--system-prompt-file", "{prompt_file}"]
# prompt = "file"          # file | agents-md
# env = {}
# ro_binds = []
# prompt_pattern = "^> "
# cost_per_exchange = 0    # integer minor units, declared estimate
"""
