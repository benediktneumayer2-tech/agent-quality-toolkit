"""Paths, configuration and policy.

Config: ``$XDG_CONFIG_HOME/aqt/signoff.toml`` (``AQT_SIGNOFF_CONFIG``).
Registry: ``$XDG_CONFIG_HOME/aqt/signers.json`` (``AQT_SIGNERS``), keys in
``$XDG_CONFIG_HOME/aqt/keys/`` (``AQT_KEYS_DIR``). State (the action index):
``$XDG_STATE_HOME/aqt/signoff/`` (``AQT_SIGNOFF_STATE``). Every path can also be
set by a command-line flag.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from aqt_evidence import MEANINGS

from .errors import UsageError


def config_home(environ=None) -> Path:
    environ = os.environ if environ is None else environ
    return Path(environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "aqt"


def state_home(environ=None) -> Path:
    environ = os.environ if environ is None else environ
    return Path(environ.get("XDG_STATE_HOME") or Path.home() / ".local/state") / "aqt"


@dataclass
class Policy:
    """Who may sign with a meaning, and how many distinct signers are needed."""
    min_signatures: int = 1
    roles: list[str] = field(default_factory=list)
    distinct_from_author: bool = False

    @classmethod
    def from_dict(cls, value: dict, *, default_distinct: bool = False) -> "Policy":
        unknown = set(value) - {"min_signatures", "roles", "distinct_from_author"}
        if unknown:
            raise UsageError(f"unknown policy keys: {', '.join(sorted(unknown))}")
        policy = cls(int(value.get("min_signatures", 1)), list(value.get("roles", [])),
                     bool(value.get("distinct_from_author", default_distinct)))
        if policy.min_signatures < 1:
            raise UsageError("min_signatures must be at least 1")
        return policy

    def as_dict(self) -> dict:
        return {"min_signatures": self.min_signatures, "roles": self.roles,
                "distinct_from_author": self.distinct_from_author}


@dataclass
class Settings:
    config_path: Path
    registry_path: Path
    keys_dir: Path
    state_dir: Path
    sink: str | None = None
    evidence: list[Path] | None = None
    tz: str = "UTC"
    signer: str | None = None
    passphrase_min_length: int = 12
    claim_grace_ms: int = 660_000      # never shorter than run_timeout_ms (see claim_grace)
    run_timeout_ms: int = 600_000
    policies: dict[str, Policy] = field(default_factory=dict)
    action_policy: Policy = field(default_factory=lambda: Policy(1, [], True))

    @property
    def claim_grace(self) -> int:
        """Milliseconds after a claim before it shows ``unknown``: at least ``run_timeout_ms``, so a
        command that ``run`` still executes is never offered for resolution."""
        return max(self.claim_grace_ms, self.run_timeout_ms)

    def policy(self, meaning: str) -> Policy:
        return self.policies.get(meaning, Policy())

    @property
    def db_path(self) -> Path:
        return self.state_dir / "signoff.db"


def load_settings(*, config: str | os.PathLike | None = None, registry=None, keys_dir=None, state_dir=None,
                  sink: str | None = None, evidence: list | None = None, environ=None) -> Settings:
    environ = os.environ if environ is None else environ
    config_path = Path(config or environ.get("AQT_SIGNOFF_CONFIG") or config_home(environ) / "signoff.toml")
    data: dict = {}
    if config_path.exists():
        try:
            data = tomllib.loads(config_path.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
            raise UsageError(f"{config_path}: {error}") from error
    main = data.get("signoff", {})
    paths = data.get("paths", {})

    def pick(flag, env, key, default):
        value = flag or environ.get(env) or paths.get(key)
        return Path(value).expanduser() if value else default

    settings = Settings(
        config_path=config_path,
        registry_path=pick(registry, "AQT_SIGNERS", "registry", config_home(environ) / "signers.json"),
        keys_dir=pick(keys_dir, "AQT_KEYS_DIR", "keys", config_home(environ) / "keys"),
        state_dir=pick(state_dir, "AQT_SIGNOFF_STATE", "state", state_home(environ) / "signoff"),
        sink=sink or paths.get("sink") or None,
        evidence=[Path(p) for p in evidence] if evidence else (
            [Path(p).expanduser() for p in paths["evidence"]] if paths.get("evidence") else None),
        tz=main.get("tz", "UTC"),
        signer=main.get("signer"),
        passphrase_min_length=int(main.get("passphrase_min_length", 12)),
        run_timeout_ms=int(main.get("run_timeout_ms", 600_000)),
    )
    # A shorter configured grace (the old example said 300000) is raised to run_timeout_ms by ``claim_grace``.
    settings.claim_grace_ms = int(main.get("claim_grace_ms", settings.run_timeout_ms + 60_000))
    for meaning, value in data.get("policy", {}).items():
        if meaning not in MEANINGS:
            raise UsageError(f"policy for unknown meaning {meaning!r}")
        settings.policies[meaning] = Policy.from_dict(value)
    if "actions" in data:
        settings.action_policy = Policy.from_dict(data["actions"], default_distinct=True)
    return settings
