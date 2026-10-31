"""Settings and folders.

User settings: ``$XDG_CONFIG_HOME/aqt/egress.toml``::

    store = "excerpt"        # or "full": also keep headers and bodies in the body store
    retention_days = 90      # full-storage bodies; 7 or more, or "forever"
    excerpt_chars = 512      # length of the masked excerpts in the records
    passthrough = []         # hosts whose TLS is passed through unread (clients that pin certificates)

Command-line flags override them for one session. A project may commit ``.aqt/egress.toml`` with
``require = true``: the session record carries it, so a later status check can warn about agent
sessions that ran outside the box.

Egress state lives in ``$XDG_STATE_HOME/aqt/egress`` (folders 0700, files 0600): the private CA
(``ca/``), the body store (``bodies/``), the fingerprint key, per-session files and the last
session summary. The whole folder is hidden inside the box.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from aqt_evidence import state_dir

STORES = ("excerpt", "full")
MIN_RETENTION_DAYS = 7
DEFAULT_RETENTION_DAYS = 90


class SettingsError(ValueError):
    """A setting has a value outside its range."""


@dataclass
class Settings:
    store: str = "excerpt"
    retention_days: int | None = DEFAULT_RETENTION_DAYS   # None = forever
    excerpt_chars: int = 512
    passthrough: list[str] = field(default_factory=list)
    source: str | None = None                              # the file the values came from

    def retention_text(self) -> str:
        return "forever" if self.retention_days is None else f"{self.retention_days} days"


def config_home() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "aqt"


def settings_file() -> Path:
    return config_home() / "egress.toml"


def egress_state() -> Path:
    return state_dir() / "egress"


def private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def parse_retention(value) -> int | None:
    """``"forever"`` -> None; an integer number of days, at least 7."""
    if isinstance(value, str) and value.strip().lower() == "forever":
        return None
    try:
        days = int(value)
    except (TypeError, ValueError):
        raise SettingsError(f"retention_days must be a number of days or 'forever', not {value!r}") from None
    if isinstance(value, bool) or days < MIN_RETENTION_DAYS:
        raise SettingsError(f"retention_days must be at least {MIN_RETENTION_DAYS} (or 'forever'), not {value!r}")
    return days


def check_store(value) -> str:
    if value not in STORES:
        raise SettingsError(f"store must be one of {', '.join(STORES)}, not {value!r}")
    return value


def check_excerpt(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 4096:
        raise SettingsError(f"excerpt_chars must be a whole number from 0 to 4096, not {value!r}")
    return value


def load_settings(path: Path | None = None) -> Settings:
    path = path or settings_file()
    settings = Settings()
    if not path.exists():
        return settings
    with open(path, "rb") as handle:
        try:
            values = tomllib.load(handle)
        except tomllib.TOMLDecodeError as error:
            raise SettingsError(f"{path}: {error}") from None
    settings.source = str(path)
    if "store" in values:
        settings.store = check_store(values["store"])
    if "retention_days" in values:
        settings.retention_days = parse_retention(values["retention_days"])
    if "excerpt_chars" in values:
        settings.excerpt_chars = check_excerpt(values["excerpt_chars"])
    if "passthrough" in values:
        hosts = values["passthrough"]
        if not isinstance(hosts, list) or not all(isinstance(host, str) for host in hosts):
            raise SettingsError("passthrough must be a list of host names")
        settings.passthrough = [host.lower().rstrip(".") for host in hosts]
    return settings


def project_settings(project: Path) -> dict:
    """``.aqt/egress.toml`` of the project, as far as this stage reads it: ``require``."""
    path = project / ".aqt" / "egress.toml"
    facts = {"path": str(project), "require": False}
    if path.exists():
        with open(path, "rb") as handle:
            try:
                values = tomllib.load(handle)
            except tomllib.TOMLDecodeError as error:
                raise SettingsError(f"{path}: {error}") from None
        facts["require"] = bool(values.get("require", False))
        facts["settings"] = str(path.relative_to(project))
    return facts
