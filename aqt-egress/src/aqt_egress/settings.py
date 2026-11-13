"""Settings and folders.

User settings: ``$XDG_CONFIG_HOME/aqt/egress.toml``::

    store = "excerpt"        # or "full": also keep headers and bodies in the body store
    retention_days = 90      # full-storage bodies; 7 or more, or "forever"
    excerpt_chars = 280      # length of the masked excerpts in the records (0: none)
    passthrough = []         # hosts whose TLS is passed through unread (clients that pin certificates)
    llm_hosts = []           # more LLM API hosts (besides the built-in list): no text excerpts, only structure
    local_endpoints = []     # inference servers on this host the box may reach, e.g. ["127.0.0.1:8080"]

Command-line flags override them for one session. A project may commit ``.aqt/egress.toml`` with
``require = true``: the session record carries it, so a later status check can warn about agent
sessions that ran outside the box.

Egress state lives in ``$XDG_STATE_HOME/aqt/egress`` (folders 0700, files 0600): the private CA
(``ca/``), the body store (``bodies/``), the fingerprint key, per-session files and the last
session summary. The whole folder is hidden inside the box.
"""

from __future__ import annotations

import ipaddress
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from aqt_evidence import platform, state_dir

STORES = ("excerpt", "full")
RESERVED_PORTS = (53, 80, 443, 3128, 15001)       # the box's own listeners (netns)
MIN_RETENTION_DAYS = 7
DEFAULT_RETENTION_DAYS = 90


class SettingsError(ValueError):
    """A setting has a value outside its range."""


@dataclass
class Settings:
    store: str = "excerpt"
    retention_days: int | None = DEFAULT_RETENTION_DAYS   # None = forever
    excerpt_chars: int = 280
    passthrough: list[str] = field(default_factory=list)
    llm_hosts: list[str] = field(default_factory=list)
    local_endpoints: list[tuple[str, int]] = field(default_factory=list)
    source: str | None = None                              # the file the values came from

    def retention_text(self) -> str:
        return "forever" if self.retention_days is None else f"{self.retention_days} days"


def config_home() -> Path:
    return platform.config_dir()


def settings_file() -> Path:
    return config_home() / "egress.toml"


def egress_state() -> Path:
    return state_dir() / "egress"


def private_dir(path: Path) -> Path:
    return platform.ensure_private_dir(path)


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


def parse_endpoint(text: str) -> tuple[str, int]:
    """``127.0.0.1:8080``, ``localhost:11434`` or ``[::1]:8080`` -> (loopback address, port).

    Only the host's own loopback: other addresses are reached through the proxy anyway."""
    if not isinstance(text, str):
        raise SettingsError(f"a local endpoint is host:port, not {text!r}")
    host, sep, port = text.strip().rpartition(":")
    host = host.strip("[]").lower()
    if host == "localhost":
        host = "127.0.0.1"
    try:
        address = ipaddress.ip_address(host)
        number = int(port)
    except ValueError:
        raise SettingsError(f"a local endpoint is host:port with a loopback address, not {text!r}") from None
    if not sep or not address.is_loopback or not 0 < number < 65536:
        raise SettingsError(f"a local endpoint is host:port with a loopback address, not {text!r}")
    if number in RESERVED_PORTS:
        raise SettingsError(f"port {number} is one of the box's own listeners ({', '.join(map(str, RESERVED_PORTS))})")
    return str(address), number


def _hosts(values, name: str) -> list[str]:
    if not isinstance(values, list) or not all(isinstance(host, str) for host in values):
        raise SettingsError(f"{name} must be a list of host names")
    return [host.lower().rstrip(".") for host in values]


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
        settings.passthrough = _hosts(values["passthrough"], "passthrough")
    if "llm_hosts" in values:
        settings.llm_hosts = _hosts(values["llm_hosts"], "llm_hosts")
    if "local_endpoints" in values:
        if not isinstance(values["local_endpoints"], list):
            raise SettingsError("local_endpoints must be a list of host:port")
        settings.local_endpoints = [parse_endpoint(item) for item in values["local_endpoints"]]
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
