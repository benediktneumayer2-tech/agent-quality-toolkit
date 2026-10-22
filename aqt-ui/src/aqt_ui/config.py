"""Configuration: ``$XDG_CONFIG_HOME/aqt/ui.toml`` (or ``AQT_UI_CONFIG``). Every key is optional.

```toml
port = 0                  # 0 picks a free port at each start
open_browser = true
review_due_days = 7       # "Needs you": no trail review for this many days
qualification_warn_days = 30

[changes]
projects = ["~/code/my-project"]   # repository roots whose aqt-change ledgers to show
```

Everything else comes from the other tools' own configuration and environment variables
(``AQT_SINK``, ``AQT_EVIDENCE``, ``AQT_TRAIL_STATE``, ...), so the UI sees what the CLIs see.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


def config_home() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "aqt"


@dataclass
class UiConfig:
    path: Path | None = None
    port: int = 0
    open_browser: bool = True
    review_due_days: int = 7
    qualification_warn_days: int = 30
    projects: list[Path] = field(default_factory=list)


def load_config(path: str | os.PathLike | None = None) -> UiConfig:
    path = path or os.environ.get("AQT_UI_CONFIG")
    candidate = Path(path).expanduser() if path else config_home() / "ui.toml"
    if not candidate.exists():
        if path:
            raise FileNotFoundError(f"config file {candidate} not found")
        return UiConfig()
    with open(candidate, "rb") as handle:
        doc = tomllib.load(handle)
    config = UiConfig(path=candidate)
    for key in ("port", "review_due_days", "qualification_warn_days"):
        if key in doc:
            setattr(config, key, int(doc[key]))
    if "open_browser" in doc:
        config.open_browser = bool(doc["open_browser"])
    projects = (doc.get("changes") or {}).get("projects") or []
    config.projects = [Path(str(item)).expanduser() for item in projects]
    return config
