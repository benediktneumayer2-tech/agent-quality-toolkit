"""aqt-capa: deviations and CAPA for AI coding agent work (Agent Quality Toolkit)."""

from .capa import Blocked, Capa, CapaError, Refused
from .config import Config, load_config
from .store import Store
from .trends import render_markdown, trends

__version__ = "0.1.0"

__all__ = ["Blocked", "Capa", "CapaError", "Config", "Refused", "Store", "load_config", "render_markdown", "trends"]
