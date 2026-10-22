"""View adapters: thin wrappers around the package APIs, one module per view.

Each adapter imports its package lazily, so a missing package only disables its view.
"""

from __future__ import annotations

import importlib.util


class ViewProblem(Exception):
    status = 400


class UsageProblem(ViewProblem):
    status = 400


class NotFound(ViewProblem):
    status = 404


class Stale(ViewProblem):
    """The decision does not match the current state shown to the person (nothing was signed)."""
    status = 409


class NotInstalled(ViewProblem):
    status = 501

    def __init__(self, package: str):
        super().__init__(f"{package} is not installed: uv pip install -e {package}  (or pip install {package})")
        self.package = package


def installed(module: str) -> bool:
    return importlib.util.find_spec(module) is not None


def require(module: str, package: str) -> None:
    if not installed(module):
        raise NotInstalled(package)
