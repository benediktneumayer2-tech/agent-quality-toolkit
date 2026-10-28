import os
import shutil
import tempfile
import threading
from pathlib import Path

import pytest

from aqt_cli import checks

PASSPHRASE = "correct-horse-battery-1"
_SESSION_HOME: str | None = None


def pytest_configure(config):
    """Throw-away HOME and XDG dirs for the whole run, so no test can reach the real user's state."""
    global _SESSION_HOME
    _SESSION_HOME = tempfile.mkdtemp(prefix="aqt-home-")
    os.environ["HOME"] = _SESSION_HOME
    for name, sub in (("XDG_STATE_HOME", "state"), ("XDG_CONFIG_HOME", "config")):
        os.environ[name] = os.path.join(_SESSION_HOME, sub)
    os.environ.pop("XDG_RUNTIME_DIR", None)
    os.environ.pop("DBUS_SESSION_BUS_ADDRESS", None)


def pytest_unconfigure(config):
    if _SESSION_HOME:
        shutil.rmtree(_SESSION_HOME, ignore_errors=True)


class FakeSystemd:
    """Stands in for ``systemctl --user``; ``start`` launches a real writer in a thread when asked."""

    def __init__(self):
        self.available = False
        self.enabled = False
        self.calls: list[tuple] = []
        self.on_start = None

    def __call__(self, *args):
        self.calls.append(args)
        if not self.available:
            return 1, "Failed to connect to bus"
        if args[0] == "is-enabled":
            return (0, "enabled") if self.enabled else (1, "disabled")
        if args[:2] == ("enable", "--now"):
            self.enabled = True
        if (args[:2] == ("enable", "--now") or args[0] == "start") and self.on_start:
            self.on_start()
        return 0, ""


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    """Isolated HOME/XDG dirs, a short runtime dir (AF_UNIX path limit), a fixed time zone, no
    AQT_* overrides, and a fake systemctl: the real one is never called."""
    runtime = Path(tempfile.mkdtemp(prefix="aqt", dir="/tmp" if len(str(tmp_path)) > 60 else None))
    (tmp_path / "home").mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    monkeypatch.setenv("TZ", "Europe/Vienna")
    for name in [name for name in os.environ if name.startswith("AQT_")]:
        monkeypatch.delenv(name)
    fake = FakeSystemd()
    monkeypatch.setattr(checks, "systemctl_user", fake)
    yield tmp_path
    shutil.rmtree(runtime, ignore_errors=True)


@pytest.fixture
def systemd():
    return checks.systemctl_user


@pytest.fixture
def start_writer():
    """``start_writer()`` runs the aqt-trail writer of the current (test) environment in a thread."""
    from aqt_trail.config import load_config
    from aqt_trail.server import build_server, start_event
    from aqt_trail.state import open_writer
    running = []

    def start():
        config = load_config()
        writer = open_writer(config)
        server = build_server(config, writer)
        start_event(config, writer)
        threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        running.append((server, writer))

    yield start
    for server, writer in running:
        server.shutdown()
        server.server_close()
        writer.close()


def enrol(signer_id="human:alice", name="Alice Example", role="quality-manager"):
    """Enrol a signer through aqt-signoff's API with a fixed passphrase (the CLI would prompt)."""
    from aqt_signoff import Signoff, StaticPassphrase, load_settings
    Signoff(load_settings(), authenticator=StaticPassphrase(PASSPHRASE), environ={}, chain=[],
            require_tty=False).init_signer(signer_id, name, role)


def by_id(results):
    return {result.id: result for result in results}
