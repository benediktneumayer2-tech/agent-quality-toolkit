"""Shared fixtures: isolated paths, a fake terminal host, a fake /proc tree.

Sockets need short paths (AF_UNIX allows about 107 bytes), so runtime folders
live in a short temporary folder rather than under pytest's tmp_path.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

import pytest

from aqt_evidence import read_jsonl
from aqt_sensei.bridge import Bridge
from aqt_sensei.config import Config, Paths, create_token
from aqt_sensei.hosts import FakeHost
from aqt_sensei.ledger import Ledger

WORKER_PID = 4100
ADVISOR_PID = 4200


class Clock:
    def __init__(self, start: float = 1_800_000_000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeProc:
    """A /proc tree: proc/<pid>/{status,stat,environ,fd/0}."""

    def __init__(self, root: Path):
        self.root = root

    def add(self, pid: int, name: str, ppid: int, *, env: dict | None = None, tty: str | None = None) -> int:
        folder = self.root / str(pid)
        (folder / "fd").mkdir(parents=True, exist_ok=True)
        (folder / "status").write_text(f"Name:\t{name}\nPPid:\t{ppid}\nUid:\t1000\n")
        (folder / "stat").write_text(f"{pid} ({name}) S {ppid} " + " ".join(["0"] * 17) + " 12345 0\n")
        (folder / "environ").write_bytes(b"\0".join(f"{k}={v}".encode() for k, v in (env or {}).items()))
        link = folder / "fd" / "0"
        if link.is_symlink():
            link.unlink()
        os.symlink(tty or "pipe:[1]", link)
        return pid


@pytest.fixture(autouse=True)
def isolated_xdg(tmp_path_factory, monkeypatch):
    """INTERFACES I13: never touch the real ~/.local/state/aqt or ~/.config/aqt."""
    base = tmp_path_factory.mktemp("xdg")
    for name in ("XDG_STATE_HOME", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(name, str(base / name.lower()))
    runtime = Path(tempfile.mkdtemp(prefix="aqx", dir="/tmp"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    for name in ("AQT_SINK", "AQT_EVIDENCE", "AQT_SENSEI_CONFIG", "AQT_SENSEI_STATE", "AQT_SENSEI_RUNTIME",
                 "AQT_SENSEI_TOKEN", "AQT_SENSEI_SOCKET"):
        monkeypatch.delenv(name, raising=False)
    yield
    shutil.rmtree(runtime, ignore_errors=True)


@pytest.fixture
def short_dir():
    folder = Path(tempfile.mkdtemp(prefix="aqs", dir="/tmp"))
    yield folder
    shutil.rmtree(folder, ignore_errors=True)


@pytest.fixture
def paths(tmp_path, short_dir) -> Paths:
    result = Paths(config_file=tmp_path / "config" / "sensei.toml", token_file=tmp_path / "config" / "owner.token",
                   state=tmp_path / "state", runtime=short_dir / "run")
    create_token(result.token_file)
    return result


@pytest.fixture
def sink_path(tmp_path) -> Path:
    return tmp_path / "evidence.jsonl"


@pytest.fixture
def config(sink_path) -> Config:
    return Config(owner_id="alice", owner_display="Alice Example", sink=f"file:{sink_path}")


@pytest.fixture
def project(tmp_path) -> Path:
    folder = tmp_path / "project"
    folder.mkdir()
    (folder / "app.py").write_text("print('hello')\n")
    return folder


@pytest.fixture
def host() -> FakeHost:
    fake = FakeHost()
    fake.add("%1", status="idle", root_pid=WORKER_PID, tty="/dev/pts/1")
    return fake


@pytest.fixture
def clock() -> Clock:
    return Clock()


def make_bridge(paths, config, host, clock, **kwargs) -> Bridge:
    ledger = Ledger(sink_spec=config.sink, spool=paths.state / "ledger-spool.jsonl",
                    owner_id=config.owner_actor_id, owner_display=config.owner_display)
    return Bridge(paths=paths, config=config, host=host, ledger=ledger, clock=clock,
                  resolve=lambda name: (f"/usr/bin/{name}", []), **kwargs)


@pytest.fixture
def bridge(paths, config, host, clock) -> Bridge:
    return make_bridge(paths, config, host, clock)


def records(sink_path: Path, type_: str | None = None) -> list[dict]:
    if not sink_path.exists():
        return []
    return [r for r in read_jsonl(sink_path) if type_ is None or r["type"] == type_]


def pair_up(bridge: Bridge, project: Path, *, mode: str = "confirm", advisor: str = "claude", **extra) -> dict:
    reply = bridge.owner_op({"op": "pair", "worker": "%1", "advisor": advisor, "project": str(project),
                             "mode": mode, "reason": "test pair", "worker_platform": "pi",
                             "worker_model": "acme/small", **extra}, None)
    pair = reply["pair"]
    advisor_pane = pair["advisor"]["pane_id"]
    bridge.host.store[advisor_pane].info.agent = True
    bridge.host.store[advisor_pane].info.status = "idle"
    bridge.host.store[advisor_pane].info.root_pid = ADVISOR_PID
    bridge.host.store[advisor_pane].info.tty = "/dev/pts/2"
    return pair
