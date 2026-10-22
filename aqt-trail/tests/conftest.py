import os
import shutil
import tempfile
import threading
from pathlib import Path

import pytest

from aqt_evidence import actor, new_record

from aqt_trail.config import load_config
from aqt_trail.server import build_server, start_event
from aqt_trail.state import init_state, open_writer

FIXTURES = Path(__file__).parent / "fixtures"


_SESSION_HOME: str | None = None


def pytest_configure(config):
    """Point HOME and the XDG dirs at a throw-away directory for the whole run, so no test can
    ever touch the real user's state, config or spool, even when a fixture is undone."""
    global _SESSION_HOME
    _SESSION_HOME = tempfile.mkdtemp(prefix="aqt-home-")
    os.environ["HOME"] = _SESSION_HOME
    for name, sub in (("XDG_STATE_HOME", "state"), ("XDG_CONFIG_HOME", "config")):
        os.environ[name] = os.path.join(_SESSION_HOME, sub)
    os.environ.pop("XDG_RUNTIME_DIR", None)


def pytest_unconfigure(config):
    if _SESSION_HOME:
        shutil.rmtree(_SESSION_HOME, ignore_errors=True)


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Isolated XDG directories; a short runtime dir because AF_UNIX paths are limited."""
    runtime = Path(tempfile.mkdtemp(prefix="aqt", dir="/tmp" if len(str(tmp_path)) > 60 else None))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    for name in ("AQT_SINK", "AQT_TRAIL_STATE", "AQT_EVIDENCE", "AQT_ACTOR"):
        monkeypatch.delenv(name, raising=False)
    yield tmp_path
    shutil.rmtree(runtime, ignore_errors=True)


@pytest.fixture
def config(env):
    cfg = load_config()
    init_state(cfg, log_id="trail_test")
    return cfg


@pytest.fixture
def writer(config):
    w = open_writer(config)
    yield w
    w.close()


@pytest.fixture
def server(config):
    """A running writer service in a background thread."""
    w = open_writer(config)
    srv = build_server(config, w)
    start_event(config, w)
    thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()
    w.close()


def human(name="alice", **kw):
    return actor("human", f"human:{name}", **kw)


def agent(session="s1", harness="claude-code"):
    return actor("agent", f"agent:{harness}:{session}", harness=harness, session=session)


def event(action="demo", who=None, **kw):
    kw.setdefault("reason", "test")
    return new_record("trail.event", who or human(), action, **kw)


@pytest.fixture
def fixtures():
    return FIXTURES


@pytest.fixture
def local_fixture(tmp_path):
    """Copy a fixture so it is a single-link file owned by the test user."""
    def copy(name):
        target = tmp_path / "fx" / name
        target.parent.mkdir(exist_ok=True)
        shutil.copyfile(FIXTURES / name, target)
        return target
    return copy


def observed_stub(**kw):
    base = {"pid": os.getpid(), "uid": os.getuid(), "gid": os.getgid(), "process_chain": ["python3"],
            "processes": [{"pid": os.getpid(), "comm": "python3", "start_time": 1}], "harness": None, "via": "socket"}
    base.update(kw)
    return base
