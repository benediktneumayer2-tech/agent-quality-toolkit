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
    if os.name == "nt":   # Windows takes the home and the AQT folders from these
        for name, sub in (("USERPROFILE", ""), ("APPDATA", "appdata"), ("LOCALAPPDATA", "localappdata")):
            os.environ[name] = os.path.join(_SESSION_HOME, sub)
    for name, sub in (("XDG_STATE_HOME", "state"), ("XDG_CONFIG_HOME", "config")):
        os.environ[name] = os.path.join(_SESSION_HOME, sub)
    os.environ.pop("XDG_RUNTIME_DIR", None)


def pytest_unconfigure(config):
    if _SESSION_HOME:
        shutil.rmtree(_SESSION_HOME, ignore_errors=True)


@pytest.fixture(autouse=True)
def without_signoff(monkeypatch):
    """aqt-trail does not depend on aqt-signoff: by default the tests run as without it (registry keys
    unchecked), whatever the venv holds. ``tests/test_enrolment.py`` uses aqt-signoff's real rules."""
    monkeypatch.setattr("aqt_trail.signers._signoff_registry", lambda: None)


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Isolated XDG directories; a short runtime dir because AF_UNIX paths are limited."""
    runtime = Path(tempfile.mkdtemp(prefix="aqt", dir="/tmp" if os.name == "posix" and len(str(tmp_path)) > 60
                                    else None))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    for name in ("AQT_SINK", "AQT_TRAIL_STATE", "AQT_EVIDENCE", "AQT_ACTOR", "AQT_SIGNERS", "AQT_KEYS_DIR"):
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
    base = {"pid": os.getpid(), "uid": 1000, "gid": 1000, "process_chain": ["python3"],
            "processes": [{"pid": os.getpid(), "comm": "python3", "start_time": 1}], "harness": None, "via": "socket"}
    base.update(kw)
    return base


def pipe_security(name) -> tuple[str, str]:
    """Windows: the owner (SID) and the security descriptor (SDDL) of the writer's named pipe, read through a
    client handle."""
    import _winapi
    from aqt_evidence import pipes
    handle = _winapi.CreateFile(str(name), _winapi.GENERIC_READ | _winapi.GENERIC_WRITE, 0, _winapi.NULL,
                                _winapi.OPEN_EXISTING, 0, _winapi.NULL)
    try:
        return pipes.owner(handle), pipes.security_text(handle)
    finally:
        _winapi.CloseHandle(handle)


def only_the_user(sid: str) -> str:
    """The SDDL Windows writes for "owner and the only access entry: the user": well-known SIDs come back as
    aliases (``LA`` for the built-in administrator account, which runs the CI)."""
    import ctypes
    from ctypes import wintypes
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    descriptor, text = ctypes.c_void_p(), wintypes.LPWSTR()
    assert advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(f"O:{sid}D:P(A;;FA;;;{sid})", 1,
                                                                        ctypes.byref(descriptor), None)
    assert advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, 1, 0x5, ctypes.byref(text), None)
    return text.value
