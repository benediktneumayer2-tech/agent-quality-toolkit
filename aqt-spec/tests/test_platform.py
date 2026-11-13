"""aqt_evidence.platform on the system the tests run on (Linux, macOS, Windows), plus the Linux
/proc parser on a fake tree, which works everywhere."""

import os
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from aqt_evidence import platform, process_chain

POSIX = not platform.IS_WINDOWS


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    return tmp_path


def test_xdg_variables_win_on_every_system(tmp_path):
    env = {"XDG_CONFIG_HOME": str(tmp_path / "c"), "XDG_STATE_HOME": str(tmp_path / "s"),
           "XDG_RUNTIME_DIR": str(tmp_path / "r")}
    assert platform.config_dir(env) == tmp_path / "c" / "aqt"
    assert platform.state_dir(env) == tmp_path / "s" / "aqt"
    assert platform.runtime_base(env) == tmp_path / "r"


def test_linux_folders_are_the_xdg_defaults(home, monkeypatch):
    monkeypatch.setattr(platform, "IS_MACOS", False)
    monkeypatch.setattr(platform, "IS_WINDOWS", False)
    assert platform.config_dir({}) == home / ".config" / "aqt"
    assert platform.state_dir({}) == home / ".local" / "state" / "aqt"
    assert platform.runtime_base({}) is None   # callers fall back to their state folder


def test_macos_folders(home, monkeypatch):
    monkeypatch.setattr(platform, "IS_MACOS", True)
    monkeypatch.setattr(platform, "IS_WINDOWS", False)
    base = home / "Library" / "Application Support" / "AQT"
    assert platform.config_dir({}) == base / "config"
    assert platform.state_dir({}) == base / "state"


def test_windows_folders(home, monkeypatch):
    monkeypatch.setattr(platform, "IS_MACOS", False)
    monkeypatch.setattr(platform, "IS_WINDOWS", True)
    env = {"APPDATA": str(home / "Roaming"), "LOCALAPPDATA": str(home / "Local")}
    assert platform.config_dir(env) == home / "Roaming" / "AQT"
    assert platform.state_dir(env) == home / "Local" / "AQT"
    assert platform.runtime_base(env) is None
    assert platform.config_dir({}) == home / "AppData" / "Roaming" / "AQT"


@pytest.mark.skipif(not platform.IS_MACOS, reason="macOS's own runtime folder")
def test_macos_runtime_folder_is_private_and_short():
    base = platform.runtime_base({})
    assert base is not None and base.is_dir()
    info = os.stat(base)
    assert info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) & 0o077 == 0
    # the longest AQT socket below it stays under macOS's 104-byte limit
    assert len(os.fsencode(base / "aqt-sensei" / "pairs" / ("p" * 24) / "advisor.sock")) < 104


def test_lock_excludes_a_second_open_file_until_unlocked(tmp_path):
    path = tmp_path / "file"
    path.write_bytes(b"data")
    with open(path, "rb+") as first, open(path, "rb+") as second:
        platform.lock(first)
        with pytest.raises(BlockingIOError):
            platform.lock(second, blocking=False)
        platform.unlock(first)
        platform.lock(second, blocking=False)
        platform.unlock(second)


def test_lock_works_on_an_append_only_descriptor_and_keeps_the_position(tmp_path):
    path = tmp_path / "log"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | platform.O_BINARY, 0o600)
    with os.fdopen(fd, "ab") as handle:
        handle.write(b"one\n")
        handle.flush()
        platform.lock(handle)
        try:
            handle.write(b"two\n")
            handle.flush()
        finally:
            platform.unlock(handle)
    assert path.read_bytes() == b"one\ntwo\n"


def test_open_nofollow_refuses_a_link(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"x")
    link = tmp_path / "link"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("this account cannot create symbolic links")
    with pytest.raises(OSError):
        platform.open_nofollow(link, os.O_RDONLY)
    os.close(platform.open_nofollow(target, os.O_RDONLY))
    fd = platform.open_nofollow(tmp_path / "new", os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    os.close(fd)
    assert (tmp_path / "new").exists()


@pytest.mark.skipif(not POSIX, reason="no POSIX file modes on Windows")
def test_private_modes(tmp_path):
    folder = platform.ensure_private_dir(tmp_path / "a" / "b")
    assert stat.S_IMODE(os.stat(folder).st_mode) == 0o700
    path = folder / "f"
    path.write_bytes(b"")
    os.chmod(path, 0o644)
    platform.make_private(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_private_dir_and_ownership_everywhere(tmp_path):
    folder = platform.ensure_private_dir(tmp_path / "x")
    assert folder.is_dir()
    assert platform.owned_by_user(os.stat(folder))


def test_user_id():
    uid = platform.user_id()
    if POSIX:
        assert uid == os.getuid()
    else:
        assert isinstance(uid, str) and uid.startswith("S-1-")


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX") or platform.IS_WINDOWS, reason="Unix sockets (POSIX)")
def test_peer_credentials_of_a_socket_pair():
    ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    with ours, theirs:
        peer = platform.peer_credentials(ours)
    assert peer.pid == os.getpid() and peer.uid == os.getuid() and peer.gid == os.getegid()


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX") or platform.IS_WINDOWS, reason="Unix sockets (POSIX)")
def test_peer_credentials_name_the_connecting_process(tmp_path):
    path = Path("/tmp" if len(str(tmp_path)) > 60 else tmp_path) / f"aqt-plat-{os.getpid()}.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(1)
    try:
        child = subprocess.Popen([sys.executable, "-c", "import socket, sys, time\n"
                                  "c = socket.socket(socket.AF_UNIX); c.connect(sys.argv[1]); c.recv(1)", str(path)])
        connection, _ = server.accept()
        with connection:
            peer = platform.peer_credentials(connection)
            connection.sendall(b"x")
        child.wait(timeout=10)
    finally:
        server.close()
        path.unlink(missing_ok=True)
    assert peer.pid == child.pid and peer.uid == os.getuid()


def test_this_process_and_its_parent():
    info = platform.process_info(os.getpid())
    assert info is not None and info.pid == os.getpid() and info.name
    assert info.ppid == os.getppid()
    assert info.uid == platform.user_id()
    assert isinstance(info.start_time, int)
    chain = platform.process_chain()
    assert chain[0].pid == os.getpid()
    if os.getppid() > 1:
        assert chain[1].pid == os.getppid()
        assert chain[1].start_time <= info.start_time
    assert process_chain() == [entry.name for entry in chain]
    assert platform.process_info(2 ** 22 + 12345) is None


def test_exe_cmdline_and_environment_of_a_child():
    env = dict(os.environ, AQT_PLATFORM_TEST="marker-value")
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", "marker-argument"], env=env)
    try:
        deadline = time.monotonic() + 10
        cmdline = None
        while time.monotonic() < deadline:
            cmdline = platform.process_cmdline(child.pid)
            if cmdline and "marker-argument" in cmdline:
                break
            time.sleep(0.05)
        assert cmdline and cmdline[-1] == "marker-argument"
        exe = platform.process_exe(child.pid)
        assert exe and os.path.isfile(exe)
        environ = platform.process_environ(child.pid)
        if POSIX:
            assert environ is not None and environ.get("AQT_PLATFORM_TEST") == "marker-value"
        else:
            assert environ is None
        assert platform.process_tty(child.pid) in (None, platform.process_tty(os.getpid()))
    finally:
        child.kill()
        child.wait()


def _fake_proc(root: Path, pid: int, name: str, ppid: int, *, start: int, session: int, tty: str | None = None):
    folder = root / str(pid)
    (folder / "fd").mkdir(parents=True)
    fields = [ppid, 0, session] + [0] * 15 + [start, 0]     # field 22 (index 19 after the state) is the start
    (folder / "stat").write_text(f"{pid} ({name}) S " + " ".join(map(str, fields)) + "\n")
    (folder / "status").write_text(f"Name:\t{name}\nPPid:\t{ppid}\nUid:\t1000\t1001\t1000\t1000\n")
    (folder / "environ").write_bytes(b"A=1\0B=two=2\0")
    (folder / "cmdline").write_bytes(name.encode() + b"\0--flag\0")
    try:
        os.symlink(tty or "pipe:[1]", folder / "fd" / "0")
    except (OSError, NotImplementedError):
        pass


def test_a_fake_proc_tree_is_read_on_every_system(tmp_path):
    _fake_proc(tmp_path, 1, "init", 0, start=1, session=1)
    _fake_proc(tmp_path, 50, "bash (login)", 1, start=10, session=50, tty="/dev/pts/4")
    _fake_proc(tmp_path, 60, "claude", 50, start=20, session=50)
    info = platform.process_info(50, proc=tmp_path)
    assert info == platform.ProcessInfo(50, 1, "bash (login)", 1001, 10, 50)
    assert [entry.pid for entry in platform.process_chain(60, proc=tmp_path)] == [60, 50]
    assert process_chain(60, proc=tmp_path) == ["claude", "bash (login)"]
    assert platform.process_environ(60, proc=tmp_path) == {"A": "1", "B": "two=2"}
    assert platform.process_cmdline(60, proc=tmp_path) == ["claude", "--flag"]
    if (tmp_path / "50" / "fd" / "0").is_symlink():
        assert platform.process_tty(50, proc=tmp_path) == "/dev/pts/4"
        assert platform.process_tty(60, proc=tmp_path) is None
    assert platform.process_info(70, proc=tmp_path) is None


def test_not_available_names_the_system():
    assert platform.not_available("the box", "it needs bubblewrap").startswith(f"the box is not available on "
                                                                              f"{platform.SYSTEM_NAME}: ")
