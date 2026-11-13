"""What differs between Linux, macOS and Windows, in one place.

Every AQT package asks this module instead of assuming Linux:

- **folders**: ``config_dir()``, ``state_dir()`` (the AQT folders themselves) and
  ``runtime_base()`` (the user's folder for sockets, to which callers add their own name);
- **files**: ``lock()`` / ``unlock()``, ``open_nofollow()``, ``make_private()``,
  ``ensure_private_dir()``, ``owned_by_user()``;
- **identity**: ``user_id()`` and ``peer_credentials()`` of a connected Unix socket;
- **processes**: ``process_info()``, ``process_chain()``, ``process_exe()``,
  ``process_cmdline()``, ``process_environ()``, ``process_tty()``.

Linux keeps exactly what the packages did before: XDG folders, ``fcntl.flock``,
``O_NOFOLLOW``, ``SO_PEERCRED`` and ``/proc``. ``XDG_CONFIG_HOME``, ``XDG_STATE_HOME``
and ``XDG_RUNTIME_DIR`` are honoured on every system when they are set.

| | Linux | macOS | Windows |
|---|---|---|---|
| config | ``~/.config/aqt`` | ``~/Library/Application Support/AQT/config`` | ``%APPDATA%\\AQT`` |
| state | ``~/.local/state/aqt`` | ``~/Library/Application Support/AQT/state`` | ``%LOCALAPPDATA%\\AQT`` |
| sockets | ``$XDG_RUNTIME_DIR``, else none | the per-user cache folder (``getconf DARWIN_USER_CACHE_DIR``) | none yet |
| locks | ``fcntl.flock`` | ``fcntl.flock`` | ``msvcrt.locking`` on the first byte |
| processes | ``/proc`` | ``sysctl`` and ``libproc`` | Toolhelp snapshot, process token |
| socket peer | ``SO_PEERCRED`` | ``LOCAL_PEERCRED`` and ``LOCAL_PEERPID`` | (named pipes follow) |

Limits, stated rather than hidden:

- Windows has no POSIX file modes. ``make_private()`` does nothing there; AQT's folders lie
  in the user profile, whose default access list admits only the user, SYSTEM and
  administrators. ``owned_by_user()`` cannot tell the owner from ``os.stat`` and returns True.
- ``open_nofollow()`` on Windows checks for a link or reparse point before it opens; another
  process could swap the path in between.
- Process start times have a different unit on each system (Linux: clock ticks since boot,
  macOS: microseconds since 1970, Windows: 100 ns since 1601). They are only compared
  within one system, to notice a reused pid.
- A process of another user may hide its executable, command line, environment and
  terminal (macOS, Windows); those functions then return None.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import socket
import stat as stat_module
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path

if sys.platform.startswith("linux"):
    SYSTEM = "linux"
elif sys.platform == "darwin":
    SYSTEM = "macos"
elif sys.platform in ("win32", "cygwin"):
    SYSTEM = "windows"
else:
    SYSTEM = sys.platform
IS_LINUX, IS_MACOS, IS_WINDOWS = SYSTEM == "linux", SYSTEM == "macos", SYSTEM == "windows"
SYSTEM_NAME = {"linux": "Linux", "macos": "macOS", "windows": "Windows"}.get(SYSTEM, SYSTEM)
PROC = Path("/proc")


def not_available(feature: str, reason: str = "") -> str:
    """The sentence AQT prints for a feature this system does not have (yet)."""
    return f"{feature} is not available on {SYSTEM_NAME}" + (f": {reason}" if reason else "")


# -- folders -----------------------------------------------------------------------------------

def _environ(environ) -> dict:
    return os.environ if environ is None else environ


def _app_support() -> Path:
    return Path.home() / "Library" / "Application Support" / "AQT"


def config_dir(environ=None) -> Path:
    """The AQT configuration folder: ``$XDG_CONFIG_HOME/aqt`` when set, else the system's own place.
    ``environ`` (default ``os.environ``) supplies the variables; the home folder is ``Path.home()``."""
    env = _environ(environ)
    if env.get("XDG_CONFIG_HOME"):
        return Path(env["XDG_CONFIG_HOME"]) / "aqt"
    if IS_MACOS:
        return _app_support() / "config"
    if IS_WINDOWS:
        return Path(env.get("APPDATA") or Path.home() / "AppData" / "Roaming") / "AQT"
    return Path.home() / ".config" / "aqt"


def state_dir(environ=None) -> Path:
    """The AQT state folder (trail, spool, keys of the services): ``$XDG_STATE_HOME/aqt`` when set."""
    env = _environ(environ)
    if env.get("XDG_STATE_HOME"):
        return Path(env["XDG_STATE_HOME"]) / "aqt"
    if IS_MACOS:
        return _app_support() / "state"
    if IS_WINDOWS:
        return Path(env.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "AQT"
    return Path.home() / ".local" / "state" / "aqt"


_CS_DARWIN_USER_CACHE_DIR = 65538


def runtime_base(environ=None) -> Path | None:
    """The user's folder for sockets, private to the user; callers add their own name
    (``aqt/trail.sock``, ``aqt-sensei``). ``$XDG_RUNTIME_DIR`` when set. Without it: on macOS
    the per-user cache folder (``/var/folders/…/C``, about 50 bytes, so socket paths stay under
    the 104-byte limit; not the temporary folder, which macOS empties of files older than three
    days); elsewhere None, and callers use their state folder as before."""
    env = _environ(environ)
    if env.get("XDG_RUNTIME_DIR"):
        return Path(env["XDG_RUNTIME_DIR"])
    if IS_MACOS:
        try:
            folder = os.confstr(_CS_DARWIN_USER_CACHE_DIR)
        except (OSError, ValueError):
            folder = None
        if folder:
            return Path(folder)
    return None


# -- files -------------------------------------------------------------------------------------

if IS_WINDOWS:
    import msvcrt

    def lock(handle, *, blocking: bool = True) -> None:
        """Exclusive lock of an open file (a file object or descriptor). ``blocking=False``
        raises ``BlockingIOError`` when another process holds it. Windows: the first byte is
        locked (``msvcrt.locking``), which every AQT writer of the file also does."""
        fd = handle if isinstance(handle, int) else handle.fileno()
        position = os.lseek(fd, 0, os.SEEK_CUR)
        try:
            while True:
                os.lseek(fd, 0, os.SEEK_SET)
                try:
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    return
                except OSError as error:
                    if not blocking:
                        raise BlockingIOError(*error.args) from error
                time.sleep(0.05)
        finally:
            os.lseek(fd, position, os.SEEK_SET)

    def unlock(handle) -> None:
        fd = handle if isinstance(handle, int) else handle.fileno()
        position = os.lseek(fd, 0, os.SEEK_CUR)
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        finally:
            os.lseek(fd, position, os.SEEK_SET)
else:
    import fcntl

    def lock(handle, *, blocking: bool = True) -> None:
        """Exclusive lock of an open file (a file object or descriptor): ``flock``.
        ``blocking=False`` raises ``BlockingIOError`` when another process holds it."""
        fcntl.flock(handle, fcntl.LOCK_EX if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB)

    def unlock(handle) -> None:
        fcntl.flock(handle, fcntl.LOCK_UN)


O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_REPARSE_POINT = getattr(stat_module, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def open_nofollow(path, flags: int, mode: int = 0o600) -> int:
    """``os.open`` that refuses a symbolic link as the last path part (``O_NOFOLLOW``; an
    ``OSError`` such as ``ELOOP``). Where the flag is missing (Windows), a link or reparse point
    found by ``lstat`` is refused instead."""
    if not O_NOFOLLOW:
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            pass
        else:
            if stat_module.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & _REPARSE_POINT:
                raise OSError(40, "refusing to follow a link", str(path))
    return os.open(path, flags | O_NOFOLLOW, mode)


def make_private(path, *, directory: bool | None = None) -> None:
    """Only the user may read it: 0700 for folders, 0600 for files. Nothing on Windows (see the
    module text)."""
    if IS_WINDOWS:
        return
    if directory is None:
        directory = os.path.isdir(path)
    os.chmod(path, 0o700 if directory else 0o600)


def ensure_private_dir(path) -> Path:
    """Create ``path`` (and its parents) and make it private; returns it."""
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    make_private(path, directory=True)
    return path


def owned_by_user(info: os.stat_result) -> bool:
    """Is the file of ``os.stat``/``os.fstat`` owned by the current user? Always True on Windows."""
    return True if IS_WINDOWS else info.st_uid == os.getuid()


# -- identity ----------------------------------------------------------------------------------

def user_id() -> int | str:
    """The current user: the uid on POSIX, the SID string (``S-1-5-21-…``) on Windows."""
    if IS_WINDOWS:
        return _win_process_sid(None) or os.environ.get("USERNAME", "")
    return os.getuid()


@dataclass(frozen=True)
class PeerCredentials:
    """The process at the other end of a local connection, as the kernel reports it.
    ``uid`` is an int on POSIX; a Windows named pipe will report the SID string (stage to come)."""
    pid: int | None
    uid: int | str | None
    gid: int | None


_SOL_LOCAL, _LOCAL_PEERCRED, _LOCAL_PEERPID = 0, 1, 2   # macOS <sys/un.h>
_XUCRED = struct.Struct("=IIh2x16I")                    # struct xucred: version, uid, ngroups, groups[16]


def peer_credentials(connection: socket.socket) -> PeerCredentials:
    """pid, uid and gid of the peer of a connected Unix socket (Linux ``SO_PEERCRED``;
    macOS ``LOCAL_PEERPID`` and ``LOCAL_PEERCRED``, where gid is the peer's effective group)."""
    if IS_LINUX:
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        return PeerCredentials(*struct.unpack("3i", raw))
    if IS_MACOS:
        pid = struct.unpack("i", connection.getsockopt(_SOL_LOCAL, _LOCAL_PEERPID, 4))[0]
        fields = _XUCRED.unpack(connection.getsockopt(_SOL_LOCAL, _LOCAL_PEERCRED, _XUCRED.size))
        return PeerCredentials(pid, fields[1], fields[3] if fields[2] > 0 else None)
    raise OSError(not_available("socket peer credentials"))


# -- processes ---------------------------------------------------------------------------------

@dataclass(frozen=True)
class ProcessInfo:
    """One process. ``name`` is the short command name (Linux ``comm``, macOS ``p_comm``,
    Windows the executable's file name); ``start_time`` and ``session`` may be None."""
    pid: int
    ppid: int
    name: str
    uid: int | str | None
    start_time: int | None
    session: int | None


def process_info(pid: int, *, proc: Path | None = None) -> ProcessInfo | None:
    """The process ``pid``, or None when it is gone or hidden. ``proc`` reads a Linux-style
    ``/proc`` tree at that path instead of asking the system (tests use a fake one)."""
    if proc is not None or IS_LINUX:
        return _linux_info(pid, proc or PROC)
    if IS_MACOS:
        return _mac_info(pid)
    if IS_WINDOWS:
        return _win_info(pid)
    return None


def process_chain(pid: int | None = None, *, limit: int = 32, proc: Path | None = None) -> list[ProcessInfo]:
    """``pid`` (default: this process) and its ancestors, nearest first, up to the last process
    below init, or up to the first one that cannot be read."""
    chain, current = [], pid or os.getpid()
    for _ in range(limit):
        info = process_info(current, proc=proc)
        if info is None:
            break
        chain.append(info)
        if info.ppid <= 1 or info.ppid == info.pid:
            break
        current = info.ppid
    return chain


def process_exe(pid: int, *, proc: Path | None = None) -> str | None:
    """Full path of the process's executable, or None."""
    if proc is not None or IS_LINUX:
        try:
            return os.readlink((proc or PROC) / str(pid) / "exe")
        except OSError:
            return None
    if IS_MACOS:
        return _mac_path(pid)
    if IS_WINDOWS:
        return _win_exe(pid)
    return None


def process_cmdline(pid: int, *, proc: Path | None = None) -> list[str] | None:
    """The process's arguments (argv), or None."""
    if proc is not None or IS_LINUX:
        try:
            raw = ((proc or PROC) / str(pid) / "cmdline").read_bytes()
        except OSError:
            return None
        return [part.decode(errors="replace") for part in raw.split(b"\0")[:-1]] if raw else []
    if IS_MACOS:
        args = _mac_procargs(pid)
        return args[0] if args else None
    if IS_WINDOWS:
        return _win_cmdline(pid)
    return None


def process_environ(pid: int, *, proc: Path | None = None) -> dict[str, str] | None:
    """The process's environment as it started, or None (another user's process; Windows)."""
    if proc is not None or IS_LINUX:
        try:
            raw = ((proc or PROC) / str(pid) / "environ").read_bytes()
        except OSError:
            return None
        items = raw.split(b"\0")
    elif IS_MACOS:
        args = _mac_procargs(pid)
        if args is None:
            return None
        items = args[1]
    else:
        return None
    pairs = (item.split(b"=", 1) for item in items if b"=" in item)
    return {key.decode(errors="replace"): value.decode(errors="replace") for key, value in pairs}


def process_tty(pid: int, *, proc: Path | None = None) -> str | None:
    """The terminal on the process's standard input (``/dev/pts/3``, ``/dev/ttys003``), or None."""
    if proc is not None or IS_LINUX:
        try:
            target = os.readlink((proc or PROC) / str(pid) / "fd" / "0")
        except OSError:
            return None
    elif IS_MACOS:
        target = _mac_fd_path(pid, 0)
    else:
        return None
    return target if target and (target.startswith("/dev/pts/") or target.startswith("/dev/tty")) else None


# Linux: /proc/<pid>/stat (comm, ppid, session and start time) and /proc/<pid>/status (uid).

def linux_stat(pid: int, proc: Path = PROC) -> tuple[str, int, int, int] | None:
    """(comm, ppid, start_time in clock ticks since boot, session id) from ``/proc/<pid>/stat``."""
    try:
        raw = (proc / str(pid) / "stat").read_text(errors="replace")
    except OSError:
        return None
    # comm is in parentheses and may itself contain spaces or parentheses.
    left, right = raw.find("("), raw.rfind(")")
    if left < 0 or right < 0:
        return None
    fields = raw[right + 2:].split()
    try:
        return raw[left + 1:right], int(fields[1]), int(fields[19]), int(fields[3])
    except (IndexError, ValueError):
        return None


def _linux_uid(pid: int, proc: Path) -> int | None:
    """The effective uid (second ``Uid:`` field of ``/proc/<pid>/status``)."""
    try:
        for line in (proc / str(pid) / "status").read_text(errors="replace").splitlines():
            if line.startswith("Uid:"):
                values = line.split()[1:]
                return int(values[1] if len(values) > 1 else values[0])
    except (OSError, ValueError, IndexError):
        pass
    return None


def _linux_info(pid: int, proc: Path) -> ProcessInfo | None:
    found = linux_stat(pid, proc)
    if found is None:
        return None
    comm, ppid, start, session = found
    return ProcessInfo(pid, ppid, comm, _linux_uid(pid, proc), start, session)


# macOS: sysctl(KERN_PROC_PID) for struct kinfo_proc, libproc for path and open files.

_libc = _libproc = None
if IS_MACOS:
    _libc = ctypes.CDLL(None, use_errno=True)
    _libproc = ctypes.CDLL(ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib", use_errno=True)

_KINFO_SIZE = 648                                   # sizeof(struct kinfo_proc) on 64-bit macOS
_KP_START, _KP_COMM, _KP_UID, _KP_PPID = 0, 243, 420, 560   # e_ucred.cr_uid: effective uid


def _sysctl(mib: list[int]) -> bytes | None:
    names = (ctypes.c_int * len(mib))(*mib)
    size = ctypes.c_size_t(0)
    if _libc.sysctl(names, len(mib), None, ctypes.byref(size), None, 0) != 0 or not size.value:
        return None
    buffer = ctypes.create_string_buffer(size.value)
    if _libc.sysctl(names, len(mib), buffer, ctypes.byref(size), None, 0) != 0:
        return None
    return buffer.raw[:size.value]


def _mac_info(pid: int) -> ProcessInfo | None:
    raw = _sysctl([1, 14, 1, pid])                    # CTL_KERN, KERN_PROC, KERN_PROC_PID
    if not raw or len(raw) < _KINFO_SIZE:
        return None
    seconds, micros = struct.unpack_from("=qi", raw, _KP_START)
    name = raw[_KP_COMM:_KP_COMM + 17].split(b"\0", 1)[0].decode(errors="replace")
    (uid,) = struct.unpack_from("=I", raw, _KP_UID)
    (ppid,) = struct.unpack_from("=i", raw, _KP_PPID)
    try:
        session = os.getsid(pid)
    except OSError:
        session = None
    return ProcessInfo(pid, ppid, name, uid, seconds * 1_000_000 + micros, session)


def _mac_path(pid: int) -> str | None:
    buffer = ctypes.create_string_buffer(4096)
    length = _libproc.proc_pidpath(pid, buffer, ctypes.sizeof(buffer))
    return buffer.raw[:length].decode(errors="replace") if length > 0 else None


def _mac_procargs(pid: int) -> tuple[list[str], list[bytes]] | None:
    """(argv, environment entries) from ``KERN_PROCARGS2``: argc, the executable path, padding,
    then argv and the environment, each NUL-terminated."""
    raw = _sysctl([1, 49, pid])                        # CTL_KERN, KERN_PROCARGS2
    if not raw or len(raw) < 4:
        return None
    (argc,) = struct.unpack_from("=i", raw, 0)
    rest = raw[4:]
    end = rest.find(b"\0")
    if end < 0:
        return None
    rest = rest[end:].lstrip(b"\0")
    parts = rest.split(b"\0")
    argv = [part.decode(errors="replace") for part in parts[:argc]]
    environ = []
    for part in parts[argc:]:
        if not part:
            break
        environ.append(part)
    return argv, environ


_FD_PATH_OFFSET, _FD_PATH_SIZE = 176, 1200          # struct vnode_fdinfowithpath: vip_path, size


def _mac_fd_path(pid: int, fd: int) -> str | None:
    buffer = ctypes.create_string_buffer(_FD_PATH_SIZE)
    got = _libproc.proc_pidfdinfo(pid, fd, 2, buffer, _FD_PATH_SIZE)   # PROC_PIDFDVNODEPATHINFO
    if got < _FD_PATH_SIZE:
        return None
    return buffer.raw[_FD_PATH_OFFSET:].split(b"\0", 1)[0].decode(errors="replace") or None


# Windows: a Toolhelp snapshot (pid, parent, executable name) and the process itself (start
# time, path, command line, token).

if IS_WINDOWS:
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _ntdll = ctypes.WinDLL("ntdll")

    class _ProcessEntry(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)]

    _kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessEntry)]
    _kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessEntry)]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    _kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    _kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                                     ctypes.POINTER(wintypes.DWORD)]
    _kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    _advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    _advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                              ctypes.POINTER(wintypes.DWORD)]
    _advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    _ntdll.NtQueryInformationProcess.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.ULONG,
                                                 ctypes.POINTER(wintypes.ULONG)]
    _shell32 = ctypes.WinDLL("shell32")
    _shell32.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
    _shell32.CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]

_INVALID_HANDLE = ctypes.c_void_p(-1).value
_QUERY_LIMITED = 0x1000                             # PROCESS_QUERY_LIMITED_INFORMATION


def _win_snapshot_entry(pid: int):
    snapshot = _kernel32.CreateToolhelp32Snapshot(0x2, 0)           # TH32CS_SNAPPROCESS
    if not snapshot or snapshot == _INVALID_HANDLE:
        return None
    try:
        entry = _ProcessEntry()
        entry.dwSize = ctypes.sizeof(_ProcessEntry)
        found = _kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while found:
            if entry.th32ProcessID == pid:
                return entry
            found = _kernel32.Process32NextW(snapshot, ctypes.byref(entry))
        return None
    finally:
        _kernel32.CloseHandle(snapshot)


class _WinProcess:
    """An open process handle with only the right to query (works for most processes)."""

    def __init__(self, pid: int):
        self.handle = _kernel32.OpenProcess(_QUERY_LIMITED, False, pid)

    def __enter__(self):
        return self.handle

    def __exit__(self, *exc):
        if self.handle:
            _kernel32.CloseHandle(self.handle)


def _win_start_time(handle) -> int | None:
    times = [wintypes.FILETIME() for _ in range(4)]
    if not _kernel32.GetProcessTimes(handle, *(ctypes.byref(item) for item in times)):
        return None
    return (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime


def _win_token_sid(handle) -> str | None:
    token = wintypes.HANDLE()
    if not _advapi32.OpenProcessToken(handle, 0x8, ctypes.byref(token)):      # TOKEN_QUERY
        return None
    try:
        size = wintypes.DWORD(0)
        _advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))   # TokenUser
        if not size.value:
            return None
        buffer = ctypes.create_string_buffer(size.value)
        if not _advapi32.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
            return None
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]           # TOKEN_USER.User.Sid
        text = wintypes.LPWSTR()
        if not _advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            return None
        try:
            return text.value
        finally:
            _kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))
    finally:
        _kernel32.CloseHandle(token)


def _win_process_sid(pid: int | None) -> str | None:
    if pid is None:
        return _win_token_sid(_kernel32.GetCurrentProcess())
    with _WinProcess(pid) as handle:
        return _win_token_sid(handle) if handle else None


def _win_info(pid: int) -> ProcessInfo | None:
    entry = _win_snapshot_entry(pid)
    if entry is None:
        return None
    start = sid = None
    with _WinProcess(pid) as handle:
        if handle:
            start, sid = _win_start_time(handle), _win_token_sid(handle)
    return ProcessInfo(pid, int(entry.th32ParentProcessID), entry.szExeFile, sid, start, None)


def _win_exe(pid: int) -> str | None:
    with _WinProcess(pid) as handle:
        if not handle:
            return None
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not _kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return None
        return buffer.value


def _win_cmdline(pid: int) -> list[str] | None:
    """``NtQueryInformationProcess(ProcessCommandLineInformation)`` (Windows 8.1+), split as the
    C runtime would (``CommandLineToArgvW``)."""
    with _WinProcess(pid) as handle:
        if not handle:
            return None
        size = wintypes.ULONG(0)
        _ntdll.NtQueryInformationProcess(handle, 60, None, 0, ctypes.byref(size))
        if not size.value:
            return None
        buffer = ctypes.create_string_buffer(size.value)
        if _ntdll.NtQueryInformationProcess(handle, 60, buffer, size, ctypes.byref(size)) != 0:
            return None
        length = ctypes.c_ushort.from_buffer(buffer).value                       # UNICODE_STRING.Length
        address = ctypes.c_void_p.from_buffer(buffer, ctypes.sizeof(ctypes.c_void_p)).value   # .Buffer
        line = ctypes.wstring_at(address, length // 2) if address else ""
    if not line:
        return []
    count = ctypes.c_int(0)
    argv = _shell32.CommandLineToArgvW(line, ctypes.byref(count))
    if not argv:
        return [line]
    try:
        return [argv[index] for index in range(count.value)]
    finally:
        _kernel32.LocalFree(ctypes.cast(argv, ctypes.c_void_p))
