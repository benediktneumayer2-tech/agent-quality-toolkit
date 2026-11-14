"""Windows named pipes: how clients reach the aqt-trail writer on Windows, where Python has no
Unix sockets. The writer's address is ``\\\\.\\pipe\\aqt-trail-<hash>`` (``platform.trail_socket()``).

What the Unix socket in the user's private runtime folder gives on Linux, the pipe gets this way:

- **only the user can connect**: the writer creates every pipe instance with a security
  descriptor whose owner and only access entry are the user's SID (no inherited entries), and
  refuses remote clients;
- **no one else can serve it**: the writer's first instance uses ``FILE_FLAG_FIRST_PIPE_INSTANCE``,
  so it fails when the name already exists; a client checks that the pipe it opened is owned by
  its own user before it sends anything, and allows the server only to identify it, not to act
  as it (``SECURITY_IDENTIFICATION``);
- **who sent it**: the writer asks for the client's pid (``GetNamedPipeClientProcessId``) and
  reads the user from that process's token (``platform.peer_credentials``).

Protocol as on the socket: one request line (canonical JSON, which has no raw newlines), one
answer line. A pipe has no half-close, so the request ends at its newline.

Overlapped I/O through ``_winapi`` (as ``multiprocessing.connection`` uses it) gives the time-outs;
``ctypes`` builds the security descriptor and reads the pipe's owner.
"""

from __future__ import annotations

import time

from . import platform

if platform.IS_WINDOWS:
    import _winapi
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    class _SecurityAttributes(ctypes.Structure):
        _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                    ("bInheritHandle", wintypes.BOOL)]

    _kernel32.CreateNamedPipeW.restype = wintypes.HANDLE
    _kernel32.CreateNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                                           wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.ULONG)]
    _advapi32.GetSecurityInfo.restype = wintypes.DWORD
    _advapi32.GetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD,
                                          ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
                                          ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
                                          ctypes.POINTER(ctypes.c_void_p)]
    _advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    _advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(wintypes.ULONG)]

_BUFFER = 65536
_PIPE_REJECT_REMOTE_CLIENTS = 0x8
_SECURITY_SQOS_PRESENT, _SECURITY_IDENTIFICATION = 0x00100000, 0x00010000
_SE_KERNEL_OBJECT, _OWNER_INFO, _DACL_INFO = 6, 0x1, 0x4
_ERROR_ACCESS_DENIED, _ERROR_BROKEN_PIPE, _ERROR_NO_DATA, _ERROR_PIPE_NOT_CONNECTED = 5, 109, 232, 233
_ERROR_PIPE_BUSY, _ERROR_IO_PENDING, _ERROR_FILE_NOT_FOUND = 231, 997, 2
_WAIT_TIMEOUT, _INFINITE = 0x102, 0xFFFFFFFF
_CLOSED = (_ERROR_BROKEN_PIPE, _ERROR_NO_DATA, _ERROR_PIPE_NOT_CONNECTED)


class PipeError(OSError):
    pass


def _milliseconds(timeout: float | None) -> int:
    return _INFINITE if timeout is None else max(0, int(timeout * 1000))


def _wait(overlapped, timeout: float | None) -> None:
    """Wait for an overlapped operation; cancel it and raise ``TimeoutError`` when it takes too long."""
    if _winapi.WaitForMultipleObjects([overlapped.event], False, _milliseconds(timeout)) == _WAIT_TIMEOUT:
        overlapped.cancel()
        try:
            overlapped.GetOverlappedResult(True)
        except OSError:
            pass
        raise TimeoutError("the named pipe did not answer in time")


def _read(handle: int, size: int, timeout: float | None) -> bytes:
    """Up to ``size`` bytes; b"" when the other end has closed."""
    try:
        overlapped, error = _winapi.ReadFile(handle, size, overlapped=True)
    except OSError as failure:
        if failure.winerror in _CLOSED:
            return b""
        raise
    try:
        if error == _ERROR_IO_PENDING:
            _wait(overlapped, timeout)
        overlapped.GetOverlappedResult(True)
    except OSError as failure:
        if failure.winerror in _CLOSED:
            return b""
        raise
    return bytes(overlapped.getbuffer())


def _write(handle: int, data: bytes, timeout: float | None) -> None:
    view = memoryview(data)
    while view:
        overlapped, error = _winapi.WriteFile(handle, bytes(view[:_BUFFER]), overlapped=True)
        if error == _ERROR_IO_PENDING:
            _wait(overlapped, timeout)
        written, _ = overlapped.GetOverlappedResult(True)
        view = view[written:]


def _sid_text(sid) -> str | None:
    text = wintypes.LPWSTR()
    if not _advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)):
        return None
    try:
        return text.value
    finally:
        _kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))


def owner(handle: int) -> str | None:
    """The SID string of the owner of an open pipe (or any kernel object), or None."""
    sid, descriptor = ctypes.c_void_p(), ctypes.c_void_p()
    if _advapi32.GetSecurityInfo(handle, _SE_KERNEL_OBJECT, _OWNER_INFO, ctypes.byref(sid), None, None, None,
                                 ctypes.byref(descriptor)) != 0:
        return None
    try:
        return _sid_text(sid)
    finally:
        _kernel32.LocalFree(descriptor)


def security_text(handle: int) -> str | None:
    """Owner and access list of an open pipe in SDDL (``O:S-1-5-21-…D:P(A;;FA;;;S-1-5-21-…)``), for tests
    and diagnosis."""
    descriptor = ctypes.c_void_p()
    if _advapi32.GetSecurityInfo(handle, _SE_KERNEL_OBJECT, _OWNER_INFO | _DACL_INFO, None, None, None, None,
                                 ctypes.byref(descriptor)) != 0:
        return None
    try:
        text = wintypes.LPWSTR()
        if not _advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor, 1, _OWNER_INFO | _DACL_INFO, ctypes.byref(text), None):
            return None
        try:
            return text.value
        finally:
            _kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))
    finally:
        _kernel32.LocalFree(descriptor)


# -- client ------------------------------------------------------------------------------------

def _open(name: str, timeout: float) -> int:
    deadline = time.monotonic() + timeout
    while True:
        try:
            return _winapi.CreateFile(name, _winapi.GENERIC_READ | _winapi.GENERIC_WRITE, 0, _winapi.NULL,
                                      _winapi.OPEN_EXISTING,
                                      _winapi.FILE_FLAG_OVERLAPPED | _SECURITY_SQOS_PRESENT | _SECURITY_IDENTIFICATION,
                                      _winapi.NULL)
        except OSError as failure:
            left = deadline - time.monotonic()
            if failure.winerror != _ERROR_PIPE_BUSY or left <= 0:
                raise
            try:      # every instance is busy: wait until the writer offers the next one
                _winapi.WaitNamedPipe(name, max(1, int(left * 1000)))
            except OSError:
                pass


def request(name: str, data: bytes, *, timeout: float = 5.0) -> bytes:
    """Send one request line to the pipe server ``name`` and return its answer (up to and including
    its newline, or what came before it closed). Raises ``OSError`` (``FileNotFoundError`` when no
    one serves the name, ``TimeoutError``, ``PipeError`` when the pipe is not the user's own)."""
    deadline = time.monotonic() + timeout
    handle = _open(name, timeout)
    try:
        me, found = platform.user_id(), owner(handle)
        if found != me:
            raise PipeError(_ERROR_ACCESS_DENIED, f"the pipe belongs to {found or 'an unknown user'}, not to you "
                                                  f"({me}); refusing to send", name)
        _write(handle, data, max(0.0, deadline - time.monotonic()))
        chunks = []
        while True:
            chunk = _read(handle, _BUFFER, max(0.0, deadline - time.monotonic()))
            if not chunk:
                break
            chunks.append(chunk)
            if b"\n" in chunk:
                break
        return b"".join(chunks)
    finally:
        _winapi.CloseHandle(handle)


# -- server ------------------------------------------------------------------------------------

class PipeConnection:
    """The server end of one client connection, shaped like the socket ``socketserver`` hands to a
    handler: ``settimeout``, ``recv`` (b"" once the request line is complete), ``sendall``, ``close``.
    ``handle`` is what ``platform.peer_credentials`` reads."""

    def __init__(self, handle: int):
        self.handle, self.timeout, self._done = handle, None, False

    def settimeout(self, timeout: float | None) -> None:
        self.timeout = timeout

    def recv(self, size: int) -> bytes:
        if self._done:
            return b""
        data = _read(self.handle, size, self.timeout)
        if not data or b"\n" in data:
            self._done = True
        return data

    def sendall(self, data: bytes) -> None:
        _write(self.handle, data, self.timeout)

    def close(self) -> None:
        """Close once the client has read the answer and closed its end (at most two seconds)."""
        if self.handle is None:
            return
        deadline = time.monotonic() + 2.0
        try:
            while time.monotonic() < deadline and _read(self.handle, _BUFFER, max(0.0, deadline - time.monotonic())):
                pass
        except OSError:
            pass
        _winapi.CloseHandle(self.handle)
        self.handle = None


class PipeListener:
    """Accepts clients on the named pipe ``name``; only the current user can connect (see the module text).
    Raises ``FileExistsError`` when the name is already served."""

    def __init__(self, name: str):
        self.name, self._pending = name, None
        sid = platform.user_id()
        self._descriptor = ctypes.c_void_p()
        if not _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                f"O:{sid}D:P(A;;GA;;;{sid})", 1, ctypes.byref(self._descriptor), None):
            raise ctypes.WinError(ctypes.get_last_error())
        self._attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), self._descriptor, False)
        self._handle = self._create(first=True)

    def _create(self, *, first: bool = False) -> int:
        mode = _winapi.PIPE_ACCESS_DUPLEX | _winapi.FILE_FLAG_OVERLAPPED
        if first:
            mode |= _winapi.FILE_FLAG_FIRST_PIPE_INSTANCE
        handle = _kernel32.CreateNamedPipeW(self.name, mode, _winapi.PIPE_WAIT | _PIPE_REJECT_REMOTE_CLIENTS,
                                            _winapi.PIPE_UNLIMITED_INSTANCES, _BUFFER, _BUFFER, 0,
                                            ctypes.byref(self._attributes))
        if handle is None or handle == ctypes.c_void_p(-1).value:
            error = ctypes.get_last_error()
            if first and error in (_ERROR_ACCESS_DENIED, _ERROR_PIPE_BUSY):
                raise FileExistsError(error, "the named pipe is already served", self.name)
            raise ctypes.WinError(error)
        return handle

    def accept(self, timeout: float | None = None) -> PipeConnection | None:
        """The next client, or None when none connected within ``timeout`` seconds."""
        if self._pending is None:
            try:
                self._pending = _winapi.ConnectNamedPipe(self._handle, overlapped=True)
            except OSError as failure:
                if failure.winerror != _ERROR_NO_DATA:
                    raise
                self._pending = None      # a client came and went already: hand it over, the read sees EOF
                return self._hand_over()
        if _winapi.WaitForMultipleObjects([self._pending.event], False, _milliseconds(timeout)) == _WAIT_TIMEOUT:
            return None
        try:
            self._pending.GetOverlappedResult(True)
        finally:
            self._pending = None
        return self._hand_over()

    def _hand_over(self) -> PipeConnection:
        connected, self._handle = self._handle, self._create()
        return PipeConnection(connected)

    def close(self) -> None:
        if self._pending is not None:
            self._pending.cancel()
            try:
                self._pending.GetOverlappedResult(True)
            except OSError:
                pass
            self._pending = None
        if self._handle is not None:
            _winapi.CloseHandle(self._handle)
            self._handle = None
        if self._descriptor:
            _kernel32.LocalFree(self._descriptor)
            self._descriptor = ctypes.c_void_p()
