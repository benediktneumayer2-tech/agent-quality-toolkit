"""Attribution: which process in the box owns the client end of a connection.

The proxy sees the client's address and port. The box's own ``/proc/<pid>/net/tcp`` (and
``tcp6``, ``udp``, ``udp6``) lists the sockets of the box's network namespace with their inode;
the box process that holds ``socket:[inode]`` among its open files is the sender. From there the
chain goes up the parents to the box's first process (the command ``aqt egress run`` started),
as aqt-trail's writer records the observed sender (``chain_status``):

- ``complete``: the chain reached the box's first process;
- ``partial``: a process exited during the walk, or a parent started after its child (pid reused);
- ``shared``: more than one box process holds the socket (inherited or passed on); every holder is
  listed in ``holders`` and the chain is that of the most recently started one;
- ``unavailable``: no box process holds the socket any more (the sender exited or passed it on
  and closed it before it could be read).

The socket is matched by both ends (the client's address and the address it connected to), so a
second socket with the same local address cannot stand in for it. Each entry carries the host pid,
the pid inside the box, the command name, the executable, the first arguments (masked, truncated)
and the start time (clock ticks since boot). The pids, start times and the executable path are the
kernel's; the command name and the arguments are what the process says about itself.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import struct
from pathlib import Path

from aqt_evidence import platform

from .mask import masked_argv

MAX_DEPTH = 32
STATES = {"tcp": "01", "udp": None}      # tcp: ESTABLISHED only; udp: any
WILDCARDS = ("0.0.0.0", "::")


def _hex_address(text: str) -> tuple[str, int]:
    """``0100007F:1F90`` or the 32-digit IPv6 form (host byte order per 32-bit word) -> (ip, port)."""
    raw, port = text.split(":")
    data = bytes.fromhex(raw)
    if len(data) == 4:
        ip = socket.inet_ntop(socket.AF_INET, data[::-1])
    else:
        ip = socket.inet_ntop(socket.AF_INET6, b"".join(data[i:i + 4][::-1] for i in range(0, 16, 4)))
    return normal_ip(ip), int(port, 16)


def normal_ip(ip: str) -> str:
    """``::ffff:1.2.3.4`` -> ``1.2.3.4``; other addresses unchanged (scope ids dropped)."""
    ip = ip.split("%")[0]
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return str(address.ipv4_mapped)
    return str(address)


def socket_table(text: str, kind: str) -> list[tuple[tuple[str, int], tuple[str, int], str, int]]:
    """Rows of a ``/proc/net/{tcp,udp}{,6}`` file: (local, remote, state, inode)."""
    rows = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10:
            continue
        try:
            rows.append((_hex_address(fields[1]), _hex_address(fields[2]), fields[3], int(fields[9])))
        except ValueError:
            continue
    return rows


class Box:
    """A running box, seen from the host: its first process (bwrap's child, pid 1 inside)."""

    def __init__(self, init_pid: int, *, proc: Path = Path("/proc")):
        self.init_pid = init_pid
        self.proc = proc
        self.pidns = os.readlink(proc / str(init_pid) / "ns" / "pid")

    # -- sockets ---------------------------------------------------------------------------------
    def inode(self, kind: str, local: tuple[str, int], remote: tuple | None = None) -> int | None:
        """Inode of the box socket whose local end is ``local`` (the proxy's peer) and, when given,
        whose remote end is ``remote`` (the address the client connected to)."""
        want = (normal_ip(local[0]), int(local[1]))
        there_want = (normal_ip(remote[0]), int(remote[1])) if remote else None
        for name in (kind, kind + "6"):
            try:
                text = (self.proc / str(self.init_pid) / "net" / name).read_text()
            except OSError:
                continue
            for here, there, state, inode in socket_table(text, kind):
                if not inode or (STATES[kind] is not None and state != STATES[kind]):
                    continue
                if there_want and there != there_want:
                    continue
                # an unconnected UDP socket shows its wildcard address; the port tells it apart
                if here == want or (kind == "udp" and here[1] == want[1] and here[0] in WILDCARDS):
                    return inode
        return None

    def pids(self) -> list[int]:
        """Host pids of the processes in the box, the box's first process excluded."""
        found = []
        for entry in os.scandir(self.proc):
            if not entry.name.isdigit() or int(entry.name) == self.init_pid:
                continue
            try:
                if os.readlink(f"{entry.path}/ns/pid") == self.pidns:
                    found.append(int(entry.name))
            except OSError:
                continue
        return found

    def holders(self, inode: int) -> list[int]:
        """The box processes holding ``socket:[inode]``, most recently started first."""
        target = f"socket:[{inode}]"
        owners = []
        for pid in self.pids():
            fd_dir = self.proc / str(pid) / "fd"
            try:
                names = os.listdir(fd_dir)
            except OSError:
                continue
            for name in names:
                try:
                    if os.readlink(fd_dir / name) == target:
                        owners.append(pid)
                        break
                except OSError:
                    continue
        return sorted(owners, key=lambda pid: (_stat(pid, self.proc) or ("", 0, 0))[2], reverse=True)

    # -- processes -------------------------------------------------------------------------------
    def entry(self, pid: int) -> dict | None:
        info = _stat(pid, self.proc)
        if info is None:
            return None
        comm, _ppid, start = info
        base = self.proc / str(pid)
        entry = {"pid": pid, "box_pid": _box_pid(base), "comm": comm, "start_time": start}
        try:
            entry["exe"] = os.readlink(base / "exe")
        except OSError:
            pass
        try:
            argv = [arg.decode("utf-8", "replace") for arg in (base / "cmdline").read_bytes().split(b"\0") if arg]
            entry["argv"] = masked_argv(argv)
        except OSError:
            pass
        return {key: value for key, value in entry.items() if value is not None}

    def chain(self, pid: int | None) -> dict:
        if pid is None:
            return {"chain": [], "chain_status": "unavailable",
                    "chain_detail": "no box process holds the socket (the sender had exited)"}
        chain, current, detail, status = [], pid, None, "partial"
        for _ in range(MAX_DEPTH):
            entry = self.entry(current)
            if entry is None:
                detail = f"process {current} exited before it could be read"
                break
            if chain and entry["start_time"] > chain[-1]["start_time"]:
                detail = f"parent {current} started after its child {chain[-1]['pid']} (pid reused)"
                break
            chain.append(entry)
            parent = (_stat(current, self.proc) or ("", 0, 0))[1]
            if parent == self.init_pid:
                status = "complete"
                break
            if parent <= 1:
                detail = f"process {current} has no parent in the box"
                break
            current = parent
        else:
            detail = f"more than {MAX_DEPTH} ancestors"
        if not chain:
            status = "unavailable"
        result = {"chain": chain, "chain_status": status}
        if detail and status != "complete":
            result["chain_detail"] = detail
        return result

    def attribute(self, kind: str, peer: tuple, remote: tuple | None = None) -> dict:
        """``process`` for a record: the chain of the box process whose socket is ``peer`` (connected to
        ``remote``); ``shared`` with every holder when several processes hold it."""
        inode = self.inode(kind, (peer[0], peer[1]), remote)
        if inode is None:
            return {"chain": [], "chain_status": "unavailable",
                    "chain_detail": f"no {kind} socket {peer[0]}:{peer[1]} in the box (closed already)"}
        holders = self.holders(inode)
        result = self.chain(holders[0] if holders else None)
        if len(holders) > 1:
            result["chain_status"] = "shared"
            result["chain_detail"] = f"{len(holders)} box processes hold the socket"
            result["holders"] = [{key: value for key, value in (self.entry(pid) or {"pid": pid}).items()
                                  if key in ("pid", "box_pid", "comm", "exe", "start_time")} for pid in holders]
        return result


def _stat(pid: int, proc: Path) -> tuple[str, int, int] | None:
    """(comm, ppid, start_time) from /proc/<pid>/stat, or None when the process is gone."""
    try:
        raw = (proc / str(pid) / "stat").read_text(errors="replace")
    except OSError:
        return None
    left, right = raw.find("("), raw.rfind(")")
    fields = raw[right + 2:].split()
    try:
        return raw[left + 1:right], int(fields[1]), int(fields[19])
    except (IndexError, ValueError):
        return None


def _box_pid(base: Path) -> int | None:
    """The pid inside the box: the last value of ``NSpid`` in /proc/<pid>/status."""
    try:
        for line in (base / "status").read_text().splitlines():
            if line.startswith("NSpid:"):
                return int(line.split()[-1])
    except (OSError, ValueError):
        pass
    return None


def unattributed(reason: str) -> dict:
    return {"chain": [], "chain_status": "unavailable", "chain_detail": reason}


# -- macOS: the Seatbelt box -------------------------------------------------------------------------

_SOCKET_INFO_SIZE = 792                       # struct socket_fdinfo (macOS 26, arm64 and x86_64)
_FAMILY, _KIND, _LPORT, _FPORT, _VFLAG, _FADDR, _LADDR = 184, 256, 268, 264, 288, 296, 312
_SOCKINFO_TCP, _FDTYPE_SOCKET, _PIDLISTFDS, _PIDFDSOCKETINFO, _UID_ONLY = 2, 2, 1, 3, 4
_libproc = None


def _proc():
    global _libproc
    if _libproc is None:
        import ctypes
        _libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    return _libproc


def _user_pids() -> list[int]:
    import ctypes
    lib = _proc()
    count = lib.proc_listpids(_UID_ONLY, os.getuid(), None, 0) // 4 + 64
    buffer = (ctypes.c_int * count)()
    got = lib.proc_listpids(_UID_ONLY, os.getuid(), buffer, ctypes.sizeof(buffer)) // 4
    return [pid for pid in buffer[:got] if pid > 0]


def _socket_fds(pid: int) -> list[int]:
    import ctypes
    lib = _proc()
    size = lib.proc_pidinfo(pid, _PIDLISTFDS, 0, None, 0)
    if size <= 0:
        return []
    buffer = ctypes.create_string_buffer(size + 8 * 32)
    got = lib.proc_pidinfo(pid, _PIDLISTFDS, 0, buffer, len(buffer))
    entries = [struct.unpack_from("=iI", buffer.raw, offset) for offset in range(0, max(got, 0), 8)]
    return [fd for fd, kind in entries if kind == _FDTYPE_SOCKET]


def _tcp_ends(pid: int, fd: int) -> tuple[tuple[str, int], tuple[str, int]] | None:
    """(local, remote) of a TCP socket of ``pid``, from ``proc_pidfdinfo(PROC_PIDFDSOCKETINFO)``."""
    import ctypes
    buffer = ctypes.create_string_buffer(_SOCKET_INFO_SIZE)
    if _proc().proc_pidfdinfo(pid, fd, _PIDFDSOCKETINFO, buffer, _SOCKET_INFO_SIZE) < _SOCKET_INFO_SIZE:
        return None
    raw = buffer.raw
    if struct.unpack_from("=i", raw, _KIND)[0] != _SOCKINFO_TCP:
        return None
    ipv4 = raw[_VFLAG] & 1

    def end(address_at: int, port_at: int) -> tuple[str, int]:
        port = socket.ntohs(struct.unpack_from("=i", raw, port_at)[0] & 0xFFFF)
        ip = (socket.inet_ntop(socket.AF_INET, raw[address_at + 12:address_at + 16]) if ipv4
              else socket.inet_ntop(socket.AF_INET6, raw[address_at:address_at + 16]))
        return normal_ip(ip), port

    return end(_LADDR, _LPORT), end(_FADDR, _FPORT)


class MacBox:
    """A running Seatbelt box, seen from the launcher. ``sandbox-exec`` execs the start gate, which execs the
    command: the process the launcher started is the box's root, and the box is that process and its
    descendants. A process that left the tree (reparented to launchd) is not found; its connections are
    recorded as ``unavailable``, as are connections from outside the box, which can reach the proxy's port on
    the host's loopback."""

    def __init__(self, init_pid: int):
        self.init_pid = init_pid

    def pids(self) -> list[int]:
        """The box's root and its descendants, the root first."""
        children: dict[int, list[int]] = {}
        for pid in _user_pids():
            info = platform.process_info(pid)
            if info:
                children.setdefault(info.ppid, []).append(pid)
        found, stack = [self.init_pid], [self.init_pid]
        while stack:
            for child in children.get(stack.pop(), []):
                if child not in found:
                    found.append(child)
                    stack.append(child)
        return found

    def holders(self, local: tuple[str, int], remote: tuple | None) -> list[int]:
        owners = []
        for pid in self.pids():
            for fd in _socket_fds(pid):
                ends = _tcp_ends(pid, fd)
                if ends and ends[0] == local and (remote is None or ends[1] == remote):
                    owners.append(pid)
                    break
        return sorted(owners, key=lambda pid: getattr(platform.process_info(pid), "start_time", 0) or 0, reverse=True)

    def entry(self, pid: int) -> dict | None:
        info = platform.process_info(pid)
        if info is None:
            return None
        entry = {"pid": pid, "comm": info.name, "start_time": info.start_time, "exe": platform.process_exe(pid)}
        argv = platform.process_cmdline(pid)
        if argv:
            entry["argv"] = masked_argv(argv)
        return {key: value for key, value in entry.items() if value is not None}

    def chain(self, pid: int | None) -> dict:
        if pid is None:
            return unattributed("no process of the box holds the socket (it exited, left the box's process tree, "
                                "or is outside the box)")
        chain, current, detail, status = [], pid, None, "partial"
        for _ in range(MAX_DEPTH):
            entry = self.entry(current)
            if entry is None:
                detail = f"process {current} exited before it could be read"
                break
            if chain and (entry.get("start_time") or 0) > (chain[-1].get("start_time") or 0):
                detail = f"parent {current} started after its child {chain[-1]['pid']} (pid reused)"
                break
            chain.append(entry)
            if current == self.init_pid:
                status = "complete"
                break
            info = platform.process_info(current)
            if info is None or info.ppid <= 1:
                detail = f"process {current} has no parent in the box"
                break
            current = info.ppid
        else:
            detail = f"more than {MAX_DEPTH} ancestors"
        if not chain:
            status = "unavailable"
        result = {"chain": chain, "chain_status": status}
        if detail and status != "complete":
            result["chain_detail"] = detail
        return result

    def attribute(self, kind: str, peer: tuple, remote: tuple | None = None) -> dict:
        if kind != "tcp":
            return unattributed(f"no {kind} in the macOS box")
        local = (normal_ip(peer[0]), int(peer[1]))
        there = (normal_ip(remote[0]), int(remote[1])) if remote else None
        holders = self.holders(local, there)
        result = self.chain(holders[0] if holders else None)
        if len(holders) > 1:
            result["chain_status"] = "shared"
            result["chain_detail"] = f"{len(holders)} box processes hold the socket"
            result["holders"] = [{key: value for key, value in (self.entry(pid) or {"pid": pid}).items()
                                  if key in ("pid", "comm", "exe", "start_time")} for pid in holders]
        return result
