"""Observed attribution: who is on the other end of the socket.

The writer reads the peer's pid, uid and gid from the kernel (``SO_PEERCRED``)
and walks ``/proc`` up the parent chain. This is evidence the writer saw, not a
claim by the client. PIDs are reused, so each process carries its start time
(clock ticks since boot, ``/proc/<pid>/stat`` field 22).
"""

from __future__ import annotations

import os
import socket
import struct
from pathlib import Path

from aqt_evidence.session import PROCESS_MARKERS

MAX_DEPTH = 16


def peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
    """(pid, uid, gid) of a connected Unix-socket peer (Linux)."""
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", raw)


def _stat(pid: int, proc: Path) -> tuple[str, int, int] | None:
    """(comm, ppid, start_time) from /proc/<pid>/stat, or None if gone."""
    try:
        raw = (proc / str(pid) / "stat").read_text(errors="replace")
    except OSError:
        return None
    # comm is in parentheses and may itself contain spaces or parentheses.
    left, right = raw.find("("), raw.rfind(")")
    if left < 0 or right < 0:
        return None
    comm = raw[left + 1:right]
    fields = raw[right + 2:].split()
    try:
        return comm, int(fields[1]), int(fields[19])
    except (IndexError, ValueError):
        return None


def processes(pid: int, *, proc: Path = Path("/proc"), limit: int = MAX_DEPTH) -> tuple[list[dict], bool]:
    """Process chain from ``pid`` towards init, nearest first, and whether it is complete."""
    chain, current = [], pid
    for _ in range(limit):
        info = _stat(current, proc)
        if info is None:
            chain.append({"pid": current, "comm": "?"})  # exited before it could be observed
            return chain, False
        comm, parent, start = info
        chain.append({"pid": current, "comm": comm, "start_time": start})
        if parent <= 1:
            return chain, True
        current = parent
    return chain, False


def harness_of(chain: list[dict]) -> str | None:
    for entry in chain:
        found = PROCESS_MARKERS.get(entry.get("comm", ""))
        if found:
            return found
    return None


def observe(pid: int | None, uid: int | None, gid: int | None, *, via: str = "socket",
            proc: Path = Path("/proc")) -> dict:
    """Build the writer-owned ``observed`` object (INTERFACES I2); ``client_time`` is added on append."""
    chain, complete = processes(pid, proc=proc) if pid else ([], False)
    observed = {
        "pid": pid, "uid": uid, "gid": gid,
        "process_chain": [entry["comm"] for entry in chain],
        "processes": chain,
        "harness": harness_of(chain),
        "via": via,
    }
    if pid and not complete:
        observed["chain_complete"] = False
    return observed


def observe_self() -> dict:
    """``observed`` for records the writer creates itself: no ``via`` (nothing was received),
    ``origin: writer`` instead, plus the writer's own process."""
    observed = observe(os.getpid(), os.getuid(), os.getgid())
    del observed["via"]
    observed["origin"] = "writer"
    return observed


def unobserved(via: str = "spool") -> dict:
    """``observed`` for spooled records: delivered later, the sender was never observed."""
    return {"process_chain": [], "processes": [], "harness": None, "via": via}


def agent_markers(observed: dict) -> list[str]:
    return [f"process:{entry['comm']}" for entry in observed.get("processes", [])
            if entry.get("comm") in PROCESS_MARKERS]
