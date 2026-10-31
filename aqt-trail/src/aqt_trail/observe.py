"""Observed attribution: who is on the other end of the socket.

The writer reads the peer's pid, uid and gid from the kernel (``SO_PEERCRED``)
and walks ``/proc`` up the parent chain. This is evidence the writer saw, not a
claim by the client. PIDs are reused, so each process carries its start time
(clock ticks since boot, ``/proc/<pid>/stat`` field 22).

``chain_status`` says how far that evidence goes. Finding no agent marker in a
chain only means something when the chain is ``complete``:

- ``unavailable``: no peer pid, the sender's own ``/proc`` entry could not be
  read, or the sender had exited before it was observed (``SO_PEERPIDFD``,
  Linux >= 6.5; it also rules out a reused pid);
- ``partial``: an ancestor exited during the walk, the walk hit ``MAX_DEPTH``,
  a parent started after its child (pid reuse), or a process belongs to a
  session whose leader is not among its ancestors: it was reparented to init
  or a subreaper such as the systemd user manager after its parent exited, so
  whoever started it is no longer visible;
- ``complete``: the chain was read up to init and none of the above applies.

A process that detaches into a new session (``setsid``), or one started by a
service manager or an existing terminal server on an agent's request, still
looks ``complete``: the chain is a heuristic, not proof of who acted.
"""

from __future__ import annotations

import os
import select
import socket
import struct
from pathlib import Path

from aqt_evidence import Text
from aqt_evidence.session import PROCESS_MARKERS

MAX_DEPTH = 16
CHAIN_STATUSES = ("complete", "partial", "unavailable")
SO_PEERPIDFD = getattr(socket, "SO_PEERPIDFD", 77)  # Linux >= 6.5


def peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
    """(pid, uid, gid) of a connected Unix-socket peer (Linux)."""
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", raw)


def peer_pidfd(connection: socket.socket) -> int | None:
    """A pidfd of the process that connected (Linux >= 6.5), or None where unsupported.
    The caller closes it."""
    try:
        return connection.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD)
    except OSError:
        return None


def _exited(pidfd: int) -> bool:
    """A pidfd becomes readable when its process has exited."""
    try:
        return bool(select.select([pidfd], [], [], 0)[0])
    except (OSError, ValueError):
        return False


def _stat(pid: int, proc: Path) -> tuple[str, int, int, int] | None:
    """(comm, ppid, start_time, session id) from /proc/<pid>/stat, or None if gone."""
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
        return comm, int(fields[1]), int(fields[19]), int(fields[3])
    except (IndexError, ValueError):
        return None


def _walk(pid: int, proc: Path, limit: int) -> tuple[list[dict], list[int], str]:
    """Chain entries (nearest first), their session ids, and how the walk ended:
    ``top`` (reached init), ``gone`` (a process could not be read) or ``depth``."""
    chain, sessions, current = [], [], pid
    for _ in range(limit):
        info = _stat(current, proc)
        if info is None:
            chain.append({"pid": current, "comm": "?"})  # exited before it could be observed
            return chain, sessions, "gone"
        comm, parent, start, session = info
        chain.append({"pid": current, "comm": comm, "start_time": start})
        sessions.append(session)
        if parent <= 1:
            return chain, sessions, "top"
        current = parent
    return chain, sessions, "depth"


def processes(pid: int, *, proc: Path = Path("/proc"), limit: int = MAX_DEPTH) -> tuple[list[dict], bool]:
    """Process chain from ``pid`` towards init, nearest first, and whether it reached init."""
    chain, _, end = _walk(pid, proc, limit)
    return chain, end == "top"


def chain_status(chain: list[dict], sessions: list[int], end: str) -> tuple[str, str | None]:
    """(``complete`` | ``partial`` | ``unavailable``, why not complete) for a walk (see the module text)."""
    if not chain or chain[0].get("comm") == "?":
        return "unavailable", Text("trail.observe.unreadable",
                                   "the sender's /proc entry could not be read (exited or hidden)")
    if end == "gone":
        return "partial", Text("trail.observe.exited", "process {pid} exited before it could be read",
                               pid=chain[-1]["pid"])
    if end == "depth":
        return "partial", Text("trail.observe.too_deep", "more than {n} ancestors", n=MAX_DEPTH)
    for child, parent in zip(chain, chain[1:]):
        if parent["start_time"] > child["start_time"]:
            return "partial", Text("trail.observe.pid_reused", "parent {parent} started after its child {child} (pid "
                                   "reused)", parent=parent["pid"], child=child["pid"])
    on_chain = {entry["pid"] for entry in chain}
    for entry, session in zip(chain, sessions):
        if session > 0 and session != entry["pid"] and session not in on_chain:
            return "partial", Text("trail.observe.reparented", "{comm} ({pid}) belongs to session {session}, whose "
                                   "leader is not among its ancestors (reparented after its parent exited)",
                                   comm=entry["comm"], pid=entry["pid"], session=session)
    return "complete", None


def harness_of(chain: list[dict]) -> str | None:
    for entry in chain:
        found = PROCESS_MARKERS.get(entry.get("comm", ""))
        if found:
            return found
    return None


def observe(pid: int | None, uid: int | None, gid: int | None, *, via: str = "socket",
            proc: Path = Path("/proc"), pidfd: int | None = None) -> dict:
    """Build the writer-owned ``observed`` object (aqt-spec spec §3.2); ``client_time`` is added on append.

    ``pidfd`` (from ``peer_pidfd``) ties the observation to the connecting process: when that process
    has exited by the end of the walk, what /proc showed may belong to another process."""
    chain, sessions, end = _walk(pid, proc, MAX_DEPTH) if pid else ([], [], "gone")
    status, detail = chain_status(chain, sessions, end) if pid else ("unavailable", "no peer pid")
    if pidfd is not None and _exited(pidfd):
        status, detail = "unavailable", "the sender exited before it could be observed"
    observed = {
        "pid": pid, "uid": uid, "gid": gid,
        "process_chain": [entry["comm"] for entry in chain],
        "processes": chain,
        "harness": harness_of(chain),
        "via": via,
        "chain_status": status,
    }
    if detail:
        observed["chain_detail"] = detail
    if pid and end != "top":
        observed["chain_complete"] = False  # kept for older readers; chain_status is the full answer
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
