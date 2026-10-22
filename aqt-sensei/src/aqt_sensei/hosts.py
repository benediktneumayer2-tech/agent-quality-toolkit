"""Terminal hosts: where the agents' panes live (tmux, Herdr, or a fake for tests).

The bridge needs only a handful of operations: list panes with an agent status,
read recent pane text, type a message into an idle pane, split a pane, run a
command in a pane, close a pane and show a notification.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

READY = ("idle", "done")
STATUSES = ("idle", "working", "blocked", "done", "unknown")
SHELLS = {"bash", "zsh", "sh", "fish", "dash", "ksh", "tcsh", "csh", "nu"}
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\x1b[@-Z\\-_]")
# Generic input prompts of agent TUIs (">", "❯", "›"), near the bottom of the screen.
DEFAULT_PROMPT = r"(^|[│|]\s*)[>❯›](\s|$)"  # capture-pane trims trailing spaces


class HostError(RuntimeError):
    pass


@dataclass
class PaneInfo:
    pane_id: str
    status: str = "unknown"          # idle | working | blocked | done | unknown
    agent: bool = False              # an agent (not a plain shell) occupies the pane
    root_pid: int | None = None      # the pane's shell or first process
    tty: str | None = None           # e.g. /dev/pts/7
    session: str | None = None       # agent session id when the host knows it
    title: str | None = None


class TerminalHost(Protocol):
    name: str

    def panes(self) -> dict[str, PaneInfo]: ...
    def capture(self, pane_id: str, lines: int = 200) -> str: ...
    def deliver(self, pane_id: str, text: str) -> None: ...
    def split(self, pane_id: str, cwd: str, env: dict | None = None) -> str: ...
    def run(self, pane_id: str, argv: list[str]) -> None: ...
    def close(self, pane_id: str) -> None: ...
    def notify(self, title: str, body: str) -> None: ...


def strip_ansi(text: str) -> str:
    return ANSI.sub("", text)


def pane_file(pane_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", pane_id) + ".state"


def write_pane_state(folder: Path, pane_id: str, state: str) -> Path:
    """Called from agent hooks (`aqt-sensei hook-state`): the pane's reported lifecycle."""
    if state not in ("idle", "working", "blocked", "done"):
        raise ValueError("state must be idle, working, blocked or done")
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = folder / pane_file(pane_id)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps({"state": state, "at_ms": int(time.time() * 1000)}))
    os.replace(temporary, path)
    return path


# --------------------------------------------------------------------- tmux

class TmuxHost:
    """tmux backend. Status comes from hook-reported state files, else from a
    quiet-screen heuristic: unchanged for `quiet_seconds` and a prompt visible."""

    name = "tmux"

    def __init__(self, *, socket_name: str | None = None, binary: str | None = None,
                 state_dir: Path | None = None, quiet_seconds: float = 3.0, paste_delay: float = 0.3,
                 clock=time.monotonic):
        self.binary = binary or shutil.which("tmux") or "tmux"
        self.socket_name = socket_name
        self.state_dir = state_dir
        self.quiet_seconds = quiet_seconds
        self.paste_delay = paste_delay
        self.clock = clock
        self.prompt_patterns: dict[str, re.Pattern] = {}
        self._screens: dict[str, tuple[str, float]] = {}  # pane -> (screen hash, unchanged since)

    def set_prompt_pattern(self, pane_id: str, pattern: str | None) -> None:
        self.prompt_patterns[pane_id] = re.compile(pattern or DEFAULT_PROMPT, re.M)

    def _cmd(self, *args: str, input: str | None = None, timeout: float = 10) -> str:
        argv = [self.binary] + (["-L", self.socket_name] if self.socket_name else []) + list(args)
        try:
            done = subprocess.run(argv, input=input, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise HostError(f"tmux is not reachable ({error.__class__.__name__})") from error
        if done.returncode != 0:
            raise HostError(f"tmux {args[0]}: {(done.stderr or 'failed').strip()[:300]}")
        return done.stdout

    def _hook_state(self, pane_id: str) -> str | None:
        if not self.state_dir:
            return None
        try:
            return json.loads((self.state_dir / pane_file(pane_id)).read_text()).get("state")
        except (OSError, ValueError, AttributeError):
            return None

    def _heuristic(self, pane_id: str) -> str:
        screen = strip_ansi(self.capture(pane_id, 0))
        digest = hashlib.sha256(screen.encode()).hexdigest()
        now = self.clock()
        previous = self._screens.get(pane_id)
        if previous is None or previous[0] != digest:
            self._screens[pane_id] = (digest, now)
            return "working" if previous is not None else "unknown"
        if now - previous[1] < self.quiet_seconds:
            return "unknown"
        pattern = self.prompt_patterns.get(pane_id) or re.compile(DEFAULT_PROMPT, re.M)
        tail = "\n".join([line for line in screen.splitlines() if line.strip()][-8:])
        return "idle" if pattern.search(tail) else "unknown"

    def panes(self) -> dict[str, PaneInfo]:
        out = self._cmd("list-panes", "-a", "-F",
                        "#{pane_id}\t#{pane_pid}\t#{pane_tty}\t#{pane_current_command}\t#{pane_title}")
        panes = {}
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            pane_id, pid, tty, command, title = parts[:5]
            agent = command not in SHELLS
            info = PaneInfo(pane_id, root_pid=int(pid) if pid.isdigit() else None, tty=tty or None,
                            agent=agent, title=title or None)
            if agent:
                info.status = self._hook_state(pane_id) or self._heuristic(pane_id)
            panes[pane_id] = info
        return panes

    def capture(self, pane_id: str, lines: int = 200) -> str:
        args = ["capture-pane", "-p", "-J", "-t", pane_id]
        if lines:
            args += ["-S", f"-{int(lines)}"]
        return self._cmd(*args)

    def deliver(self, pane_id: str, text: str) -> None:
        buffer = f"aqt-sensei-{secrets.token_hex(4)}"
        self._cmd("load-buffer", "-b", buffer, "-", input=text)
        self._cmd("paste-buffer", "-p", "-d", "-b", buffer, "-t", pane_id)  # bracketed paste
        if self.paste_delay:
            time.sleep(self.paste_delay)
        self._cmd("send-keys", "-t", pane_id, "Enter")
        self._screens.pop(pane_id, None)

    def split(self, pane_id: str, cwd: str, env: dict | None = None) -> str:
        args = ["split-window", "-h", "-d", "-P", "-F", "#{pane_id}", "-t", pane_id, "-c", cwd]
        for key, value in (env or {}).items():
            args += ["-e", f"{key}={value}"]
        new = self._cmd(*args).strip()
        if not new.startswith("%"):
            raise HostError("tmux did not return the new pane")
        return new

    def run(self, pane_id: str, argv: list[str]) -> None:
        self._cmd("send-keys", "-t", pane_id, "-l", shlex.join(argv))
        self._cmd("send-keys", "-t", pane_id, "Enter")

    def close(self, pane_id: str) -> None:
        self._cmd("kill-pane", "-t", pane_id)

    def notify(self, title: str, body: str) -> None:
        try:
            self._cmd("display-message", "-d", "8000", f"{title}: {body}"[:200])
        except HostError:
            pass


# -------------------------------------------------------------------- Herdr

class HerdrHost:
    """Herdr backend through its CLI; agent status comes from Herdr's integrations."""

    name = "herdr"

    def __init__(self, *, binary: str | None = None):
        self.binary = binary or os.environ.get("AQT_SENSEI_HERDR_BIN") or shutil.which("herdr") or "herdr"
        self._process: dict[str, tuple[int | None, str | None]] = {}

    def set_prompt_pattern(self, pane_id: str, pattern: str | None) -> None:
        pass  # Herdr detects agent states itself

    def call(self, *args: str, timeout: float = 20) -> dict:
        try:
            done = subprocess.run([self.binary, *args], capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise HostError(f"Herdr is not reachable ({error.__class__.__name__})") from error
        try:
            reply = json.loads(done.stdout or "{}")
        except ValueError:
            reply = {}
        error = reply.get("error") if isinstance(reply, dict) else None
        if done.returncode != 0 or error:
            message = (error.get("message") or error.get("code")) if isinstance(error, dict) else done.stderr.strip()
            raise HostError(f"herdr {' '.join(args[:2])}: {(message or 'failed')[:300]}")
        return reply.get("result", {}) if isinstance(reply, dict) else {}

    def _process_info(self, pane_id: str) -> tuple[int | None, str | None]:
        if pane_id not in self._process:
            try:
                result = self.call("pane", "process-info", "--pane", pane_id)
                info = result.get("process_info") or result
                self._process[pane_id] = (info.get("shell_pid"), info.get("tty"))
            except HostError:
                return None, None
        return self._process[pane_id]

    def panes(self) -> dict[str, PaneInfo]:
        panes = {}
        for pane in self.call("pane", "list").get("panes", []):
            if not isinstance(pane, dict) or not pane.get("pane_id"):
                continue
            session = pane.get("agent_session") if isinstance(pane.get("agent_session"), dict) else {}
            status = pane.get("agent_status") if pane.get("agent_status") in STATUSES else "unknown"
            root_pid, tty = self._process_info(pane["pane_id"])
            panes[pane["pane_id"]] = PaneInfo(
                pane["pane_id"], status=status if pane.get("agent") else "unknown", agent=bool(pane.get("agent")),
                root_pid=root_pid, tty=tty, session=session.get("value"),
                title=pane.get("terminal_title_stripped"))
        return panes

    def capture(self, pane_id: str, lines: int = 200) -> str:
        args = ["pane", "read", pane_id, "--source", "recent", "--format", "text"]
        if lines:
            args += ["--lines", str(int(lines))]
        result = self.call(*args)
        return (result.get("read") or {}).get("text", "")

    def deliver(self, pane_id: str, text: str) -> None:
        self.call("agent", "prompt", pane_id, text)

    def split(self, pane_id: str, cwd: str, env: dict | None = None) -> str:
        args = ["pane", "split", pane_id, "--direction", "right", "--no-focus", "--cwd", cwd]
        for key, value in (env or {}).items():
            args += ["--env", f"{key}={value}"]
        pane = self.call(*args).get("pane") or {}
        if not pane.get("pane_id"):
            raise HostError("Herdr did not return the new pane")
        return pane["pane_id"]

    def run(self, pane_id: str, argv: list[str]) -> None:
        self.call("pane", "run", pane_id, shlex.join(argv))

    def close(self, pane_id: str) -> None:
        self._process.pop(pane_id, None)
        self.call("pane", "close", pane_id)

    def notify(self, title: str, body: str) -> None:
        try:
            self.call("notification", "show", title, "--body", body, "--sound", "request")
        except HostError:
            pass


# --------------------------------------------------------------------- fake

@dataclass
class FakePane:
    info: PaneInfo
    screen: list[str] = field(default_factory=list)
    received: list[str] = field(default_factory=list)
    commands: list[list[str]] = field(default_factory=list)


class FakeHost:
    """In-memory host for tests and offline demos. Delivery appends to `received`."""

    name = "fake"

    def __init__(self):
        self.store: dict[str, FakePane] = {}
        self.notifications: list[tuple[str, str]] = []
        self.fail_deliveries = 0
        self.down = False
        self._next = 1

    def add(self, pane_id: str | None = None, *, status: str = "idle", agent: bool = True,
            root_pid: int | None = None, tty: str | None = None, session: str | None = None) -> str:
        pane_id = pane_id or f"%{self._next}"
        self._next += 1
        self.store[pane_id] = FakePane(PaneInfo(pane_id, status, agent, root_pid, tty, session))
        return pane_id

    def set_status(self, pane_id: str, status: str) -> None:
        self.store[pane_id].info.status = status

    def set_prompt_pattern(self, pane_id: str, pattern: str | None) -> None:
        pass

    def panes(self) -> dict[str, PaneInfo]:
        if self.down:
            raise HostError("fake host is down")
        return {pane_id: PaneInfo(**vars(pane.info)) for pane_id, pane in self.store.items()}

    def capture(self, pane_id: str, lines: int = 200) -> str:
        screen = self.store[pane_id].screen
        return "\n".join(screen[-lines:] if lines else screen)

    def deliver(self, pane_id: str, text: str) -> None:
        if self.fail_deliveries:
            self.fail_deliveries -= 1
            raise HostError("fake delivery failure")
        pane = self.store.get(pane_id)
        if pane is None:
            raise HostError("no such pane")
        pane.received.append(text)
        pane.screen.extend(text.splitlines())
        pane.info.status = "working"

    def split(self, pane_id: str, cwd: str, env: dict | None = None) -> str:
        if pane_id not in self.store:
            raise HostError("no such pane")
        return self.add(status="unknown", agent=False)

    def run(self, pane_id: str, argv: list[str]) -> None:
        self.store[pane_id].commands.append(list(argv))

    def close(self, pane_id: str) -> None:
        self.store.pop(pane_id, None)

    def notify(self, title: str, body: str) -> None:
        self.notifications.append((title, body))


def make_host(backend: str, *, tmux_socket: str | None = None, state_dir: Path | None = None,
              quiet_seconds: float = 3.0) -> TerminalHost:
    if backend == "tmux":
        return TmuxHost(socket_name=tmux_socket, state_dir=state_dir, quiet_seconds=quiet_seconds)
    if backend == "herdr":
        return HerdrHost()
    if backend == "fake":
        return FakeHost()
    raise HostError(f"unknown backend {backend!r}")
