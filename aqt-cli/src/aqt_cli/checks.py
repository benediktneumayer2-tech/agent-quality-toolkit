"""The setup checklist as code.

Every entry of ``CHECKS`` has a test (result ok / warn / fail / skip, a one-line explanation
and the fix as a command) and, where the toolkit can do the fix itself, a step. ``aqt status``
runs the tests; ``aqt setup`` runs them and applies the steps. Both use this one list, so the
status and the setup cannot drift apart. ``project.PROJECT_CHECKS`` does the same for one
repository (``aqt project status`` / ``aqt project init``).

Steps never overwrite keys, the signer registry or an existing configuration file. The one
personal step (enrolling a signer) always leaves the passphrase to aqt-signoff's own prompt.
"""

from __future__ import annotations

import importlib.util
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import date
from importlib import metadata
from pathlib import Path
from typing import Callable

from aqt_evidence import Text, platform

from . import tools

OK, WARN, FAIL, SKIP, INFO = "ok", "warn", "fail", "skip", "info"   # info: worth knowing, nothing to do
DISTRIBUTIONS = ("aqt-spec", "aqt-trail", "aqt-signoff", "aqt-change", "aqt-sensei", "aqt-quarantine",
                 "aqt-validate", "aqt-capa", "aqt-ui")
UNIT = "aqt-trail.service"
LABEL = "io.github.benediktneumayer2tech.aqt.trail"   # the writer's LaunchAgent (macOS), after the app's identifier
SIGNER_FIX = 'aqt-signoff init --id human:<you> --name "<Your Name>" --role <role>'


class StepSkipped(Exception):
    """The step was not applied (declined, or it needs something first)."""


class StepFailed(Exception):
    """The step ran and did not succeed."""


@dataclass
class Result:
    result: str
    explanation: str
    fix: str | None = None
    data: dict | None = None
    can_apply: bool = True     # False: the check's step cannot fix this case (the fix is for the person)
    id: str = ""

    def as_dict(self) -> dict:
        value = {"id": self.id, "result": self.result, "explanation": self.explanation, "fix": self.fix}
        if self.data:
            value["data"] = self.data
        return value


def systemctl_user(*args: str) -> tuple[int, str]:
    """Run ``systemctl --user ARGS``; returns (exit code, stdout or else stderr)."""
    if not shutil.which("systemctl"):
        return 127, "systemctl not found"
    try:
        done = subprocess.run(["systemctl", "--user", *args], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as error:
        return 127, str(error)
    return done.returncode, done.stdout.strip() or done.stderr.strip()


def launchctl_run(*args: str) -> tuple[int, str]:
    """Run ``launchctl ARGS`` (macOS); returns (exit code, stdout or else stderr)."""
    if not shutil.which("launchctl"):
        return 127, "launchctl not found"
    try:
        done = subprocess.run(["launchctl", *args], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as error:
        return 127, str(error)
    return done.returncode, done.stdout.strip() or done.stderr.strip()


@dataclass
class Context:
    """What the checks and steps need from the outside; tests replace the runners."""
    verify: bool = False                         # full trail verification (aqt status --verify)
    yes: bool = False                            # aqt setup --yes: apply non-personal steps unasked
    interactive: bool = False                    # a person at the keyboard (stdin is a terminal)
    signer_id: str | None = None                 # aqt setup --id/--name/--role
    name: str | None = None
    role: str | None = None
    systemctl: Callable[..., tuple[int, str]] | None = None   # default: systemctl_user
    launchctl: Callable[..., tuple[int, str]] | None = None   # default: launchctl_run (macOS)
    run_tool: Callable[[str, list[str]], int] | None = None   # default: tools.run_tool
    ask: Callable[[str], str] = input
    say: Callable[[str], None] = print
    writer_wait_s: float = 5.0                   # how long a step waits for a started writer
    _systemd: bool | None = field(default=None, repr=False)
    _launchd: bool | None = field(default=None, repr=False)

    def systemd(self, *args: str) -> tuple[int, str]:
        return (self.systemctl or systemctl_user)(*args)

    def launchd(self, *args: str) -> tuple[int, str]:
        return (self.launchctl or launchctl_run)(*args)

    def tool(self, name: str, argv: list[str]) -> int:
        return (self.run_tool or tools.run_tool)(name, argv)

    def systemd_available(self) -> bool:
        if self._systemd is None:
            self._systemd = platform.IS_LINUX and self.systemd("show-environment")[0] == 0
        return self._systemd

    def launchd_available(self) -> bool:
        """macOS with a login session whose launchd domain takes LaunchAgents (``gui/<uid>``)."""
        if self._launchd is None:
            self._launchd = platform.IS_MACOS and self.launchd("print", launchd_domain())[0] == 0
        return self._launchd

    def confirm(self, question: str) -> bool:
        try:
            answer = self.ask(f"{question} [Y/n] ").strip().lower()
        except EOFError:
            return False
        return answer in ("", "y", "yes", "j", "ja")

    def prompt(self, question: str) -> str:
        try:
            return self.ask(question).strip()
        except EOFError:
            return ""


@dataclass
class Check:
    id: str
    test: Callable[[Context], Result]
    step: Callable[[Context], None] | None = None
    does: str | Callable[[Context], str] = ""   # what the step does, as aqt setup lists it
    personal: bool = False    # needs the person: an ID to choose and a passphrase to type
    part_of: str | None = None   # the step of this check id also does this one (listed once)

    def describe(self, ctx: Context) -> str:
        return self.does(ctx) if callable(self.does) else self.does


# -- helpers ---------------------------------------------------------------------------------
def _trail():
    from aqt_trail.config import load_config
    return load_config()


def _writer_head(config, timeout: float = 1.5) -> dict | None:
    """The writer's ``head`` answer, or None when no writer answers on the socket."""
    from aqt_evidence import SinkError
    from aqt_trail.client import request
    try:
        response = request(config.socket_path, {"op": "head"}, timeout=timeout)
    except (SinkError, OSError, ValueError):
        return None
    return response if response.get("ok") else None


def _wait_for_writer(ctx: Context, config) -> bool:
    deadline = time.monotonic() + ctx.writer_wait_s
    while True:
        if _writer_head(config, timeout=1.0):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.2)


def _external_writer(config) -> dict | None:
    """A writer that answers although this account has no trail state (separate-user mode)."""
    return None if config.meta_path.exists() else _writer_head(config)


def unit_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(base) / "systemd" / "user" / UNIT


def trail_command() -> list[str]:
    """The ``aqt-trail`` of the environment ``aqt`` runs in. From the desktop app's frozen runtime: ``aqt trail``
    by a path that stays valid (the ``aqt`` on PATH when it is this one, else the AppImage file in CLI mode),
    because an AppImage is mounted at a new place on every start."""
    if getattr(sys, "frozen", False):
        for name in NAMES:
            found = shutil.which(name)
            if is_this(found, name):
                return [found, "trail"]
        image = os.environ.get("APPIMAGE")
        return [image, "--cli", "trail"] if image else [sys.executable, "trail"]
    beside = Path(sys.executable).parent / "aqt-trail"
    if beside.exists():
        return [str(beside)]
    found = shutil.which("aqt-trail")
    return [found] if found else [sys.executable, "-m", "aqt_trail.cli"]


def _quote(value: str) -> str:
    return f'"{value}"' if any(c.isspace() for c in value) else value


def serve_command() -> str:
    return " ".join(_quote(part) for part in [*trail_command(), "serve"])


def unit_text() -> str:
    lines = ["# Written by aqt setup: the aqt-trail audit-trail writer in user mode.",
             "# aqt never overwrites this file; edit it and run 'systemctl --user daemon-reload'.",
             "[Unit]", "Description=aqt-trail audit-trail writer (user mode)", "",
             "[Service]", "Type=simple", f"ExecStart={serve_command()}"]
    for name in ("XDG_STATE_HOME", "XDG_CONFIG_HOME", "AQT_TRAIL_STATE"):
        if os.environ.get(name):   # the service must use the same trail as this shell
            lines.append(f"Environment={_quote(f'{name}={os.environ[name]}')}")
    lines += ["Restart=on-failure", "RestartSec=3", "", "[Install]", "WantedBy=default.target", ""]
    return "\n".join(lines)


def _unit_executable(unit: Path) -> str | None:
    for line in unit.read_text(encoding="utf-8").splitlines():
        if line.strip().startswith("ExecStart="):
            value = line.split("=", 1)[1].strip().lstrip("@-:+!")
            first = value[1:].split('"', 1)[0] if value.startswith('"') else value.split()[0] if value else ""
            return first.replace("%h", str(Path.home())) or None
    return None


# macOS: a LaunchAgent in the user's login session, loaded with launchctl bootstrap (not at the next login only).
def launchd_domain() -> str:
    return f"gui/{os.getuid()}"


def launchd_target() -> str:
    return f"{launchd_domain()}/{LABEL}"


def agent_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def writer_log() -> Path:
    """Where the LaunchAgent's writer writes its output: the AQT state folder."""
    return platform.state_dir() / "trail-writer.log"


def agent_plist() -> bytes:
    value = {"Label": LABEL, "ProgramArguments": [*trail_command(), "serve"], "RunAtLoad": True,
             "KeepAlive": {"SuccessfulExit": False}, "ProcessType": "Background",
             "StandardOutPath": str(writer_log()), "StandardErrorPath": str(writer_log())}
    environment = {name: os.environ[name] for name in ("XDG_STATE_HOME", "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR",
                                                       "AQT_TRAIL_STATE") if os.environ.get(name)}
    # the agent must use the same trail and socket as this shell (launchd sets none of these)
    if environment:
        value["EnvironmentVariables"] = environment
    head, rest = plistlib.dumps(value).split(b"<plist", 1)
    note = (b"<!-- Written by aqt setup: the aqt-trail audit-trail writer in user mode. aqt never overwrites this "
            b"file; after editing it: launchctl bootout " + launchd_target().encode() + b", then launchctl "
            b"bootstrap " + launchd_domain().encode() + b" <this file>. -->\n")
    return head + note + b"<plist" + rest


def _agent_program(path: Path) -> str | None:
    try:
        value = plistlib.loads(path.read_bytes())
    except (OSError, ValueError, plistlib.InvalidFileException):
        return None
    argv = value.get("ProgramArguments") or ([value["Program"]] if value.get("Program") else [])
    return str(argv[0]) if argv else None


def _agent_state(ctx: Context) -> str | None:
    """None when the agent is not loaded, else its state as launchctl prints it ("running", "not running")."""
    code, output = ctx.launchd("print", launchd_target())
    if code != 0:
        return None
    found = re.search(r"^\s*state = (.+)$", output, re.M)
    return found.group(1).strip() if found else "loaded"


def _service_installed(ctx: Context) -> bool:
    if platform.IS_MACOS:
        return ctx.launchd_available() and agent_path().exists()
    return ctx.systemd_available() and unit_path().exists()


def _start_fix(ctx: Context, config) -> str:
    if platform.IS_MACOS and _service_installed(ctx):
        return f"launchctl kickstart {launchd_target()}"
    if ctx.systemd_available() and unit_path().exists():
        return "systemctl --user start aqt-trail"
    return serve_command()


def detect_timezone() -> str:
    """The system's IANA time zone: ``TZ``, the ``/etc/localtime`` link or ``/etc/timezone``; else UTC."""
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
    candidates = []
    value = os.environ.get("TZ", "").lstrip(":")
    if value:
        candidates.append(value.split("zoneinfo/", 1)[1] if "zoneinfo/" in value else value)
    try:
        target = os.readlink("/etc/localtime")
        if "zoneinfo/" in target:
            candidates.append(target.split("zoneinfo/", 1)[1])
    except OSError:
        pass
    try:
        candidates.append(Path("/etc/timezone").read_text(encoding="utf-8").strip())
    except OSError:
        pass
    for name in candidates:
        try:
            ZoneInfo(name)
            return name
        except (ValueError, ZoneInfoNotFoundError):
            continue
    return "UTC"


def _write_new(path: Path, text: str) -> None:
    """Create ``path``; never replaces an existing file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "x", encoding="utf-8") as handle:
        handle.write(text)


def _count_lines(path: Path) -> int:
    try:
        with open(path, "rb") as handle:
            return sum(1 for line in handle if line.strip())
    except OSError:
        return 0


def _last_line(path: Path) -> bytes | None:
    """The last line of a file without reading all of it (None for an empty file)."""
    with open(path, "rb") as handle:
        handle.seek(0, os.SEEK_END)
        position, data = handle.tell(), b""
        while position > 0:
            size = min(65536, position)
            position -= size
            handle.seek(position)
            data = handle.read(size) + data
            body = data[:-1] if data.endswith(b"\n") else data
            cut = body.rfind(b"\n")
            if cut >= 0:
                return data[cut + 1:]
        return data or None


def _signoff():
    from aqt_signoff.registry import Registry
    from aqt_signoff.settings import load_settings
    settings = load_settings()
    return settings, Registry(settings.registry_path, settings.keys_dir)


def _active_signers(registry) -> list[str]:
    return [signer.id for signer in registry.signers if signer.active_key()]


# -- the checks ------------------------------------------------------------------------------
def check_packages(ctx: Context) -> Result:
    versions = {}
    for dist in DISTRIBUTIONS:
        try:
            versions[dist] = metadata.version(dist)
        except metadata.PackageNotFoundError:
            versions[dist] = None
    missing = [dist for dist, version in versions.items() if version is None]
    if missing:
        return Result(FAIL, Text("cli.check.packages.missing", "not installed: {names}", names=", ".join(missing)),
                      tools.install_command(*missing),
                      data={"versions": versions})
    distinct = sorted(set(versions.values()))
    text = (Text("cli.check.packages.ok", "all {n} packages installed, version {version}", n=len(versions),
                 version=distinct[0]) if len(distinct) == 1 else
            "installed: " + ", ".join(f"{dist} {version}" for dist, version in versions.items()))
    return Result(OK, text, data={"versions": versions})


# The toolkit's command has two names: aqt-toolkit stands in where another aqt (aqtinstall's) comes first on PATH.
NAMES = ("aqt", "aqt-toolkit")


def this_command(name: str = "aqt") -> Path | None:
    """The program of this ``aqt`` (or ``aqt-toolkit``): the desktop app's frozen runtime (from an AppImage: the
    AppImage file, which runs it), else the console script beside this interpreter."""
    if getattr(sys, "frozen", False):
        return Path(os.environ.get("APPIMAGE") or sys.executable)
    beside = Path(sys.executable).parent / (f"{name}.exe" if os.name == "nt" else name)
    return beside if beside.exists() else None


def is_this(path: str | None, name: str = "aqt") -> bool:
    """Whether the program at ``path`` is this installation's ``name`` (the same file once links are followed)."""
    mine = this_command(name)
    return bool(path and mine and Path(path).resolve() == mine.resolve())


def is_toolkit(path: str) -> bool:
    """Whether the program at ``path`` is AQT's command: this one, or another installation of the toolkit."""
    if is_this(path):
        return True
    try:
        done = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return False
    return done.stdout.startswith("agent-quality-toolkit")


def command_name() -> str:
    """The name that hooks call: ``aqt``, or ``aqt-toolkit`` when the first ``aqt`` on PATH is another program
    (aqtinstall's) or missing while ``aqt-toolkit`` is there."""
    found = shutil.which("aqt")
    if found and is_toolkit(found):
        return "aqt"
    return "aqt-toolkit" if found or shutil.which("aqt-toolkit") else "aqt"


def _command_fix(mine: Path | None) -> str:
    if getattr(sys, "frozen", False) and os.environ.get("APPIMAGE"):
        return f"ln -s {_quote(str(mine))} ~/.local/bin/aqt"      # the app's Settings install it too
    if getattr(sys, "frozen", False) and platform.IS_MACOS:     # the runtime inside the .app
        return f"sudo ln -s {_quote(str(mine))} /usr/local/bin/aqt"   # the app's Settings: Install 'aqt' command
    if getattr(sys, "frozen", False):
        return f"put {_quote(str(mine))} on PATH (the .deb package installs it as /usr/bin/aqt)"
    return f"add {_quote(str(Path(sys.executable).parent))} to PATH"


def toolkit_version(path: str) -> str | None:
    """The version of the AQT command at ``path`` (``aqt --version``), or None when it is another program."""
    try:
        done = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    words = done.stdout.split()
    return words[1] if len(words) > 1 and words[0] == "agent-quality-toolkit" else None


def check_command(ctx: Context) -> Result:
    """Which AQT command agents run: hooks call ``aqt`` (or ``aqt-toolkit``, see ``command_name``) from PATH.
    A warning only when that is not AQT's command, or AQT of another version; the same version installed
    elsewhere (a clone, a uv tool) is worth knowing, nothing more."""
    from . import __version__
    name = command_name()
    found = shutil.which(name)
    mine = this_command(name)
    data = {"name": name, "path": found, "this": str(mine) if mine else None, "aqt": shutil.which("aqt")}
    other = (Text("cli.check.command.other_aqt", "; the first aqt on PATH ({aqt}) is another program", aqt=data["aqt"])
             if name == "aqt-toolkit" and data["aqt"] else "")
    if not found:
        data["in_app"] = "aqt_command" if getattr(sys, "frozen", False) and os.environ.get("APPIMAGE") else None
        return Result(WARN, Text("cli.check.command.missing", "no {name} command on PATH{other}: the hooks aqt project "
                                 "init writes cannot run", name=name, other=other),
                      _command_fix(mine), data=data, can_apply=False)
    if is_this(found, name):
        return Result(OK, Text("cli.check.command.ok", "agents run this AQT as {name} ({path}){other}", name=name,
                               path=found, other=other), data=data)
    version = toolkit_version(found)
    data["version"] = version
    if version == __version__:
        return Result(INFO, Text("cli.check.command.same_version", "agents run another installation of AQT "
                                 "{version} as {name} ({path}){other}", version=version, name=name, path=found,
                                 other=other), data=data)
    if version:
        return Result(WARN, Text("cli.check.command.other_version", "agents run AQT {version} as {name} ({path}), "
                                 "not this AQT {mine}{other}", version=version, name=name, path=found,
                                 mine=__version__, other=other),
                      f"remove or move the other {name}, or reorder PATH, if this one should run", data=data,
                      can_apply=False)
    return Result(WARN, Text("cli.check.command.other", "agents run another {name}: {path} comes first on PATH, "
                             "not this one ({mine}){other}", name=name, path=found, mine=str(mine or sys.executable),
                             other=other),
                  f"remove or move the other {name}, or reorder PATH, if this one should run", data=data,
                  can_apply=False)


def check_trail_init(ctx: Context) -> Result:
    config = _trail()
    if config.meta_path.exists():
        return Result(OK, Text("cli.check.trail.ok", "trail {log_id} in {state}", log_id=config.meta()["log_id"],
                               state=str(config.state)))
    external = _writer_head(config)
    if external:
        return Result(OK, f"no trail state here, but a writer serves trail {external.get('log_id')} on "
                          f"{config.socket_path} (separate-user mode)")
    return Result(FAIL, Text("cli.check.trail.missing", "no trail in {state}", state=str(config.state)), "aqt-trail init")


def step_trail_init(ctx: Context) -> None:
    if ctx.tool("trail", ["init"]) != 0:
        raise StepFailed("aqt-trail init did not succeed")


def service_unavailable() -> str | None:
    """None where ``aqt setup`` can install the writer as a user service (Linux: systemd, macOS: a launchd
    LaunchAgent), else why not. A logon task (Windows) will plug in here."""
    if platform.IS_LINUX or platform.IS_MACOS:
        return None
    return platform.not_available("the writer as a background service", "it is installed with systemd, which "
                                  "this system does not have; start the writer by hand")


def check_service(ctx: Context) -> Result:
    unavailable = service_unavailable()
    if unavailable:
        return Result(SKIP, unavailable)
    if platform.IS_MACOS:
        return check_agent(ctx)
    if not ctx.systemd_available():
        return Result(SKIP, Text("cli.check.service.no_systemd", "systemd --user is not available here; the writer is "
                                 "started by hand"))
    unit = unit_path()
    if not unit.exists():
        if _external_writer(_trail()):
            return Result(SKIP, "the writer runs outside your user services (separate-user mode)")
        return Result(WARN, Text("cli.check.service.missing", "no user service {unit}: the writer does not start at login",
                                 unit=str(unit)), "aqt setup")
    executable = _unit_executable(unit)
    if executable and not Path(executable).exists():
        return Result(WARN, f"{unit} starts {executable}, which does not exist",
                      f"edit ExecStart in {unit}, then: systemctl --user daemon-reload", can_apply=False)
    _code, state = ctx.systemd("is-enabled", "aqt-trail")
    if state not in ("enabled", "enabled-runtime"):
        return Result(WARN, Text("cli.check.service.disabled", "{unit} is installed but not enabled ({state})", unit=UNIT,
                                 state=state or "unknown"),
                      "systemctl --user enable --now aqt-trail")
    return Result(OK, Text("cli.check.service.ok", "{unit} enabled, starts {executable}", unit=UNIT,
                           executable=str(executable)))


def check_agent(ctx: Context) -> Result:
    if not ctx.launchd_available():
        return Result(SKIP, Text("cli.check.service.no_launchd", "no launchd login session ({domain}) here; the writer is "
                                 "started by hand", domain=launchd_domain()))
    agent = agent_path()
    if not agent.exists():
        if _external_writer(_trail()):
            return Result(SKIP, "the writer runs outside your LaunchAgents (separate-user mode)")
        return Result(WARN, Text("cli.check.service.no_agent", "no LaunchAgent {agent}: the writer does not start at login",
                                 agent=str(agent)), "aqt setup")
    program = _agent_program(agent)
    if not program or not Path(program).exists():
        return Result(WARN, f"{agent} starts {program or 'no program'}, which does not exist",
                      f"edit ProgramArguments in {agent}, then: launchctl bootout {launchd_target()}; "
                      f"launchctl bootstrap {launchd_domain()} {agent}", can_apply=False)
    state = _agent_state(ctx)
    if state is None:
        return Result(WARN, Text("cli.check.service.not_loaded", "the LaunchAgent {label} is installed but not loaded",
                                 label=LABEL), f"launchctl bootstrap {launchd_domain()} {agent}")
    return Result(OK, Text("cli.check.service.agent_ok", "LaunchAgent {label} loaded ({state}), starts {program}",
                           label=LABEL, state=state, program=program))


def step_agent(ctx: Context) -> None:
    agent = agent_path()
    if not agent.exists():
        writer_log().parent.mkdir(parents=True, exist_ok=True)
        _write_new(agent, agent_plist().decode())
        ctx.say(f"wrote {agent}")
    if _agent_state(ctx) is None:
        code, output = ctx.launchd("bootstrap", launchd_domain(), str(agent))
        if code != 0:
            raise StepFailed(f"launchctl bootstrap {launchd_domain()} {agent}: {output}")
    _wait_for_writer(ctx, _trail())


def step_service(ctx: Context) -> None:
    if not _trail().meta_path.exists():
        raise StepSkipped("create the trail first (aqt-trail init)")
    if platform.IS_MACOS:
        return step_agent(ctx)
    unit = unit_path()
    if not unit.exists():
        _write_new(unit, unit_text())
        ctx.say(f"wrote {unit}")
        ctx.systemd("daemon-reload")
    code, output = ctx.systemd("enable", "--now", "aqt-trail")
    if code != 0:
        raise StepFailed(f"systemctl --user enable --now aqt-trail: {output}")
    _wait_for_writer(ctx, _trail())


def check_writer(ctx: Context) -> Result:
    config = _trail()
    head = _writer_head(config)
    if head:
        return Result(OK, Text("cli.check.writer.ok", "running on {socket}, head seq {seq}", socket=str(config.socket_path),
                               seq=head.get("seq")),
                      data={"socket": str(config.socket_path), "head_seq": head.get("seq")})
    if not config.meta_path.exists():
        return Result(SKIP, Text("cli.check.writer.no_trail", "no trail yet"))
    can_start = _service_installed(ctx)
    how = "" if can_start else Text("cli.check.writer.by_hand", "; start it in a terminal of its own and keep it running")
    return Result(FAIL, Text("cli.check.writer.down", "no writer answers on {socket}{how}", socket=str(config.socket_path),
                             how=how), _start_fix(ctx, config),
                  can_apply=can_start)


def step_writer(ctx: Context) -> None:
    if platform.IS_MACOS:
        if _agent_state(ctx) is None:
            code, output = ctx.launchd("bootstrap", launchd_domain(), str(agent_path()))
        else:
            code, output = ctx.launchd("kickstart", launchd_target())
        if code != 0:
            raise StepFailed(f"launchctl could not start {LABEL}: {output}")
        if not _wait_for_writer(ctx, _trail()):
            raise StepFailed(f"the LaunchAgent started, but the writer does not answer yet; see {writer_log()}")
        return
    code, output = ctx.systemd("start", "aqt-trail")
    if code != 0:
        raise StepFailed(f"systemctl --user start aqt-trail: {output}")
    if not _wait_for_writer(ctx, _trail()):
        raise StepFailed("the service started, but the writer does not answer yet; see: "
                         "journalctl --user -u aqt-trail")


def check_spool(ctx: Context) -> Result:
    from aqt_evidence import spool_file
    count = _count_lines(spool_file())
    if not count:
        return Result(OK, Text("cli.check.spool.empty", "spool empty"))
    waiting = (Text("cli.check.spool.one", "1 record waits in {path} and is not in the trail yet", path=str(spool_file()))
               if count == 1 else Text("cli.check.spool.many", "{n} records wait in {path} and are not in the trail yet",
                                       n=count, path=str(spool_file())))
    return Result(WARN, waiting,
                  "aqt-trail drain", data={"spooled": count})


def step_spool(ctx: Context) -> None:
    if ctx.tool("trail", ["drain"]) != 0:
        raise StepFailed("aqt-trail drain did not succeed")


_SOURCES = {"env": Text("cli.check.sink.env", "set by AQT_SINK"), "discovered": Text("cli.check.sink.discovered",
            "found automatically"), "default": Text("cli.check.sink.default", "the default")}


def check_sink(ctx: Context) -> Result:
    import aqt_evidence
    resolve = getattr(aqt_evidence, "resolve_sink", None)
    if resolve is None:
        return Result(WARN, "sink: unknown (aqt-spec too old to report where records go)",
                      tools.install_command("aqt-spec"))
    try:
        info = resolve()
    except aqt_evidence.SinkError as error:
        return Result(FAIL, f"AQT_SINK is not usable: {error}", "set AQT_SINK to file:PATH or unix:PATH, or unset it")
    kind, target, warning = info.get("kind"), info.get("target"), info.get("warning")
    origin = _SOURCES.get(info.get("source"), info.get("source"))
    if not warning:
        where = Text("cli.check.sink.writer", "the trail writer") if kind == "unix" else Text("cli.check.sink.file", "the file")
        return Result(OK, Text("cli.check.sink.ok", "records go to {where} {target} ({origin})", where=where,
                               target=str(target), origin=origin), data=info)
    config = _trail()
    if kind == "unix" and info.get("writer"):       # a writer answered but refused the check
        fix = "aqt-trail status"
    elif config.meta_path.exists():
        fix = _start_fix(ctx, config)
    else:
        fix = "aqt setup"
    return Result(WARN, warning, fix, data=info)


def check_signer(ctx: Context) -> Result:
    """A signer with an active key, and every registry key backed by its enrolment record
    (``aqt_signoff.check_signers``, as ``aqt-signoff signers check``): a key that does not count is
    ignored by every signature check, so it is a failure here."""
    import aqt_signoff
    settings, registry = _signoff()
    active = _active_signers(registry)
    if not active:
        return Result(FAIL, Text("cli.check.signer.none", "no signer with an active key in {registry}",
                                 registry=str(settings.registry_path)), SIGNER_FIX)
    check_signers = getattr(aqt_signoff, "check_signers", None)
    if check_signers is None:
        return Result(WARN, f"{len(active)} signer(s) enrolled: {', '.join(active)}; aqt-signoff is too old to check "
                            "their keys against the enrolment records", tools.install_command("aqt-signoff"),
                      can_apply=False)
    report = check_signers()
    keys = report.get("keys", [])
    data = {"registry": report.get("registry"), "evidence": report.get("evidence"),
            "keys": [{name: key.get(name) for name in ("signer", "key_id", "state", "counts", "problems", "notes")}
                     for key in keys]}
    problems = report.get("problems") or []
    if problems:
        fix = ("aqt-signoff signers import" if any("signers import" in str(p) for p in problems)
               else "aqt-signoff signers check")
        return Result(FAIL, f"the enrolment records of {report.get('registry')} have problems: "
                            + "; ".join(str(p) for p in problems), fix, data=data, can_apply=False)
    pending = report.get("pending") or []
    approvals = {(entry.get("signer"), entry.get("key_id")): entry.get("approve") for entry in pending}
    bad = [key for key in keys if not key.get("counts")]
    waiting = [key for key in bad if (key.get("signer"), key.get("key_id")) in approvals]
    if waiting and len(waiting) == len(bad):
        what = ", ".join(f"{key['signer']} key {key['key_id']}" for key in waiting)
        return Result(FAIL, f"{len(waiting)} key(s) wait for approval by an enrolled signer and do not count yet: {what}",
                      "; ".join(approvals[(key["signer"], key["key_id"])] + " --signer <you>" for key in waiting),
                      data=data, can_apply=False)
    if bad:
        what = "; ".join(f"{key['signer']} key {key['key_id']}: {', '.join(key.get('problems') or ['does not count'])}"
                         for key in bad)
        unrecorded = [key for key in bad if not key.get("enrolment") and not key.get("revoked_at")
                      and all(p.startswith("no signoff.key.enrolled record") for p in key.get("problems") or [])]
        fix = ("; ".join(f"aqt-signoff rekey --signer {key['signer']}" for key in unrecorded)
               if len(unrecorded) == len(bad) else "aqt-signoff signers check")
        return Result(FAIL, f"{len(bad)} key(s) in {report.get('registry')} do not count: {what}", fix,
                      data=data, can_apply=False)
    counting = sorted({key["signer"] for key in keys if not key.get("revoked_at")})
    if not counting:
        return Result(FAIL, f"no active key that counts in {report.get('registry')} (revocation records apply)",
                      "aqt-signoff signers check", data=data, can_apply=False)
    unconfirmed = [entry for entry in report.get("rebootstrap") or [] if not entry.get("confirmed_by")]
    if unconfirmed:
        what = ", ".join(f"{entry.get('signer')} key {entry.get('key_id')}" for entry in unconfirmed)
        unsigned = sorted({f"{item.get('signer')} key {item.get('key_id')}" for entry in unconfirmed
                           for item in entry.get("unsigned_revocations") or []})
        text = (f"RE-BOOTSTRAP: {what} counts although every earlier key was revoked, and no signer whose key counted "
                "before it has confirmed it; make sure it was you (the trail shows who enrolled it)")
        if unsigned:
            text += (f". The revocations before it were NOT signed ({', '.join(unsigned)}): any process can write "
                     "those; if you did not revoke these keys yourself (for example with 'aqt-signoff revoke --lost'), "
                     "treat this as an incident")
        return Result(WARN, text, "aqt-signoff signers check", data=data, can_apply=False)
    requests = [entry for entry in pending if not entry.get("in_registry")]
    if requests:
        what = ", ".join(f"{entry.get('signer')} key {entry.get('key_id')}" for entry in requests)
        return Result(WARN, f"enrolment request(s) wait for approval: {what}; approve only people you know",
                      "aqt-signoff signers check", data=data, can_apply=False)
    notes = [f"{key['signer']}: {note}" for key in keys for note in key.get("notes") or []]
    if notes:
        return Result(WARN, f"{len(counting)} signer(s) enrolled ({', '.join(counting)}), to check: {'; '.join(notes)}",
                      "aqt-signoff signers check", data=data, can_apply=False)
    first = report.get("bootstrap")
    first = first.get("signer") if isinstance(first, dict) else first
    first = Text("cli.check.signer.first", " (first signer: {signer})", signer=first) if first else ""
    if len(counting) == 1:
        text = Text("cli.check.signer.ok_one", "1 signer enrolled and backed by enrolment records in the {evidence}: "
                    "{signers}{first}", evidence=str(report.get("evidence")), signers=counting[0], first=first)
    else:
        text = Text("cli.check.signer.ok_many", "{n} signers enrolled and backed by enrolment records in the {evidence}: "
                    "{signers}{first}", n=len(counting), evidence=str(report.get("evidence")),
                    signers=", ".join(counting), first=first)
    return Result(OK, text, data=data)


SIGNER_ID = re.compile(r"^human:[a-z0-9][a-z0-9._-]{0,63}$")   # aqt-signoff's rule for signer IDs


def _signer_id(text: str) -> str:
    """``alice`` -> ``human:alice``; the ID as aqt-signoff will check it."""
    text = text.strip()
    return text if not text or text.startswith("human:") else f"human:{text}"


def _suggest_signer_id(signer_id: str) -> str:
    """A valid ID close to an invalid one: ``human:Bene Test`` -> ``human:bene-test``."""
    name = re.sub(r"[^a-z0-9._-]+", "-", signer_id.removeprefix("human:").lower()).strip("-._")
    return f"human:{name[:64] or 'yourname'}"


def step_signer(ctx: Context) -> None:
    signer_id, name, role = _signer_id(ctx.signer_id or ""), ctx.name, ctx.role
    if signer_id and not SIGNER_ID.match(signer_id):
        raise StepFailed(f"{signer_id} is not a valid signer ID: lower case letters, digits, . _ or -, "
                         f"for example {_suggest_signer_id(signer_id)}")
    if not signer_id:
        if not ctx.interactive:
            raise StepSkipped(f"needs you at the keyboard: run 'aqt setup' in your terminal, or: {SIGNER_FIX}")
        if not ctx.confirm("Enrol your signing identity now (you choose an ID and type a passphrase)?"):
            raise StepSkipped(f"not now; later: {SIGNER_FIX}")
        for _attempt in range(3):     # checked before the name, role and passphrase are asked
            signer_id = _signer_id(ctx.prompt("Your ID: lower case letters, digits, . _ or -, for example alice "
                                              "(becomes human:alice; never reused): "))
            if not signer_id or SIGNER_ID.match(signer_id):
                break
            ctx.say(f"{signer_id} cannot be used: lower case letters, digits, . _ or - only "
                    f"(for example {_suggest_signer_id(signer_id)}).")
        else:
            raise StepSkipped(f"no valid ID given; later: {SIGNER_FIX}")
    if ctx.interactive:
        name = name or ctx.prompt("Your printed name, for example Alice Example: ")
        role = role or ctx.prompt("Your role, for example quality-manager or developer: ")
    if not (signer_id and name and role):
        raise StepSkipped(f"an ID, a name and a role are needed: {SIGNER_FIX}")
    ctx.say("aqt-signoff now asks for a new passphrase (twice). Type it yourself; aqt does not store it.")
    if ctx.tool("signoff", ["init", "--id", signer_id, "--name", name, "--role", role]) != 0:
        raise StepFailed("aqt-signoff init did not succeed")
    ctx.signer_id = signer_id


def check_signoff_config(ctx: Context) -> Result:
    settings, registry = _signoff()
    path = settings.config_path
    active = _active_signers(registry)
    if not path.exists():
        need = "" if active else Text("cli.check.signoff.enrol_first", " (enrol a signer first)")
        return Result(WARN, Text("cli.check.signoff.missing", "no {path}: signing commands need --signer every time{need}",
                                 path=str(path), need=need), "aqt setup")
    if not settings.signer:
        return Result(WARN, f"{path} names no default signer",
                      f'add signer = "{active[0] if active else "human:<you>"}" under [signoff] in {path}',
                      can_apply=False)
    if settings.signer not in active:
        return Result(FAIL, f"{path} names {settings.signer}, who has no active key in {settings.registry_path}",
                      "aqt-signoff signers list", can_apply=False)
    return Result(OK, Text("cli.check.signoff.ok", "default signer {signer}, time zone {tz}", signer=settings.signer,
                           tz=settings.tz))


def step_signoff_config(ctx: Context) -> None:
    settings, registry = _signoff()
    active = _active_signers(registry)
    if ctx.signer_id in active:
        signer = ctx.signer_id
    elif len(active) == 1:
        signer = active[0]
    elif active and ctx.interactive:
        signer = ctx.prompt(f"Default signer ({', '.join(active)}): ")
        if signer not in active:
            raise StepSkipped(f"{signer!r} is not one of {', '.join(active)}")
    elif active:
        raise StepSkipped(f"several signers ({', '.join(active)}): pass --id to choose the default")
    else:
        raise StepSkipped("no signer enrolled yet")
    tz = detect_timezone()
    _write_new(settings.config_path, f"# Written by aqt setup on {date.today().isoformat()}. All settings: "
                                     "aqt-signoff/examples/signoff.toml in the repository.\n"
                                     f"[signoff]\nsigner = {json.dumps(signer)}\ntz = {json.dumps(tz)}\n")
    ctx.say(f"wrote {settings.config_path} (signer {signer}, time zone {tz})")


def check_trail_config(ctx: Context) -> Result:
    from aqt_trail.config import config_dir
    path = config_dir() / "trail.toml"
    if not path.exists():
        return Result(WARN, Text("cli.check.trail_config.missing", "no {path}: the audit-trail review assumes UTC and "
                                 "07:00-19:00 on weekdays", path=str(path)),
                      "aqt setup")
    review = _trail().section("review")
    return Result(OK, Text("cli.check.trail_config.ok", "{path}: review time zone {tz}, {start}-{end}", path=str(path),
                           tz=review["timezone"], start=review["work_start"], end=review["work_end"]))


def step_trail_config(ctx: Context) -> None:
    from aqt_trail.config import config_dir
    path, tz = config_dir() / "trail.toml", detect_timezone()
    _write_new(path, f"# Written by aqt setup on {date.today().isoformat()}. All settings: "
                     "aqt-trail/examples/trail.toml in the repository.\n"
                     f'[review]\ntimezone = {json.dumps(tz)}\nwork_start = "07:00"\nwork_end = "19:00"\n'
                     "workdays = [1, 2, 3, 4, 5]\n")
    ctx.say(f"wrote {path} (review time zone {tz})")


def check_trail_intact(ctx: Context) -> Result:
    from aqt_evidence import record_hash, verify_checkpoint, verify_record_signatures
    from aqt_trail.state import service_keys
    config = _trail()
    if not config.meta_path.exists():
        return Result(SKIP, Text("cli.check.intact.no_state", "no trail state here"))
    if not config.trail_path.exists():
        return Result(OK, Text("cli.check.intact.empty", "the trail has no records yet"))
    keys = service_keys(config)
    if ctx.verify:
        return _full_verify(config, keys)
    writer = _writer_head(config)          # before reading the file: the writer may append meanwhile
    line = _last_line(config.trail_path)
    if line is None:
        return Result(OK, Text("cli.check.intact.empty", "the trail has no records yet"))
    try:
        record = json.loads(line)
        seq = record["chain"]["seq"]
    except (ValueError, KeyError, TypeError):
        return Result(FAIL, f"the last line of {config.trail_path} is not a complete record", "aqt-trail verify")
    signatures = verify_record_signatures(record, keys)
    if not signatures or not all(valid is True for _key, valid in signatures):
        return Result(FAIL, f"the last record (seq {seq}) is not signed by this trail's service key",
                      "aqt-trail verify")
    head = record_hash(record)
    if writer and isinstance(writer.get("seq"), int):
        if writer["seq"] > seq:
            return Result(FAIL, f"the log ends at seq {seq}, but the writer is at seq {writer['seq']}: "
                                "records are missing", "aqt-trail verify")
        if writer["seq"] == seq and writer.get("head") != head:
            return Result(FAIL, f"the last record (seq {seq}) differs from the writer's head", "aqt-trail verify")
    if config.checkpoints_path.exists():
        point_line = _last_line(config.checkpoints_path)
        if point_line:
            try:
                point = json.loads(point_line)
            except ValueError:
                return Result(FAIL, f"the last line of {config.checkpoints_path} is unreadable", "aqt-trail verify")
            if not verify_checkpoint(point, keys):
                return Result(FAIL, "the last checkpoint is not signed by this trail's service key", "aqt-trail verify")
            if point.get("seq", -1) > seq:
                return Result(FAIL, f"the last checkpoint is at seq {point['seq']}, beyond the end of the log "
                                    f"(seq {seq}): the trail was cut short", "aqt-trail verify")
            if point.get("seq") == seq and point.get("head") != head:
                return Result(FAIL, f"the record at the last checkpoint (seq {seq}) was rewritten", "aqt-trail verify")
    matched = Text("cli.check.intact.matches", " and matches the writer") if writer else ""
    return Result(OK, Text("cli.check.intact.ok", "head seq {seq} is signed by the service key{matched}; full check: "
                           "aqt status --verify", seq=seq, matched=matched),
                  data={"head_seq": seq, "head": head, "verified": False})


def _full_verify(config, keys) -> Result:
    from aqt_trail.signers import load_registry, registry_keys
    from aqt_trail.tsa import load_ca
    from aqt_trail.verify import verify_trail
    ca_path = config.section("anchor").get("tsa_ca")
    report = verify_trail(config.trail_path, keys=keys, checkpoints=config.checkpoints_path,
                          tsa_ca=load_ca(ca_path) if ca_path else None, signer_keys=registry_keys(load_registry()),
                          log_id=config.meta().get("log_id"))
    data = {"head_seq": report.head_seq, "head": report.head, "verified": True, "warnings": len(report.warnings)}
    if report.ok:
        return Result(OK, report.summary(), data=data)
    return Result(FAIL, report.summary(), "aqt-trail verify", data=data)


def check_vectors(ctx: Context) -> Result:
    from aqt_evidence.vectors import run_all
    results = run_all()
    failed = [result.file for result in results if not result.ok]
    if failed:
        return Result(FAIL, f"{len(failed)} of {len(results)} test vectors disagree ({', '.join(failed[:3])})",
                      "aqt-evidence vectors")
    return Result(OK, Text("cli.check.vectors.ok", "{n} of {total} test vectors agree", n=len(results), total=len(results)))


def _egress_status() -> dict | None:
    """aqt-egress's own status, or None when the optional package is not installed."""
    if importlib.util.find_spec("aqt_egress") is None:
        return None
    from aqt_egress.cli import status
    return status()


def _box_fix() -> str:
    """What makes bubblewrap work here: on Ubuntu with the AppArmor user-namespace restriction, a profile for bwrap."""
    if shutil.which("bwrap") is None:
        return "install bubblewrap (bwrap)"
    try:
        restricted = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").read_text().strip() == "1"
    except OSError:
        restricted = False
    if restricted:
        return ("AppArmor blocks bwrap's user namespaces: add an AppArmor profile for bwrap "
                "(manual 6.4, 'bubblewrap cannot create namespaces')")
    return "allow unprivileged user namespaces for bwrap (manual 6.4)"


def check_egress(ctx: Context) -> Result:
    """The optional outbound checkpoint: never a failure, whether it is installed or not."""
    try:
        value = _egress_status()
    except Exception as error:  # noqa: BLE001 - an optional part must not fail the verdict
        return Result(WARN, f"aqt-egress is installed but its status could not be read: {type(error).__name__}: "
                            f"{error}", tools.install_command("aqt-egress"))
    if value is None:
        return Result(SKIP, Text("cli.check.egress.missing", "aqt-egress (optional outbound checkpoint) is not installed"))
    if not value.get("box") and not platform.IS_LINUX:   # the box needs Linux: no fix to offer elsewhere
        return Result(SKIP, f"aqt-egress {value.get('version')} is installed, but {value.get('box_detail')}",
                      data=value)
    last = value.get("last_session")
    parts = [f"aqt-egress {value.get('version')}",
             "CA present" if value.get("ca") else "no CA yet (the first run creates it)",
             f"last session {last.get('session')} ended {last.get('ended')}, {last.get('requests', 0)} request(s)"
             if last else "no session yet"]
    if not value.get("box"):
        return Result(WARN, ", ".join(parts) + f"; the box cannot start here: {value.get('box_detail')}",
                      _box_fix(), data=value)
    if platform.IS_MACOS:          # what Seatbelt cannot do that the Linux box does, said rather than hidden
        parts.append(value.get("box_detail"))
    return Result(OK, ", ".join(parts), data=value)


CHECKS: list[Check] = [
    Check("packages", check_packages),
    Check("command", check_command),
    Check("trail.init", check_trail_init, step_trail_init, "create the trail (aqt-trail init)"),
    Check("service", check_service, step_service,
          lambda ctx: f"install and load the LaunchAgent {LABEL}" if platform.IS_MACOS
          else f"install and start the systemd user service {UNIT}"),
    Check("writer", check_writer, step_writer,
          lambda ctx: f"start the writer (launchctl kickstart {launchd_target()})" if platform.IS_MACOS
          else "start the writer (systemctl --user start aqt-trail)"),
    Check("spool", check_spool, step_spool, "move spooled records into the trail (aqt-trail drain)"),
    Check("sink", check_sink),
    Check("signer", check_signer, step_signer, "enrol your signing identity (aqt-signoff init)", personal=True),
    Check("signoff.config", check_signoff_config, step_signoff_config,
          "write signoff.toml with your default signer and time zone"),
    Check("trail.config", check_trail_config, step_trail_config,
          "write trail.toml with the review time zone and working hours"),
    Check("trail.intact", check_trail_intact),
    Check("vectors", check_vectors),
    Check("egress", check_egress),
]


# -- running ---------------------------------------------------------------------------------
def run_check(ctx: Context, check: Check) -> Result:
    try:
        result = check.test(ctx)
    except ModuleNotFoundError as error:
        dist = tools.distribution_of(error.name)
        result = Result(FAIL, f"needs {dist}, which is not installed", tools.install_command(dist))
    except Exception as error:  # noqa: BLE001 - one broken check must not hide the others
        result = Result(FAIL, f"could not check: {type(error).__name__}: {error}")
    result.id = check.id
    return result


def run_checks(ctx: Context, checks: list[Check] | None = None) -> list[Result]:
    return [run_check(ctx, check) for check in (CHECKS if checks is None else checks)]


def verdict(results: list[Result]) -> str:
    found = {result.result for result in results}
    return FAIL if FAIL in found else WARN if WARN in found else OK


def needs_step(check: Check, result: Result) -> bool:
    return check.step is not None and result.result in (WARN, FAIL) and result.can_apply
