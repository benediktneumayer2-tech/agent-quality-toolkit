"""The advisor's sandbox: platform profiles and the bubblewrap command line.

The advisor sees the system read-only, the project read-only, its scratch
folder read-write, its own pair's runtime folder read-only (advisor socket,
`sensei` shim, Herdr proxy), the resolved advisor CLI read-only and a private
agent home for its platform. Everything else in /home, /tmp and /run is hidden.
The environment is cleared and rebuilt from an allow-list.

`build_argv()` is a pure function of its inputs, so tests assert the exact
command line without running bwrap.

On macOS the same limits come from a generated Seatbelt profile (``sandbox-exec``, see
``seatbelt_profile()``): reads are refused in the user folders (``/Users``, ``/Volumes``, the
temporary folders) except the project, the CLI, the private home, the scratch folder and the pair's
runtime folder; writes only in the private home and the scratch folder; Unix sockets only in the pair's
runtime folder (and the system resolver's, with network); the keychain is not reachable (it would
show the owner's own logins). Seatbelt cannot give an empty home or ``/tmp``: ``HOME`` is the
private home and ``TMPDIR`` a folder in the scratch folder. ``docs/sandbox.md`` compares the two.

``sandbox_unavailable()`` says why the sandbox cannot run on other systems.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import socket
import threading
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from string import Template

from aqt_evidence import content_hash, platform, seatbelt

PROMPT_FILE = ".sensei-prompt.md"
HERDR_REPORTS = ("pane.report_agent", "pane.report_agent_session", "pane.release_agent")
BASE_ENV = ("LANG", "LC_ALL", "TERM", "COLORTERM", "TZ")

# Built-in profiles. Flags switch off the CLIs' own approval prompts and nested
# sandboxes: bubblewrap enforces the limits, and prompts would stall the pair.
BUILTIN_PROFILES: dict[str, dict] = {
    "claude": {
        "command": ["claude", "--append-system-prompt-file", "{prompt_file}", "--add-dir", "{project}",
                    "--permission-mode", "bypassPermissions", "--strict-mcp-config",
                    "--settings", '{"sandbox":{"enabled":false}}'],
        "model_args": ["--model", "{model}"],
        "prompt": "file",
        "env": {"CLAUDE_CONFIG_DIR": "{home}", "DISABLE_AUTOUPDATER": "1"},
        "prompt_pattern": r"(^|[│|]\s*)[>❯](\s|$)",
        "cost_per_exchange": 0,
    },
    "codex": {
        "command": ["codex", "--search", "-s", "danger-full-access", "-a", "never", "-C", "{scratch}"],
        "model_args": ["-m", "{model}"],
        "prompt": "agents-md",
        "env": {"CODEX_HOME": "{home}"},
        "prompt_pattern": r"(^|\s)›(\s|$)",
        "cost_per_exchange": 0,
    },
    "pi": {
        "command": ["pi"],
        "model_args": ["--model", "{model}"],
        "prompt": "agents-md",
        "env": {"PI_CODING_AGENT_DIR": "{home}"},
        "prompt_pattern": None,
        "cost_per_exchange": 0,
    },
}


class SandboxError(RuntimeError):
    pass


@dataclass
class Profile:
    name: str
    command: list[str]
    model_args: list[str] = field(default_factory=list)
    prompt: str = "agents-md"           # file | agents-md
    env: dict = field(default_factory=dict)
    ro_binds: list[str] = field(default_factory=list)
    prompt_pattern: str | None = None
    cost_per_exchange: int = 0
    platform: str = "custom"

    def as_dict(self) -> dict:
        return {"name": self.name, "command": self.command, "model_args": self.model_args, "prompt": self.prompt,
                "env": self.env, "ro_binds": self.ro_binds, "prompt_pattern": self.prompt_pattern,
                "cost_per_exchange": self.cost_per_exchange, "platform": self.platform}

    def sha256(self) -> str:
        return content_hash(self.as_dict())


def resolve_profile(advisor: str, overrides: dict | None = None) -> Profile:
    """A built-in or configured profile by name, or a custom command line."""
    overrides = overrides or {}
    if advisor in BUILTIN_PROFILES or advisor in overrides:
        merged = {**BUILTIN_PROFILES.get(advisor, {}), **overrides.get(advisor, {})}
        if not merged.get("command"):
            raise SandboxError(f"profile {advisor!r} has no command")
        platform = advisor if advisor in BUILTIN_PROFILES else "custom"
        return Profile(name=advisor, platform=platform, command=list(merged["command"]),
                       model_args=list(merged.get("model_args") or []), prompt=merged.get("prompt", "agents-md"),
                       env=dict(merged.get("env") or {}), ro_binds=list(merged.get("ro_binds") or []),
                       prompt_pattern=merged.get("prompt_pattern"),
                       cost_per_exchange=int(merged.get("cost_per_exchange") or 0))
    argv = shlex.split(advisor)
    if not argv:
        raise SandboxError("the advisor command is empty")
    return Profile(name="custom", platform="custom", command=argv)


# ------------------------------------------------------------------- prompt

def render_prompt(pair: dict) -> str:
    template = resources.files("aqt_sensei").joinpath("prompts/advisor.md").read_text()
    budget = pair.get("budget") or {}
    limits = ", ".join(f"{key.removeprefix('max_')} {value}" for key, value in budget.items() if value) or "unlimited"
    return Template(template).safe_substitute(
        pair_name=pair.get("name") or pair["id"], project_root=pair["project_root"],
        scratch_dir=pair["scratch_dir"], worker_platform=pair["worker"].get("platform") or "unknown",
        worker_model=pair["worker"].get("model") or "its default model", mode=pair["mode"], budget=limits,
        network=("Web search and fetch are available for research." if pair.get("network") == "share"
                 else "There is no network access."))


def write_prompt(pair: dict, profile: Profile) -> Path:
    scratch = Path(pair["scratch_dir"])
    scratch.mkdir(parents=True, exist_ok=True)
    target = scratch / (PROMPT_FILE if profile.prompt == "file" else "AGENTS.md")
    target.write_text(render_prompt(pair))
    return target


# --------------------------------------------------------------- resolution

def _under(path: Path, folders: list[Path]) -> bool:
    return any(path == folder or folder in path.parents for folder in folders)


def sandbox_unavailable() -> str | None:
    """None where the advisor sandbox can run (Linux: bubblewrap, macOS: Seatbelt), else why not."""
    if platform.IS_LINUX:
        return None
    if platform.IS_MACOS:
        reason = seatbelt.unavailable()
        return platform.not_available("the sensei sandbox", reason) if reason else None
    return platform.not_available("the sensei sandbox", "the system has no sandbox like bubblewrap that works "
                                  "without administrator rights")


def require_sandbox() -> None:
    """Raise ``SandboxError`` where the sandbox cannot run (before anything is started)."""
    reason = sandbox_unavailable()
    if reason:
        raise SandboxError(reason)


def resolve_cli(argv0: str, *, which=shutil.which, home: Path | None = None) -> tuple[str, list[str]]:
    """The executable path and the bwrap binds that make it (and its runtime) visible.

    Symlinks are recreated; the real file's install root is bound read-only: the
    folder above `node_modules` for npm packages, else the file's folder. A
    `#!/usr/bin/env node`-style script also gets its interpreter resolved.
    """
    home = home or Path.home()
    found = which(argv0)
    if not found:
        raise SandboxError(f"advisor command {argv0!r} was not found on PATH")
    binds: list[str] = []
    system = [Path("/usr"), Path("/bin"), Path("/sbin"), Path("/lib"), Path("/lib64"), Path("/opt"), Path("/etc")]
    path = Path(found)
    seen = 0
    while path.is_symlink() and seen < 16:
        target = os.readlink(path)
        if not _under(path, system):
            binds += ["--symlink", target, str(path)]
        path = (path.parent / target).resolve() if not os.path.isabs(target) else Path(target)
        seen += 1
    real = path.resolve()
    if not _under(real, system):
        parts = real.parts
        root = (Path(*parts[:parts.index("node_modules")]) if "node_modules" in parts else real.parent)
        binds += ["--ro-bind", str(root), str(root)]
    try:
        first = real.open("rb").readline(200)
    except OSError:
        first = b""
    if first.startswith(b"#!") and b"env " in first:
        words = first.split(b"env ", 1)[1].split()
        interpreter = words[0].decode() if words else ""
        if interpreter and interpreter not in ("sh", "bash"):
            binds += resolve_cli(interpreter, which=which, home=home)[1]
    return found, binds


# ----------------------------------------------------------------- the argv

def _expand(value: str, values: dict) -> str:
    for key, replacement in values.items():
        value = value.replace("{" + key + "}", replacement)
    return value


def _values(pair: dict, platform_home: Path) -> dict:
    return {"prompt_file": str(Path(pair["scratch_dir"]) / PROMPT_FILE), "scratch": pair["scratch_dir"],
            "project": pair["project_root"], "home": str(platform_home),
            "model": pair["advisor"].get("model") or "", "session": pair["advisor"].get("session") or ""}


def _environment(pair: dict, profile: Profile, *, paths, config, environ, home: Path, values: dict) -> dict:
    pair_runtime = paths.pair_runtime(pair["id"])
    env = {"HOME": str(home), "PATH": f"{pair_runtime / 'bin'}:/usr/local/bin:/usr/bin:/bin",
           "AQT_SENSEI_SOCKET": str(paths.advisor_socket(pair["id"])), "AQT_AGENT_SESSION": "1",
           "AQT_SENSEI_ROLE": "advisor", "AQT_SENSEI_PAIR": pair["id"]}
    for name in (*BASE_ENV, *config.env_allow):
        if environ.get(name) is not None:
            env[name] = environ[name]
    env.update({key: _expand(value, values) for key, value in profile.env.items()})
    return env


def _command(pair: dict, profile: Profile, cli_path: str, platform_home: Path, values: dict) -> list[str]:
    command = [cli_path] + [_expand(part, values) for part in profile.command[1:]]
    if pair["advisor"].get("model") and profile.model_args:
        command += [_expand(part, values) for part in profile.model_args]
    if profile.platform == "claude" and pair["advisor"].get("session"):
        session = pair["advisor"]["session"]
        known = any(platform_home.glob(f"projects/*/{session}.jsonl")) if platform_home.exists() else False
        command += ["--resume" if known else "--session-id", session]
    return command


def env_names(argv: list[str]) -> list[str]:
    """The variable names a sandbox command line sets (bwrap ``--setenv``, or ``env -i NAME=value`` on macOS)."""
    if "--clearenv" in argv:
        return [argv[i + 1] for i, item in enumerate(argv[:-1]) if item == "--setenv"]
    names, start = [], argv.index("-i") + 1 if "-i" in argv else len(argv)
    for item in argv[start:]:
        name, equals, _value = item.partition("=")
        if not equals or not name.replace("_", "a").isalnum() or name[0].isdigit():
            break
        names.append(name)
    return names


def build_argv(pair: dict, profile: Profile, *, paths, config, cli_path: str, cli_binds: list[str],
               environ: dict | None = None, home: Path | None = None, command: list[str] | None = None,
               proxy: tuple[str, str] | None = None, root_dirs: tuple[str, ...] = ("bin", "sbin", "lib", "lib64", "lib32"),
               fs=os.path, macos: bool | None = None) -> list[str]:
    """The full sandbox command line for this pair's advisor (or `command` instead of the CLI): bwrap on
    Linux, ``sandbox-exec`` on macOS (``macos`` chooses explicitly, for tests)."""
    if platform.IS_MACOS if macos is None else macos:
        return seatbelt_argv(pair, profile, paths=paths, config=config, cli_path=cli_path, cli_binds=cli_binds,
                             environ=environ, home=home, command=command, proxy=proxy)
    environ = os.environ if environ is None else environ
    home = home or Path.home()
    platform_home = paths.home(profile.platform if profile.platform != "custom" else f"custom-{profile.name}")
    pair_runtime = paths.pair_runtime(pair["id"])
    values = _values(pair, platform_home)

    args = [config.bwrap, "--unshare-all", "--die-with-parent"]
    if pair.get("network", config.network) == "share":
        args.append("--share-net")
    args += ["--ro-bind", "/usr", "/usr", "--ro-bind", "/etc", "/etc", "--ro-bind-try", "/opt", "/opt"]
    for name in root_dirs:
        path = "/" + name
        if fs.islink(path):
            args += ["--symlink", os.readlink(path), path]
        elif fs.isdir(path):
            args += ["--ro-bind", path, path]
    args += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/run",
             "--ro-bind-try", "/run/systemd/resolve", "/run/systemd/resolve",
             "--tmpfs", str(home.parent), "--dir", str(home)]
    args += ["--ro-bind", pair["project_root"], pair["project_root"]]
    args += cli_binds
    for item in [*profile.ro_binds, *config.extra_ro_binds]:
        path = os.path.expanduser(_expand(item, values))
        args += ["--ro-bind-try", path, path]
    args += ["--bind", str(platform_home), str(platform_home)]
    args += ["--bind", pair["scratch_dir"], pair["scratch_dir"]]
    args += ["--ro-bind", str(pair_runtime), str(pair_runtime)]
    if proxy:
        args += ["--ro-bind", proxy[0], proxy[1]]
    args += ["--chdir", pair["scratch_dir"], "--clearenv"]

    env = _environment(pair, profile, paths=paths, config=config, environ=environ, home=home, values=values)
    if proxy:
        env.update({"HERDR_ENV": "1", "HERDR_SOCKET_PATH": proxy[1], "HERDR_PANE_ID": pair["advisor"]["pane_id"]})
    for key, value in env.items():
        args += ["--setenv", key, value]

    if command is None:
        command = _command(pair, profile, cli_path, platform_home, values)
    return args + ["--"] + command


# ------------------------------------------------------------- macOS: Seatbelt

TMP_FOLDER = ".tmp"       # TMPDIR inside the scratch folder (Seatbelt cannot give an empty /tmp)


def user_folders(home: Path) -> list[str]:
    """Where the user's own files are on macOS: hidden from the advisor, except what it is given."""
    return [seatbelt.real(home.parent), "/Volumes", "/private/tmp", "/private/var/folders", "/private/var/root"]


def cli_paths(cli_binds: list[str]) -> list[str]:
    """The paths a bwrap bind list of ``resolve_cli`` makes visible: link paths and bound folders."""
    found = []
    for index, item in enumerate(cli_binds):
        if item == "--symlink":
            found.append(cli_binds[index + 2])
        elif item in ("--ro-bind", "--ro-bind-try"):
            found.append(cli_binds[index + 1])
    return found


def seatbelt_profile(*, project: str, scratch: str, private_home: str, pair_runtime: str, readable: list[str],
                     hidden: list[str], network: bool) -> str:
    """The advisor's profile: read the system and the given folders, write the private home and the scratch
    folder, connect to Unix sockets in the pair's runtime folder only; the IP network only with ``network``."""
    real = seatbelt.real
    writable = [real(private_home), real(scratch)]
    visible = [real(project), *(real(path) for path in readable), *writable, real(pair_runtime)]
    # A link on the way to the CLI (Claude Code's installer: ~/.local/bin/claude -> its version) is read
    # itself before its target; real() would allow only the target.
    links = [os.path.join(real(os.path.dirname(path)), os.path.basename(path))
             for path in readable if os.path.islink(path)]
    lines = seatbelt.base_rules(seatbelt.MACH_SERVICES + (seatbelt.NETWORK_SERVICES if network else ()))
    lines += ["(allow file-read*)"]
    lines += seatbelt.rule("deny", "file-read*", "subpath", hidden)
    lines += seatbelt.rule("allow", "file-read*", "subpath", visible)
    lines += seatbelt.rule("allow", "file-read*", "literal", links)
    folders = [folder for path in visible for folder in seatbelt.ancestors(path)]
    for link in links:
        folders += [os.path.dirname(link), *seatbelt.ancestors(os.path.dirname(link))]
    lines += seatbelt.rule("allow", "file-read-metadata", "literal", folders)   # realpath() walks them
    lines += [*seatbelt.DEVICES]
    lines += seatbelt.rule("allow", "file-write*", "subpath", writable)
    lines += ["(allow system-socket (socket-domain AF_UNIX))"]
    quote = seatbelt.quote
    lines += [f"(allow network-bind (local unix-socket (subpath {quote(path)})))" for path in writable]
    lines += [f"(allow network-outbound (remote unix-socket (subpath {quote(path)})))"
              for path in [real(pair_runtime), *writable]]
    if network:
        lines += [f"(allow network-outbound (remote unix-socket (path-literal {seatbelt.quote(seatbelt.MDNS_SOCKET)})))",
                  '(allow network-outbound (remote ip "*:*"))', '(allow network-bind (local ip "*:*"))',
                  '(allow network-inbound (local ip "*:*"))']
    return "\n".join(lines) + "\n"


def seatbelt_argv(pair: dict, profile: Profile, *, paths, config, cli_path: str, cli_binds: list[str],
                  environ: dict | None = None, home: Path | None = None, command: list[str] | None = None,
                  proxy: tuple[str, str] | None = None) -> list[str]:
    """``sandbox-exec -p PROFILE /usr/bin/env -i NAME=value ... COMMAND``; the caller starts it in the
    scratch folder."""
    environ = os.environ if environ is None else environ
    home = home or Path.home()
    platform_home = paths.home(profile.platform if profile.platform != "custom" else f"custom-{profile.name}")
    values = _values(pair, platform_home)
    readable = cli_paths(cli_binds)
    for item in [*profile.ro_binds, *config.extra_ro_binds]:
        readable.append(os.path.expanduser(_expand(item, values)))
    text = seatbelt_profile(project=pair["project_root"], scratch=pair["scratch_dir"],
                            private_home=str(platform_home), pair_runtime=str(paths.pair_runtime(pair["id"])),
                            readable=readable, hidden=user_folders(home),
                            network=pair.get("network", config.network) == "share")
    env = _environment(pair, profile, paths=paths, config=config, environ=environ, home=platform_home,
                       values=values)
    env["TMPDIR"] = str(Path(pair["scratch_dir"]) / TMP_FOLDER)
    if proxy:
        env.update({"HERDR_ENV": "1", "HERDR_SOCKET_PATH": proxy[0], "HERDR_PANE_ID": pair["advisor"]["pane_id"]})
    if command is None:
        command = _command(pair, profile, cli_path, platform_home, values)
    return [seatbelt.SANDBOX_EXEC, "-p", text, "/usr/bin/env", "-i",
            *(f"{key}={value}" for key, value in env.items()), *command]


# -------------------------------------------------------------- Herdr proxy

def herdr_request_allowed(line: bytes, pane_id: str) -> bool:
    try:
        request = json.loads(line)
    except ValueError:
        return False
    return (isinstance(request, dict) and request.get("method") in HERDR_REPORTS
            and isinstance(request.get("params"), dict) and request["params"].get("pane_id") == pane_id)


def proxy_connection(connection: socket.socket, pane_id: str, upstream_path: str) -> None:
    """Forward only the advisor's own lifecycle reports to the real Herdr socket."""
    with connection:
        connection.settimeout(30)
        buffer = b""
        while True:
            try:
                chunk = connection.recv(65536)
            except OSError:
                return
            if not chunk:
                return
            buffer += chunk
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                if herdr_request_allowed(line, pane_id):
                    try:
                        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as upstream:
                            upstream.settimeout(5)
                            upstream.connect(upstream_path)
                            upstream.sendall(line + b"\n")
                            reply = b""
                            while not reply.endswith(b"\n"):
                                part = upstream.recv(65536)
                                if not part:
                                    break
                                reply += part
                    except OSError:
                        reply = b'{"error":{"code":"unavailable","message":"herdr unreachable"}}\n'
                else:
                    reply = b'{"error":{"code":"forbidden","message":"sensei sandbox: only own reports"}}\n'
                try:
                    connection.sendall(reply if reply.endswith(b"\n") else reply + b"\n")
                except OSError:
                    return


def start_herdr_proxy(path: Path, pane_id: str, upstream_path: str) -> None:
    """Fork a proxy that lives as long as its parent (which then execs bwrap)."""
    path.unlink(missing_ok=True)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    os.chmod(path, 0o600)
    server.listen(8)
    parent = os.getpid()
    if os.fork() == 0:
        os.setsid()  # leave the pane's foreground group, so the host sees only the agent
        server.settimeout(1)
        while os.getppid() == parent:
            try:
                connection, _ = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=proxy_connection, args=(connection, pane_id, upstream_path), daemon=True).start()
        path.unlink(missing_ok=True)
        os._exit(0)
    server.close()


# --------------------------------------------------------------------- shim

def write_shim(folder: Path) -> Path:
    """The stdlib-only `sensei` command the advisor runs inside the sandbox."""
    source = resources.files("aqt_sensei").joinpath("agent.py").read_text()
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = folder / "sensei"
    target.write_text("#!/usr/bin/env python3\n" + source)
    target.chmod(0o700)
    return target
