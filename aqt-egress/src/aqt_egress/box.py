"""The box: bubblewrap with its own network namespace, whose only way out is the proxy.

``bwrap`` gets new user, network, PID and IPC namespaces, ``--disable-userns`` (no nested user
namespaces, so no ``unshare`` inside), ``--die-with-parent``, ``--info-fd`` (the launcher learns
the box's first process) and a start gate (the command starts only after the launcher has set
up the box's network and opened the listeners in it, see ``netns``).

Files stay as they are: ``/`` is bound read-write, so the user's home and the agents'
configuration work unchanged. Exceptions:

- fresh ``/proc``, a minimal ``/dev``, an empty ``/run`` (it holds the host's service sockets:
  the system and session D-Bus, systemd, systemd-resolved, docker, libvirt, the user's runtime
  folder), with the AQT runtime folder (the trail writer's socket) put back read-only;
- ``/etc/resolv.conf`` names the box resolver; the system CA bundle includes the session CA;
- ``/run/aqt-egress``: the CA certificate and the combined bundle (read-only);
- hidden (empty): the egress state (CA key, body store, fingerprint key), the quarantine state,
  the X11 and tmux socket folders in ``/tmp``;
- read-only: the AQT configuration and state folders (the spool folder stays writable, so
  records of agent hooks still reach the trail when its writer is down);
- with ``private_tmp``: a fresh, empty ``/tmp`` (the project, the home folder and the AQT folders are
  put back where they live under ``/tmp``), which also closes the Unix sockets of other programs there.

The empty ``/run`` has side effects: keyrings reached over the session D-Bus (``gh``, git's libsecret
credential helper, secret-service clients) and aqt-sensei's bridge sockets are not available in the box.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import signal
import subprocess
import sys
import tomllib
from pathlib import Path

from aqt_evidence import spool_file, state_dir

from .netns import PROXY_PORT, system_tool
from .settings import config_home, egress_state

BOX_DIR = "/run/aqt-egress"
SYSTEM_BUNDLES = ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem")
CA_VARIABLES = ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "PIP_CERT")
# The start gate, the box's first command: it starts the real command only on the exact token from the
# launcher. The end of the pipe (a launcher killed before release) is not a start: the gate exits.
GATE = 'IFS= read -r go < "/proc/self/fd/$1" && [ "$go" = "$2" ] || exit 125; shift 2; exec "$@"'


class BoxUnavailable(RuntimeError):
    pass


def bwrap_path() -> str | None:
    """bwrap from a root-owned system folder only (``netns.system_tool``), never from PATH."""
    return system_tool("bwrap")


def tool_facts() -> dict:
    """Path and SHA-256 of the programs that build the box, for the session record."""
    facts = {}
    for name in ("bwrap", "nft", "ip"):
        path = system_tool(name)
        if path:
            facts[name] = {"path": path, "sha256": "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()}
    return facts


def installation() -> list[str]:
    """The folders aqt-egress runs from (its interpreter, packages and sources), read-only in the box:
    otherwise the box could change the code of the next session's launcher or helper."""
    import aqt_egress
    import aqt_evidence
    import mitmproxy
    folders = {Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve()}
    folders |= {Path(module.__file__).resolve().parent for module in (aqt_egress, aqt_evidence, mitmproxy)}
    ordered = sorted(folders, key=lambda path: len(path.parts))
    kept = [path for index, path in enumerate(ordered) if not any(path.is_relative_to(other) for other in ordered[:index])]
    return [str(path) for path in kept if path != Path("/")]


def available() -> tuple[bool, str]:
    """Can a box start here? (bubblewrap present, user and network namespaces allowed)."""
    bwrap = bwrap_path()
    if not bwrap:
        return False, "bubblewrap (bwrap) is not installed"
    try:
        done = subprocess.run([bwrap, "--ro-bind", "/", "/", "--unshare-user", "--unshare-net", "--unshare-pid",
                               "--disable-userns", "--die-with-parent", "--", "true"],
                              capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as error:
        return False, f"bwrap could not run: {error}"
    if done.returncode != 0:
        return False, f"bwrap cannot create the box here: {done.stderr.strip() or done.returncode}"
    return True, "bubblewrap with user and network namespaces works"


def bwrap_version() -> str | None:
    bwrap = bwrap_path()
    try:
        return subprocess.run([bwrap, "--version"], capture_output=True, text=True, timeout=10).stdout.strip() \
            if bwrap else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def system_bundle() -> Path | None:
    return next((Path(path) for path in SYSTEM_BUNDLES if Path(path).is_file()), None)


def write_public(folder: Path, ca_cert: bytes) -> dict[str, Path]:
    """The files the box sees in ``/run/aqt-egress``: CA certificate, combined bundle, resolv.conf."""
    folder.mkdir(parents=True, exist_ok=True)
    files = {"ca": folder / "ca.pem", "bundle": folder / "bundle.pem", "resolv": folder / "resolv.conf"}
    files["ca"].write_bytes(ca_cert)
    system = system_bundle()
    files["bundle"].write_bytes((system.read_bytes().rstrip(b"\n") + b"\n" if system else b"") + ca_cert)
    files["resolv"].write_text("# aqt-egress: every name is answered by the box resolver\n"
                               "nameserver 127.0.0.1\noptions edns0 trust-ad\n")
    for path in files.values():
        os.chmod(path, 0o644)
    return files


def box_environment(base: dict, session: str) -> dict:
    proxy = f"http://127.0.0.1:{PROXY_PORT}"
    env = dict(base)
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        env[name] = env[name.lower()] = proxy
    # the box's own loopback is not outbound: local servers inside the box stay reachable directly
    env["NO_PROXY"] = env["no_proxy"] = "localhost,127.0.0.1,::1"
    for name in CA_VARIABLES:
        env[name] = f"{BOX_DIR}/bundle.pem"
    env["NODE_EXTRA_CA_CERTS"] = f"{BOX_DIR}/ca.pem"
    env["NODE_USE_ENV_PROXY"] = "1"
    env["AQT_EGRESS_SESSION"] = session
    env["AQT_AGENT_SESSION"] = session        # AQT human checks see an agent; hook records name this session
    for name in [key for key in env if key.startswith("AQT_EGRESS_TEST")]:
        del env[name]
    return env


def _quarantine_state() -> Path:
    if os.environ.get("AQT_QUARANTINE_STATE"):
        return Path(os.environ["AQT_QUARANTINE_STATE"]).expanduser()
    config = Path(os.environ.get("AQT_QUARANTINE_CONFIG") or config_home() / "quarantine.toml").expanduser()
    try:
        with open(config, "rb") as handle:
            value = tomllib.load(handle).get("paths", {}).get("state_dir")
        if value:
            return Path(value).expanduser()
    except (OSError, tomllib.TOMLDecodeError):
        pass
    return state_dir() / "quarantine"


def _legacy_tiocsti() -> bool:
    try:
        return Path("/proc/sys/dev/tty/legacy_tiocsti").read_text().strip() != "0"
    except OSError:
        return True      # older kernels: TIOCSTI always works, so keep the box off the terminal's session


def _under_tmp(path: Path) -> bool:
    return path.resolve().is_relative_to("/tmp") and path.resolve() != Path("/tmp")


def bwrap_argv(command: list[str], *, project: Path, public: dict[str, Path], info_fd: int,
               block_fd: int, token: str = "go", private_tmp: bool = False) -> tuple[list[str], dict]:
    """The bwrap command line and the facts about it (for the session record)."""
    bwrap = bwrap_path()
    if not bwrap:
        raise BoxUnavailable("bubblewrap (bwrap) is not installed in a system folder (/usr/bin, /bin)")
    argv = [bwrap, "--die-with-parent", "--unshare-user", "--unshare-net", "--unshare-pid", "--unshare-ipc",
            "--disable-userns", "--bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/run"]
    hidden, read_only = [], []
    if Path("/sys/fs/cgroup").is_dir():          # the user's cgroups hold the proxy too: no freezing or killing it
        argv += ["--ro-bind", "/sys/fs/cgroup", "/sys/fs/cgroup"]
        read_only.append("/sys/fs/cgroup")
    if private_tmp:
        argv += ["--tmpfs", "/tmp"]
        for folder in (project, Path.home(), config_home().parent, state_dir().parent):
            if folder.is_dir() and _under_tmp(folder):
                argv += ["--bind", str(folder.resolve()), str(folder.resolve())]
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime and (Path(runtime) / "aqt").is_dir():
        argv += ["--ro-bind", str(Path(runtime) / "aqt"), str(Path(runtime) / "aqt")]
        read_only.append(str(Path(runtime) / "aqt"))
    resolv = Path(os.path.realpath("/etc/resolv.conf"))
    argv += ["--ro-bind", str(public["resolv"]), str(resolv)]
    bundle = system_bundle()
    if bundle:
        argv += ["--ro-bind", str(public["bundle"]), os.path.realpath(bundle)]
    argv += ["--ro-bind", str(public["ca"].parent), BOX_DIR]
    for folder in (config_home(), state_dir()):
        if folder.is_dir():
            argv += ["--ro-bind", str(folder), str(folder)]
            read_only.append(str(folder))
    for folder in installation():
        argv += ["--ro-bind", folder, folder]
        read_only.append(folder)
    spool = spool_file().parent
    if spool.is_relative_to(state_dir()) and state_dir().is_dir():
        spool.mkdir(parents=True, exist_ok=True)
        os.chmod(spool, 0o700)
        argv += ["--bind", str(spool), str(spool)]
    sockets = () if private_tmp else (Path("/tmp/.X11-unix"), Path(f"/tmp/tmux-{os.getuid()}"))
    for folder in (egress_state(), _quarantine_state(), *sockets):
        if folder.is_dir():
            argv += ["--tmpfs", str(folder)]
            hidden.append(str(folder))
    new_session = _legacy_tiocsti()
    if new_session:
        argv.append("--new-session")
    argv += ["--chdir", str(project), "--info-fd", str(info_fd), "--", "/bin/sh", "-c", GATE, "aqt-egress-gate",
             str(block_fd), token, *command]
    facts = {"bwrap": bwrap_version(), "tools": tool_facts(), "kernel": platform.release(), "hidden": hidden,
             "read_only": read_only,
             "run": "empty tmpfs", "tmp": "private" if private_tmp else "shared", "new_session": new_session}
    return argv, facts


class BoxProcess:
    """A started bwrap whose command waits until ``release()``."""

    def __init__(self, command: list[str], *, project: Path, public: dict[str, Path], env: dict,
                 private_tmp: bool = False):
        info_r, info_w = os.pipe()
        block_r, block_w = os.pipe()
        self._token = os.urandom(16).hex()
        try:
            argv, self.facts = bwrap_argv(command, project=project, public=public, info_fd=info_w,
                                          block_fd=block_r, token=self._token, private_tmp=private_tmp)
            self.process = subprocess.Popen(argv, pass_fds=(info_w, block_r), env=env)
        except BaseException:
            for fd in (info_r, info_w, block_r, block_w):
                os.close(fd)
            raise
        os.close(info_w)
        os.close(block_r)
        self._block = block_w
        self.info = self._read_info(info_r)
        self.init_pid: int = self.info["child-pid"]

    def _read_info(self, fd: int) -> dict:
        data = b""
        try:
            while True:
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                data += chunk
                try:
                    return json.loads(data)
                except ValueError:
                    continue
        finally:
            os.close(fd)
        self.process.wait()
        raise BoxUnavailable(f"bwrap did not start the box (exit {self.process.returncode})")

    def release(self) -> None:
        """Let the command start."""
        os.write(self._block, self._token.encode() + b"\n")
        os.close(self._block)
        self._block = None

    def kill(self) -> None:
        # The box's first process outlives the outer bwrap until the command starts (its parent-death
        # signal is set only then); the gate would exit on the pipe's end anyway, but kill it by its pid
        # first, then bwrap, and only then close the pipe.
        init_pid = getattr(self, "init_pid", None)
        if init_pid:
            try:
                os.kill(init_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait()
        if self._block is not None:
            os.close(self._block)
            self._block = None
