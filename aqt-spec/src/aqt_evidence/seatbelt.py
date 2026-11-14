"""Seatbelt (macOS ``sandbox-exec``): the parts of a profile that aqt-sensei's advisor sandbox and
aqt-egress's box share.

The profiles follow the approach of Anthropic's sandbox-runtime and the Codex CLI: closed by default
(``(deny default)``), then what a command-line program needs from the system (processes, ``sysctl``
reads, terminals, a short list of system services), then each tool's own file and network rules.

Rules of the profile language that the tools rely on (checked on macOS 26 with ``sandbox-exec``):

- the last matching rule wins, so a later ``allow`` re-opens part of an earlier ``deny``;
- paths are matched after symbolic links are resolved: profiles name real paths (``/private/tmp``,
  not ``/tmp``), and a link to a denied file is denied too;
- a hard link to a file in a folder without write access is refused (so a read-only file cannot be
  written through a link made elsewhere);
- a folder can be renamed (and with it everything below moved out of a rule's path) unless
  ``file-write-unlink`` is denied on it: ``move_guard()`` denies that for every folder above a
  protected path;
- signals and process inspection are limited to the same sandbox (``kill``, task ports); setuid
  programs such as ``ps`` do not start; launchd refuses to create jobs (``launchctl submit`` or
  ``bootstrap``) for a sandboxed process;
- ``(remote ip "localhost:PORT")`` matches connections to ``127.0.0.1`` and ``::1`` on that port only.

What Seatbelt cannot do, compared with Linux namespaces: give a process an empty or private view of a
folder (a path is allowed or refused, never replaced), its own loopback interface, or its own process
list (names and arguments of the user's other processes stay readable through ``sysctl``).
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

SANDBOX_EXEC = "/usr/bin/sandbox-exec"

# System services a command-line program needs (sandbox-runtime's list without the keychain).
MACH_SERVICES = (
    "com.apple.audio.systemsoundserver", "com.apple.distributed_notifications@Uv3", "com.apple.FontObjectsServer",
    "com.apple.fonts", "com.apple.logd", "com.apple.lsd.mapdb", "com.apple.PowerManagement.control",
    "com.apple.system.logger", "com.apple.system.notification_center", "com.apple.system.opendirectoryd.libinfo",
    "com.apple.system.opendirectoryd.membership", "com.apple.bsd.dirhelper", "com.apple.coreservices.launchservicesd",
)
KEYCHAIN_SERVICES = ("com.apple.SecurityServer", "com.apple.securityd.xpc")
# Network configuration and certificate checks (the Codex CLI's network policy). trustd and ocspd fetch
# URLs named in certificates themselves, outside any proxy: only for a sandbox whose network is open anyway.
NETWORK_SERVICES = ("com.apple.SecurityServer", "com.apple.networkd", "com.apple.ocspd", "com.apple.trustd.agent",
                    "com.apple.SystemConfiguration.DNSConfiguration", "com.apple.SystemConfiguration.configd")
MDNS_SOCKET = "/private/var/run/mDNSResponder"     # every name lookup of the system resolver goes through it


def quote(value) -> str:
    """A string literal of the profile language."""
    return json.dumps(str(value))


def real(path) -> str:
    """The path as Seatbelt matches it (links resolved; ``/tmp`` is ``/private/tmp``)."""
    return os.path.realpath(os.path.expanduser(str(path)))


def ancestors(path) -> list[str]:
    """The folders above ``path``, nearest first, without ``/``."""
    found, current = [], os.path.dirname(real(path))
    while current not in ("/", ""):
        found.append(current)
        current = os.path.dirname(current)
    return found


def rule(action: str, operations: str, kind: str, paths) -> list[str]:
    """``(action operations (kind "p1") (kind "p2") ...)``, or nothing for no paths."""
    paths = list(dict.fromkeys(paths))
    if not paths:
        return []
    return [f"({action} {operations}", *(f"  ({kind} {quote(path)})" for path in paths), ")"]


def move_guard(paths) -> list[str]:
    """Deny renaming or removing each protected path and every folder above it: otherwise a folder could be
    moved away with the protected path inside, out of the rule's reach (sandbox-runtime does the same)."""
    folders = []
    for path in paths:
        folders += [real(path), *ancestors(path)]
    return rule("deny", "file-write-unlink", "literal", folders)


def base_rules(services=MACH_SERVICES) -> list[str]:
    lines = [
        "(version 1)",
        "(deny default)",
        "(allow process-exec)",
        "(allow process-fork)",
        "(allow process-info* (target same-sandbox))",
        "(allow signal (target same-sandbox))",
        "(allow mach-priv-task-port (target same-sandbox))",
        "(allow user-preference-read)",
        "(allow sysctl-read)",
        '(allow sysctl-write (sysctl-name "kern.tcsm_enable") (sysctl-name "kern.grade_cputype"))',
        "(allow ipc-posix-shm)",
        "(allow ipc-posix-sem)",
        '(allow iokit-open (iokit-registry-entry-class "IOSurfaceRootUserClient")',
        '  (iokit-registry-entry-class "RootDomainUserClient") (iokit-user-client-class "IOSurfaceSendRight"))',
        "(allow iokit-get-properties)",
        "(allow distributed-notification-post)",
        "(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))",
        "(allow pseudo-tty)",
        '(allow file-ioctl (literal "/dev/ptmx") (literal "/dev/tty") (regex #"^/dev/ttys[0-9]+$")',
        '  (literal "/dev/null") (literal "/dev/zero") (literal "/dev/random") (literal "/dev/urandom")',
        '  (literal "/dev/dtracehelper"))',
    ]
    lines += rule("allow", "mach-lookup", "global-name", services)
    return lines


DEVICES = ('(allow file-read* file-write* (literal "/dev/ptmx") (literal "/dev/tty") (regex #"^/dev/ttys[0-9]+$")',
           '  (literal "/dev/null") (literal "/dev/zero") (literal "/dev/dtracehelper") (regex #"^/dev/fd/"))')


def unavailable() -> str | None:
    """None when ``sandbox-exec`` runs a profile here, else why not."""
    if not os.access(SANDBOX_EXEC, os.X_OK):
        return f"{SANDBOX_EXEC} is missing"
    try:
        done = subprocess.run([SANDBOX_EXEC, "-p", "(version 1)(allow default)", "/usr/bin/true"],
                              capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as error:
        return f"sandbox-exec could not run: {error}"
    if done.returncode != 0:
        return f"sandbox-exec cannot apply a profile here: {done.stderr.strip() or done.returncode}"
    return None


def write_profile(path: Path, text: str) -> Path:
    """The profile as a private file (kept as evidence of what ran)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    os.chmod(path, 0o600)
    return path
