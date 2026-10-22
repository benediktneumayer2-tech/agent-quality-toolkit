"""`aqt-sensei doctor`: prove the host setup and the advisor sandbox.

Host checks run outside the sandbox. The probe runs *inside* the exact sandbox
of a pair (or of a profile for a project) and reports, with evidence, that the
project is read-only, the scratch folder writable, the owner's files, token,
state and sockets invisible, the environment limited to the allow-list, and
the advisor socket reachable.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .config import Config, Paths
from .launch import home_of, load_pair, prepare, profile_of
from .sandbox import SandboxError, resolve_cli, resolve_profile

# Runs inside the sandbox with `python3 -I -c PROBE SPEC`; standard library only.
PROBE = r'''
import json, os, socket, sys
spec = json.loads(sys.argv[1]); checks = []
def check(name, passed, detail=""):
    checks.append({"name": name, "passed": bool(passed), "detail": str(detail)[:300]})
probe = os.path.join(spec["project"], ".aqt-sensei-probe")
try:
    with open(probe, "w") as handle:
        handle.write("x")
    os.unlink(probe)
    check("project is read-only", False, "a file could be written into the project")
except OSError as error:
    check("project is read-only", True, error.strerror)
target = os.path.join(spec["scratch"], ".aqt-sensei-probe")
try:
    with open(target, "w") as handle:
        handle.write("x")
    os.unlink(target)
    check("scratch folder is writable", True)
except OSError as error:
    check("scratch folder is writable", False, error.strerror)
for path in spec["hidden"]:
    check(f"hidden: {path}", not os.path.lexists(path), "visible" if os.path.lexists(path) else "not visible")
extra = sorted(set(os.environ) - set(spec["env_allowed"]))
check("environment limited to the allow-list", not extra, ", ".join(extra) or "only allowed names")
parent = spec.get("pairs_dir")
if parent:
    try:
        others = sorted(set(os.listdir(parent)) - {spec["pair_id"]})
    except OSError:
        others = []
    check("other pairs are invisible", not others, ", ".join(others) or "only this pair")
if spec.get("socket"):
    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(5)
        client.connect(spec["socket"])
        client.sendall(b'{"op": "status"}\n')
        reply = json.loads(client.recv(65536) or b"{}")
        client.close()
        check("advisor socket answers", reply.get("status") == "available", reply.get("message") or "status ok")
    except (OSError, ValueError) as error:
        check("advisor socket answers", False, error)
print(json.dumps(checks))
'''


def host_checks(config: Config, paths: Paths, backend: str) -> list[dict]:
    checks = []

    def check(name, passed, detail=""):
        checks.append({"name": name, "passed": bool(passed), "detail": str(detail)[:300]})

    bwrap = shutil.which(config.bwrap)
    check("bubblewrap installed", bwrap, bwrap or f"{config.bwrap} not found")
    if bwrap:
        try:
            done = subprocess.run([bwrap, "--ro-bind", "/", "/", "--unshare-all", "true"],
                                  capture_output=True, text=True, timeout=20)
            detail = "ok" if done.returncode == 0 else (
                (done.stderr.strip() or "failed") + " (Ubuntu's AppArmor may restrict user namespaces; "
                "see docs/sandbox.md)")
            check("bubblewrap can create namespaces", done.returncode == 0, detail)
        except (OSError, subprocess.TimeoutExpired) as error:
            check("bubblewrap can create namespaces", False, error)
    tool = {"tmux": "tmux", "herdr": "herdr"}.get(backend)
    if tool:
        found = shutil.which(tool)
        check(f"{tool} installed", found, found or "not found")
    check("owner token exists", paths.token_file.exists(), str(paths.token_file) if paths.token_file.exists()
          else "run aqt-sensei init")
    return checks


def _env_names(argv: list[str]) -> list[str]:
    return [argv[i + 1] for i, item in enumerate(argv[:-1]) if item == "--setenv"]


def hidden_paths(paths: Paths, home: Path, pair_id: str) -> list[str]:
    candidates = [paths.token_file, paths.config_file, paths.state / "pairs.json", paths.state / "messages",
                  paths.owner_socket, paths.agent_socket, home / ".ssh", home / ".gnupg", home / ".claude",
                  home / ".claude.json", home / ".codex", home / ".pi", home / ".config", home / ".netrc"]
    return [str(path) for path in candidates]


def sandbox_probe(pair: dict, *, paths: Paths, config: Config, home: Path | None = None,
                  runner=subprocess.run, with_socket: bool = True, resolve=resolve_cli) -> list[dict]:
    home = home or Path.home()
    spec = {"project": pair["project_root"], "scratch": pair["scratch_dir"], "pair_id": pair["id"],
            "pairs_dir": str(paths.runtime / "pairs"), "hidden": hidden_paths(paths, home, pair["id"]),
            "socket": str(paths.advisor_socket(pair["id"])) if with_socket else None, "env_allowed": []}
    argv = prepare(pair, paths=paths, config=config, command=["python3", "-I", "-c", PROBE, "{spec}"], proxy=False,
                   resolve=resolve)
    spec["env_allowed"] = _env_names(argv) + ["PWD"]  # bwrap sets PWD itself on --chdir
    argv[-1] = json.dumps(spec)
    done = runner(argv, capture_output=True, text=True, timeout=60)
    try:
        checks = json.loads(done.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return [{"name": "sandbox probe ran", "passed": False,
                 "detail": (done.stderr or done.stdout or "no output").strip()[-300:]}]
    profile = profile_of(pair)
    if profile.platform != "custom":
        try:
            cli_path = resolve(profile.command[0])[0]
            argv = prepare(pair, paths=paths, config=config, command=[cli_path, "--version"], proxy=False,
                           resolve=resolve)
            version = runner(argv, capture_output=True, text=True, timeout=60)
            checks.append({"name": "advisor CLI starts in the sandbox", "passed": version.returncode == 0,
                           "detail": (version.stdout or version.stderr).strip()[:300]})
        except (OSError, SandboxError, subprocess.TimeoutExpired) as error:
            checks.append({"name": "advisor CLI starts in the sandbox", "passed": False, "detail": str(error)})
    return [{"name": "sandbox probe ran", "passed": True, "detail": "ok"}, *checks]


def doctor_pair(pair_id: str, *, paths: Paths, config: Config) -> dict:
    pair = load_pair(paths, pair_id)
    checks = host_checks(config, paths, pair["backend"])
    checks += sandbox_probe(pair, paths=paths, config=config)
    return {"pair_id": pair_id, "checks": checks, "passed": all(c["passed"] for c in checks)}


def doctor_profile(advisor: str, project: str, *, paths: Paths, config: Config, backend: str) -> dict:
    """Probe a profile's sandbox for a project without a running pair."""
    profile = resolve_profile(advisor, config.profiles)
    project = os.path.realpath(project)
    if not os.path.isdir(project):
        raise SandboxError("--project must be an existing folder")
    pair_id = "doctor-" + os.urandom(3).hex()
    scratch = Path(tempfile.mkdtemp(prefix="aqt-sensei-doctor-", dir=project))
    pair = {"id": pair_id, "backend": backend, "project_root": project, "scratch_dir": str(scratch),
            "mode": "confirm", "budget": {}, "network": config.network, "name": "doctor",
            "worker": {"pane_id": None, "platform": None, "model": None},
            "advisor": {"pane_id": "doctor", "platform": profile.platform, "model": None, "session": None},
            "profile": profile.as_dict()}
    try:
        home_of(paths, profile).mkdir(parents=True, exist_ok=True, mode=0o700)
        checks = host_checks(config, paths, backend) + sandbox_probe(pair, paths=paths, config=config,
                                                                     with_socket=False)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
        shutil.rmtree(paths.pair_runtime(pair_id), ignore_errors=True)
    return {"profile": profile.name, "checks": checks, "passed": all(c["passed"] for c in checks)}


def print_checks(result: dict, out=sys.stdout) -> None:
    for check in result["checks"]:
        print(f"{'PASS' if check['passed'] else 'FAIL'}  {check['name']}" +
              (f"  ({check['detail']})" if check.get("detail") else ""), file=out)
    print("doctor: all checks passed" if result["passed"] else "doctor: some checks FAILED", file=out)
