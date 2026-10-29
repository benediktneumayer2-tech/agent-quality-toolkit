"""The setup checklist as code.

Every entry of ``CHECKS`` has a test (result ok / warn / fail / skip, a one-line explanation
and the fix as a command) and, where the toolkit can do the fix itself, a step. ``aqt status``
runs the tests; ``aqt setup`` runs them and applies the steps. Both use this one list, so the
status and the setup cannot drift apart.

Steps never overwrite keys, the signer registry or an existing configuration file. The one
personal step (enrolling a signer) always leaves the passphrase to aqt-signoff's own prompt.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import date
from importlib import metadata
from pathlib import Path
from typing import Callable

from . import tools

OK, WARN, FAIL, SKIP = "ok", "warn", "fail", "skip"
DISTRIBUTIONS = ("aqt-spec", "aqt-trail", "aqt-signoff", "aqt-change", "aqt-sensei", "aqt-quarantine",
                 "aqt-validate", "aqt-capa", "aqt-ui")
UNIT = "aqt-trail.service"
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
    run_tool: Callable[[str, list[str]], int] | None = None   # default: tools.run_tool
    ask: Callable[[str], str] = input
    say: Callable[[str], None] = print
    writer_wait_s: float = 5.0                   # how long a step waits for a started writer
    _systemd: bool | None = field(default=None, repr=False)

    def systemd(self, *args: str) -> tuple[int, str]:
        return (self.systemctl or systemctl_user)(*args)

    def tool(self, name: str, argv: list[str]) -> int:
        return (self.run_tool or tools.run_tool)(name, argv)

    def systemd_available(self) -> bool:
        if self._systemd is None:
            self._systemd = self.systemd("show-environment")[0] == 0
        return self._systemd

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
    does: str = ""            # what the step does, as aqt setup lists it
    personal: bool = False    # needs the person: an ID to choose and a passphrase to type


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
    """The ``aqt-trail`` of the environment ``aqt`` runs in."""
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


def _start_fix(ctx: Context, config) -> str:
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
        return Result(FAIL, f"not installed: {', '.join(missing)}", tools.install_command(*missing),
                      data={"versions": versions})
    distinct = sorted(set(versions.values()))
    text = (f"all {len(versions)} packages installed, version {distinct[0]}" if len(distinct) == 1 else
            "installed: " + ", ".join(f"{dist} {version}" for dist, version in versions.items()))
    return Result(OK, text, data={"versions": versions})


def check_trail_init(ctx: Context) -> Result:
    config = _trail()
    if config.meta_path.exists():
        return Result(OK, f"trail {config.meta()['log_id']} in {config.state}")
    external = _writer_head(config)
    if external:
        return Result(OK, f"no trail state here, but a writer serves trail {external.get('log_id')} on "
                          f"{config.socket_path} (separate-user mode)")
    return Result(FAIL, f"no trail in {config.state}", "aqt-trail init")


def step_trail_init(ctx: Context) -> None:
    if ctx.tool("trail", ["init"]) != 0:
        raise StepFailed("aqt-trail init did not succeed")


def check_service(ctx: Context) -> Result:
    if not ctx.systemd_available():
        return Result(SKIP, "systemd --user is not available here; the writer is started by hand")
    unit = unit_path()
    if not unit.exists():
        if _external_writer(_trail()):
            return Result(SKIP, "the writer runs outside your user services (separate-user mode)")
        return Result(WARN, f"no user service {unit}: the writer does not start at login", "aqt setup")
    executable = _unit_executable(unit)
    if executable and not Path(executable).exists():
        return Result(WARN, f"{unit} starts {executable}, which does not exist",
                      f"edit ExecStart in {unit}, then: systemctl --user daemon-reload", can_apply=False)
    _code, state = ctx.systemd("is-enabled", "aqt-trail")
    if state not in ("enabled", "enabled-runtime"):
        return Result(WARN, f"{UNIT} is installed but not enabled ({state or 'unknown'})",
                      "systemctl --user enable --now aqt-trail")
    return Result(OK, f"{UNIT} enabled, starts {executable}")


def step_service(ctx: Context) -> None:
    if not _trail().meta_path.exists():
        raise StepSkipped("create the trail first (aqt-trail init)")
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
        return Result(OK, f"running on {config.socket_path}, head seq {head.get('seq')}",
                      data={"socket": str(config.socket_path), "head_seq": head.get("seq")})
    if not config.meta_path.exists():
        return Result(SKIP, "no trail yet")
    can_start = ctx.systemd_available() and unit_path().exists()
    how = "" if can_start else "; start it in a terminal of its own and keep it running"
    return Result(FAIL, f"no writer answers on {config.socket_path}{how}", _start_fix(ctx, config),
                  can_apply=can_start)


def step_writer(ctx: Context) -> None:
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
        return Result(OK, "spool empty")
    return Result(WARN, f"{count} record(s) wait in {spool_file()} and are not in the trail yet",
                  "aqt-trail drain", data={"spooled": count})


def step_spool(ctx: Context) -> None:
    if ctx.tool("trail", ["drain"]) != 0:
        raise StepFailed("aqt-trail drain did not succeed")


_SOURCES = {"env": "set by AQT_SINK", "discovered": "found automatically", "default": "the default"}


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
        where = "the trail writer" if kind == "unix" else "the file"
        return Result(OK, f"records go to {where} {target} ({origin})", data=info)
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
        return Result(FAIL, f"no signer with an active key in {settings.registry_path}", SIGNER_FIX)
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
    bad = [key for key in keys if not key.get("counts")]
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
    notes = [f"{key['signer']}: {note}" for key in keys for note in key.get("notes") or []]
    if notes:
        return Result(WARN, f"{len(counting)} signer(s) enrolled ({', '.join(counting)}), to check: {'; '.join(notes)}",
                      "aqt-signoff signers check", data=data, can_apply=False)
    return Result(OK, f"{len(counting)} signer(s) enrolled and backed by enrolment records in the "
                      f"{report.get('evidence')}: {', '.join(counting)}", data=data)


def step_signer(ctx: Context) -> None:
    signer_id, name, role = ctx.signer_id, ctx.name, ctx.role
    if not signer_id:
        if not ctx.interactive:
            raise StepSkipped(f"needs you at the keyboard: run 'aqt setup' in your terminal, or: {SIGNER_FIX}")
        if not ctx.confirm("Enrol your signing identity now (you choose an ID and type a passphrase)?"):
            raise StepSkipped(f"not now; later: {SIGNER_FIX}")
        signer_id = ctx.prompt("Your ID, for example human:alice (never reused): ")
    if signer_id and not signer_id.startswith("human:"):
        signer_id = f"human:{signer_id}"
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
        need = "" if active else " (enrol a signer first)"
        return Result(WARN, f"no {path}: signing commands need --signer every time{need}", "aqt setup")
    if not settings.signer:
        return Result(WARN, f"{path} names no default signer",
                      f'add signer = "{active[0] if active else "human:<you>"}" under [signoff] in {path}',
                      can_apply=False)
    if settings.signer not in active:
        return Result(FAIL, f"{path} names {settings.signer}, who has no active key in {settings.registry_path}",
                      "aqt-signoff signers list", can_apply=False)
    return Result(OK, f"default signer {settings.signer}, time zone {settings.tz}")


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
        return Result(WARN, f"no {path}: the audit-trail review assumes UTC and 07:00-19:00 on weekdays",
                      "aqt setup")
    review = _trail().section("review")
    return Result(OK, f"{path}: review time zone {review['timezone']}, "
                      f"{review['work_start']}-{review['work_end']}")


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
        return Result(SKIP, "no trail state here")
    if not config.trail_path.exists():
        return Result(OK, "the trail has no records yet")
    keys = service_keys(config)
    if ctx.verify:
        return _full_verify(config, keys)
    writer = _writer_head(config)          # before reading the file: the writer may append meanwhile
    line = _last_line(config.trail_path)
    if line is None:
        return Result(OK, "the trail has no records yet")
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
    matched = " and matches the writer" if writer else ""
    return Result(OK, f"head seq {seq} is signed by the service key{matched}; full check: aqt status --verify",
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
    return Result(OK, f"{len(results)} of {len(results)} test vectors agree")


CHECKS: list[Check] = [
    Check("packages", check_packages),
    Check("trail.init", check_trail_init, step_trail_init, "create the trail (aqt-trail init)"),
    Check("service", check_service, step_service, f"install and start the systemd user service {UNIT}"),
    Check("writer", check_writer, step_writer, "start the writer (systemctl --user start aqt-trail)"),
    Check("spool", check_spool, step_spool, "move spooled records into the trail (aqt-trail drain)"),
    Check("sink", check_sink),
    Check("signer", check_signer, step_signer, "enrol your signing identity (aqt-signoff init)", personal=True),
    Check("signoff.config", check_signoff_config, step_signoff_config,
          "write signoff.toml with your default signer and time zone"),
    Check("trail.config", check_trail_config, step_trail_config,
          "write trail.toml with the review time zone and working hours"),
    Check("trail.intact", check_trail_intact),
    Check("vectors", check_vectors),
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
