"""Setup and projects for the page: aqt-cli's own checks and steps (``aqt status``, ``aqt setup``,
``aqt project status`` / ``init``) behind the first-run onboarding, Settings and the Projects area.

Nothing here is a second implementation. The checks, their explanations, their fixes and their steps are
aqt-cli's (``checks.CHECKS`` and ``project.PROJECT_CHECKS``); the page shows their results and applies their
steps one at a time. Enrolling a signer is aqt-signoff's ``init_signer``, as ``aqt-signoff init`` runs it, with
the passphrase the person typed instead of a terminal prompt. The core runs its guard before every step that
changes anything (``Core._setup_step`` and ``Core._decide``).

aqt-cli (the ``agent-quality-toolkit`` distribution) is imported lazily: without it these routes answer
"not installed", as a view without its package does.
"""

from __future__ import annotations

import os
import shutil
import sys
import unicodedata
from pathlib import Path
from typing import Callable

from . import UsageProblem, coded_fields, require

# The machine steps the page may apply (aqt setup's steps without the personal one, enrolling a signer).
MACHINE_STEPS = ("trail.init", "service", "writer", "spool", "signoff.config", "trail.config")
# The project items the preview lists and Connect may apply, in the order aqt project init applies them.
PROJECT_ITEMS = ("claude.hooks", "claude.deny", "instructions", "change.settings", "ui.project", "git.hook")
GERMAN = {"ä": "ae", "ö": "oe", "ü": "ue", "ß": "ss", "Ä": "Ae", "Ö": "Oe", "Ü": "Ue"}


def _cli():
    require("aqt_cli", "agent-quality-toolkit")
    from aqt_cli import checks, project
    return checks, project


def _quiet(_text: str) -> None:
    pass


def _row(checks, check, result) -> dict:
    """A check result as the page shows it: aqt status's fields plus whether the page can apply its step."""
    return {**result.as_dict(), **coded_fields("explanation", result.explanation),
            "can_apply": checks.needs_step(check, result) and not check.personal,
            "personal": check.personal, "does": check.describe(checks.Context(say=_quiet)) if check.step else ""}


# -- the machine -----------------------------------------------------------------------------------------
def state() -> dict:
    """Is the setup complete enough to use the desk? (a trail and a signer with an active key); cheap."""
    checks, _ = _cli()
    trail = checks.run_check(checks.Context(say=_quiet),
                             next(c for c in checks.CHECKS if c.id == "trail.init")).result == checks.OK
    try:
        _settings, registry = checks._signoff()
        signers = checks._active_signers(registry)
    except Exception:  # noqa: BLE001 - a broken registry shows up in the signer check
        signers = []
    return {"needed": not (trail and signers), "trail": trail, "signer": bool(signers), "signers": signers}


def command_info() -> dict:
    """Where the ``aqt`` command is: on PATH, and the one this process runs as (when it is one)."""
    own = os.path.abspath(sys.argv[0]) if sys.argv and os.path.basename(sys.argv[0]).split(".")[0] in (
        "aqt", "aqt-toolkit") else None
    return {"on_path": shutil.which("aqt"), "this": own}


def status() -> dict:
    """``aqt status``: every check with its result, explanation and fix, plus what the onboarding needs."""
    checks, _ = _cli()
    ctx = checks.Context(say=_quiet)
    rows = [_row(checks, check, checks.run_check(ctx, check)) for check in checks.CHECKS]
    try:
        settings, _registry = checks._signoff()
        minimum = settings.passphrase_min_length
    except Exception:  # noqa: BLE001 - shown by the signer check
        minimum = 12
    service = next(row for row in rows if row["id"] == "service")
    return {"verdict": checks.verdict([checks.Result(row["result"], "") for row in rows]), "checks": rows,
            **state(), "passphrase_min": minimum, "service": service["result"] != checks.SKIP or None,
            "command": command_info()}


def apply(check_id: str) -> dict:
    """Apply one machine step of ``aqt setup`` as ``aqt setup --yes`` would, then check again."""
    checks, _ = _cli()
    if check_id not in MACHINE_STEPS:
        raise UsageProblem(f"{check_id or '(none)'} is not a setup step the page can apply")
    check = next(c for c in checks.CHECKS if c.id == check_id)
    said: list[str] = []
    ctx = checks.Context(yes=True, say=said.append)
    applied = checks.needs_step(check, checks.run_check(ctx, check))
    error = _apply(checks, ctx, check)
    result = checks.run_check(ctx, check)
    return {"ok": error is None and result.result != checks.FAIL, "check": _row(checks, check, result),
            "error": error, "said": said, "applied": applied and error is None}


def _apply(checks, ctx, check, step: Callable | None = None) -> str | None:
    """Run the check's step when it needs one; the error in words, or None."""
    if not checks.needs_step(check, checks.run_check(ctx, check)):
        return None
    try:
        (step or check.step)(ctx)
    except checks.StepSkipped as skipped:
        return f"skipped: {skipped}"
    except Exception as error:  # noqa: BLE001 - reported to the page, as aqt setup reports it
        return str(error) or type(error).__name__
    return None


def ascii_name(name: str) -> str:
    """``Jürgen Müller`` -> ``Juergen Mueller``: the letters an ID can keep."""
    text = "".join(GERMAN.get(char, char) for char in name)
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")


def signer_id(name: str = "", custom: str = "") -> dict:
    """The signer ID for ``name`` (or the ``custom`` one typed under Customise), checked with aqt-signoff's rule
    (``checks.SIGNER_ID``) and against the registry: IDs are never reused."""
    checks, _ = _cli()
    if custom.strip():
        value = checks._signer_id(custom)
    elif name.strip():
        value = checks._suggest_signer_id("human:" + ascii_name(name))
    else:
        value = ""
    valid = bool(value) and bool(checks.SIGNER_ID.match(value))
    taken = False
    if valid:
        try:
            _settings, registry = checks._signoff()
            taken = any(signer.id == value for signer in registry.signers)
        except Exception:  # noqa: BLE001 - the enrolment itself refuses a reused ID
            taken = False
    suggestion = None if valid else checks._suggest_signer_id(ascii_name(value)) if value else None
    return {"id": value, "valid": valid and not taken, "taken": taken, "suggestion": suggestion,
            "rule": "lower case letters, digits, . _ or -, after human:"}


def enrol(*, name: str, role: str, signer: str, passphrase: str, human_check: Callable) -> dict:
    """Create the signer and its key, as ``aqt-signoff init --id --name --role`` does, then write signoff.toml
    with this signer as the default (aqt setup's next step). The passphrase unlocks nothing else and is
    dropped with the request."""
    checks, _ = _cli()
    from .changes import signoff_call
    from .signatures import open_signoff
    value = checks._signer_id(signer)
    if not checks.SIGNER_ID.match(value):
        raise UsageProblem(f"{value or '(empty)'} is not a valid signer ID: lower case letters, digits, . _ or -, "
                           f"for example {checks._suggest_signer_id(ascii_name(value))}")
    if not name.strip() or not role.strip():
        raise UsageProblem("a printed name and a role are needed")
    so = open_signoff(passphrase=passphrase, human_check=human_check)
    stored, refusal = signoff_call(so, lambda: so.init_signer(value, name.strip(), role.strip()))
    if refusal:
        return refusal
    key_id = (stored.get("data") or {}).get("key_id")
    evidence = so.trust().key_evidence(key_id, value) if key_id else None
    counts = bool(evidence and evidence.counts)
    ctx = checks.Context(yes=True, signer_id=value, say=_quiet)
    config = next(c for c in checks.CHECKS if c.id == "signoff.config")
    _apply(checks, ctx, config)
    return {"ok": True, "record_id": stored.get("id"), "time": stored.get("time"), "signer_id": value,
            "key_id": key_id, "counts": counts,
            "message": f"enrolled {value} with key {key_id}" + ("" if counts else
                                                                 "; it counts once another enrolled signer approves it")}


# -- projects ----------------------------------------------------------------------------------------------
def _project_ctx(path: str, say=_quiet):
    _checks, project = _cli()
    if not str(path or "").strip():
        raise UsageProblem("choose a folder")
    candidate = Path(str(path)).expanduser()
    if not candidate.is_absolute():
        raise UsageProblem("give the folder as a full path, for example ~/code/my-project")
    try:
        root, git = project.resolve_root(candidate)
    except (OSError, ValueError) as error:
        raise UsageProblem(str(error)) from error
    return project.ProjectContext(root=root, git=git, say=say, yes=True)


def _shown(project, ctx, path: Path) -> str:
    return project.show(ctx, path)


def _preview_text(project, ctx, check_id: str, result) -> tuple[str | None, str]:
    """(the file it writes, what goes into it) for one project item."""
    data = result.data or {}
    if check_id == "claude.hooks":
        lines = [f"{hook['event']}{' ' + hook['matcher'] if hook.get('matcher') not in (None, '', '*') else ''}: "
                 f"{hook['command']}" for hook in data.get("missing", [])]
        return _shown(project, ctx, project.settings_target(ctx)), "\n".join(lines)
    if check_id == "claude.deny":
        return _shown(project, ctx, project.settings_target(ctx)), "\n".join(data.get("missing", []))
    if check_id == "instructions":
        files = [name for name, state in (data.get("files") or {}).items() if state != "current"]
        return " + ".join(files) or "CLAUDE.md", project.instructions_block()
    if check_id == "change.settings":
        return ".aqt/change.toml", project.change_settings_text(project.service_key_id())
    if check_id == "ui.project":
        return _shown(project, ctx, project.ui_config_path()), f"[changes] projects += \"{project._project_entry(ctx.root)}\""
    if check_id == "git.hook":
        try:
            hook = _shown(project, ctx, project._commit_msg_hook(ctx))
        except Exception:  # noqa: BLE001 - no aqt-change or no git: the check says so
            hook = ".git/hooks/commit-msg"
        return hook, 'aqt-change hook commit-msg "$1"'
    return None, ""


def _exists(project, ctx, check_id: str) -> bool:
    if check_id in ("claude.hooks", "claude.deny"):
        return project.settings_target(ctx).exists()
    if check_id == "instructions":
        return any(path.exists() for path in project.instruction_files(ctx))
    if check_id == "ui.project":
        return project.ui_config_path().exists()
    return False


def _project_rows(checks, project, ctx) -> list[dict]:
    rows = []
    for check in project.PROJECT_CHECKS:
        result = checks.run_check(ctx, check)
        row = {**result.as_dict(), **coded_fields("explanation", result.explanation),
               "can_apply": checks.needs_step(check, result)}
        if check.id in PROJECT_ITEMS:
            row["file"], row["preview"] = _preview_text(project, ctx, check.id, result)
            row["backup"] = row["can_apply"] and _exists(project, ctx, check.id)
        rows.append(row)
    return rows


def project_preview(path: str) -> dict:
    """What ``aqt project init DIR`` would write, item by item, without writing anything."""
    checks, project = _cli()
    ctx = _project_ctx(path)
    rows = _project_rows(checks, project, ctx)
    return {"root": str(ctx.root), "git": ctx.git, "checks": rows,
            "items": [row for row in rows if row["id"] in PROJECT_ITEMS],
            "backup_dir": project.show(ctx, project.backup_dir(ctx.root)),
            "connected": any(row["id"] == "ui.project" and row["result"] == checks.OK for row in rows)}


def project_connect(path: str, items) -> dict:
    """Apply the chosen items of ``aqt project init`` in its order (each changed file is backed up first, nothing
    is committed), then check the project again."""
    checks, project = _cli()
    chosen = {str(item) for item in items or []} & set(PROJECT_ITEMS)
    if not chosen:
        raise UsageProblem("choose at least one item")
    said: list[str] = []
    ctx = _project_ctx(path, say=said.append)
    errors = {}
    for check in project.PROJECT_CHECKS:
        if check.step is None or check.id not in chosen:
            continue
        step = None
        if check.id == "claude.hooks":       # the hooks, with the deny rules only when those are chosen too
            step = lambda c: project._merge_settings(c, hooks=True, deny="claude.deny" in chosen)  # noqa: E731
        error = _apply(checks, ctx, check, step)
        if error:
            errors[check.id] = error
    rows = _project_rows(checks, project, ctx)
    done = [row["id"] for row in rows if row["id"] in chosen and row["result"] == checks.OK and row["id"] not in errors]
    return {"ok": not errors, "root": str(ctx.root), "errors": errors, "said": said, "checks": rows, "done": done,
            "backups": sum(1 for line in said if "(backup:" in line),
            "backup_dir": project.show(ctx, project.backup_dir(ctx.root))}


def projects(paths) -> dict:
    """``aqt project status`` of every project listed in ui.toml."""
    checks, project = _cli()
    out = []
    for index, path in enumerate(paths):
        entry = {"index": index, "root": str(path)}
        if not Path(path).is_dir():
            out.append({**entry, "missing": True, "verdict": checks.FAIL, "checks": []})
            continue
        try:
            ctx = _project_ctx(str(Path(path).expanduser().resolve()))
        except UsageProblem as error:
            out.append({**entry, "missing": True, "verdict": checks.FAIL, "checks": [], "error": str(error)})
            continue
        rows = [{**result.as_dict(), **coded_fields("explanation", result.explanation),
                 "can_apply": checks.needs_step(check, result)}
                for check, result in ((check, checks.run_check(ctx, check)) for check in project.PROJECT_CHECKS)]
        out.append({**entry, "root": str(ctx.root), "git": ctx.git, "checks": rows,
                    "verdict": checks.verdict([checks.Result(row["result"], "") for row in rows])})
    return {"projects": out, "config": str(project.ui_config_path()), "can_disconnect": False}
