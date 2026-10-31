"""What AQT needs in one repository, as checks plus steps: ``aqt project status`` and ``aqt project init``.

The same ``Check``/``Result``/``Context`` as the machine setup (``checks.py``), with the repository in
``ProjectContext``. The steps edit only by adding: missing Claude Code hooks and deny rules merged into
``.claude/settings.json`` (``settings.local.json`` with ``--local``), the agent-instruction block between
``<!-- aqt:begin -->`` and ``<!-- aqt:end -->`` in ``CLAUDE.md``/``AGENTS.md``, a new ``.aqt/change.toml``, this
repository in aqt-ui's ``[changes] projects``, and the aqt-change commit-msg hook when there is none. Every file
they change is backed up first, outside the repository (an untracked file in it would make aqt-change receipts
stale). They never commit.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
import tomllib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .checks import FAIL, OK, SKIP, WARN, Check, Context, Result, StepSkipped, _trail

MODULES = {"aqt-trail": "aqt_trail", "aqt-quarantine": "aqt_quarantine", "aqt-change": "aqt_change",
           "aqt-signoff": "aqt_signoff", "aqt-capa": "aqt_capa", "aqt-validate": "aqt_validate",
           "aqt-sensei": "aqt_sensei", "aqt-ui": "aqt_ui"}

# aqt-trail's Claude Code hooks (manual 4.8, aqt-trail/examples/claude-code-hooks.json): (event, matcher).
TRAIL_HOOK = "aqt-trail hook claude-code"
TRAIL_EVENTS = (("SessionStart", None), ("UserPromptSubmit", None), ("PreToolUse", "*"), ("PostToolUse", "*"),
                ("Stop", None), ("SessionEnd", None))
EVENT_ORDER = ("SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop", "SubagentStop",
               "TaskCompleted", "SessionEnd")

# The human-decision subcommands of each tool: they refuse in an agent session (aqt_evidence.require_human),
# need the signer's passphrase, or (aqt-sensei) the owner token. Denied in both spellings, aqt-<tool> and aqt <tool>.
DECISIONS = {
    "aqt-quarantine": ("release", "declare-threat", "trust-source", "init"),
    "aqt-signoff": ("init", "signers approve", "signers import", "rekey", "revoke", "sign", "invalidate",
                    "approve", "reject", "resolve"),
    "aqt-trail": ("review sign",),
    "aqt-capa": ("candidate accept", "candidate dismiss", "deviation classify", "action approve", "action cancel",
                 "close"),
    "aqt-validate": ("qualify",),
    "aqt-sensei": ("init", "pair", "approve", "discard", "forward", "mode", "budget", "pause", "resume", "end"),
}

BEGIN, END = "<!-- aqt:begin -->", "<!-- aqt:end -->"
CHANGE_MD = """## Change control (aqt-change)

- Work on a change under a plan: `aqt-change plan new plans/<id>.md --id <id> --title "<title>"`, fill in the
  approved paths, tasks and verification items, accept it with
  `aqt-change reconcile plans/<id>.md --kind semantic --reason "<why>"`, then
  `aqt-change begin plans/<id>.md --reason "<why>"`.
- Verify only with `aqt-change run --plan plans/<id>.md --item <V-id>` (or `--all`): the tool runs the declared
  command itself and records a receipt. Never tick a `[V..]` item without a fresh passing receipt.
- Close the work with `aqt-change finish plans/<id>.md --key <key> --summary "<what changed>"`.
"""
PERSON_MD = """## Decisions belong to a person

- Never run the toolkit's decision commands: releasing or trusting quarantined content, declaring a threat,
  approving, signing, revoking, enrolling or re-keying, CAPA and qualification decisions, the audit-trail
  review signature, advisor (aqt-sensei) decisions and `aqt-ui`. Most refuse in an agent session and record
  the attempt. Never type or ask for a passphrase.
- Never edit the AQT configuration or state folders (`$XDG_CONFIG_HOME/aqt` and `$XDG_STATE_HOME/aqt`, by
  default `~/.config/aqt` and `~/.local/state/aqt`).
- When a person is needed, tell the user the case or plan ID and what waits for them.
"""
COMMIT_MESSAGE = "AQT project setup"
LOCAL_SETTINGS = ".claude/settings.local.json"


@dataclass
class ProjectContext(Context):
    root: Path = field(default_factory=Path.cwd)   # the git top level, or the directory itself
    git: bool = False                              # root is a git repository
    local: bool = False                            # aqt project init --local: write .claude/settings.local.json


def resolve_root(directory: str | os.PathLike | None) -> tuple[Path, bool]:
    """DIR (default: the current directory) -> (its git top level or itself, is a git repository)."""
    start = Path(directory or ".").expanduser().resolve()
    if not start.is_dir():
        raise NotADirectoryError(f"not a directory: {start}")
    try:
        done = subprocess.run(["git", "-C", str(start), "rev-parse", "--show-toplevel"], capture_output=True,
                              text=True)
    except OSError:
        return start, False
    if done.returncode == 0 and done.stdout.strip():
        return Path(done.stdout.strip()).resolve(), True
    return start, False


def installed(dist: str) -> bool:
    return importlib.util.find_spec(MODULES[dist]) is not None


# -- paths -----------------------------------------------------------------------------------
def _home() -> Path:
    return Path(os.path.abspath(Path.home()))


def show(ctx: ProjectContext, path: Path) -> str:
    """A path as the person reads it: relative inside the repository, ``~/`` under the home folder."""
    path = Path(os.path.abspath(path))
    for base, prefix in ((ctx.root, ""), (_home(), "~/")):
        try:
            return prefix + path.relative_to(base).as_posix()
        except ValueError:
            continue
    return str(path)


def rule_path(path: Path) -> str:
    """A path for a Claude Code Read/Edit rule: ``~/…`` under the home folder, else ``//abs`` (a single
    leading ``/`` would be relative to the settings file)."""
    path = Path(os.path.abspath(path))
    try:
        return "~/" + path.relative_to(_home()).as_posix()
    except ValueError:
        return "/" + path.as_posix()


def config_dir() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "aqt"


def user_settings() -> Path:
    return Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude") / "settings.json"


def settings_target(ctx: ProjectContext) -> Path:
    return ctx.root / ".claude" / ("settings.local.json" if ctx.local else "settings.json")


def backup_dir(root: Path) -> Path:
    from aqt_evidence import state_dir
    return state_dir() / "backups" / "project-init" / f"{root.name}-{hashlib.sha256(str(root).encode()).hexdigest()[:8]}"


# -- writing ---------------------------------------------------------------------------------
def _backup(ctx: ProjectContext, path: Path) -> Path:
    folder = backup_dir(ctx.root)
    folder.mkdir(parents=True, exist_ok=True)
    folder.chmod(0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target, number = folder / f"{path.name}.{stamp}", 1
    while target.exists():
        number += 1
        target = folder / f"{path.name}.{stamp}.{number}"
    shutil.copy2(path, target)
    return target


def write_file(ctx: ProjectContext, path: Path, text: str) -> None:
    """Create ``path``, or replace it atomically (through a symlink, keeping the mode) after a backup."""
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "x", encoding="utf-8") as handle:
            handle.write(text)
        ctx.say(f"wrote {show(ctx, path)}")
        return
    real = path.resolve()
    backup = _backup(ctx, real)
    fd, temp = tempfile.mkstemp(prefix=f".{real.name}.", suffix=".aqt-tmp", dir=real.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(temp, stat.S_IMODE(real.stat().st_mode))
        os.replace(temp, real)
    except BaseException:
        if os.path.exists(temp):
            os.unlink(temp)
        raise
    ctx.say(f"wrote {show(ctx, path)} (backup: {show(ctx, backup)})")


# -- Claude Code settings: hooks and deny rules -----------------------------------------------
class SettingsError(Exception):
    """A settings file that cannot be read or has a structure this tool does not edit."""


def _structure_problem(data) -> str | None:
    if not isinstance(data, dict):
        return "the top level is not an object"
    hooks = data.get("hooks", {})
    if not isinstance(hooks, dict):
        return '"hooks" is not an object'
    for event, groups in hooks.items():
        if not isinstance(groups, list):
            return f'"hooks.{event}" is not a list'
        for group in groups:
            handlers = group.get("hooks", []) if isinstance(group, dict) else None
            if not isinstance(handlers, list) or not all(isinstance(handler, dict) for handler in handlers):
                return f'an entry of "hooks.{event}" is not an object with a "hooks" list'
    permissions = data.get("permissions", {})
    if not isinstance(permissions, dict):
        return '"permissions" is not an object'
    if not isinstance(permissions.get("deny", []), list):
        return '"permissions.deny" is not a list'
    return None


def read_settings(ctx: ProjectContext, path: Path) -> dict | None:
    """The parsed settings file, None when it does not exist."""
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise SettingsError(f"{show(ctx, path)} is not valid JSON ({error})") from error
    problem = _structure_problem(data)
    if problem:
        raise SettingsError(f"{show(ctx, path)} has a structure aqt does not edit: {problem}")
    return data


def _snippet_hooks(tool: str, snippet: dict) -> list[tuple]:
    return [(tool, event, group.get("matcher"), handler["command"])
            for event, groups in snippet.get("hooks", {}).items() for group in groups for handler in group["hooks"]]


def wanted_hooks() -> list[tuple[str, str, str | None, str]]:
    """(tool, event, matcher, command) for the installed tools, ordered by event as in manual 4.8."""
    hooks = []
    if installed("aqt-trail"):
        hooks += [("aqt-trail", event, matcher, TRAIL_HOOK) for event, matcher in TRAIL_EVENTS]
    if installed("aqt-quarantine"):
        from aqt_quarantine.cli import CLAUDE_SNIPPET
        hooks += _snippet_hooks("aqt-quarantine", CLAUDE_SNIPPET)
    if installed("aqt-change"):
        from aqt_change.hooks import SNIPPET
        hooks += _snippet_hooks("aqt-change", SNIPPET)
    order = {event: number for number, event in enumerate(EVENT_ORDER)}
    return sorted(hooks, key=lambda hook: order.get(hook[1], len(order)))


def _matcher(value) -> str:
    return "" if value in (None, "", "*") else str(value)        # Claude Code: all three match everything


def _command(value) -> str:
    """``/path/to/aqt-trail hook claude-code`` and ``aqt-trail hook claude-code`` are the same hook."""
    try:
        parts = shlex.split(str(value))
    except ValueError:
        return str(value)
    return " ".join([os.path.basename(parts[0]), *parts[1:]]) if parts else ""


def _has_hook(data: dict, event: str, matcher, command: str) -> bool:
    for group in data.get("hooks", {}).get(event, []):
        if _matcher(group.get("matcher")) == _matcher(matcher) and any(
                _command(handler.get("command", "")) == _command(command) for handler in group.get("hooks", [])):
            return True
    return False


def deny_rules() -> list[str]:
    rules = []
    for dist, subcommands in DECISIONS.items():
        if installed(dist):
            tool = dist.removeprefix("aqt-")
            for sub in subcommands:
                rules += [f"Bash({dist} {sub}:*)", f"Bash(aqt {tool} {sub}:*)"]
    if installed("aqt-ui"):
        rules += ["Bash(aqt-ui:*)", "Bash(aqt ui:*)"]
    from aqt_evidence import state_dir
    edit = [state_dir(), config_dir()]
    if installed("aqt-quarantine"):
        from aqt_quarantine.config import load_config
        try:
            quarantine = load_config().state_dir
        except Exception:  # noqa: BLE001 - a broken quarantine.toml: its doctor reports it; use the default
            quarantine = state_dir() / "quarantine"
        rules.append(f"Read({rule_path(quarantine)}/**)")
        edit.append(quarantine)
    if installed("aqt-trail"):
        trail = _trail().state
        rules.append(f"Read({rule_path(trail / 'keys')}/**)")      # the writer's unencrypted service key
        edit.append(trail)
    if installed("aqt-sensei"):
        from aqt_sensei.config import Paths
        rules.append(f"Read({rule_path(Paths.default().token_file)})")
    kept: list[Path] = []
    for folder in (Path(os.path.abspath(path)) for path in edit):
        if not any(folder == other or other in folder.parents for other in kept):
            kept.append(folder)
            rules.append(f"Edit({rule_path(folder)}/**)")
    return rules


def claude_state(ctx: ProjectContext) -> tuple[dict, list[tuple], list[str]]:
    """({path: settings} of the user, project and local file, missing hooks, missing deny rules)."""
    sources = {}
    for path in (user_settings(), ctx.root / ".claude" / "settings.json", ctx.root / LOCAL_SETTINGS):
        data = read_settings(ctx, path)
        if data is not None:
            sources[path] = data
    hooks = [hook for hook in wanted_hooks() if not any(_has_hook(data, *hook[1:]) for data in sources.values())]
    present = {rule for data in sources.values() for rule in data.get("permissions", {}).get("deny", [])
               if isinstance(rule, str)}
    return sources, hooks, [rule for rule in deny_rules() if rule not in present]


def _settings_fail(error: SettingsError) -> Result:
    return Result(FAIL, str(error), "repair the file by hand; aqt project init edits only a valid settings file",
                  can_apply=False)


def check_hooks(ctx: ProjectContext) -> Result:
    try:
        _sources, missing, _deny = claude_state(ctx)
    except SettingsError as error:
        return _settings_fail(error)
    wanted = wanted_hooks()
    tools = list(dict.fromkeys(hook[0] for hook in wanted))
    if not wanted:
        return Result(SKIP, "none of aqt-trail, aqt-quarantine and aqt-change is installed")
    if not missing:
        return Result(OK, f"all {len(wanted)} Claude Code hooks of {', '.join(tools)} are set")
    per_tool = ", ".join(f"{tool} {sum(1 for hook in missing if hook[0] == tool)}" for tool in tools
                         if any(hook[0] == tool for hook in missing))
    return Result(FAIL, f"{len(missing)} of {len(wanted)} Claude Code hooks are missing ({per_tool})",
                  "aqt project init", data={"target": show(ctx, settings_target(ctx)), "missing": [
                      {"tool": tool, "event": event, "matcher": matcher, "command": command}
                      for tool, event, matcher, command in missing]})


def check_deny(ctx: ProjectContext) -> Result:
    try:
        _sources, _hooks, missing = claude_state(ctx)
    except SettingsError as error:
        return _settings_fail(error)
    total = len(deny_rules())
    if not missing:
        return Result(OK, f"all {total} deny rules are set (decision commands, AQT folders)")
    return Result(WARN, f"{len(missing)} of {total} deny rules are missing: the agent is not stopped before "
                        "decision commands or edits of the AQT folders", "aqt project init",
                  data={"target": show(ctx, settings_target(ctx)), "missing": missing})


def _merge_settings(ctx: ProjectContext, hooks: bool) -> None:
    sources, missing_hooks, missing_deny = claude_state(ctx)
    target = settings_target(ctx)
    data = sources.get(target, {})
    if hooks:
        for _tool, event, matcher, command in missing_hooks:
            group = {} if matcher is None else {"matcher": matcher}
            group["hooks"] = [{"type": "command", "command": command}]
            data.setdefault("hooks", {}).setdefault(event, []).append(group)
    if missing_deny:
        data.setdefault("permissions", {}).setdefault("deny", []).extend(missing_deny)
    write_file(ctx, target, json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def step_hooks(ctx: ProjectContext) -> None:
    _merge_settings(ctx, hooks=True)          # the deny rules go in the same write


def step_deny(ctx: ProjectContext) -> None:
    _merge_settings(ctx, hooks=False)


# -- agent instructions ----------------------------------------------------------------------
def instructions_block() -> str:
    parts = [BEGIN, "<!-- Written by aqt project init: a rerun replaces the text between these markers. -->", ""]
    if installed("aqt-quarantine"):
        from aqt_quarantine.cli import CLAUDE_MD
        parts += [CLAUDE_MD.strip(), ""]
    if installed("aqt-change"):
        parts += [CHANGE_MD.strip(), ""]
    return "\n".join([*parts, PERSON_MD.strip(), END])


def with_block(text: str, block: str) -> str:
    """``text`` with ``block`` in place of its aqt block, or appended when it has none."""
    starts, ends = text.count(BEGIN), text.count(END)
    if not starts and not ends:
        gap = "" if not text else "\n" if text.endswith("\n") else "\n\n"
        return f"{text}{gap}{block}\n"
    start, end = text.find(BEGIN), text.find(END)
    if starts != 1 or ends != 1 or end < start:
        raise ValueError(f"has unmatched or repeated {BEGIN} / {END} markers")
    return text[:start] + block + text[end + len(END):]


def instruction_files(ctx: ProjectContext) -> list[Path]:
    """The existing CLAUDE.md and AGENTS.md at the root (one of them when one links to the other), else a new
    CLAUDE.md."""
    found, seen = [], set()
    for name in ("CLAUDE.md", "AGENTS.md"):
        path = ctx.root / name
        if path.is_file() and path.resolve() not in seen:
            seen.add(path.resolve())
            found.append(path)
    return found or [ctx.root / "CLAUDE.md"]


def _instruction_edits(ctx: ProjectContext) -> list[tuple[Path, str, str]]:
    """(file, state, new text) for each instruction file; state: current, missing, outdated or new."""
    block, edits = instructions_block(), []
    for path in instruction_files(ctx):
        if not path.exists():
            edits.append((path, "new", block + "\n"))
            continue
        text = path.read_text(encoding="utf-8")
        try:
            new = with_block(text, block)
        except ValueError as error:
            raise ValueError(f"{show(ctx, path)} {error}") from error
        edits.append((path, "current" if new == text else "outdated" if BEGIN in text else "missing", new))
    return edits


def check_instructions(ctx: ProjectContext) -> Result:
    try:
        edits = _instruction_edits(ctx)
    except ValueError as error:
        return Result(FAIL, str(error), f"leave one {BEGIN} … {END} pair (or none) in the file", can_apply=False)
    names = ", ".join(show(ctx, path) for path, _state, _text in edits)
    todo = [(path, state) for path, state, _text in edits if state != "current"]
    if not todo:
        return Result(OK, f"the agent instructions in {names} are current")
    words = {"new": "no CLAUDE.md or AGENTS.md", "missing": "no aqt block in {}", "outdated": "outdated aqt block in {}"}
    return Result(WARN, "; ".join(words[state].format(show(ctx, path)) for path, state in todo), "aqt project init",
                  data={"files": {show(ctx, path): state for path, state, _text in edits}})


def step_instructions(ctx: ProjectContext) -> None:
    for path, state, text in _instruction_edits(ctx):
        if state != "current":
            write_file(ctx, path, text)


def _instructions_does(ctx: ProjectContext) -> str:
    return f"write the agent-instruction block into {' and '.join(show(ctx, p) for p in instruction_files(ctx))}"


# -- aqt-change project settings -------------------------------------------------------------
def service_key_id() -> str | None:
    """The trail writer's service key ID, as aqt-trail init printed it (trail.json), when this account has it."""
    if not installed("aqt-trail"):
        return None
    try:
        config = _trail()
        return config.meta().get("key_id") if config.meta_path.exists() else None
    except (OSError, ValueError):
        return None


def change_settings_text(key: str | None) -> str:
    lines = ["# aqt-change project settings for this repository, written by aqt project init.",
             "# Commit this file before you begin a plan: a change to it during a plan gives MANUAL_VERIFY_REQUIRED",
             "# (project_settings_changed). Settings here can only make the checks stricter. All keys: \"Project",
             "# settings\" in aqt-change/docs/usage.md."]
    if key:
        lines += ["require_trail = true                # receipts and reviews count only when the trail confirms them",
                  f"trail_keys = [{json.dumps(key)}]  # the trail writer's service key ID",
                  "fingerprint_exclude = [\"plans/**\"]  # edits to other plan files do not make receipts stale"]
    else:
        lines += ["# The trail check is off: no trail writer's service key was found on this machine. Set both lines",
                  "# once the records of everyone who works here (CI included) go to an aqt-trail writer; otherwise",
                  "# every gate is NO-GO (trail_required). The key ID is the 'service key' line of aqt-trail init.",
                  "# require_trail = true",
                  "# trail_keys = [\"ed25519:<service key id>\"]",
                  "fingerprint_exclude = [\"plans/**\"]  # edits to other plan files do not make receipts stale"]
    lines += ["", "[gate]",
              "require_signed_approval = true             # a person signs each plan version before GO is possible",
              "min_review_independence = \"fresh-context\"  # none | same-session | fresh-context | different-model | human",
              "always_allowed_paths = [\"plans/**\"]        # plan files never count as unapproved changes", ""]
    return "\n".join(lines)


def plans_in_progress(ctx: ProjectContext) -> list[str]:
    from aqt_change.ledger import Ledger
    from aqt_change.plans import active_plans
    return [plan.id for _rel, plan in active_plans(Ledger.open(ctx.root))]


def check_change(ctx: ProjectContext) -> Result:
    if not installed("aqt-change"):
        return Result(SKIP, "aqt-change is not installed")
    if not ctx.git:
        return Result(SKIP, "not a git repository (aqt-change needs git)")
    from aqt_change.config import PROJECT_FILE, parse_project_settings
    from aqt_change.errors import ChangeError
    path, key = ctx.root / PROJECT_FILE, service_key_id()
    if not path.exists():
        busy = plans_in_progress(ctx)
        if busy:
            return Result(WARN, f"no {PROJECT_FILE}, and plan {', '.join(busy)} is in progress: writing it now gives "
                                "MANUAL_VERIFY_REQUIRED (project_settings_changed)",
                          f"after 'aqt-change finish': aqt project init, then commit {PROJECT_FILE}", can_apply=False)
        return Result(WARN, f"no {PROJECT_FILE}: the project sets no trail check, signed approval or review "
                            "independence for aqt-change", "aqt project init", data={"service_key": key})
    try:
        settings = parse_project_settings(path.read_text(encoding="utf-8"), PROJECT_FILE)
    except (ChangeError, OSError, UnicodeDecodeError) as error:
        return Result(FAIL, str(error), f"repair {PROJECT_FILE} (aqt never rewrites it)", can_apply=False)
    data = {"settings": settings, "service_key": key}
    edit = f"in {PROJECT_FILE} and commit it (not while a plan is in progress)"
    if key and key not in settings["trail_keys"]:
        return Result(WARN, f"{PROJECT_FILE}: trail_keys does not name this machine's trail writer key {key}",
                      f'add "{key}" to trail_keys {edit}', data=data, can_apply=False)
    if not (settings["require_trail"] or settings["trail_keys"]):
        return Result(WARN, f"{PROJECT_FILE}: require_trail is off, so receipts count without the trail's confirmation",
                      f"set require_trail = true and trail_keys = [\"<service key id>\"] {edit}", data=data,
                      can_apply=False)
    return Result(OK, f"{PROJECT_FILE}: trail check on" + (f" ({', '.join(settings['trail_keys'])})"
                                                          if settings["trail_keys"] else ""), data=data)


def step_change(ctx: ProjectContext) -> None:
    from aqt_change.config import PROJECT_FILE
    key = service_key_id()
    write_file(ctx, ctx.root / PROJECT_FILE, change_settings_text(key))
    if not key:
        ctx.say(f"{PROJECT_FILE}: require_trail and trail_keys are commented out (no trail service key found)")


# -- aqt-ui project list ---------------------------------------------------------------------
_TABLE = re.compile(r"^\s*\[\s*([^\[\]]+?)\s*\]\s*(#.*)?$")
_PROJECTS = re.compile(r"^(\s*projects\s*=\s*\[)(.*)(\]\s*(#.*)?)$")


def ui_config_path() -> Path:
    from aqt_ui.config import config_home
    value = os.environ.get("AQT_UI_CONFIG")
    return Path(value).expanduser() if value else config_home() / "ui.toml"


def _project_entry(root: Path) -> str:
    try:
        return "~/" + root.relative_to(_home()).as_posix()
    except ValueError:
        return str(root)


def _listed(projects, root: Path) -> bool:
    return any(Path(str(item)).expanduser().resolve() == root.resolve() for item in projects)


def _ui_edit(ctx: ProjectContext) -> tuple[str, str | None, str]:
    """(state, new text or None, fix): state ok, new, append, rewrite or manual."""
    path, entry = ui_config_path(), _project_entry(ctx.root)
    add = f"add {json.dumps(entry)} to projects under [changes] in {show(ctx, path)}"
    line = f"projects = [{json.dumps(entry)}]"
    if not path.exists():
        return "new", ("# aqt-ui configuration, written by aqt project init. All keys: the aqt-ui README.\n"
                       f"[changes]\n{line}\n"), "aqt project init"
    text = path.read_text(encoding="utf-8")
    doc = tomllib.loads(text)
    changes = doc.get("changes")
    if changes is None:
        gap = "" if not text else "\n" if text.endswith("\n") else "\n\n"
        return "append", f"{text}{gap}[changes]\n{line}\n", "aqt project init"
    projects = changes.get("projects") if isinstance(changes, dict) else None
    if isinstance(projects, list) and _listed(projects, ctx.root):
        return "ok", None, ""
    if not isinstance(projects, list):
        return "manual", None, add
    lines, table = text.splitlines(keepends=True), None
    for number, current in enumerate(lines):
        body = current.rstrip("\r\n")
        header = _TABLE.match(body)
        if header:
            table = header.group(1).strip()
            continue
        match = _PROJECTS.match(body) if table == "changes" else None
        if not match:
            continue
        inner = match.group(2).strip().rstrip(",").rstrip()
        lines[number] = (f"{match.group(1)}{inner + ', ' if inner else ''}{json.dumps(entry)}{match.group(3)}"
                         + current[len(body):])
        new = "".join(lines)
        try:
            check = tomllib.loads(new).get("changes", {}).get("projects")
        except tomllib.TOMLDecodeError:
            break
        if check == [*projects, entry]:
            return "rewrite", new, "aqt project init"
        break
    return "manual", None, add


def check_ui(ctx: ProjectContext) -> Result:
    if not installed("aqt-ui"):
        return Result(SKIP, "aqt-ui is not installed")
    path = ui_config_path()
    try:
        state, _text, fix = _ui_edit(ctx)
    except (tomllib.TOMLDecodeError, OSError, UnicodeDecodeError) as error:
        return Result(FAIL, f"{show(ctx, path)} cannot be read: {error}", f"repair {show(ctx, path)}", can_apply=False)
    if state == "ok":
        return Result(OK, f"aqt-ui shows this repository's changes ({show(ctx, path)})")
    what = {"new": f"no {show(ctx, path)}", "append": f"{show(ctx, path)} has no [changes] table"}.get(
        state, f"this repository is not in [changes] projects of {show(ctx, path)}")
    return Result(WARN, f"{what}: aqt-ui does not show this repository's plans and gates", fix,
                  can_apply=state != "manual")


def step_ui(ctx: ProjectContext) -> None:
    state, text, fix = _ui_edit(ctx)
    if text is None:
        raise StepSkipped(fix)
    write_file(ctx, ui_config_path(), text)


def _ui_does(ctx: ProjectContext) -> str:
    return f"add this repository to [changes] projects in {show(ctx, ui_config_path())}"


# -- git commit-msg hook ---------------------------------------------------------------------
def _commit_msg_hook(ctx: ProjectContext) -> Path:
    from aqt_change.gitio import Git
    return Git(ctx.root).hooks_dir() / "commit-msg"


def check_git_hook(ctx: ProjectContext) -> Result:
    if not installed("aqt-change"):
        return Result(SKIP, "aqt-change is not installed")
    if not ctx.git:
        return Result(SKIP, "not a git repository")
    hook = _commit_msg_hook(ctx)
    if not hook.exists():
        return Result(WARN, "no git commit-msg hook: commits are not checked for valid AQT-* trailers (optional)",
                      "aqt-change hooks install-git")
    text = hook.read_text(encoding="utf-8", errors="replace")
    if "aqt_change.cli hook commit-msg" in text or "aqt-change hook commit-msg" in text:
        return Result(OK, f"the commit-msg hook runs aqt-change ({show(ctx, hook)})")
    return Result(WARN, f"{show(ctx, hook)} does not run aqt-change: AQT-* trailers are not checked (optional)",
                  f"add the line  aqt-change hook commit-msg \"$1\"  to {show(ctx, hook)}", can_apply=False)


def step_git_hook(ctx: ProjectContext) -> None:
    from aqt_change.hooks import install_git_hook
    from aqt_change.ledger import Ledger
    ctx.say(f"wrote {show(ctx, install_git_hook(Ledger.open(ctx.root)))}")


# -- committed -------------------------------------------------------------------------------
def check_committed(ctx: ProjectContext) -> Result:
    if not ctx.git:
        return Result(SKIP, "not a git repository")
    names = [name for name in (".claude/settings.json", "CLAUDE.md", "AGENTS.md", ".aqt/change.toml")
             if (ctx.root / name).exists()]
    pending = {}
    if names:
        out = subprocess.run(["git", "-C", str(ctx.root), "status", "--porcelain=v1", "-z", "--untracked-files=all",
                              "--", *names], capture_output=True, text=True, check=True).stdout
        for entry in out.split("\0"):
            if len(entry) > 3 and entry[3:] in names:
                pending[entry[3:]] = "untracked" if entry[:2] == "??" else "changed"
    unignored = False
    if (ctx.root / LOCAL_SETTINGS).exists() and installed("aqt-change"):
        from aqt_change.gitio import Git
        unignored = LOCAL_SETTINGS in Git(ctx.root).untracked(repository_rules=True)
    if not pending and not unignored:
        return Result(OK, "the files aqt project init writes here are committed" if names else
                          "aqt project init has written nothing here yet")
    ordered = [name for name in names if name in pending]
    files = ordered + ([".gitignore"] if unignored else [])
    command = (f"echo {LOCAL_SETTINGS} >> .gitignore && " if unignored else "") + \
        f"git add {' '.join(shlex.quote(name) for name in files)} && git commit -m \"{COMMIT_MESSAGE}\""
    if Path.cwd().resolve() != ctx.root:
        command = f"cd {shlex.quote(str(ctx.root))} && {command}"
    what = [f"{name} ({pending[name]})" for name in ordered]
    if unignored:
        what.append(f"{LOCAL_SETTINGS} (no committed .gitignore rule: aqt-change counts it as a change)")
    return Result(WARN, "not committed yet: " + ", ".join(what), command, can_apply=False,
                  data={"files": pending, "local_settings_unignored": unignored})


def check_project(ctx: ProjectContext) -> Result:
    if ctx.git:
        return Result(OK, f"git repository {ctx.root}")
    return Result(WARN, f"{ctx.root} is not a git repository: aqt-change needs git (its checks are skipped)",
                  "git init", can_apply=False)


PROJECT_CHECKS: list[Check] = [
    Check("project", check_project),
    Check("claude.hooks", check_hooks, step_hooks,
          lambda ctx: f"merge the missing Claude Code hooks and deny rules into {show(ctx, settings_target(ctx))}"),
    Check("claude.deny", check_deny, step_deny,
          lambda ctx: f"add the missing deny rules to {show(ctx, settings_target(ctx))}", part_of="claude.hooks"),
    Check("instructions", check_instructions, step_instructions, _instructions_does),
    Check("change.settings", check_change, step_change, "write .aqt/change.toml (aqt-change project settings)"),
    Check("ui.project", check_ui, step_ui, _ui_does),
    Check("git.hook", check_git_hook, step_git_hook, "install the aqt-change commit-msg hook"),
    Check("committed", check_committed),
]
