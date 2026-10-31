import json
import os
import subprocess
import tomllib
from pathlib import Path

import pytest
from aqt_change.config import parse_project_settings

from aqt_cli import project, tools
from aqt_cli.checks import run_checks
from aqt_cli.cli import main, project_init
from aqt_cli.project import ProjectContext, resolve_root
from conftest import by_id

GIT = ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid"]


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    return root.resolve()


def commit(root, *paths, message="test"):
    subprocess.run(["git", "-C", str(root), "add", *paths], check=True)
    subprocess.run([*GIT, "-C", str(root), "commit", "-q", "--allow-empty", "-m", message], check=True)


def ctx_for(root, **kw):
    kw.setdefault("say", lambda text: None)
    found, git = resolve_root(root)
    return ProjectContext(root=found, git=git, **kw)


def init(root, **kw):
    kw.setdefault("yes", True)
    return project_init(ctx_for(root, **kw))


def status(root, **kw):
    return by_id(run_checks(ctx_for(root, **kw), project.PROJECT_CHECKS))


def settings(root, name="settings.json"):
    return json.loads((root / ".claude" / name).read_text())


def tree(root):
    """Every file in the repository (outside .git) and its bytes."""
    return {path: path.read_bytes() for path in sorted(root.rglob("*")) if path.is_file() and ".git" not in path.parts}


def ui_toml():
    return Path(os.environ["XDG_CONFIG_HOME"]) / "aqt" / "ui.toml"


def backups(root):
    folder = project.backup_dir(root)
    return sorted(folder.iterdir()) if folder.exists() else []


# -- the whole run -----------------------------------------------------------------------------
def test_fresh_repo_init_then_rerun_changes_nothing(repo):
    said = []
    assert init(repo, say=said.append) == 0
    assert said[0] == "aqt project init: 5 step(s) to do"
    data = settings(repo)
    assert {"command": "aqt-trail hook claude-code", "type": "command"} in data["hooks"]["SessionStart"][0]["hooks"]
    assert [group.get("matcher") for group in data["hooks"]["PostToolUse"]] == ["*", "WebFetch|WebSearch|mcp__.*"]
    assert [group["hooks"][0]["command"] for group in data["hooks"]["Stop"]] == [
        "aqt-trail hook claude-code", "aqt-change hook claude-code"]
    deny = data["permissions"]["deny"]
    for sub in ("release", "trust-source", "declare-threat", "init"):           # both spellings
        assert f"Bash(aqt-quarantine {sub}:*)" in deny and f"Bash(aqt quarantine {sub}:*)" in deny
    assert {"Bash(aqt-signoff signers approve:*)", "Bash(aqt trail review sign:*)", "Bash(aqt-capa close:*)",
            "Bash(aqt validate qualify:*)", "Bash(aqt-ui:*)", "Bash(aqt ui:*)"} <= set(deny)
    assert not any("aqt-change" in rule or "aqt change" in rule for rule in deny)  # agents run aqt-change
    assert (repo / "CLAUDE.md").read_text() == project.instructions_block() + "\n"
    change = (repo / ".aqt/change.toml").read_text()
    parsed = parse_project_settings(change, ".aqt/change.toml")
    assert parsed["require_trail"] is False and parsed["trail_keys"] == [] and "# require_trail = true" in change
    assert parsed["fingerprint_exclude"] == ["plans/**"] and parsed["gate"] == {
        "require_signed_approval": True, "min_review_independence": "fresh-context", "always_allowed_paths": ["plans/**"]}
    from aqt_ui.config import load_config as ui_config
    assert ui_config().projects == [repo]
    hook = repo / ".git/hooks/commit-msg"
    assert "aqt_change.cli hook commit-msg" in hook.read_text() and os.access(hook, os.X_OK)
    results = status(repo)
    assert {key: r.result for key, r in results.items()} == {
        "project": "ok", "claude.hooks": "ok", "claude.deny": "ok", "instructions": "ok", "change.settings": "warn",
        "ui.project": "ok", "git.hook": "ok", "committed": "warn"}
    assert results["committed"].fix.endswith(
        'git add .claude/settings.json CLAUDE.md .aqt/change.toml && git commit -m "AQT project setup"')
    assert backups(repo) == []                                    # only new files: nothing to back up

    files = {**tree(repo), ui_toml(): ui_toml().read_bytes(), hook: hook.read_bytes()}
    said.clear()
    assert init(repo, say=said.append) == 0
    assert said[0] == "aqt project init: nothing to do"
    assert {path: path.read_bytes() for path in files} == files and set(tree(repo)) <= set(files)
    assert backups(repo) == []

    commit(repo, ".")
    assert status(repo)["committed"].result == "ok"


def test_status_json_and_exit_codes(repo, capsys):
    assert main(["project", "status", str(repo), "--json"]) == 1           # hooks missing: fail
    report = json.loads(capsys.readouterr().out)
    assert report["verdict"] == "fail" and report["project"] == str(repo)
    assert [c["id"] for c in report["checks"]] == [c.id for c in project.PROJECT_CHECKS]
    hooks = {c["id"]: c for c in report["checks"]}["claude.hooks"]
    assert hooks["result"] == "fail" and hooks["fix"] == "aqt project init" and len(hooks["data"]["missing"]) == 11
    assert not (repo / ".claude").exists()                                  # status is read-only
    assert main(["project", "init", str(repo), "--yes"]) == 0
    capsys.readouterr()
    assert main(["project", "status", str(repo)]) == 0
    assert capsys.readouterr().out.startswith("aqt project status: WARN")
    assert main(["project", "status", str(repo / "missing")]) == 2
    assert main(["project"]) == 2


def test_without_a_terminal_and_without_yes_nothing_is_written(repo):
    said = []
    assert init(repo, yes=False, say=said.append) == 1
    assert "no terminal to confirm the steps: they are skipped; rerun with --yes to apply them" in said
    assert "claude.hooks: skipped (no terminal; --yes applies it)" in said
    assert tree(repo) == {} and not ui_toml().exists()


def test_interactive_answers(repo):
    asked = []

    def answer(question):
        asked.append(question)
        return "y" if question.startswith("No CLAUDE.md") else "n"

    init(repo, yes=False, interactive=True, ask=answer)
    assert asked[0].startswith("11 of 11 Claude Code hooks are missing") and asked[0].endswith(
        "Merge the missing Claude Code hooks and deny rules into .claude/settings.json? [Y/n] ")
    assert asked[1].endswith("Add the missing deny rules to .claude/settings.json? [Y/n] ")   # asked on its own
    assert set(tree(repo)) == {repo / "CLAUDE.md"}


# -- Claude Code settings ----------------------------------------------------------------------
def test_existing_settings_keep_the_users_hooks_keys_order_and_mode(repo):
    path = repo / ".claude/settings.json"
    path.parent.mkdir()
    mine = {"model": "opus", "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command",
                                                                                     "command": "my-check"}]}]},
            "permissions": {"allow": ["Bash(ls:*)"], "deny": ["Bash(rm:*)"]}, "env": {"A": "1"}}
    original = json.dumps(mine, indent=4).encode()
    path.write_bytes(original)
    path.chmod(0o640)
    assert init(repo) == 0
    data = settings(repo)
    assert list(data) == ["model", "hooks", "permissions", "env"] and data["env"] == {"A": "1"}
    assert data["hooks"]["PreToolUse"][0] == mine["hooks"]["PreToolUse"][0]
    assert data["hooks"]["PreToolUse"][1]["hooks"][0]["command"] == "aqt-trail hook claude-code"
    assert data["permissions"]["allow"] == ["Bash(ls:*)"] and data["permissions"]["deny"][0] == "Bash(rm:*)"
    assert path.read_text().endswith("}\n") and path.stat().st_mode & 0o777 == 0o640
    saved = backups(repo)
    assert [p.name.split(".json.")[0] for p in saved] == ["settings"] and saved[0].read_bytes() == original
    assert str(project.backup_dir(repo)).startswith(os.environ["XDG_STATE_HOME"])     # outside the repository
    assert project.backup_dir(repo).name.startswith("repo-") and saved[0].stat().st_mode & 0o777 == 0o640


@pytest.mark.parametrize("text", ["{", "[]", '{"hooks": []}', '{"hooks": {"Stop": {}}}', '{"permissions": []}',
                                  '{"permissions": {"deny": "Bash(rm:*)"}}', '{"hooks": {"Stop": ["x"]}}'])
def test_invalid_or_unknown_settings_are_refused(repo, text):
    path = repo / ".claude/settings.json"
    path.parent.mkdir()
    path.write_text(text)
    results = status(repo)
    assert results["claude.hooks"].result == "fail" and not results["claude.hooks"].can_apply
    assert results["claude.deny"].result == "fail"
    assert init(repo) == 1
    assert path.read_text() == text and backups(repo) == []
    assert (repo / "CLAUDE.md").exists()                                # the other steps still run


def test_hooks_and_rules_in_the_user_settings_are_not_duplicated(repo):
    user = Path(os.environ["HOME"]) / ".claude/settings.json"
    user.parent.mkdir()
    trail = {"type": "command", "command": "/opt/aqt/bin/aqt-trail hook claude-code"}   # absolute path counts too
    user.write_text(json.dumps({"hooks": {
        "SessionStart": [{"hooks": [trail]}], "UserPromptSubmit": [{"hooks": [trail]}],
        "PreToolUse": [{"hooks": [trail]}],                                # no matcher is the same as "*"
        "PostToolUse": [{"matcher": "", "hooks": [trail]}], "Stop": [{"hooks": [trail]}],
        "SessionEnd": [{"hooks": [trail]}]}, "permissions": {"deny": ["Bash(aqt-ui:*)"]}}))
    before = user.read_bytes()
    assert init(repo) == 0
    data = settings(repo)
    commands = [handler["command"] for groups in data["hooks"].values() for group in groups for handler in group["hooks"]]
    assert "aqt-trail hook claude-code" not in commands and len(commands) == 5      # quarantine 2, change 3
    assert "Bash(aqt-ui:*)" not in data["permissions"]["deny"] and "Bash(aqt ui:*)" in data["permissions"]["deny"]
    assert user.read_bytes() == before
    assert status(repo)["claude.hooks"].result == "ok"


def test_local_writes_settings_local_json_and_asks_for_a_gitignore_rule(repo):
    assert init(repo, local=True) == 0
    assert not (repo / ".claude/settings.json").exists()
    assert len(settings(repo, "settings.local.json")["permissions"]["deny"]) == len(project.deny_rules())
    committed = status(repo)["committed"]
    assert committed.result == "warn" and committed.data["local_settings_unignored"] is True
    assert "echo .claude/settings.local.json >> .gitignore && git add CLAUDE.md .aqt/change.toml .gitignore" in committed.fix
    (repo / ".gitignore").write_text(".claude/settings.local.json\n")
    commit(repo, ".")
    assert status(repo)["committed"].result == "ok" and status(repo)["claude.hooks"].result == "ok"


def test_only_the_installed_tools(repo, monkeypatch):
    real = project.installed
    monkeypatch.setattr(project, "installed", lambda dist: dist not in ("aqt-quarantine", "aqt-sensei") and real(dist))
    assert init(repo) == 0
    data = settings(repo)
    text = json.dumps(data)
    assert "aqt-quarantine" not in text and "aqt quarantine" not in text and "sensei" not in text
    assert "aqt-change hook claude-code" in text
    assert "External content" not in (repo / "CLAUDE.md").read_text()


def test_rule_paths_follow_xdg_dirs(tmp_path, monkeypatch):
    home = Path(os.environ["HOME"])
    monkeypatch.setenv("XDG_STATE_HOME", str(home / ".local/state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    from aqt_quarantine.cli import CLAUDE_SNIPPET
    file_rules = [rule for rule in CLAUDE_SNIPPET["permissions"]["deny"] if not rule.startswith("Bash(")]
    assert set(file_rules) <= set(project.deny_rules())          # the defaults: the same rules as aqt-quarantine's
    assert "Read(~/.local/state/aqt/trail/keys/**)" in project.deny_rules()
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "elsewhere"))
    rules = project.deny_rules()
    assert f"Read(/{tmp_path}/elsewhere/aqt/quarantine/**)" in rules and f"Edit(/{tmp_path}/elsewhere/aqt/**)" in rules
    assert f"Read(/{tmp_path}/elsewhere/aqt/trail/keys/**)" in rules
    monkeypatch.setenv("AQT_TRAIL_STATE", str(tmp_path / "trail"))         # a trail outside the AQT state folder
    assert f"Edit(/{tmp_path}/trail/**)" in project.deny_rules()


# -- agent instructions ------------------------------------------------------------------------
def test_block_appended_replaced_and_both_files(repo):
    (repo / "CLAUDE.md").write_text("# My project\n\nKeep this.")
    (repo / "AGENTS.md").write_text(f"Intro\n\n{project.BEGIN}\nold text\n{project.END}\n\nTail\n")
    assert init(repo) == 0
    block = project.instructions_block()
    assert (repo / "CLAUDE.md").read_text() == f"# My project\n\nKeep this.\n\n{block}\n"
    assert (repo / "AGENTS.md").read_text() == f"Intro\n\n{block}\n\nTail\n"
    assert sorted(p.name.split(".md.")[0] for p in backups(repo)) == ["AGENTS", "CLAUDE"]
    assert status(repo)["instructions"].result == "ok"


def test_linked_claude_md_is_edited_once_and_stays_a_link(repo):
    (repo / "AGENTS.md").write_text("Rules\n")
    (repo / "CLAUDE.md").symlink_to("AGENTS.md")
    assert init(repo) == 0
    assert (repo / "CLAUDE.md").is_symlink() and (repo / "AGENTS.md").read_text().count(project.BEGIN) == 1


def test_broken_markers_are_refused(repo):
    (repo / "CLAUDE.md").write_text(f"{project.BEGIN}\nno end\n")
    assert status(repo)["instructions"].result == "fail"
    init(repo)
    assert (repo / "CLAUDE.md").read_text() == f"{project.BEGIN}\nno end\n"


# -- aqt-change project settings ---------------------------------------------------------------
def test_change_settings_with_a_known_service_key(repo):
    from aqt_trail.config import load_config
    from aqt_trail.state import init_state
    config = load_config()
    init_state(config, log_id="trail_test")
    key = config.meta()["key_id"]
    assert init(repo) == 0
    parsed = parse_project_settings((repo / ".aqt/change.toml").read_text(), "x")
    assert parsed["require_trail"] is True and parsed["trail_keys"] == [key]
    assert status(repo)["change.settings"].result == "ok"


def test_existing_change_settings_are_never_rewritten(repo):
    from aqt_trail.config import load_config
    from aqt_trail.state import init_state
    path = repo / ".aqt/change.toml"
    path.parent.mkdir()
    path.write_text('trail_keys = ["ed25519:0123456789abcdef"]\n')
    assert status(repo)["change.settings"].result == "ok"
    init_state(load_config(), log_id="trail_test")             # now this machine's writer has another key
    result = status(repo)["change.settings"]
    assert result.result == "warn" and "does not name this machine's trail writer key" in result.explanation
    path.write_text("require_trail = 1\n")
    assert status(repo)["change.settings"].result == "fail"
    init(repo)
    assert path.read_text() == "require_trail = 1\n"


def test_no_change_settings_while_a_plan_is_in_progress(repo, monkeypatch):
    commit(repo)
    monkeypatch.chdir(repo)
    assert tools.run_tool("change", ["plan", "new", "plans/s01.md", "--id", "s01", "--title", "Demo"]) == 0
    assert tools.run_tool("change", ["begin", "plans/s01.md", "--reason", "start"]) == 0
    result = status(repo)["change.settings"]
    assert result.result == "warn" and "plan s01 is in progress" in result.explanation and not result.can_apply
    init(repo)
    assert not (repo / ".aqt/change.toml").exists()


# -- aqt-ui ------------------------------------------------------------------------------------
def test_ui_toml_append_rewrite_listed_and_other_shapes(repo, tmp_path):
    from aqt_ui.config import load_config as ui_config
    path = ui_toml()
    path.parent.mkdir(parents=True)
    path.write_text("port = 41377")
    init(repo)
    assert path.read_text() == f'port = 41377\n\n[changes]\nprojects = ["{repo}"]\n'
    other = tmp_path / "other"
    path.write_text(f'port = 1\n\n[changes]\nprojects = ["{other}", ]  # mine\n\n[x]\ny = 2\n')
    init(repo)
    assert path.read_text() == f'port = 1\n\n[changes]\nprojects = ["{other}", "{repo}"]  # mine\n\n[x]\ny = 2\n'
    assert ui_config().projects == [other, repo] and len(backups(repo)) == 2
    assert status(repo)["ui.project"].result == "ok"
    path.write_text(f'[changes]\nprojects = [\n  "{other}",\n]\n')
    result = status(repo)["ui.project"]
    assert result.result == "warn" and not result.can_apply and result.fix.startswith(f'add "{repo}" to projects')
    path.write_text("[changes\n")
    assert status(repo)["ui.project"].result == "fail"


def test_home_relative_ui_entry_counts(repo, monkeypatch):
    monkeypatch.setenv("HOME", str(repo.parent))
    ui = ui_toml()
    ui.parent.mkdir(parents=True)
    ui.write_text('[changes]\nprojects = ["~/repo"]\n')
    assert status(repo)["ui.project"].result == "ok"


# -- git ---------------------------------------------------------------------------------------
def test_an_existing_commit_msg_hook_is_kept(repo):
    hook = repo / ".git/hooks/commit-msg"
    hook.write_text("#!/bin/sh\nexit 0\n")
    result = status(repo)["git.hook"]
    assert result.result == "warn" and not result.can_apply and 'aqt-change hook commit-msg "$1"' in result.fix
    init(repo)
    assert hook.read_text() == "#!/bin/sh\nexit 0\n"


def test_not_a_git_repository(tmp_path):
    folder = tmp_path / "plain"
    folder.mkdir()
    results = status(folder)
    assert results["project"].result == "warn" and "aqt-change needs git" in results["project"].explanation
    assert {results[key].result for key in ("change.settings", "git.hook", "committed")} == {"skip"}
    assert init(folder) == 0                                     # warnings only: the other steps still work
    assert (folder / ".claude/settings.json").exists() and (folder / "CLAUDE.md").exists()
    assert not (folder / ".aqt").exists()
