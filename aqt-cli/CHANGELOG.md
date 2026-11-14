# Changelog

## Unreleased

- Windows: deny rules for folders outside the home name the drive as Claude Code matches it (`//d/work/**`), and
  the time zone `aqt setup` writes comes from `TZ` with `tzdata` (a dependency on Windows only).
- Windows: `aqt setup` registers the writer as the logon task `aqt-trail` (Task Scheduler: at your logon, your
  normal rights, no time limit, started again every five minutes when it is not running; `pythonw.exe` or the
  app's `aqtw.exe`, so no console window) and never replaces an existing one; `aqt status` checks that it
  exists, is enabled and starts a program that exists.
- The agent-instruction block of `aqt project init` names the commands as `aqt change ...` and `aqt ui` (`aqt-toolkit ...` where another aqt comes first on `PATH`); a rerun replaces an older block. The git hook's fix names `aqt change` too.
- Where the first `aqt` on `PATH` is another program (aqtinstall's), `aqt project init` writes the hooks, and from the desktop app's runtime the commit-msg hook, as `aqt-toolkit <tool> ...`; the `command` check reports which name agents run.
- `aqt status` on macOS and Windows: the writer service and the egress box say that they are not available on this
  system and why (systemd and bubblewrap are Linux only), as a skipped line instead of a warning with a Linux fix.
  The AQT configuration folder comes from `aqt_evidence.platform` (unchanged on Linux).
- `aqt open CASE-OR-LINK`: shows a case in the AQT desktop app through the system (`xdg-open`, `open`, `start`): a case id such as `quarantine:Q7SEGGW`, or a link `aqt://case/<id>` or `aqt://change/<project>/<plan>`; anything else is refused. It only opens the view.
- `aqt project init` writes the Claude Code hooks as `aqt <tool> ...` (e.g. `aqt trail hook claude-code`), the one command that a pip or uv install and the desktop app both put on `PATH`. Hooks written as `aqt-<tool> ...` or `aqt-toolkit <tool> ...` still count and are not added twice.
- `aqt status` has a `command` check: which `aqt` agents run, and a warning when there is none on `PATH` or another one comes first.
- From the desktop app's frozen runtime, `aqt setup` writes the trail writer's systemd unit with a path that stays valid (the `aqt` on `PATH`, or the AppImage file with `--cli`), not the AppImage's changing mount point.
- `aqt core --stdio [--read-only]`: the core of the AQT desktop app, aqt-ui's API as JSON lines on stdin and stdout with no network; the same as `aqt-ui core --stdio`.
- The desktop app's first-run setup, Settings and Projects area run `aqt status`, `aqt setup` and `aqt project status/init` through the same checks and steps (`checks.CHECKS`, `project.PROJECT_CHECKS`). The project step that writes the Claude Code hooks can leave the deny rules out when the person deselects them.
- `aqt status`: the command check warns only when the first `aqt` on PATH is another program or another AQT version; the same version installed elsewhere is `info` (not a problem). In an AppImage its fix is one `ln -s` line (the app's Settings install it too). Check results carry message codes, so the desktop app shows them in German.
- `aqt setup` checks the signer ID as soon as it is typed (lower case letters, digits, `.`, `_`, `-`; `alice` becomes `human:alice`), suggests a valid one and asks again, before the name, the role and the passphrase. An invalid `--id` fails before anything is asked.
- `aqt status`: when the egress box cannot start because Ubuntu's AppArmor blocks bubblewrap's user namespaces, the fix names the AppArmor profile (manual 6.4) instead of "allow unprivileged user namespaces".

## 0.2.0 — 2026-11-13

First version.

- Packaging: released as `agent-quality-toolkit` at 0.2.0, the version of every AQT package; it requires the nine packages at `>=0.2,<0.3`, and the extra `egress` adds aqt-egress (Python 3.12+); the licence is an SPDX expression with the licence files in the package (PEP 639).
- `aqt-toolkit`: the same command under a second name, for systems where another `aqt` (aqtinstall's) comes first on `PATH`; `--version` and `--help` name both.
- The toolkit declares the tools' commands too (`aqt-trail` … `aqt-evidence`, the same entry points as their packages), so an install of the toolkit always provides them and the Claude Code hooks find them; `aqt-egress` stays with its package (`aqt egress` runs it too).
- A missing package's fix is the command for this installation, matched to how the toolkit was installed; in a clone of the repository, the editable install of its folder.
- `aqt status` (`--json`, `--verify`): one verdict for the setup of this machine, with a result,
  a one-line explanation and the fix for each check: packages, trail, systemd user service, writer,
  spool, where records go, signer, `signoff.toml`, `trail.toml`, the end of the trail, test vectors.
- `aqt setup` (`--yes`, `--id/--name/--role`): runs the same checks and applies the missing steps
  (`aqt-trail init`, the user service, `aqt-signoff init`, the two settings files); safe to rerun,
  never overwrites keys, the signer registry or existing files.
- The `signer` check uses `aqt_signoff.check_signers()` (as `aqt-signoff signers check`): it fails when a
  registry key is not backed by its enrolment record and names each key and its problems (fix
  `aqt-signoff rekey --signer ID` for a key with no record yet, else `aqt-signoff signers check`), warns
  for discrepancies that do not stop a key, and lists the signers whose keys count. With an aqt-signoff
  too old to check, it warns. An unconfirmed re-bootstrap is a warning that says when the revocations
  before it were not signed (`rebootstrap[].unsigned_revocations`).
- `aqt project init [DIR] [--yes] [--local]` and `aqt project status [DIR] [--json]`: set up one
  repository and show what is in place there: the Claude Code hooks of the installed tools and deny
  rules for every decision command (as `aqt-<tool>`, `aqt <tool>` and `aqt-toolkit <tool>`) and for the AQT folders, merged
  into `.claude/settings.json` (or `settings.local.json`); the agent-instruction block in `CLAUDE.md` (created when missing) and an
  existing `AGENTS.md`; `.aqt/change.toml`; this repository in aqt-ui's `[changes] projects`; the aqt-change
  commit-msg hook; and whether the files are committed. Additive edits only, backups outside the
  repository, a rerun changes nothing, never commits.
- Without a terminal and without `--yes`, `aqt setup` and `aqt project init` skip their steps and say so
  (before, a step counted as declined when the question could not be answered).
- `aqt <tool> ARGS...`: runs `aqt-trail`, `aqt-signoff`, `aqt-change`, `aqt-sensei`, `aqt-quarantine`,
  `aqt-validate`, `aqt-capa`, `aqt-ui` or `aqt-evidence` (as `spec` or `evidence`) with the same
  arguments and exit code.
- Optional outbound checkpoint: `aqt egress …` runs aqt-egress (extra `agent-quality-toolkit[egress]`, Python
  3.12+ only; the install hint says so when it is missing), and `aqt status` has an `egress` line (version, CA,
  box support, last session) that is `skip` without the package and never fails the verdict.
