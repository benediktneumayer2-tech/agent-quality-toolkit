# Changelog

## 0.2.0 — unreleased

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
