# Changelog

## Unreleased

- Security: with aqt-trail in use, `gate`, `finish`, the Claude Code hooks and the commit-msg hook count a
  receipt or review only if the trail log holds the same record (id and content hash) received over the
  writer's socket. A record only in the local `records.jsonl`, or edited there, gives NO-GO
  (`receipt_unverified`, `review_unverified`); one that came through the spool, or an unreadable log, gives
  MANUAL. An unconfirmed review cannot replace a FAIL. The gate JSON reports `trail`. The check is on whenever
  a trail log exists or a writer is the sink; `AQT_SINK=file:` does not switch it off. Without any trail log
  and without a writer, behaviour is unchanged (documented limit).
- Security: files marked `skip-worktree` or `assume-unchanged` are fingerprinted by their working-tree
  content; a hidden change gives NO-GO (`hidden_worktree_change`), a run warning, a `finish` refusal
  (`finish_hidden_changes`) and a blocking hook. Files outside a sparse checkout give MANUAL (`sparse_checkout`).
- Security: the trail check no longer depends on the caller's environment alone (an agent can point its
  XDG directories elsewhere or unset `AQT_SINK` / `AQT_EVIDENCE`). New committed project setting
  `require_trail = true` in `.aqt/change.toml`: when no trail log is found, the gate is NO-GO
  (`trail_required`; receipts and reviews `receipt_unverified` / `review_unverified`), `finish` refuses
  (`finish_trail_required`), the Claude Code hooks block and the commit-msg hook rejects `AQT-Receipts`. The
  setting counts when the working-tree copy, HEAD's copy or the copy at the base commit of a plan in progress
  sets it. Without the setting, a local copy that holds a record which came back from a writer (it has a
  `chain`) keeps the check on: no trail found gives MANUAL and `finish` refuses. A change to
  `.aqt/change.toml` gives MANUAL (`project_settings_changed`) and is listed by `reconcile-diff`
  (`settings_changed`). The gate JSON reports `trail.required`.
- Security: the tree fingerprint and the hidden-change check hash the content of every tracked file instead
  of trusting `git status`. A tracked file whose content differs from the index while `git status` (with the
  repository's settings) does not show it, through a `core.fsmonitor` hook, a relaxed `core.checkStat` /
  `core.trustctime` or edited index data, gives `hidden_worktree_change` with flag `stat-cache`. Git calls run
  with `core.fsmonitor`, `core.untrackedCache` and relaxed stat checks switched off. Fingerprints stay the same
  for trees Git sees correctly, so receipts stay fresh across the upgrade; a changed symbolic link now counts
  by its link text, as Git stores it. Cost: one `git hash-object` pass over all tracked files per run, gate or
  hook (about 0.5 s for 10,000 files).
- Security: `finish` refuses (`finish_tested_change_not_committed`) when its commit would not hold what the
  receipts tested: a tracked file inside the plan's paths or covered by the fingerprint that differs from HEAD,
  or an untracked file inside the plan's paths, and is not named with `--path`. After a finish, the gate gives
  MANUAL (`tested_change_not_committed`) while HEAD lacks that content (for example after `--no-commit` and a
  partial commit). Untracked files outside the plan's paths may still stay out of the commit.
- Security: new project setting `trail_keys` in `.aqt/change.toml` pins the trail writer's service key ids. A
  trail log then confirms a record only when its copy carries a valid signature by a pinned key (public key
  from `keys/*.pub` next to the log, checked against the key id); otherwise `unsigned` (NO-GO). A log the agent
  wrote itself no longer confirms anything. Pinning implies `require_trail`; only keys every copy of the file
  names count. The gate JSON's `trail` reports `keys`. Uses aqt_evidence only; aqt-trail need not be installed.
- Security: new `[gate]` table in `.aqt/change.toml` (`require_signed_approval`, `min_review_independence`,
  `warnings_block`): the strictest of the user configuration and every project copy wins, so
  `AQT_CHANGE_CONFIG=/dev/null` no longer drops the policy. Changes to it inside a plan give MANUAL
  (`project_settings_changed`). Unknown keys or wrong values in the project file now refuse (`config_invalid`).
- Security: untracked files that only `.git/info/exclude` or `core.excludesFile` ignore are now part of the
  tree fingerprint (deleting one after a run makes the receipt stale) and give MANUAL
  (`locally_ignored_files`); in the plan's paths they also block `finish`. Receipts made while such files
  existed become stale once after the upgrade.
- Security, change of meaning: `fingerprint_exclude` and `always_allowed_paths` in the user configuration (within
  the agent's reach, for example through `AQT_CHANGE_CONFIG`) no longer weaken checks silently. The user's
  `fingerprint_exclude` leaves out only untracked files outside the plan's paths (before: any matching file, so
  `["**"]` kept every receipt fresh); a path outside the plan's paths that only the user's `always_allowed_paths`
  allows gives MANUAL (`allowed_by_user_config`, also in `reconcile-diff`) instead of passing. Both keys may now be
  committed in `.aqt/change.toml` (`fingerprint_exclude`, `[gate] always_allowed_paths`), where they count as
  before; only globs every copy names count. The `--junit` file is left out of the fingerprint only as an
  untracked file outside the plan's paths. Receipts that relied on a user glob for a tracked or in-scope file
  become stale once.
- Security: a run that changes the fingerprinted tree while it runs (a test that patches the code and deletes
  itself) no longer counts by itself: receipts record `tree_fingerprint_before`; the gate gives MANUAL
  (`command_modified_worktree`, per check) and `finish` refuses (`finish_command_modified_worktree`) until a later
  run of the same check leaves the tree unchanged. Output ignored by the repository's `.gitignore` does not count.
- Docs: `docs/usage.md` named `plan status --json` as a place that shows the approval record; `gate`
  (`approval.record`) and the trace report do.

## 0.1.0 — 2026-10-21

First MVP.

- Plan ledger: Project Tracker Next-compatible Markdown plans with an optional `aqt:` block; `plan new|add|status`, `reconcile` (editorial/semantic, reasons, append-only history, protected identity and lifecycle), `begin`.
- Receipts: `run` captures argv, exit code, duration, output hashes and tail, pytest/unittest/JUnit counts, HEAD, tree fingerprint and plan basis hash; staleness by content; `attest` for manual items; anti-gaming warnings.
- `finish`: preflight, atomic final plan, exact-path commit with `AQT-*` trailers, `change.finish`; idempotent and crash-resumable; waivers and acknowledged warnings recorded.
- `review add` (independence classes, diff hash; human reviews require a human), `reconcile-diff`, approval state from aqt-signoff signatures.
- `report` (Markdown/HTML) and `gate` (GO / NO-GO / MANUAL_VERIFY_REQUIRED, `--rerun`).
- Hooks: Claude Code `TaskCompleted`/`Stop`/`SubagentStop`, git `commit-msg`; `hooks print|install-git`.
- `lifecycle_owner = "external"` for plans managed by Project Tracker Next.
