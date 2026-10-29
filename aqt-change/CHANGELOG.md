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
