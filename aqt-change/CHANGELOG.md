# Changelog

## Unreleased

- Security: with aqt-trail in use, `gate`, `finish`, the Claude Code hooks and the commit-msg hook count a
  receipt or review only if the trail log holds the same record (id and content hash) received over the
  writer's socket. A record only in the local `records.jsonl`, or edited there, gives NO-GO
  (`receipt_unverified`, `review_unverified`); one that came through the spool, or an unreadable log, gives
  MANUAL. An unconfirmed review cannot replace a FAIL. The gate JSON reports `trail`. Without a trail,
  behaviour is unchanged (documented limit).
- Security: files marked `skip-worktree` or `assume-unchanged` are fingerprinted by their working-tree
  content; a hidden change gives NO-GO (`hidden_worktree_change`), a run warning, a `finish` refusal
  (`finish_hidden_changes`) and a blocking hook. Files outside a sparse checkout give MANUAL (`sparse_checkout`).
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
