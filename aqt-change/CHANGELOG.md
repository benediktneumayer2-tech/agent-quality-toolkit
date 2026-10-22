# Changelog

## 0.1.0 — 2026-10-21

First MVP.

- Plan ledger: PTN-compatible Markdown plans with an optional `aqt:` block; `plan new|add|status`, `reconcile` (editorial/semantic, reasons, append-only history, protected identity and lifecycle), `begin`.
- Receipts: `run` captures argv, exit code, duration, output hashes and tail, pytest/unittest/JUnit counts, HEAD, tree fingerprint and plan basis hash; staleness by content; `attest` for manual items; anti-gaming warnings.
- `finish`: preflight, atomic final plan, exact-path commit with `AQT-*` trailers, `change.finish`; idempotent and crash-resumable; waivers and acknowledged warnings recorded.
- `review add` (independence classes, diff hash; human reviews require a human), `reconcile-diff`, approval state from aqt-signoff signatures.
- `report` (Markdown/HTML) and `gate` (GO / NO-GO / MANUAL_VERIFY_REQUIRED, `--rerun`).
- Hooks: Claude Code `TaskCompleted`/`Stop`/`SubagentStop`, git `commit-msg`; `hooks print|install-git`.
- `lifecycle_owner = "external"` for plans managed by Project Tracker Next.
