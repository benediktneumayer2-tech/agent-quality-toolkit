# Changelog

## 0.1.0 — 2026-10-21

First MVP.

- `scan`: deviation candidates from aqt evidence (quarantine, change receipts/finish/review, `*.refused`, trail review findings, unknown action outcomes) and reverted git commits; idempotent.
- Human-gated candidate accept/dismiss, manual deviations, classification with recurrence links (lexical similarity in ppm).
- Structured investigations (5-Whys, Ishikawa 6M, root cause); agent drafts.
- Hash-bound corrective/preventive actions on agent control files; recorded human approval or aqt-signoff signature (verified via `aqt_signoff.is_approved` when installed).
- Effectiveness checks (`no-recurrence` over sessions/days) with honest `pending` states; window extensions; gated closure.
- Trend report (Markdown/JSON); rebuildable SQLite index; `capa.refused` records via the shared `aqt_evidence.require_human()`.
