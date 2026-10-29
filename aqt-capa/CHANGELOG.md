# Changelog

## Unreleased

- Security fix: with aqt-signoff installed, an approval counts only from signatures that verify. Independence
  (the implementer is excluded unless `allow_self_approval`) and the `approved` policy are checked on exactly
  those signatures, and `by`, `at` (the signed time) and `record` name the signature that completed the
  approval, plus `signers`. An unverified record claiming another signer no longer combines with a valid
  self-approval, and an aqt-signoff error (for example an unreadable registry) is `signature-not-valid`, never
  an approval.
- README: the threat model states that accept, dismiss, classify, investigation, recorded approval, cancel,
  extend and close are unsigned, and that `rebuild` replays a forged closure.
- Global options (`--json`, `--config`, `--db`, `--evidence`, `--root`, `--repo`) are accepted before or after
  the subcommand, as in aqt-trail, aqt-quarantine and aqt-validate.

## 0.1.0 — 2026-10-21

First MVP.

- `scan`: deviation candidates from aqt evidence (quarantine, change receipts/finish/review, `*.refused`, trail review findings, unknown action outcomes) and reverted git commits; idempotent.
- Human-gated candidate accept/dismiss, manual deviations, classification with recurrence links (lexical similarity in ppm).
- Structured investigations (5-Whys, Ishikawa 6M, root cause); agent drafts.
- Hash-bound corrective/preventive actions on agent control files; recorded human approval or aqt-signoff signature (verified via `aqt_signoff.is_approved` when installed).
- Effectiveness checks (`no-recurrence` over sessions/days) with honest `pending` states; window extensions; gated closure.
- Trend report (Markdown/JSON); rebuildable SQLite index; `capa.refused` records via the shared `aqt_evidence.require_human()`.
