# Changelog

## Unreleased

- Fix: Claude Code hook fields `source` (SessionStart) and `reason` (SessionEnd) are stored as
  `session_source` and `end_reason`; they overwrote `data.source` and broke payload conformance.
- Tests remove their temporary HOME at the end of the run.

## 0.1.0 — 2026-10-21

First MVP.

- Writer service `aqt-trail serve` on a Unix socket: writer time, observed attribution
  (`SO_PEERCRED` + `/proc` process chain), hash chain, Ed25519 service signature, fsync,
  single-writer lock, idempotent appends by id, refusals recorded as `trail.refused`,
  `service.start`/`stop`, `clock.jump` and `log.repaired` events.
- Spool and gap markers: the shared spool (`$XDG_STATE_HOME/aqt/spool/spool.jsonl`) is drained
  at start, periodically and by `aqt-trail drain`, after one `trail.gap` record.
- Checkpoints, exported heads and RFC 3161 anchors (own DER code, verified against `openssl ts`),
  with a TEST ONLY local authority for offline use.
- `verify` (chain, signatures, pinned key, checkpoints, external heads, TSA tokens, detached
  signatures), `export` bundles with manifest, Markdown/HTML `report`, `list`/`show`.
- Importers: Claude Code hooks and transcripts, Codex rollout JSONL, pi v3 sessions; hashes and
  masked excerpts only; idempotent.
- `alcoa` report citing `alcoa:*` catalogue IDs.
- Audit-trail review: ten risk queries, worksheet, signed `trail.review` with enforced reviewer
  independence, agent-session refusal and shared signer registry support.
- Separate-user setup script and systemd unit (not run by tests).
