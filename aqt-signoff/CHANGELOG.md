# Changelog

## Unreleased

- Global options (`--json`, `--config`, `--registry`, `--keys-dir`, `--state-dir`, `--sink`, `--evidence`) are
  accepted before or after the subcommand, as in aqt-trail, aqt-quarantine and aqt-validate.
- `examples/signoff.toml`: the commented trail sink is the writer's default socket `$XDG_RUNTIME_DIR/aqt/trail.sock`.

## 0.1.0 — 2026-10-21

First MVP.

- Signer identities with passphrase-encrypted Ed25519 keys; shared registry `signers.json` (version 1) and key directory in `$XDG_CONFIG_HOME/aqt/`; enrolment, revocation (with optional compromise time), new key after revocation.
- Detached signed statement aligned with `aqt-spec/schemas/signature.schema.json` (`aqt_signature`, `record_type`, `key`, `nonce`); every written record validates against the aqt-spec schemas and the sink passes `aqt-evidence conform --level 1`.
- Signatures with meaning over files, evidence records (`record_content_hash`) and external hashes, as detached signed statements in `data.signature`; re-authentication per signing; statuses valid / invalid / invalidated / unknown-signer / revoked; withdrawal; one `signoff.invalidation` record per detected change.
- Policies per meaning (minimum signatures, roles, author exclusion); `verify --require`.
- Markdown and HTML manifestation (printed name, role, meaning, local time with zone, UTC, reason, status, content hash).
- Approved actions: idempotent prepare, revision, signed approve/reject of the exact hash with optional expiry, atomic claim that re-verifies approvals and payload hash, `run` for commands, outcome reports, unknown outcomes resolved only by a signed human decision; undelivered records kept for `sync`.
- Agent-session guard via `aqt_evidence.require_human`; refusals and failed re-authentications recorded (`signoff.refused`, `signoff.auth.failed`).
- Python API including `verify_subject` and `is_approved` for other AQT tools.
