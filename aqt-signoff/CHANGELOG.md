# Changelog

## Unreleased

### Security (review fixes)
- A signed statement is identified by its digest (`statement_digest`, `SignatureStatus.statement_sha256`): a copy
  in another record counts once and is reported `invalid` (replay), and a withdrawal applies to every copy. New
  withdrawals name the withdrawn statement in the signed field `withdraws`; earlier ones apply only to the record
  their signed subject names with a matching content hash. The unsigned `data.signature_record` no longer selects
  the target, so a withdrawal cannot be redirected.
- Approved actions: the stored action is hashed again before an approval counts and before a claim; `run`
  executes that verified body. Only `signoff.action.approved` records with subject kind `action` authorise a claim
  (a file or record approval no longer does). New actions carry `preparer` (and `revised_by`) in the hashed body for
  the author exclusion. A `signoff.action.claimed` record in the evidence refuses a second claim of the same
  version after a database rollback. An action that binds a payload needs it at claim and run; `run` passes it on
  stdin. The claim grace is never shorter than the run timeout (default now 11 min); `run --timeout` may not
  exceed it. Withdrawn action approvals no longer count.
- Roles for policies come from the registry and must equal the signed role (`SignatureStatus.authorized_role`);
  a key can no longer claim a role of its own.
- Author exclusion: `sign`, `verify_hash` and `is_approved` add the actor of every record whose content hash is
  the signed hash (as `verify_record` did); `is_approved(..., authors=)` takes more.
- The registry is reconciled with the evidence: a key counts only with a matching `signoff.key.enrolled` record
  (from the trail when there is one), enrolment and revocation times come from the records, and revocation
  records apply even when `signers.json` says active. New `aqt-signoff signers check`, `check_signers()`,
  `Signoff.check_signers()`, `VerifyReport.registry_problems`. A key enrolled by another tool gets an enrolment
  record (`data.adopted`) the first time its owner unlocks it; a key whose entry contradicts its record is refused.
- Keys: new keys use the AQT key format (scrypt + AES-256-GCM, from aqt-spec); earlier PKCS#8 keys are
  re-encrypted at their next unlock or with the new `aqt-signoff rekey`. `init` sets the key directory to 0700.

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
