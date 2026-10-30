# Changelog

## Unreleased

### Security (verification round 3)
- Re-bootstrap: only a key that counted before the re-bootstrap confirms it (`rebootstrap[].counted_before`);
  approvals by a key that counts through the re-bootstrapped key are listed in `not_confirming` and do not confirm
  it. Every key that counted before is revoked by then, so a re-bootstrap stays flagged: `signers check` exit 1,
  `VerifyReport.registry_warnings` (printed by `verify`), `aqt status` warn. A request whose record time lies before
  the keys that count (backdated) is pending, never a re-bootstrap.
- Revocations that neither the revoked key nor another counting key signed are reported:
  `check_signers()["unsigned_revocations"]`, per key `unsigned_revocations`, a `WARNING` line in `signers check`,
  and `rebootstrap[].unsigned_revocations` for the ones before a re-bootstrap. They still apply. Signing with a key
  that a revocation record (or a conflict) stopped is refused (`registry_mismatch`).
- A replayed copy of an enrolment request (the same signed statement in another record) counts once (listed under
  `ignored`) instead of disabling the key. A differently signed second request is a conflict that stops the key from
  its record time (per key `stopped_at`; signatures made before keep counting) and is a `problems` entry.
- `signers import`: only the first import that counts counts (a later one is ignored, a problem when a registered
  key signed it); `import_preview` / `import_enrolments` refuse after it (`already_imported`). Records outside the
  trail written after the trail started (first record or `trail.json` `created`) or after the import are never
  importable; `check_signers()` lists them under `ignored` and no longer asks for an import. The preview has
  `outcome` (per key: `counts`, `pending`, `in-trail`, `conflict`, other keys of the signer) and `ignored`; the text
  flags another key for a signer who already has one.
- `signers export` (`Signoff.export_registry`) adds `enrolment_evidence` (`source`, `exported_at`, `records`,
  `revocations`). A registry file that carries it is used as the enrolment evidence when the sources hold no trail
  (`check_signers()["evidence"] == "registry export"`); the records are checked like any other evidence. With a
  trail they are ignored (noted), so the user's own `signers.json` cannot inject enrolments.

### Security (review round 3: counter-signed enrolment)
- A self-signed enrolment record no longer makes a counting key. The first enrolment of the evidence counts
  (bootstrap); every later enrolment, extra key or role change counts only after an enrolled signer whose key
  counts and is active approves it: new `aqt-signoff signers approve ID --key KEY [--role ROLE]`
  (`Signoff.approve_enrolment`), an approval record of type `signoff.key.enrolled` signed by the approver
  (statement field `enrolment`, bound to the request's record id and content hash). Pending enrolments are listed by
  `signers check` / `check_signers()` (`pending`, per key `pending`) and refuse to sign (`enrolment_pending`).
- Enrolment times are the record times (the trail writer's time), not the statement's claimed time; an approval is
  retroactive to its request. Roles form a timeline from approvals: `SignatureStatus.authorized_role` is the role in
  effect at `signed_at`, so a role change keeps earlier signatures valid with their role. A registry role that
  differs from the current enrolled role still stops the key.
- Two enrolment requests for one key are a conflict (the key does not count). Nobody approves their own enrolment
  or role; `init --add-key` while the key counts is a rotation (the old key approves the new one and is revoked;
  `--role` that differs is refused), otherwise it records a new request with `--role`. A new key enrolled when no
  other key counts any more is a re-bootstrap: it counts, `check_signers()["rebootstrap"]` lists it and `ok` is
  False until another signer approves it. Revocations without a signature never turn an earlier pending request into
  a re-bootstrap.
- A trail added after the fallback evidence file: new `aqt-signoff signers import` (`Signoff.import_preview`,
  `Signoff.import_enrolments`) carries the earlier enrolment and revocation records into the trail once (a
  `signoff.key.enrolled` record with `data.imported`, signed by a signer whose key counts in them or in the trail);
  their order and times are kept. Until then `check_signers()` reports them and `init`, signing and adoption refuse
  (`import_needed`). Records added to the old file afterwards do not count.
- `check_signers()` adds `bootstrap`, `rebootstrap`, `pending`, `imports`, `problems` and `ignored`; per key
  `pending`, `basis`, `approvals` and `roles`. `ok` also needs no pending key in the registry, no registry-wide
  problem and no unconfirmed re-bootstrap. `rekey` reports `pending`. New `Signoff.record_enrolment` for keys other
  tools create (aqt-quarantine). `check_block` does not judge a key's own enrolment request or revocation against
  its validity period (they are signed just before they are stored).
- Changed for existing data: after upgrading, every signer except the first needs one approval
  (`signers check` prints the command); the approval is retroactive, so their earlier signatures count again.

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
