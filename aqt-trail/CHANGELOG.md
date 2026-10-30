# Changelog

## Unreleased

- Security (round 3, with aqt-signoff): registry keys count only as aqt-signoff's counter-signed enrolment
  rules count them (a self-signed enrolment record of a new key waits for an approval by an enrolled signer);
  `check_enrolment` uses them unchanged. Reviewer independence (`scope_actors`) no longer counts a signer's
  records about their own key (enrolment, rotation, revocation) as activity; approving someone else's enrolment
  counts. `verify` still accepts reviews signed with the earlier actor list (`scope_actors(..., legacy=True)`).
- Fix: `verify` reported every signed `signoff.key.revoked` record (and now every enrolment request, which the
  writer stamps just after it is signed) as a signature problem; a key's own enrolment request and revocation are
  judged by their signature only (`verify.own_key_statement`).

- Security (writer): `observed.chain_status` (`complete` | `partial` | `unavailable`, with `chain_detail`) says how
  far the observed process chain goes; `partial` for an ancestor that exited, a reused parent pid or a process
  reparented to init or the systemd user manager (its session leader is not an ancestor), `unavailable` when the
  sender exited (`SO_PEERPIDFD`) or could not be read. `chain_complete` and `process_chain` stay as they were.
- Security (writer): client records in the writer's name (`service:aqt-trail`), of the types `trail.anchor` and
  `trail.gap`, or with the actions `service.start`, `service.stop`, `clock.jump` and `log.repaired` are refused;
  client `trail.review` and `trail.refused` records must have their payload shape (a malformed review could break
  `verify` for good).
- Security (writer): records sent through the `drain` op keep the observation of the sending client
  (`observed.drained_by`); a drain stores each record id once (same content: already stored; other content:
  `duplicate_id`), also within one batch.
- Security (writer): the `checkpoint` op uses only the configured TSA (or the TEST ONLY `test:` authority in the
  writer's state); other client-supplied URLs and `test:<dir>` are refused (`unauthorized`).
- Security (writer): `trail.lock` is created and kept 0600. Short writes are completed; a failed write or fsync is
  cut back to the last acknowledged record, and if that fails too the writer answers `unavailable` until restarted.
- Security (importers): excerpt masking covers prefixed names (`DB_PASSWORD=`, `GITHUB_TOKEN=`,
  `AWS_SECRET_ACCESS_KEY=`), quoted and JSON values, `--password value`, `Authorization:` headers and bearer tokens,
  URL and `curl -u` passwords, PEM private keys and more token formats; long inputs are masked in a bounded window.
- Security (setup): `setup-system-user.sh` refuses an installation that is not root's alone (console script,
  interpreter, virtual environment, standard library, site-packages, `aqt_trail`/`aqt_evidence` and the folders
  above them); `--check` runs only these checks.

Security review fixes, verification side:

- `review sign` (and `build_review`) recomputes the worksheet's scope, actors and findings from the trail and
  refuses an edited worksheet (`worksheet_mismatch`) or a broken trail (`trail_broken`); it never reads the
  `trail` path written in the worksheet. Queries now see the trail up to the end of the scope, so a worksheet is
  reproducible. `worksheet_digest` / `expected_sha256` let a UI bind the worksheet it showed (`worksheet_changed`).
  With a signer registry the reviewer must be registered (`unknown_signer`); a key registered to someone else is
  refused (`key_mismatch`). New review data fields `profile_queries` and `worksheet_sha256`.
- `verify` binds detached signatures to the signer registry (key owner, enrolment and revocation at `signed_at`,
  record type, meaning) and reports a `trail.review` that is unsigned, mis-bound, not about its own content, with
  a wrong head or actors, or signed by an actor of its scope. Malformed anchor and review payloads are problems,
  never crashes. Lines must be canonical AQT JSON (no duplicate keys). Warnings state which records no external
  head or CA-verified anchor covers, how many follow the newest checkpoint, and a missing checkpoints file.
- Only RFC 3161 anchors the writer wrote count (verify, `unanchored_head`, ALCOA `enduring`, `status`).
- `verify --bundle` no longer trusts the bundle's TSA CA, TEST ONLY CA (only with `--test-tsa`) or `signers.json`;
  `--tsa-ca`, `--test-tsa` and the new `--signers` apply to bundles.
- RFC 3161: issuers on the TSA's path must be CA certificates (`cA`, `keyCertSign`, path length); the TSA
  certificate needs `timeStamping` as its only, critical EKU; the `signingCertificate` attribute must name it.
- ALCOA++: `original` and `complete` fail on verification problems (truncation, rewrite, bad anchors); filtering
  with `--since/--until` no longer fails them; `alcoa` takes the trust options of `verify`. `attributable` warns on
  human claims whose process chain was incomplete (`observed.chain_status`).
- `list`, the Markdown report, the worksheet and the ALCOA table escape control characters and markup that clients
  wrote. `review run --out DIR`, and a fallback folder when the state is not writable (separate-user mode).
  `review list` shows each review's signature state.

Security review fixes, round 2:

- Registry keys count only when their `signoff.key.enrolled` record in the trail backs them, judged with
  aqt-signoff's rules (`check_enrolment`, `load_registry(records=...)`; aqt-trail still does not depend on
  aqt-signoff). `verify` reports a review signed with a key that is only in `signers.json` (and warns for other
  signatures), `review sign` refuses it (`unenrolled_key`), and revocation records apply even when the file says
  active. Without aqt-signoff the keys are left unchecked and `verify` warns that they rest on `signers.json`
  alone (ALCOA++ `accurate` warns). A registry key id that does not belong to its public key is unusable.
- TEST ONLY anchors (any client may ask the writer for one) count only in test mode: `--test-tsa` on `verify`,
  `alcoa`, `status` and `review run`, or `[anchor] test_tsa = true`. Otherwise they are a `verify` warning, never a
  problem (a configured real `tsa_ca` no longer turns them into a permanent failure), and `unanchored_head`,
  ALCOA++ `enduring`, `status` and `anchored_seq(record)` ignore them. An exported-head note no longer turns
  `enduring` from fail into warn; head copies matched with `verify --heads` do.
- A review profile's parameters are shown on the worksheet and before signing, those that differ from the built-in
  defaults flagged, and signed (`profile_params`, `profile_differs`; `verify` checks them against
  `profile_sha256`). A profile file named `default` may not change parameters.
- A signed `trail.review` copied into a later record counts once: `verify` reports the copy, `review list` shows
  it `invalid`, `status` shows the last valid review (`verify.review_statuses`).
- A human claim pushed through the `drain` op is judged by `observed.drained_by`: an agent harness is an
  `attribution_mismatch` (major, ALCOA++ `attributable` fails), an incomplete chain an unconfirmed one; the gap
  finding names the drainer instead of saying nothing was observed.

- Fix: Claude Code hook fields `source` (SessionStart) and `reason` (SessionEnd) are stored as
  `session_source` and `end_reason`; they overwrote `data.source` and broke payload conformance.
- Tests remove their temporary HOME at the end of the run.
- Fix: the signer registry and key directory honour `AQT_SIGNERS` and `AQT_KEYS_DIR`, as in aqt-signoff and
  aqt-quarantine (review signing, `verify`, `export`).
- Fix: the separate-user unit (now `examples/aqt-trail-system.service`) runs with `Group=aqt-trail-clients`,
  so clients can reach `/run/aqt-trail/trail.sock` and read the log; `setup-system-user.sh` refuses an
  `aqt-trail` installed in a home folder (`ProtectHome=true`), and `docs/separate-user.md` states the requirement.
- New `examples/aqt-trail.service`: a systemd user unit for user mode.

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
