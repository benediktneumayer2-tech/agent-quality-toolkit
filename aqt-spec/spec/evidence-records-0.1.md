# AQT Evidence Records 0.1

**Status:** draft specification, version 0.1, 2026-10-21.
**Licence:** this document is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) (SPDX `CC-BY-4.0`). The JSON Schemas and test vectors that accompany it are licensed under Apache-2.0.
**Reference implementation:** the Python package `aqt-spec` (`aqt_evidence`).

> Agent Quality Toolkit supports quality-management practices; it is not a validated system and does not by itself make any process compliant with GMP, GDP, 21 CFR Part 11 or EU Annex 11.

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, RECOMMENDED, MAY and OPTIONAL are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

---

## 1. Overview (read this first)

An **evidence record** is one JSON object that says **who** (a person, an agent or a service, with role) did **what** (an action on a subject, with before and after) **when** (UTC time plus time zone) and **why** (a reason, and for signature-like decisions a meaning). Tools of the Agent Quality Toolkit (AQT) write such records when an agent's input is held or released, a test receipt is captured, a reviewer signs, a deviation is opened, and so on. The format was designed along the audit-trail and signature concepts of ALCOA++, EU GMP Annex 11 and 21 CFR Part 11 (see `crosswalk.md`).

Every record has the same envelope; the tool-specific payload goes in `data`:

```json
{"aqt": "0.1", "id": "rec_019a0f3c2b000000000000000001", "type": "trail.event",
 "time": "2026-10-21T12:00:01.000000Z",
 "actor": {"kind": "agent", "id": "agent:claude-code:s-0001",
           "agent": {"harness": "claude-code", "model": "example-model", "session": "s-0001"}},
 "action": "step-1"}
```

Its **canonical form** sorts keys and drops whitespace:

```
{"action":"step-1","actor":{"agent":{"harness":"claude-code","model":"example-model","session":"s-0001"},"id":"agent:claude-code:s-0001","kind":"agent"},"aqt":"0.1","id":"rec_019a0f3c2b000000000000000001","time":"2026-10-21T12:00:01.000000Z","type":"trail.event"}
```

and its **record hash** is the SHA-256 of those bytes: `sha256:da7d3287e83ff5c46a92fa8377964877a0194a676302b4951dbbe9b83d702040` (vector `valid/minimal`).

Four mechanisms build on the hash:

1. **Signatures** (Ed25519) over the same canonical bytes show who vouches for a record.
2. A **chain** (`chain.seq`, `chain.prev`) links each stored record to the hash of the one before it, so editing, inserting, deleting or reordering becomes visible.
3. A **checkpoint** is a signed statement of the chain head; kept outside the writer's reach it reveals truncation and wholesale rewriting.
4. A **detached signed statement** in `data.signature` binds a person's signature, with its meaning, to the content hash of any record or file.

Who does what: tools create records and deliver them to a **sink** (a JSONL file, or the aqt-trail writer service over a Unix socket). Only the aqt-trail writer sets `time`, `observed` and `chain` and signs the stored record. A file can be checked at three **conformance levels**: L1 valid records, L2 intact chain, L3 signed by pinned keys and anchored by an external checkpoint (§9).

## 2. Terminology

- **Producer:** software that creates records. **Writer:** software that stores records in a log (for a trail, the aqt-trail service). **Verifier:** software that checks records, chains, signatures or checkpoints.
- **Canonical form:** the byte sequence defined in §4. **Record hash:** §5.1. **Content hash:** §5.2.
- **Pinned key:** a public key the verifier obtained independently of the log being verified (for example from the signer registry, §12.2) and trusts for that purpose.
- `sha256:<hex>` denotes the string `sha256:` followed by 64 lower-case hexadecimal digits.

## 3. The record envelope

A record MUST be a JSON object. It MUST NOT contain top-level members other than those listed below; extensions go into `data`. Required members are marked ●.

| Member | | Type | Content | Concept supported |
|---|---|---|---|---|
| `aqt` | ● | string | Spec version, exactly `"0.1"` | — |
| `id` | ● | string | `rec_` + 12 hex digits of milliseconds since the Unix epoch + 16 random hex digits (`^rec_[0-9a-f]{28}$`). Unique; time-ordered | ALCOA++ Complete, Consistent |
| `type` | ● | string | `<tool>.<kind>`, lower case (`^[a-z0-9-]+\.[a-z0-9_.-]+$`), from the registry (§11) or `x-<org>.<kind>` | — |
| `time` | ● | string | RFC 3339 UTC with `Z` and up to 6 fractional digits. In a trail log, the writer's time (§10.3) | Contemporaneous; Annex 11 draft §12.2 (when) |
| `tz` | | string | IANA zone name of the actor's local time (e.g. `Europe/Vienna`) | Annex 11 draft §12.2 (time zone) |
| `actor` | ● | object | Who acted (§3.1) | Attributable; Part 11 §11.10(e) |
| `observed` | | object | Writer-owned process attribution (§3.2) | Attributable (computerised system) |
| `action` | ● | string | Non-empty verb or step name; steps inside one type are told apart by `action` (§11) | Annex 11 draft §12.2 (what) |
| `subject` | | object | `{kind, ref, sha256?}`: what was acted on | Traceable |
| `before`, `after` | | object | `{sha256?, value?}`: old and new state; `value` only for short, non-sensitive values | Annex 11 draft §12.2 (old and new value) |
| `reason` | | string | Non-blank; why, in the actor's words. A human decision MUST carry one | Annex 11 draft §12.2 (why); 2011 §9 |
| `meaning` | | string | Meaning of a signature-like decision (§3.3) | Part 11 §11.50(a)(3) |
| `links` | | array | `[{rel, ref}]` to other records or artefacts (§3.4) | Traceable |
| `data` | | object | Type-specific payload (§11, schemas) | — |
| `chain` | | object | `{seq, prev}`, set by the writer (§7) | Original, Complete |
| `sig` | | array | `[{alg: "ed25519", key, value}]`, signatures of the stored record (§6.2) | Original, Accurate |

### 3.1 Actor

`actor = {kind, id, role?, display?, agent?}`. `kind` MUST be `human`, `agent` or `service`; `id` MUST be a non-empty string. IDs SHOULD follow these conventions: `human:<configured id>`, `agent:<harness>:<session id>`, `service:<tool>`. `role` is the role in which the actor acted (e.g. `quality-manager`). `display` is a printed name and MAY be omitted to minimise personal data. For agents, `agent = {harness, model, version, session}` records the configuration that produced the record (Annex 22 draft §10). An agent identity MUST NOT be shared across sessions.

### 3.2 Observed (writer-owned)

`observed` describes the process that delivered the record, as seen by the writer, not as claimed by the producer:

| Field | Content |
|---|---|
| `pid`, `uid`, `gid` | Peer credentials (`SO_PEERCRED`) |
| `process_chain` | Command names from the peer process up its ancestry, nearest first |
| `processes` | `[{pid, comm, start_time}]` for the same chain |
| `harness` | Detected agent harness, or `null` |
| `client_time` | The producer's original `time` |
| `via` | `socket` (attributed live) or `spool` (delivered later from the spool; no process attribution) |

Only the trail writer sets `observed`. A producer MUST NOT send `observed`. A tool that observes a peer itself (e.g. on its own socket) puts the same fields in `data.peer`.

### 3.3 Meaning vocabulary

| Meaning | Use |
|---|---|
| `authored` | The actor created the subject (e.g. wrote a plan or a document version) |
| `reviewed` | The actor examined the subject and recorded findings; says nothing about acceptance |
| `approved` | The actor, with authority, accepts the subject for its intended next step |
| `released` | A responsible person allows a held subject to be used (quarantine release) |
| `rejected` | The actor refuses the subject or declares it unfit (e.g. a declared threat) |
| `verified` | The actor confirms that a result or state is as stated (e.g. an attested receipt, a resolved outcome) |
| `waived` | A requirement is knowingly not met for this subject, with justification (and SHOULD carry an expiry in `data`) |
| `acknowledged` | The actor has taken note (e.g. of a warning) without approving |

Other values are invalid in 0.1.

### 3.4 Links

`rel` values are free strings; producers SHOULD use: `case`, `evidence`, `supersedes`, `invalidates`, `responds-to`, `plan`, `receipt`, `review`, `deviation`, `capa`, `signs`, `resolves`. `ref` is a record ID or another stable reference.

### 3.5 Payload rules

- `data` MUST be an object. Registered types define minimal required fields (§11); producers MAY add fields.
- **Units:** scores, rates, thresholds and bounds are integers in parts per million with the suffix `_ppm`; durations are integer milliseconds with `_ms` (§4 forbids floats).
- **Large or sensitive texts are never stored inline.** Store `sha256` (of the exact bytes) plus, where useful, a short excerpt (RECOMMENDED at most 280 characters). Secrets, credentials and raw prompts MUST NOT be stored.

## 4. Canonical JSON and parsing

The canonical form of a JSON value is UTF-8 text with:

1. object members sorted by key (keys MUST be ASCII, so code-point order equals RFC 8785's UTF-16 order);
2. no whitespace outside strings (separators `,` and `:`);
3. strings escaped as in RFC 8785: `"` and `\` escaped, U+0008, U+0009, U+000A, U+000C, U+000D as `\b \t \n \f \r`, other code points below U+0020 as `\u00xx` with lower-case hex; everything else, including non-ASCII characters, DEL and `/`, written as is;
4. numbers MUST be integers within ±(2^53 − 1), written in plain decimal; floats, exponents, NaN and Infinity are not allowed;
5. `true`, `false`, `null` as literals.

For every valid AQT record this is byte-identical to RFC 8785 (JCS), so a JCS library produces the same hash.

**Parsing.** A verifier MUST reject a record whose JSON text contains duplicate object keys, a number with a fraction or exponent (also `1.0`), a value outside the integer range, or a string with an unpaired surrogate escape. Parsers disagree on these cases, which would let two readers see two different records under one hash. JSON Schema cannot express these rules (it treats `1.0` as an integer); they are checked by the canonicaliser. Producers SHOULD write records in canonical form, one per line; verifiers MUST recompute hashes and never rely on stored bytes.

## 5. Hashes

### 5.1 Record hash

`record_hash = "sha256:" + hex(SHA-256(canonical(record without "sig")))`. It covers `chain`, `observed` and `time`, so it identifies a record *as stored*. Chains and checkpoints use it.

### 5.2 Content hash of a record

`record_content_hash = "sha256:" + hex(SHA-256(canonical(record without "sig", "chain", "observed", "time")))`. It identifies what a record *says*, independent of where and when a writer stored it. A signature over a record therefore uses `subject = {"kind": "record", "ref": <record id>, "sha256": record_content_hash(record)}` and still matches after the trail stored the record (vector `signed/statement-record`).

### 5.3 Other subjects

A file: `{"kind": "file", "ref": <path relative to the project>, "sha256": "sha256:" + hex(SHA-256(file bytes))}`; the hash, not the path, is binding. A JSON value: `sha256:` over its canonical form. Other kinds (`action`, `plan`, `diff`, …) state their hash basis in the producing tool's documentation.

## 6. Signatures

### 6.1 Keys

Signatures use Ed25519 (RFC 8032). A key ID is `ed25519:` plus the first 16 hex digits of SHA-256 over the raw 32-byte public key. Private keys are stored as PKCS#8 PEM, passphrase-encrypted for human signers, with file mode 0600.

### 6.2 Record signatures (`sig`)

Each `sig` entry is `{alg: "ed25519", key: <key id>, value: <base64 signature>}` over the canonical record without `sig`, i.e. the same bytes as the record hash. Entries are independent co-signatures; adding one does not change the record hash.

**The envelope `sig` belongs to the writer of the stored record.** In a trail log that is the aqt-trail service. A tool writing to its own JSONL file MAY sign the envelope, but MUST remove `sig` before sending a record to aqt-trail.

### 6.3 Detached signed statements (`data.signature`)

Human and actor signatures live in the payload, never in `sig`:

```json
{"statement": {"aqt_signature": "0.1",
               "signer": {"id": "human:alice", "name": "Alice Example", "role": "quality-manager"},
               "key": "ed25519:<16 hex>", "meaning": "approved", "reason": "Receipts and review checked",
               "signed_at": "2026-10-21T12:00:55.000000Z", "tz": "Europe/Vienna",
               "record_type": "change.finish",
               "subject": {"kind": "record", "ref": "rec_…", "sha256": "sha256:…"},
               "nonce": "<16 hex>"},
 "alg": "ed25519", "key": "ed25519:<16 hex>", "value": "<base64>"}
```

The value is the Ed25519 signature over `canonical(statement)`. Required statement members: `aqt_signature` (`"0.1"`, which also separates these bytes from records and checkpoints), `signer.id`, `signer.name`, `key`, `meaning`, `signed_at`, `subject` with `sha256`. RECOMMENDED: `signer.role`, `reason`, `tz`, `record_type` (the type of the record that carries the statement), `nonce`; OPTIONAL `expires_at`. Because name, meaning, time and reason are inside the signed bytes, the manifestation cannot be altered without breaking the signature (Part 11 §11.50); because the subject hash is inside, the signature cannot be moved to another record or file (§11.70). aqt-signoff defines statement handling in detail; every tool that signs a human decision uses this shape. Schema: `schemas/signature.schema.json`.

A verifier reports a statement as valid, invalid (signature does not verify), unknown signer (key not pinned) or **invalidated** (valid, but the subject's current hash differs from `subject.sha256`; vector `signed/statement-target-changed`). Revocation status comes from the signer registry (§12.2).

### 6.4 Key pinning

A signature proves only that the holder of *some* key signed. Verifiers MUST check signatures against pinned keys; a log rewritten and re-signed under a fresh key verifies otherwise (vector `tampered/rewritten-fresh-key`).

## 7. Chain

A writer that chains its log sets `chain = {seq, prev}` on every stored record: `seq` starts at 0 and increases by 1; `prev` is the record hash (§5.1) of the previous record, and `GENESIS` (`sha256:` + 64 zeros) for seq 0. Verification walks the log in order and reports either *intact* (count, head seq, head hash) or *broken from seq N* with the reason: an invalid record, a missing chain, an unexpected seq, a `prev` that does not match, or an invalid or missing signature when signatures are required.

Limits (shown by vectors): without signatures an edit of record N is detected at record N+1; an edit of the last record, and truncation, are not detectable by the chain alone. Signatures (§6.2) and checkpoints (§8) close these gaps.

## 8. Checkpoints and anchors

A checkpoint is a signed statement of a log head:

```json
{"aqt_checkpoint": "0.1", "log": "<log id>", "seq": 3, "head": "sha256:…", "time": "…Z",
 "sig": {"alg": "ed25519", "key": "ed25519:…", "value": "<base64>"}}
```

The signature covers the canonical checkpoint without `sig`. Note that `sig` is a single object here, not a list. A checkpoint *matches* a log when the record at `seq` has exactly the record hash `head`. A checkpoint is useful only when a copy is kept outside the writer's reach (another machine, an exported head file, an RFC 3161 timestamp token over it stored in a `trail.anchor` record). Schema: `schemas/checkpoint.schema.json`.

## 9. Conformance levels

| Level | A file conforms when | It detects |
|---|---|---|
| **L1 valid** | Every line parses strictly (§4); every envelope is valid (§3); types are registered or `x-` extensions; `data` is an object; registered payloads and `observed` match their schemas; IDs are unique; human decisions of types marked *reason* in §11 carry `reason` | Malformed, ambiguous and incomplete records |
| **L2 chained** | L1, and the chain verifies from GENESIS (§7); unavailability appears only as explicit `trail.gap` records | Edit, insert, delete and reorder inside the file |
| **L3 signed and anchored** | L2, every record carries a valid `sig` by a pinned key, and at least one signed checkpoint kept outside the writer verifies and matches | Truncation, rollback and rewrite under a fresh key |

`aqt-evidence conform FILE --level N [--key PEM]… [--checkpoint FILE]…` reports the highest level reached.

**Test vectors.** `vectors/` contains language-neutral vectors in six categories: `canonical`, `valid`, `invalid`, `chained`, `tampered`, `signed` (see `vectors/README.md`). An implementation conforms to this specification when it agrees with every vector. Signed vectors use the published RFC 8032 §7.1 TEST 1 and TEST 2 keys, which are **for testing only**.

## 10. Sinks and the trail socket protocol

### 10.1 Choosing a sink

`AQT_SINK=file:/path.jsonl` appends records as canonical JSON lines to a file (exclusive lock, fsync, mode 0600). `AQT_SINK=unix:/path.sock` sends them to an aqt-trail writer. Without `AQT_SINK`, records go to `$XDG_STATE_HOME/aqt/evidence.jsonl`. A JSONL sink does not chain.

### 10.2 Socket protocol

One request per connection, one JSON object per line. Request: `{"op": "append", "record": {...}}`. Response: `{"ok": true, "record": <stored record>}` or `{"ok": false, "code": <code>, "message": <text>}` with `code` one of:

| Code | Meaning |
|---|---|
| `invalid_record` | Envelope invalid, or the client sent `sig`, `chain` or `observed` |
| `unauthorized` | The peer may not append (peer credential check) |
| `duplicate_id` | A *different* record with this `id` exists |
| `unavailable` | The writer cannot store records now |
| `internal` | Any other failure |

**Appends are idempotent by `id`:** re-sending an identical record returns the stored one with `ok: true`.

### 10.3 What the writer sets

The writer refuses client records that carry `sig`, `chain` or `observed`. It never changes `data`. It moves the client's `time` to `observed.client_time`, sets `time` to its own clock, sets `observed` (§3.2) and `chain` (§7), and signs the stored record (§6.2).

### 10.4 Spool and gaps

When the socket cannot be reached, a client SHOULD append the record to `$XDG_STATE_HOME/aqt/spool/spool.jsonl` (locked, mode 0600) instead of losing it (`aqt_evidence.SocketSink` does this and sets `last_spooled`; `spool=False` raises instead). The writer drains the spool on start and on request: it first writes one `trail.gap` record, then each spooled record with `observed.via = "spool"` and no process attribution. Nothing is silently lost.

### 10.5 Reading records

Consumers read files, not the socket. `AQT_EVIDENCE` lists JSONL paths separated by colons; the default is the default sink file plus the trail log `$XDG_STATE_HOME/aqt/trail/trail.jsonl`, deduplicated by `id` (`aqt_evidence.iter_evidence`). Tools that consume records accept `--evidence PATH` (repeatable).

## 11. Record-type registry

Types are `<tool>.<kind>`. Third parties use `x-<org>.<kind>`. Steps inside one type are told apart by `action` (e.g. `change.plan.reconciled` with `baseline` | `begin` | `reconcile`). Every tool has a `<tool>.refused` type for refused attempts (typically by an agent): `action: "refused"`, `actor` = the claimed actor, `data = {attempted_action, reason_code, agent_markers}`.

The machine-readable registry is `schemas/registry.json`; each type has a payload schema in `schemas/data/`. Payload schemas in 0.1 fix only the minimal fields other tools rely on and allow additional fields. *Reason* marks decision types where a human actor MUST give `reason`.

| Type | Summary | Actions | Meanings | Reason |
|---|---|---|---|---|
| `trail.event` | Generic event (service start/stop, clock jump, user events) | — | — | |
| `trail.gap` | Spooled records follow; marks the time the writer was unavailable | spool.drained | — | |
| `trail.import` | Event imported from an agent harness (hook, session JSONL) | — | — | |
| `trail.anchor` | External anchor of a checkpoint (RFC 3161 token or exported head) | rfc3161, external-head | — | |
| `trail.review` | Signed audit-trail review | review.signed | reviewed | yes |
| `trail.refused` | Refused attempt | refused | — | |
| `signoff.signature` | Signature with meaning bound to a subject hash | sign | any | yes |
| `signoff.invalidation` | A signature stopped applying (content changed or withdrawn) | — | — | yes |
| `signoff.action.prepared` | An action proposed for approval | prepare | — | |
| `signoff.action.approved` | Approval of the exact action hash | approve | approved | yes |
| `signoff.action.rejected` | Rejection of the exact action hash | reject | rejected | yes |
| `signoff.action.claimed` | Executor claimed an approved action (at most once) | claim | — | |
| `signoff.action.outcome` | Outcome of a claimed action; unknown is never retried | outcome, resolve | verified | |
| `signoff.key.enrolled` | Signer key enrolled | enroll | — | |
| `signoff.key.revoked` | Signer key revoked | revoke | — | yes |
| `signoff.auth.failed` | Failed re-authentication | auth.failed | — | |
| `signoff.refused` | Refused attempt | refused | — | |
| `change.plan.reconciled` | Plan baseline or reconciled plan edit | baseline, begin, reconcile | — | |
| `change.receipt` | Runner-captured verification receipt | run, attest | verified | |
| `change.review` | Review record with reviewer independence class | review | reviewed | |
| `change.reconciliation` | Approved-versus-actual diff reconciliation | reconcile-diff | — | |
| `change.finish` | Evidenced finish of a plan | finish | — | |
| `change.refused` | Refused attempt | refused | — | |
| `sensei.pair` | Advisor pairing lifecycle | attached, updated, paused, resumed, ended, doctor | — | |
| `sensei.message` | Message between worker and advisor (hash + excerpt) | enqueued, delivered, failed, no-reply | — | |
| `sensei.decision` | Owner decision on a message | approved, edited, discarded, forwarded | approved, rejected, released | yes |
| `sensei.budget` | Budget consumption and limits | consumed, reached, cost-added | — | |
| `sensei.refused` | Refused attempt | refused | — | |
| `quarantine.passed` | Untrusted input passed (pass or warn band) | pass | — | |
| `quarantine.held` | Untrusted input held in quarantine | hold | — | |
| `quarantine.released` | Held input released by a responsible person | release | released | yes |
| `quarantine.source.trusted` | Source trusted (or trust revoked) with expiry | trust, revoke | approved | yes |
| `quarantine.threat.declared` | Held input declared a threat | declare | rejected | yes |
| `quarantine.delivered` | Released content delivered to the agent | deliver | — | |
| `quarantine.refused` | Refused attempt | refused | — | |
| `validate.run` | Validation run lifecycle | protocol-locked, completed, failed | — | |
| `validate.report` | Validation report | report | — | |
| `validate.qualification` | Human qualification decision with validity period | qualify | approved, rejected | yes |
| `validate.requalification` | Requalification trigger fired | requalify | — | |
| `validate.refused` | Refused attempt | refused | — | |
| `capa.deviation` | Deviation lifecycle | opened, accepted, dismissed, classified, closed | — | |
| `capa.investigation` | Root-cause investigation | drafted, recorded, revised | — | |
| `capa.action` | Corrective or preventive change to an agent control | planned, implemented, approved, cancelled | approved | |
| `capa.effectiveness` | Effectiveness check result | evaluated, extended | — | |
| `capa.closure` | CAPA closure | closed | approved | yes |
| `capa.refused` | Refused attempt | refused | — | |

Actions listed are those known at 0.1; tools MAY use further actions. Minimal `data` fields fixed for cross-tool use:

| Type | Required `data` fields |
|---|---|
| `change.receipt` | `argv` (list), `exit_code`, `passed` (bool), `plan_basis_hash`, `tree_fingerprint`, `counts` (object) |
| `change.finish` | `plan_ref`, `receipts` (record IDs), `waivers` (list), `gate` (`GO` \| `NO-GO` \| `MANUAL_VERIFY_REQUIRED`) |
| `change.review` | `verdict` (`PASS` \| `CONCERNS` \| `FAIL` \| `WAIVED`), `independence` (`same-session` \| `fresh-context` \| `different-model` \| `human`), `diff_sha256`, `findings` |
| `trail.review` | `findings` (`[{query, severity, record_ids, disposition}]`, disposition `ok` \| `explained` \| `deviation`), `head` |
| `signoff.signature` | `signature` (§6.3), `meaning` (mirrors the envelope `meaning`) |
| `signoff.action.outcome` | `outcome` (`succeeded` \| `failed` \| `unknown` \| `not-applied`), `action_id` |
| `quarantine.held`, `quarantine.threat.declared` | `case_id`, `band`, `score_ppm`, `source` (`{tool, ref, domain}`) |
| `sensei.decision` | `decision` (`approve` \| `edit` \| `discard` \| `forward`), `message_id`, `pair_id` |
| `validate.qualification` | `configuration_hash`, `valid_until`; `validate.requalification` adds `trigger` |
| `capa.action` | `target` (`{path, before_sha256, after_sha256}`), `effectiveness_criterion` |
| `<tool>.refused` | `attempted_action`, `reason_code`, `agent_markers` |

## 12. Shared files

### 12.1 Thresholds file

aqt-validate writes, and aqt-quarantine reads, a thresholds file (`schemas/thresholds.schema.json`): `{aqt_thresholds: "0.1", protocol: {id, sha256}, run, detectors: [{id, version, sha256}], bands: [{name: warn|hold, fpr_target_ppm, rule: "any" | {at_least: k}, thresholds: {<detector id>: <threshold in ppm>}}], calibration: {n, realised_fpr_ppm}}`. Thresholds are in the detectors' `score_ppm` unit. Records that apply thresholds carry the file's SHA-256.

### 12.2 Signer registry

`$XDG_CONFIG_HOME/aqt/signers.json`, owned by aqt-signoff and read directly by other tools (`schemas/signers.schema.json`): `{version: 1, signers: [{id, name, role, keys: [{key_id, public_pem, enrolled_at, revoked_at}]}]}`. Private keys: `$XDG_CONFIG_HOME/aqt/keys/<signer-id-slug>.key` (and `.pub`). Passphrases are read interactively only.

## 13. Catalogue IDs

Reports cite GxP catalogue items as `<catalogue>:<item>`, where the item is the clause number as in the source (`part11:11.50(a)`, `annex11-2025d:12.2`, `gdp-2013:6.3`, `euaiact:12(1)`); ALCOA++ items are `alcoa:attributable` … `alcoa:traceable`. Published catalogues: `alcoa`, `annex11-2011`, `annex11-2025d`, `part11`, `ch4-2025d`, `annex22-2025d`, `gdp-2013`, `iso9001-2015`, `euaiact`, `ichq10`, `ichq9`. The suffix `d` marks drafts whose numbering may change. Sources, paraphrases and the features that support each item are in `catalogues/` and `crosswalk.md`.

## 14. Security considerations

- **Tamper evidence, not prevention.** Anyone who can write the log can change it; the mechanisms make changes detectable for a verifier with pinned keys and an external checkpoint. Without both, a full rewrite is undetectable.
- **Same-user writers.** If agents run as the same OS user as the writer, they can read its key and re-sign a rewritten log. Run the writer as a separate user where the threat matters, and keep checkpoints elsewhere.
- **Time.** `time` is the writer's clock. Without an RFC 3161 anchor it is only as trustworthy as the host; clock changes SHOULD be recorded as `trail.event` records.
- **Parser differentials.** Strict parsing (§4) is REQUIRED for verifiers; lenient parsers can be shown different content under one hash.
- **Low-entropy hashes.** A `before`/`after` or subject hash of a short value (a PIN, a yes/no field) can be brute-forced; do not hash secrets, store references instead. Salting is not defined in 0.1.
- **Personal data.** Records name people (`actor`, `display`, signer names) and may carry excerpts. Minimise them, prefer IDs, and reconcile data-protection minimisation with retention duties.
- **Key compromise.** A stolen signing key lets an attacker sign as its owner. Revocation with a compromise date (§12.2) lets verifiers distrust signatures made after that date.
- **Agent-context checks are guards.** `aqt_evidence.require_human` detects environment markers and process ancestry of known agent harnesses; a same-user process can evade it. Tools layer real controls (signed decisions, passphrases) on top and record refusals as `<tool>.refused`.
- **Test keys.** The RFC 8032 keys in `vectors/keys.json` are public. Records signed with them prove nothing.

## 15. Versioning and extensions

`aqt` names the spec version. A future version may add top-level members; a 0.1 verifier rejects records of other versions. Within 0.1, payload schemas may only add optional fields. Extension types use the `x-` prefix; extension data goes into `data`. A later version may add signature algorithms as further `alg` values and an export of records as in-toto or SCITT statements.

## Appendix A. Files

| Path | Content |
|---|---|
| `schemas/envelope.schema.json` | Envelope (§3) |
| `schemas/observed.schema.json` | `observed` (§3.2) |
| `schemas/signature.schema.json` | Detached signed statement (§6.3) |
| `schemas/checkpoint.schema.json` | Checkpoint (§8) |
| `schemas/thresholds.schema.json` | Thresholds file (§12.1) |
| `schemas/signers.schema.json` | Signer registry (§12.2) |
| `schemas/common.schema.json` | Shared definitions |
| `schemas/registry.json`, `schemas/data/*.schema.json` | Record-type registry and payload schemas (§11) |
| `vectors/` | Conformance test vectors (§9) |
| `catalogues/`, `crosswalk.md` | GxP catalogues and crosswalk (§13) |

Schema `$id`s are URNs of the form `urn:aqt:schema:0.1:<name>`; payload schemas use `urn:aqt:schema:0.1:data:<type>`.

## Appendix B. References

RFC 2119 and RFC 8174 (requirement keywords); RFC 3339 (timestamps); RFC 8032 (Ed25519); RFC 8785 (JSON Canonicalization Scheme); RFC 3161 (time-stamp protocol); JSON Schema draft 2020-12; C2SP tlog-checkpoint (signed log heads, an idea this spec adapts in JSON form); 21 CFR Part 11; EudraLex Volume 4 Annex 11 (2011) and its 2025 revision draft, Chapter 4 draft (2025), Annex 22 draft (2025); EU GDP Guidelines 2013/C 343/01; PIC/S PI 041-1.
