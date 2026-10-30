# Agent Quality Toolkit: technical documentation

This document explains how the Agent Quality Toolkit (AQT) works inside. It is for developers who want to integrate or extend the suite, and for technically minded QA people who want to judge how far its evidence can be trusted. It describes version 0.1.0 (a preview, October 2026) as implemented in this repository.

- For step-by-step use of the tools, read the [user manual](manual.md).
- For the project overview and the one-command demo, read the [README](../README.md).
- The normative record format is the [Evidence Records 0.1 specification](../aqt-spec/spec/evidence-records-0.1.md). This document explains it; the specification defines it.

> Agent Quality Toolkit supports quality-management practices; it is not a validated system and does not by itself make any process compliant with GMP, GDP, 21 CFR Part 11 or EU Annex 11.

## Contents

1. [Overview and architecture](#1-overview-and-architecture)
2. [The evidence record](#2-the-evidence-record)
3. [Writing and storing evidence](#3-writing-and-storing-evidence)
4. [Identities and keys](#4-identities-and-keys)
5. [Package internals](#5-package-internals)
6. [Cross-tool interfaces](#6-cross-tool-interfaces)
7. [Data locations](#7-data-locations)
8. [Security model](#8-security-model)
9. [Testing and CI](#9-testing-and-ci)
10. [Extending the suite](#10-extending-the-suite)
11. [Reference: environment variables and conventions](#11-reference-environment-variables-and-conventions)

Paths in this document use the XDG base directories. `$XDG_CONFIG_HOME` defaults to `~/.config`, `$XDG_STATE_HOME` to `~/.local/state`, and `$XDG_RUNTIME_DIR` is the per-login runtime directory (usually `/run/user/<uid>`).

---

## 1. Overview and architecture

### 1.1 The eight packages

The repository is a monorepo of eight Python packages, plus the optional local web interface `aqt-ui` and the `aqt` command (package `aqt-cli`), each described in its README. Each package has its own `pyproject.toml`, `README.md`, `CHANGELOG.md`, `docs/`, `examples/` and an offline test suite. All need Python 3.11 or later and run on Linux.

| Package | Import name | Command | Role | Runtime dependencies |
|---|---|---|---|---|
| `aqt-spec` | `aqt_evidence` | `aqt-evidence` | Record specification, JSON Schemas, test vectors, GxP catalogues and the reference library every other package uses | `cryptography`; optional `jsonschema` (`[schema]` extra) |
| `aqt-trail` | `aqt_trail` | `aqt-trail` | Audit-trail writer service, verification, anchors, importers, ALCOA++ report, audit-trail review | `aqt-spec`, `cryptography` |
| `aqt-signoff` | `aqt_signoff` | `aqt-signoff` | Signer registry, signatures with meaning, approved actions | `aqt-spec`, `cryptography` |
| `aqt-change` | `aqt_change` | `aqt-change` | Plan reconciliation, verification receipts, reviews, finish, gate, hooks | `aqt-spec`, `cryptography`; uses `aqt-signoff` if installed |
| `aqt-sensei` | `aqt_sensei` | `aqt-sensei` (and `sensei` inside the sandbox) | Read-only advisor agent in a bubblewrap sandbox, bridge daemon, advice ledger | `aqt-spec`; external programs `bwrap`, `tmux` or Herdr |
| `aqt-quarantine` | `aqt_quarantine` | `aqt-quarantine` | Detectors, quarantine bands, signed release decisions, Claude Code hooks | `aqt-spec`, `cryptography`; optional ONNX stack (`[hf]` extra) |
| `aqt-validate` | `aqt_validate` | `aqt-validate` | Detector validation and AI-reviewer qualification with exact confidence bounds | `aqt-spec`; detector plug-ins via the `[quarantine]` extra |
| `aqt-capa` | `aqt_capa` | `aqt-capa` | Deviations, investigations, corrective actions, effectiveness checks, trends | `aqt-spec`, `cryptography`; uses `aqt-signoff` if installed |

Every package depends on `aqt-spec`. The other packages do not import each other, with optional exceptions: aqt-change and aqt-capa call `aqt_signoff.is_approved` when aqt-signoff is installed; aqt-trail and aqt-quarantine check registry keys with aqt-signoff's enrolment rules when it is installed (section 4.1); and aqt-validate loads detector plug-ins that aqt-quarantine registers. Everything else between the tools is data: evidence records in JSONL files, the signer registry, and the thresholds file.

### 1.2 Data flow

```mermaid
flowchart LR
    subgraph Producers["Producers"]
        Q["aqt-quarantine"]
        S["aqt-sensei"]
        C["aqt-change"]
        G["aqt-signoff"]
        V["aqt-validate"]
        K["aqt-capa"]
        H["aqt-trail hook / import<br/>(agent sessions)"]
    end
    Producers -->|"open_sink().append(record)"| SINK{"AQT_SINK"}
    SINK -->|"unix:"| W["aqt-trail writer<br/>restamp, observe, chain, sign"]
    SINK -.->|"socket down"| SP[("spool.jsonl")]
    SP -.->|"drain behind trail.gap"| W
    SINK -->|"file: or default"| J[("evidence.jsonl<br/>not chained")]
    W --> L[("trail.jsonl<br/>chained and signed")]
    W --> CP[("checkpoints.jsonl")]
    TSA["RFC 3161 TSA"] -->|"token in trail.anchor"| W
    W -->|"head --export"| X[("head copies<br/>kept elsewhere")]
    L --> VER["verify / conform"]
    X --> VER
    L --> AL["alcoa report"]
    L --> RV["review run → worksheet"]
    RV -->|"review sign: trail.review"| W
    L & J -->|"iter_evidence"| R["readers: aqt-capa scan,<br/>aqt-signoff verify, aqt-change gate,<br/>aqt-validate check"]
```

In words: every tool builds records with `aqt_evidence.new_record` and hands them to `aqt_evidence.open_sink()`. The environment variable `AQT_SINK` decides where they go. With `unix:` they go to the aqt-trail writer, which is the only process that chains and signs the stored log. Tools that need other tools' records read JSONL files (the trail log, a sink file, or an export); there is no query service. Verification, the ALCOA++ report and the audit-trail review all work on the stored log, plus copies of its head kept outside the writer's reach.

### 1.3 Design principles that shape the code

- **One record format.** All tools write the same envelope; tool-specific fields go into `data`.
- **The writer is not the actor.** Tools claim an actor; only the trail writer adds `observed`, the attribution it saw itself.
- **Humans sign, agents propose.** Decisions that need a person carry a detached Ed25519 statement made with a passphrase-protected key. Agents can prepare, run and report, but are refused when they try to decide.
- **Files, not services.** Apart from the trail writer and the aqt-sensei bridge, the tools are plain command-line programs. They read and write files under the XDG directories.
- **Standard library first and offline.** No network calls happen unless the user configures one (an RFC 3161 time-stamp authority, a model download for the optional ONNX detector). Tests never use the network.

---

## 2. The evidence record

### 2.1 Fields

A record is one JSON object. Only the members below may appear at the top level; anything else goes into `data`. Required members are marked ●. Source of truth: `aqt-spec/src/aqt_evidence/record.py` and `aqt-spec/schemas/envelope.schema.json`.

| Member | | Content |
|---|---|---|
| `aqt` | ● | Spec version, exactly `"0.1"` |
| `id` | ● | `rec_` + 12 hex digits of milliseconds since the Unix epoch + 16 random hex digits. Unique and time-ordered |
| `type` | ● | `<tool>.<kind>` in lower case, for example `change.receipt` (pattern `^[a-z0-9-]+\.[a-z0-9_.-]+$`) |
| `time` | ● | RFC 3339 UTC with `Z` and up to 6 fractional digits. In a trail log this is the writer's clock |
| `tz` | | IANA zone of the actor's local time, for display (for example `Europe/Vienna`) |
| `actor` | ● | `{kind, id, role?, display?, agent?}`; `kind` is `human`, `agent` or `service`; `agent` holds `{harness, model, version, session}` |
| `observed` | | Process attribution, set only by the trail writer (section 3.4) |
| `action` | ● | Non-empty step name; steps inside one type are told apart by `action` |
| `subject` | | `{kind, ref, sha256?}`: what was acted on |
| `before`, `after` | | `{sha256?, value?}`: old and new state; `value` only for short, non-sensitive values |
| `reason` | | Non-blank text: why. A human decision must carry one |
| `meaning` | | One of `authored`, `reviewed`, `approved`, `released`, `rejected`, `verified`, `waived`, `acknowledged` |
| `links` | | `[{rel, ref}]` to other records, for example `{"rel": "case", "ref": "rec_…"}` |
| `data` | | Type-specific payload (an object) |
| `chain` | | `{seq, prev}`, set only by the writer that chains the log |
| `sig` | | `[{alg: "ed25519", key, value}]`, signatures of the stored record by its writer |

Actor IDs follow conventions: `human:<configured id>`, `agent:<harness>:<session id>`, `service:<tool>`. An actor ID is a claim made by the producing tool. Section 3.4 explains what the trail writer observes instead, and how claim and observation are compared.

### 2.2 An annotated example

This `change.receipt` comes from a run of the integration demo (`examples/demo/run_demo.py`). The demo was started from inside a Claude Code session, so the writer saw that harness in the process ancestry. Hashes and the process chain are shortened, and some `data` fields are left out. The comments are not part of the format.

```jsonc
{
  "aqt": "0.1",
  "id": "rec_01a163bac4dd3653008e2906c653",        // time-ordered: 0x01a163bac4dd ms since 1970
  "type": "change.receipt",                        // registered type, payload schema data/change.receipt.schema.json
  "time": "2026-10-22T13:09:06.910229Z",           // the writer's clock, not the client's
  "actor": {"kind": "agent", "id": "agent:demo-agent:worker-1",
            "agent": {"harness": "aqt"}},           // claimed by aqt-change: an agent session
  "action": "run",                                 // change.receipt has actions run | attest
  "subject": {"kind": "plan-item", "ref": "s01#V01"},
  "data": {                                        // fields other tools rely on: argv, exit_code, passed,
    "argv": ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"],   // plan_basis_hash, tree_fingerprint, counts
    "exit_code": 0,
    "passed": true,
    "counts": {"source": "pytest", "passed": 2, "total": 2},
    "duration_ms": 213,                            // durations are integer milliseconds
    "stdout": {"bytes": 98, "sha256": "sha256:fcd4…", "tail": "…2 passed in 0.01s"},
    "plan_basis_hash": "sha256:e18a…",
    "tree_fingerprint": "sha256:4e68…",
    "git": {"head": "9f8c0382…", "dirty": true}
  },
  "observed": {                                    // added by aqt-trail; a client may never send it
    "via": "socket",
    "pid": 3370337, "uid": 1000, "gid": 1000,      // from SO_PEERCRED
    "process_chain": ["aqt-change", "python", "bash", "claude", "…", "systemd"],
    "processes": [{"pid": 3370337, "comm": "aqt-change", "start_time": 14714110}, "…"],
    "harness": "claude-code",                      // an agent harness was found in the ancestry
    "client_time": "2026-10-22T13:09:06.909722Z"   // the "time" the client had sent
  },
  "chain": {"seq": 23, "prev": "sha256:0639…"},    // hash of record seq 22
  "sig": [{"alg": "ed25519", "key": "ed25519:9d30779001df1456", "value": "ZaPI…Cg=="}]  // writer's signature
}
```

Note what is *not* in the record: the test output itself. Large or sensitive texts are stored as a SHA-256 hash plus, where useful, a short excerpt (the spec recommends at most 280 characters). Secrets, credentials and raw prompts must not be stored.

### 2.3 Canonical JSON

Hashes and signatures need one exact byte form of a record. AQT canonical JSON (`aqt_evidence.canonical_json`) is:

1. UTF-8, object keys sorted, no whitespace outside strings;
2. **keys must be ASCII**, so that simple code-point sorting equals the UTF-16 sorting of RFC 8785;
3. strings escaped as in RFC 8785; non-ASCII characters are written as they are;
4. **numbers must be integers** within ±(2^53 − 1); floats, exponents, `NaN` and `Infinity` are not allowed;
5. `true`, `false`, `null` as literals.

For every valid record this is byte-identical to RFC 8785 (the JSON Canonicalization Scheme), so a JCS library in another language produces the same hash.

Strict parsing (`parse_record`, `parse_json`) rejects what could make two parsers see two different records under one hash: duplicate keys, any number with a fraction or exponent (also `1.0`), out-of-range integers, unpaired surrogates and invalid UTF-8. JSON Schema cannot express these rules (it treats `1.0` as an integer), so the canonicaliser checks them. `read_jsonl` stays lenient for everyday reading. Verifiers read strictly (spec §4): `aqt-evidence verify` and `aqt-trail verify` parse every line with the strict parser and require it to be exactly the canonical form of its record (`read_jsonl(path, strict=True)`, `parse_canonical_line`), so the stored bytes are the record; `aqt-evidence validate` and `conform` parse strictly as well. Deeply nested input is a parse problem, not a crash.

```text
>>> canonical_json({"b": 1, "a": [True, None, "Grüße"]})
b'{"a":[true,null,"Grüße"],"b":1}'
>>> parse_record('{"a":1.0}')        → CanonicalError: floats are not allowed: 1.0
>>> parse_record('{"a":1,"a":2}')    → CanonicalError: duplicate object key 'a'
>>> parse_record('{"ä":1}')          → CanonicalError: $: object keys must be ASCII strings
```

### 2.4 `record_hash` and `record_content_hash`

There are two hashes of a record, and they answer different questions.

| Function | Covers | Identifies | Used by |
|---|---|---|---|
| `record_hash(record)` | Everything except `sig` | The record **as stored**, including the writer's `time`, `observed` and `chain` | The hash chain, checkpoints |
| `record_content_hash(record)` | Everything except `sig`, `chain`, `observed` and `time` | What the record **says**, independent of where and when it was stored | Signatures over records (`subject.sha256`), idempotent appends |

Both are `sha256:` plus the hex SHA-256 of the canonical JSON. The difference matters because the trail writer changes the record when it stores it: it restamps `time` and adds `observed`, `chain` and `sig`. A person who signs a record must be able to sign it before or after it was stored, and the signature must still match. Output from a real run (a client record sent to a running writer):

```text
client  record_hash         sha256:ab415e96b86d09a2ce298bff7eda847b7d9fad050e957575dfc6314c78291a12
stored  record_hash         sha256:3940f8e44c07b94c80136e4a0b00d6fb5d523300cca9148d2660d6d373b593a1
client  record_content_hash sha256:546e0bba960d365d54a95dd524dede30c1cc48573d6dc545663ac56c65c16d41
stored  record_content_hash sha256:546e0bba960d365d54a95dd524dede30c1cc48573d6dc545663ac56c65c16d41
```

Other subjects: a file is `{"kind": "file", "ref": "<path relative to the project>", "sha256": bytes_hash(content)}`; the hash, not the path, is binding. A JSON value is hashed in canonical form (`content_hash`).

### 2.5 The hash chain

A writer that chains its log (only aqt-trail does) sets `chain = {seq, prev}` on each stored record. `seq` starts at 0 and increases by one. `prev` is the `record_hash` of the previous record, and for `seq` 0 it is the genesis value `GENESIS` = `sha256:` followed by 64 zeros.

Because `record_hash` covers `chain`, editing, inserting, deleting or reordering a record breaks verification from that point on. `aqt_evidence.verify_chain` reports either *intact* (count, head seq, head hash) or *broken from seq N* with the reason. The chain alone has two blind spots, both shown by the test vectors:

- editing the **last** record of an unsigned chain is not detectable, because nothing points to it yet;
- **truncation** (cutting records off the end) leaves a valid shorter chain.

Writer signatures close the first gap; checkpoints kept elsewhere close the second.

Real output from a trail where one `reason` was edited after the fact:

```text
$ aqt-evidence verify edited.jsonl          # chain only, no keys
broken from seq 2: prev does not match the previous record hash
$ aqt-trail verify --trail edited.jsonl     # chain plus the writer's signatures
broken from seq 1: invalid signature
```

### 2.6 Signatures

Signatures use Ed25519 (RFC 8032). A key ID is `ed25519:` plus the first 16 hex digits of the SHA-256 of the raw 32-byte public key. Private key files have mode 0600; a key directory that `generate_key` creates gets 0700. Unattended service keys are unencrypted PKCS#8 PEM. Human keys use the **AQT key format**, version 1: an ASCII-armoured block (`-----BEGIN AQT ENCRYPTED PRIVATE KEY-----`) around the base64 of the canonical JSON `{format: "aqt-key", version: 1, key_id, kdf: {name: "scrypt", n: 131072, r: 8, p: 1, salt}, cipher: {name: "aes-256-gcm", nonce}, ciphertext}`. The 32-byte Ed25519 seed is encrypted with AES-256-GCM under a key that scrypt derives from the passphrase (about 128 MiB of memory per guess); every field except `ciphertext` is authenticated as associated data. Keys from earlier versions (passphrase-encrypted PKCS#8 with PBKDF2 at 2,048 iterations) still load; `upgrade_key` re-encrypts one in place, and `key_file_format` tells the formats apart. Public keys are SubjectPublicKeyInfo PEM. There are two kinds of signatures, and they must not be confused.

**Envelope signatures (`sig`) belong to the writer of the stored record.** Each entry signs the canonical record without `sig`, which are the same bytes as the record hash, so adding a co-signature does not change the hash. In a trail log the aqt-trail service key signs every record. The trail writer refuses client records that already carry `sig`, `chain` or `observed` (`invalid_record`). A tool that writes to its own JSONL file may sign the envelope (aqt-signoff does this for a file sink) but must not send `sig` to aqt-trail.

**Detached signed statements (`data.signature`) carry a person's signature.** They live in the payload and survive storage, restamping and re-signing by the writer. Shape (`aqt-spec/schemas/signature.schema.json`), from a real `quarantine.released` record of the demo:

```json
"signature": {
  "statement": {
    "aqt_signature": "0.1",
    "record_type": "quarantine.released",
    "signer": {"id": "human:qm-demo", "name": "Quinn Example (DEMO)", "role": "quality-manager"},
    "key": "ed25519:d2d3fc3d7282fb59",
    "meaning": "released",
    "reason": "Injection is inside an HTML comment; the visible gardening text is harmless and needed for the task",
    "signed_at": "2026-10-22T13:09:05.896575Z",
    "tz": "Europe/Vienna",
    "subject": {"kind": "quarantine-decision", "ref": "case:Q7SEGGW", "sha256": "sha256:8a71…"},
    "nonce": "d903c8bbe5481dc2"
  },
  "alg": "ed25519",
  "key": "ed25519:d2d3fc3d7282fb59",
  "value": "I1msZ12V…YND0CQ=="
}
```

| Statement member | Required | Meaning |
|---|---|---|
| `aqt_signature` | yes | `"0.1"`; also separates these bytes from records and checkpoints |
| `signer.id`, `signer.name` | yes | Who signed, with the printed name (Part 11 §11.50 manifestation) |
| `signer.role` | recommended | The role in which the person signed |
| `key` | yes | Key ID; must equal the block's `key` |
| `meaning` | yes | One of the eight meanings; equals the envelope `meaning` when the record has one |
| `signed_at` | yes | RFC 3339 UTC |
| `subject` | yes | `{kind, ref, sha256}`; the hash binds the signature to exact content |
| `reason`, `tz`, `record_type`, `nonce` | recommended | Why; the signer's zone for display; the type of the record that carries the statement; 16 random hex digits |
| `expires_at`, `outcome` | optional | Expiry of an approval; outcome of a human resolution (aqt-signoff) |
| `withdraws` | optional | In a withdrawal: the statement digest (`content_hash(statement)`) of the withdrawn statement |
| `enrolled_at` | optional | In an enrolment request: the enrolment time it states (informational; the record's time applies) |
| `enrolment` | optional | In an enrolment approval: `{signer, name, role, request, request_sha256}`, the approved signer and role and the request's record ID and `record_content_hash` |

The value is an Ed25519 signature over `canonical_json(statement)` (`aqt_evidence.sign_statement` / `verify_statement`). Because name, role, meaning, time and reason are inside the signed bytes, the manifestation cannot be changed without breaking the signature. Because the subject hash is inside, the signature cannot be moved to other content.

A verifier reports a statement as `valid`, `invalid` (does not verify), `unknown-signer` (key not pinned), `revoked`, or `invalidated` (valid, but the subject's current hash differs). `verify_statement` accepts only a statement (`aqt_signature` "0.1", `signer` and `subject` objects, `statement.key` equal to the block's `key`), so a record signature cannot pose as one. aqt-signoff adds checks on top: the key must belong to `statement.signer.id` in the signer registry and count by the enrolment evidence (its own request, and the first signer or an approval; section 4.1); `signed_at` must not be earlier than the enrolment; `signed_at` at or after the revocation counts as revoked; the role a policy uses is the signer's enrolled role in effect at `signed_at`, which must equal the signed role. A key's own enrolment request and revocation are proofs of possession and are not judged against its validity period. A statement is identified by its **statement digest** (`statement_digest`, `content_hash(statement)`): it counts once, a copy in another record is `invalid` (replay), and a withdrawal by the same signer applies to every copy. A withdrawal names its target in the signed field `withdraws`; one without it (earlier versions) applies only to the record its signed subject names, while that record's content hash still matches.

**Key pinning.** A signature only proves that the holder of *some* key signed. Verifiers must check against keys obtained independently of the log (the signer registry, or `--pin-key`). A log rewritten and re-signed under a fresh key otherwise verifies (vector `tampered/rewritten-fresh-key`).

### 2.7 Checkpoints and RFC 3161 anchors

A checkpoint is a signed statement of a log head. Real output of `aqt-trail head --export` (signature shortened):

```json
{"aqt_checkpoint": "0.1", "head": "sha256:591ffac2018772e397c8064d252f7cf6426882ba2534dd543efee47fafca0306",
 "log": "doc-trail", "seq": 9, "sig": {"alg": "ed25519", "key": "ed25519:b961db5ffa5767dc", "value": "URDo…CA=="},
 "time": "2026-10-22T13:10:11.827340Z"}
```

The signature covers the canonical checkpoint without `sig`; here `sig` is a single object, not a list. A checkpoint *matches* a log when the record at `seq` has exactly the record hash `head`. It is only useful when a copy is kept outside the writer's reach: another machine, a file the agents cannot write, or a time stamp.

An **RFC 3161 anchor** sends only the 32-byte head hash to a time-stamp authority (TSA) and stores the returned token in a `trail.anchor` record (`action: rfc3161`, `data.tsa.token_b64`). `cryptography` has no RFC 3161 verifier, so aqt-trail parses the token with a small DER module (`aqt_trail/der.py`) and checks it in `aqt_trail/tsa.py`:

1. the message imprint equals the head hash;
2. the signed `messageDigest` attribute equals the digest of the TSTInfo;
3. the signature over the signed attributes verifies with the TSA certificate (RSA PKCS#1 v1.5, ECDSA or Ed25519);
4. the certificate has `timeStamping` as its only extended key usage, marked critical, and the `signingCertificate` attribute names it;
5. the certificate chains to a configured CA, each certificate valid at `genTime`, and every issuer on the path is a CA certificate (`basicConstraints cA`, `keyCertSign`, path length).

Configure the TSA's own CA, not a broad root. Only anchors that the writer itself wrote (`observed.origin: writer`) count; the writer refuses `trail.anchor` records from clients. There is no revocation checking of TSA certificates. A token can also be checked independently with `openssl ts -verify`. The built-in authority `test:` (a CA under `<trail state>/test-tsa/`) is for tests and demos only; its certificates say TEST ONLY. Any client may ask the writer for such an anchor, so a TEST ONLY anchor (`tsa.url` `test:` or its test policy) counts only in **test mode**: `--test-tsa` on `verify`, `alcoa`, `status` and `review run`, or `[anchor] test_tsa = true`. Otherwise it is a `verify` warning, never a problem, and `unanchored_head`, ALCOA++ *enduring*, `status` and `anchored_seq(record)` ignore it. `review run` records test mode in the profile, as a difference from the built-in defaults.

### 2.8 Conformance levels and test vectors

`aqt-evidence conform FILE --level N [--key PEM]… [--checkpoint FILE]…` checks a JSONL file up to a target level.

| Level | The file conforms when | Detects |
|---|---|---|
| **L1 valid** | Every line parses strictly; every envelope is valid; types are registered or `x-` extensions; `data` is an object; registered payloads and `observed` match their schemas (needs the `[schema]` extra, otherwise a warning); IDs are unique; human decisions of types marked *reason* carry `reason` | Malformed, ambiguous and incomplete records |
| **L2 chained** | L1 and the chain verifies from `GENESIS` | Edits, inserts, deletes and reordering inside the file |
| **L3 signed and anchored** | L2, every record has a valid `sig` by a pinned key and no invalid one, and at least one checkpoint signed by a pinned key verifies and matches | Truncation, rollback and a rewrite under a fresh key |

The command stops at the requested level, which defaults to 1. Pass `--level 3` to check everything; the summary then says which level was reached. Real output:

```text
$ aqt-evidence conform ~/.local/state/aqt/trail/trail.jsonl --level 3 \
    --key ~/.local/state/aqt/trail/keys/service.key.pub --checkpoint head.json
L3 reached (target L3), 11 records
```

**Test vectors** in `aqt-spec/vectors/` are language-neutral JSON files, generated deterministically by `aqt-spec/scripts/gen_vectors.py`. There are 87 vectors in six folders: `canonical` (13), `valid` (6), `invalid` (34), `chained` (2), `tampered` (20) and `signed` (12). Since the security review of October 2026 they include a tamper corpus (wrong member types, `null` members, trailing newlines, non-ASCII digits, impossible dates; stripped, moved, re-signed and `null` signatures, duplicated and unchained records, signatures required without a key, malformed checkpoints) and the vector kind `log`, a stored JSON-lines log that must be parsed strictly before its chain is verified. Signed vectors use the published RFC 8032 TEST 1 and TEST 2 keys from `vectors/keys.json`; anyone can sign with them, so records signed with them prove nothing. An implementation in another language conforms when it agrees with every vector; [`aqt-spec/docs/implementers.md`](../aqt-spec/docs/implementers.md) describes the file format.

```text
$ aqt-evidence vectors
87 of 87 vectors agree
```

### 2.9 Units, naming and the registry

- **Units.** Floats are forbidden, so scores, rates, thresholds and confidence bounds are integers in parts per million with the suffix `_ppm` (0.898991 is written `898991`). Durations are integer milliseconds with the suffix `_ms`.
- **Types.** `<tool>.<kind>`, with steps told apart by `action` (for example `change.plan.reconciled` with `baseline`, `begin` or `reconcile`). Every tool also has `<tool>.refused` for refused attempts, with `action: "refused"`, the claimed actor as `actor`, and `data = {attempted_action, reason_code, agent_markers}`. Third parties use `x-<org>.<kind>`; such types pass L1 without a payload check.
- **Registry.** `aqt-spec/schemas/registry.json` lists the 46 registered types with their tool, summary, known actions and meanings, whether a human actor must give a reason, and the payload schema under `schemas/data/`. Payload schemas in 0.1 fix only the minimal fields other tools rely on and allow additional fields. The registry's action and meaning lists are the ones the 0.1 tools write (for example `validate.qualification` with `approve`/`reject`, `quarantine.source.trusted` revocations with meaning `rejected`, `capa.action implemented` with `authored`); `trail.event` and `trail.import` leave their actions open. The spec allows further actions. A meaning outside a type's list produces a conformance *warning*, not a failure. The integration demo checks that every type, action and meaning in its trail is registered, and a test in aqt-spec keeps the spec's table and `registry.json` in step.

---

## 3. Writing and storing evidence

### 3.1 Sinks

`aqt_evidence.open_sink(spec=None)` returns the destination for records. The spec comes from the argument, a tool's configuration, or the environment variable `AQT_SINK`:

| `AQT_SINK` | Sink | Behaviour |
|---|---|---|
| unset | Discovered (`resolve_sink()`): the aqt-trail writer's socket (`[writer] socket` in `trail.toml`, else `$XDG_RUNTIME_DIR/aqt/trail.sock`) when a writer answers or a trail exists (a trail whose writer is down gets the records through the spool); otherwise `JsonlSink($XDG_STATE_HOME/aqt/evidence.jsonl)` | As `unix:` or `file:` below |
| `file:/path.jsonl` | `JsonlSink(/path.jsonl)` | Validates the envelope, appends one canonical line under an exclusive `flock`, `fsync`s, file mode 0600. Does not chain |
| `unix:/path.sock` | `SocketSink(/path.sock)` | Sends the record to an aqt-trail writer and returns the stored record (with the writer's `time`, `observed`, `chain` and `sig`) |

```python
from aqt_evidence import actor, new_record, open_sink, subject, bytes_hash

record = new_record("change.finish", actor("agent", "agent:claude-code:s-0001"), "finish",
                    subject=subject("file", "docs/report.md", sha256=bytes_hash(b"...")),
                    data={"plan_ref": "plan-0001", "receipts": [], "waivers": [], "gate": "GO"})
stored = open_sink().append(record)
```

`new_record` validates the envelope and raises `ValueError` for an invalid record. `SocketSink.append` raises `SinkError` when the writer refuses a record (`ok: false`), and refusals are never spooled.

### 3.2 The trail writer

`aqt-trail serve` runs `TrailWriter` (`aqt-trail/src/aqt_trail/writer.py`) behind a Unix socket (`server.py`). It is the only process that appends to `trail.jsonl`. A file lock (`trail.lock`, mode 0600, non-blocking `flock`) ensures one writer per trail. For each client record it:

1. checks that the client did not send `sig`, `chain` or `observed`, that the envelope is valid, and that a human actor who sets `meaning` also gives `reason`; it refuses records that would pass for its own (the actor `service:aqt-trail`, the types `trail.anchor` and `trail.gap`, the actions `service.start`, `service.stop`, `clock.jump` and `log.repaired`), and client `trail.review` and `trail.refused` records without their payload shape;
2. checks idempotence by `id` (section 3.5);
3. reads the clock and records a `trail.event` `clock.jump` first when the wall clock moved more than `clock_jump_ms` (default 2000) away from the monotonic clock, or went backwards;
4. moves the client's `time` to `observed.client_time` and sets `time` to its own clock;
5. adds `observed` (section 3.4);
6. links the record into the chain and signs it with the service key;
7. writes one canonical JSON line (completing short writes) and `fsync`s, then answers the client. A failed write or `fsync` is cut back to the last acknowledged record; if that fails too, the writer answers `unavailable` until it is restarted.

Every refusal is itself a record: `trail.refused` with `data` = `{attempted_action, reason_code, agent_markers, message, attempted_sha256, attempted_id?, attempted_type?, attempted_record_action?}` and the claimed actor. The writer also records its own life: `trail.event` with `service.start` (version, log ID, key ID, pid, socket, configuration hash), `service.stop` (signal), and `log.repaired` when it removed an incomplete last line that was never acknowledged at start. The writer refuses to continue a log that no longer links (`LogBroken`); run `aqt-trail verify` and decide.

Socket location, in this order: `[writer] socket` in `$XDG_CONFIG_HOME/aqt/trail.toml`, the path in `AQT_SINK=unix:…`, `$XDG_RUNTIME_DIR/aqt/trail.sock`, `<state>/aqt-trail.sock`. The socket is created with mode 0600 (0660 with a group in separate-user mode). AF_UNIX paths are limited to about 104 bytes, and the server refuses longer paths. Only the writer's own uid and `[writer] allowed_uids` may use it; others get `unauthorized`.

### 3.3 Socket protocol

One request per connection: the client sends one JSON object followed by a newline, closes its write side, and reads one JSON response. Requests larger than `max_request_bytes` (16 MiB) are refused.

| Request | Successful response |
|---|---|
| `{"op": "append", "record": {…}}` | `{"ok": true, "record": <stored record>, "created": true\|false}` |
| `{"op": "drain", "records": […], "source": "…"}` | `{"ok": true, "appended": n, "already_stored": n, "refused": n, "gap": "<trail.gap id>"\|null}` |
| `{"op": "checkpoint", "anchor": bool, "export": bool, "tsa_url": "…"}` | `{"ok": true, "checkpoint": {…}, "anchor": <record>\|null}`; `tsa_url` may only be empty, the configured `[anchor] tsa_url` or `test:`, anything else is `unauthorized`. A `test:` anchor or an export note that a client asked for never counts as an anchor outside test mode (section 2.7) |
| `{"op": "head"}` | `{"ok": true, "log_id": "…", "seq": n, "head": "sha256:…"}` |
| `{"op": "ping"}` | `{"ok": true, "version": "0.1.0"}` |

Errors are `{"ok": false, "code": "<code>", "message": "…"}`:

| Code | Meaning |
|---|---|
| `invalid_record` | Envelope invalid, the client sent `sig`, `chain` or `observed`, the request is not JSON, or the op is unknown |
| `unauthorized` | The peer's uid may not use the writer, or a checkpoint names a TSA that is not configured |
| `duplicate_id` | A *different* record with this `id` is already stored (also within one drain batch) |
| `unavailable` | The writer cannot store records now, for example after a write it could not undo |
| `internal` | Any other failure (the writer catches it and keeps running) |

A real exchange, sent from Python:

```text
→ {"op":"head"}
← {"head":"sha256:3940f8e4…","log_id":"doc-trail","ok":true,"seq":14}
```

### 3.4 `observed` attribution

`observed` is the writer's own evidence about who delivered a record (`aqt-trail/src/aqt_trail/observe.py`):

| Field | Source |
|---|---|
| `pid`, `uid`, `gid` | The kernel's peer credentials of the socket connection (`SO_PEERCRED`) |
| `processes` | `[{pid, comm, start_time}]` walking `/proc/<pid>/stat` up the parent chain (at most 16 levels). `start_time` (clock ticks since boot) guards against PID reuse |
| `process_chain` | The command names of `processes`, nearest first |
| `harness` | The first agent harness found in the chain, using the process markers of `aqt_evidence.session` (`claude`, `codex`, `pi`, `pi-omni`, `aider`, `goose`, `opencode`, `gemini`, `cursor-agent`, `amp`, `crush`), or `null` |
| `client_time` | The `time` the client sent |
| `via` | `socket` (observed live) or `spool` (delivered later; no process attribution) |
| `chain_status` | How far the observed chain goes: `complete` (read up to init, nothing below applies); `partial` (an ancestor exited during the walk, more than 16 ancestors, a parent started after its child, or a process was reparented to init or a subreaper such as the systemd user manager, so whoever started it is no longer visible); `unavailable` (no peer pid, the sender's own `/proc` entry unreadable, or the sender exited before the walk ended, checked with `SO_PEERPIDFD` on Linux 6.5 and later) |
| `chain_detail` | Why a chain is not `complete` |
| `chain_complete` | `false` when the walk did not reach init; kept for older readers |
| `drained_by` | On records delivered through the `drain` op: the observation of the client that sent them |
| `origin` | `writer` on records the writer creates itself (these have no `via`) |

The writer does not reject a record whose claim and observation disagree. It stores both. The review query `attribution_mismatch` and the ALCOA++ check *attributable* compare them later: a record that claims `human:alice` but was sent by a process below `claude` is a major finding, and one whose chain is `partial` or `unavailable` is a minor finding (ALCOA++ warns). A human claim counts as attributed only with a `complete` chain and no agent marker. Even then this is a heuristic: a process that detaches into a new session (`setsid -f`) or is started by a service manager (`systemd-run --user`) or an existing terminal server (`tmux send-keys` into a person's shell) on an agent's request looks `complete`. A spooled record that claims a human and came through the `drain` op is judged by its drainer: an agent harness in `drained_by` is an `attribution_mismatch` (major), a `drained_by.chain_status` other than `complete` an unconfirmed claim (minor), and the gap finding names the drainer. Records written before `chain_status` existed have only `chain_complete`. A tool that observes peers on its own sockets (aqt-sensei) puts the same fields into `data.peer`, because the envelope's `observed` belongs to the trail writer.

### 3.5 Idempotent appends, the spool and gap markers

**Idempotence.** The writer keeps an index of `id → record_content_hash`. Re-sending an identical record returns the stored one with `ok: true, created: false`; a different record with a known `id` is refused with `duplicate_id`. This makes retries safe: a client that timed out after sending can simply send again.

**Spool.** When the socket cannot be reached, `SocketSink` (and `aqt_trail.client.TrailClient`, used by the `aqt-trail` command itself) appends the record to the shared spool `$XDG_STATE_HOME/aqt/spool/spool.jsonl` (locked, mode 0600) and sets `last_spooled = True`. `SocketSink(path, spool=False)` raises `SinkUnavailable` instead.

**Drain.** The writer drains the spool at start and every `drain_interval_s` (default 30 s) while it runs; `aqt-trail drain` does it on demand (through the socket when the writer runs, so that a separate-user writer can receive a user's spool). The writer first writes one `trail.gap` record, then each spooled record with `observed.via = "spool"` and no process attribution. When the records come through the socket's `drain` op, each carries `observed.drained_by`, the observation of the client that sent them, and the `trail.gap` before them carries it as its own `observed`. A drain stores each record ID once: a repeat with the same content counts as already stored, one with other content is refused (`duplicate_id`). Unparseable spool lines become `trail.refused` records instead of disappearing.

A real sequence: the writer was stopped, a client wrote one record, the writer was started again.

```text
$ aqt-trail list
     5 2026-10-22T13:10:04.082143Z trail.event      service.stop       service:aqt-trail
     6 2026-10-22T13:10:05.034151Z trail.event      service.start      service:aqt-trail
     7 2026-10-22T13:10:05.040661Z trail.gap        spool.drained      service:aqt-trail  — records were spooled while the writer was unavailable
     8 2026-10-22T13:10:05.044455Z trail.event      note               agent:claude-code:unknown  — written while the writer is down
```

The `trail.gap` payload is `{reason: "writer-unavailable", count, first_time, last_time, spool_ids, source}`. Its `reason`, `first_time` and `last_time` come from the spooled records, so they are the client's account, not the writer's observation. Record 8 carries `observed = {"via": "spool", "process_chain": [], "processes": [], "harness": null, "client_time": "…"}`. The review query `gaps` and the ALCOA++ check *complete* report both.

### 3.6 Reading evidence

Consumers read files, never the socket. `aqt_evidence.iter_evidence(paths=None)` yields records file by file and de-duplicates them by `id`. Without `paths` it uses `evidence_sources()`:

1. `AQT_EVIDENCE`, a colon-separated list of JSONL paths, when set;
2. otherwise the trail log (`trail.jsonl` in the trail state directory: `[trail] state` in `trail.toml`, else `AQT_TRAIL_STATE`, else `$XDG_STATE_HOME/aqt/trail/`), the default sink file (the `file:` path in `AQT_SINK`, or `$XDG_STATE_HOME/aqt/evidence.jsonl`) and the spool, each only if it exists.

Files named `trail.jsonl` are always read first, whatever the order of `paths`, so a record in a side file (sink file, spool) can neither hide nor replace a trail record with the same `id`. A later copy with other content is not used; it is reported (`iter_evidence(paths, conflicts=list)` collects `{id, kept, dropped}`, otherwise one warning on stderr). Copies with the same content are deduplicated silently. A separate-user log such as `/var/lib/aqt-trail/trail.jsonl` is not in the user's default places; name it in `AQT_EVIDENCE` (or `--evidence`) and keep its file name, because readers recognise trail logs by it. Records that exist only in side files are not chained or writer-signed, and consumers do not yet require trail records when a trail exists (spec §10.5). Every consuming command accepts `--evidence PATH` (repeatable), and aqt-signoff, aqt-capa and aqt-validate also accept an evidence list in their configuration files.

Some tools additionally keep a local mirror of their own records as a working store: aqt-quarantine's `journal.jsonl` and aqt-change's `records.jsonl`. These mirrors are indexes for the tool; the sink is the evidence.

---

## 4. Identities and keys

### 4.1 The signer registry and key files

The signer registry `$XDG_CONFIG_HOME/aqt/signers.json` (schema `aqt-spec/schemas/signers.schema.json`) is owned by aqt-signoff. aqt-trail and aqt-quarantine read it directly and, when aqt-signoff is installed, check its keys with aqt-signoff's enrolment rules. aqt-change and aqt-capa use it indirectly through `aqt_signoff.is_approved` when aqt-signoff is installed.

```json
{"version": 1,
 "signers": [{"id": "human:qm-demo", "name": "Quinn Example (DEMO)", "role": "quality-manager",
              "keys": [{"key_id": "ed25519:d2d3fc3d7282fb59",
                        "public_pem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA…\n-----END PUBLIC KEY-----\n",
                        "enrolled_at": "2026-10-22T13:09:05.760588Z", "revoked_at": null}]}]}
```

- **Signer IDs** match `human:[a-z0-9][a-z0-9._-]{0,63}` in aqt-signoff and are never reused.
- **Key files** are `$XDG_CONFIG_HOME/aqt/keys/<slug>.key` (the AQT key format of section 2.6, mode 0600; the folder 0700) and `<slug>.key.pub`. The slug is the signer ID with `:` replaced by `-` (`human:alice` → `human-alice.key`).
- **Revocation** sets `revoked_at` (the revocation time, or the declared start of a compromise with `--compromised-since`) and renames the key files to `<slug>.<key hex>.revoked.key`, so that a new key can take the standard name. Signatures made at or after `revoked_at` show as `revoked`.
- **Enrolment and revocation are records** (`signoff.key.enrolled`, `signoff.key.revoked`). A failed passphrase entry is recorded as `signoff.auth.failed`.
- **The registry is configuration; the enrolment records decide** (aqt-signoff; through `is_approved` aqt-change and aqt-capa; with aqt-signoff installed also aqt-trail, aqt-quarantine and the aqt-ui record inspector). The records come from the trail when there is one, else from every evidence source (`aqt_signoff.registry.Registry.reconcile`, rules in `aqt_signoff/enrolment.py`). A `signoff.key.enrolled` record is a **request** (signed by the new key), an **approval** (signed by an enrolled key; the statement field `enrolment` binds the request's ID and content hash) or an **import** of records written before the trail (spec §6.3). The rules, in evidence order:
  - The first request counts at once (the **bootstrap**, `check_signers()["bootstrap"]`). Every later request counts only after an approval by another signer whose key counts and is active at the approval's record time; the key then counts from its request's record time (the trail writer's time, never a time the client states). Until then it is **pending**: listed, ignored by every check, and refused for signing (`enrolment_pending`).
  - Nobody approves their own enrolment or role (`self_approval`). A signer's own other key approves only a **rotation** (`init --add-key` while the old key counts): same role, and the old key is revoked in the same step.
  - A role changes only through an approval by another signer (`signers approve ID --key KEY --role ROLE`). `SignatureStatus.authorized_role` is the role in effect at `signed_at`, so earlier signatures keep their role. A registry role that differs from the current enrolled role stops the key (`registry_mismatch`).
  - A copy of a request (the same signed statement in another record) counts once. A second, differently signed request for a key is a conflict: the key stops counting from that record's time (per key `stopped_at`), signatures made before it keep counting, and it is a `problems` entry.
  - A request made when no earlier key counts and is active any more is a **re-bootstrap**: it counts, and `check_signers()` lists it under `rebootstrap` (`counted_before`, `confirmed_by`, `not_confirming`, `unsigned_revocations`) and keeps `ok` False until a signer whose key counted *before* it approves it. A key that counts through the re-bootstrapped key (approved by it, directly or through others) never confirms it (`not_confirming`); every key that counted before is revoked by then, so in practice a re-bootstrap stays flagged, also in `verify` (`VerifyReport.registry_warnings`). A request whose record time lies before the keys that count (backdated) is pending, never a re-bootstrap.
  - A revocation without a signature (`revoke --lost`) is accepted from anyone, because it only takes rights away. A revocation counts as *signed* when the revoked key or another key that counts at its record time signed it; unsigned ones apply all the same and are reported (`check_signers()["unsigned_revocations"]`, per key `unsigned_revocations`, and on the re-bootstrap they made possible). Revocation records apply even when `signers.json` says the key is active, and signing with a key that a revocation or a conflict stopped is refused (`registry_mismatch`).
  - With a trail, enrolments count only from the trail. Records written before it in the fallback evidence file count after `aqt-signoff signers import`, an import record signed by a signer whose key counts in them (or in the trail); their order and times are kept. Only the first import that counts has effect: a later one is refused (`already_imported`) and ignored if written anyway. Records outside the trail written after the trail started (the earlier of its first record's time and `trail.json` `created`) or after the import are never importable; `check_signers()` lists them under `ignored` instead of asking for an import. `import_preview()` adds `outcome` (per key: `counts`, `pending`, `in-trail` or `conflict`, and the signer's other keys) and `ignored`. Until the import, signing, `init` and adoption refuse with `import_needed`.
  - A key that another tool created (`aqt-quarantine init`) gets its request, marked `data.adopted`, the first time its owner unlocks it in aqt-signoff (or with `rekey`); it then waits for approval unless it is the first signer's.
- **Reports.** `aqt-signoff signers check` and `check_signers()` return `ok`, `evidence` (where the enrolment records came from: `trail`, `registry export` or `evidence`), `bootstrap`, `rebootstrap`, `pending` (with the approve command), `imports`, `problems`, `ignored` and `unsigned_revocations`, and per key `counts`, `pending`, `basis` (`bootstrap`, `rebootstrap` or `approved`), `enrolled_at`, `revoked_at`, `stopped_at`, `approvals`, `roles`, `unsigned_revocations`, `problems` and `notes`. aqt-trail checks keys with `aqt_trail.signers.check_enrolment` (`load_registry(records=...)`) and aqt-quarantine with `enrolment_view`, both through aqt-signoff's rules; without aqt-signoff installed they use `signers.json` alone, and `aqt-trail verify` (ALCOA++ *accurate*) and `aqt-quarantine doctor` warn.
- **Overrides.** aqt-signoff, aqt-quarantine and aqt-trail honour `AQT_SIGNERS` and `AQT_KEYS_DIR`; aqt-signoff and aqt-quarantine also take the matching flags or configuration keys, and aqt-trail `--key PEM` for the reviewer key.
- **Sharing.** `aqt-signoff signers export` (`Signoff.export_registry()`) writes the registry for verification on another machine, plus `enrolment_evidence`: `source`, `exported_at`, `records` (the enrolment and revocation records, in evidence order) and `revocations` (revocations from other sources). A registry file that carries it (`--registry FILE`) supplies the enrolment evidence when the sources hold no trail (`check_signers()["evidence"] == "registry export"`), checked like any other evidence; with a trail it is not used (a note says so), so an edited `signers.json` cannot inject enrolments. `aqt-trail verify --signers FILE` does not use it. aqt-trail's export bundle includes a copy of `signers.json`, which `verify --bundle` does not trust (pass `--signers`).

### 4.2 Passphrases

Passphrases are only read interactively from the terminal (`getpass`). There is no flag and no environment variable for them. Each signature asks again (re-authentication per signing). The libraries accept injected authenticators for tests (`aqt_signoff.StaticPassphrase`, a passphrase callback in aqt-quarantine); the integration demo uses them and marks them DEMO ONLY.

Service keys are the exception: the aqt-trail service key (`<trail state>/keys/service.key`) is unencrypted so that the writer can start unattended, which is why its protection depends on file permissions (section 8).

### 4.3 The human check

Human-only decisions (sign, approve, release, qualify, close a CAPA, sign a review) call `aqt_evidence.require_human()` first. It raises `HumanCheckError` unless:

- no **environment marker** of an agent harness is set: `AQT_AGENT_SESSION`, `CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT`, `CODEX_SANDBOX`, `CODEX_SANDBOX_NETWORK_DISABLED`, `CODEX_THREAD_ID`, `PI_CODING_AGENT`, `GEMINI_CLI`, `AIDER_MODEL`, `GOOSE_SESSION_ID`, `OPENCODE`;
- no **process marker** appears among the ancestors in `/proc` (the same names as in section 3.4);
- standard input is a **terminal** (`require_tty=True` by default).

`detect_agent_context()` returns the same analysis without raising (`is_agent`, `harness`, `markers`, `process_chain`). Each tool records a refusal as `<tool>.refused` with the markers it found. Real output when an agent tried to sign a review:

```text
$ aqt-trail review sign worksheet.json --reviewer human:dora --disposition all=ok --reason "weekly review"
refused: refused: this command looks like it runs inside an agent session (env:CLAUDECODE, env:CLAUDE_CODE_ENTRYPOINT, process:claude); run it yourself in a terminal
```

The stored `trail.refused` record has `data = {attempted_action: "review.sign", reason_code: "agent_context", agent_markers: ["env:CLAUDECODE", "env:CLAUDE_CODE_ENTRYPOINT", "process:claude"], message: …}`.

The check is a guard against an agent deciding by accident or because of an injected instruction. It is **not** a security boundary: a same-user process can clear its environment and detach from its parents. The real controls are the passphrase-protected keys and, for the trail, the separate writer.

### 4.4 How actor identities are chosen

Actor IDs in records are claims. The tools resolve them as follows:

| Tool | Resolution |
|---|---|
| aqt-change | Agent context detected → `agent:<harness>:<session>` (session from `AQT_AGENT_SESSION`, `CLAUDE_SESSION_ID`, `CODEX_THREAD_ID`, `PI_SESSION_ID` or `GOOSE_SESSION_ID`). `AQT_ACTOR` can set the ID but never turns an agent context into a human |
| aqt-signoff | Human steps use the registry entry of `--signer` or `[signoff] signer`. Non-human steps (`prepare`, `claim`, `outcome`) use `AQT_ACTOR`, else a detected agent, else the configured signer, else `service:aqt-signoff` |
| aqt-capa, aqt-validate | `[identity] id` (aqt-capa) or `actor` (aqt-validate) in the configuration, or `AQT_ACTOR`; an agent context makes the actor `agent:<harness>:<session>`, with the session from `AQT_AGENT_SESSION` (aqt-validate also tries `CODEX_THREAD_ID`), else `unknown` |
| aqt-trail `event` | `--actor`, else `AQT_ACTOR`, else a detected agent (`agent:<harness>:unknown`), else `human:<login name>` |
| aqt-quarantine, aqt-sensei | Decisions are made by the configured responsible person or owner; service steps use `service:aqt-quarantine` / `service:aqt-sensei` |

Because these are claims, the trail's `observed` attribution matters: it is what lets a reviewer see that a "human" record came from an agent process.

---

## 5. Package internals

Each subsection summarises one package. The packages' own `docs/` hold full command references.

### 5.1 aqt-spec (`aqt_evidence`)

**Purpose.** The shared ground: the specification, schemas, vectors, catalogues and the reference library.

**Library modules** (`aqt-spec/src/aqt_evidence/`):

| Module | Content |
|---|---|
| `canonical.py` | `canonical_json`, `content_hash`, `bytes_hash`, strict `parse_json` / `parse_record` |
| `record.py` | `new_record`, `actor`, `subject`, `validate_record`, `record_hash`, `record_content_hash`, `MEANINGS` |
| `crypto.py` | `generate_key`, `load_signer`, `load_public_key`, `key_id`, `upgrade_key`, `key_file_format`, `sign_record`, `verify_record_signatures`, `sign_statement`, `verify_statement` |
| `chain.py` | `GENESIS`, `link`, `verify_chain`, `make_checkpoint`, `verify_checkpoint`, `checkpoint_matches` |
| `sink.py` | `open_sink`, `resolve_sink`, `JsonlSink`, `SocketSink`, `read_jsonl` (`strict=True` for verifiers), `parse_canonical_line`, `RecordLineError`, `evidence_sources`, `iter_evidence`, `state_dir`, `spool_file`, `ERROR_CODES` |
| `session.py` | `detect_agent_context`, `require_human`, `process_chain`, the marker tables |
| `conformance.py` | `conformance`, `read_strict` (levels L1–L3) |
| `schemas.py` | Registry and schema access; validation with the optional `jsonschema` |
| `catalogues.py` | Catalogue access (standard library only): `item`, `items`, `features`, `supporting` |
| `vectors.py` | Runs the test vectors |

The API is listed in [`aqt-spec/docs/api.md`](../aqt-spec/docs/api.md); it is stable since 0.1.0 and changes only additively.

**CLI** `aqt-evidence`: `validate FILE`, `hash FILE`, `verify FILE [--key PEM]… [--require-signature]` (`--require-signature` without `--key` is a usage error), `keygen PATH [--passphrase]`, `conform FILE --level N …`, `vectors [DIR]`.

**Generated files.** `schemas/` and `schemas/registry.json` come from `scripts/build_schemas.py`; `vectors/` from `scripts/gen_vectors.py`; `crosswalk.md` and `catalogues/catalogues.json` from `scripts/build_crosswalk.py`. The tests fail when a generated file is out of date. Wheels package the schemas, vectors and `catalogues.json` under `aqt_evidence/_data/`.

**Catalogues.** `catalogues/*.yaml` hold 121 paraphrased items in 11 catalogues (ALCOA++, Annex 11 2011 and 2025 draft, Part 11, Chapter 4 draft, Annex 22 draft, GDP 2013, ISO 9001:2015, EU AI Act, ICH Q10, ICH Q9). `catalogues/features.yaml` names the AQT features each item is `supported_by`, and the record types that evidence each feature.

### 5.2 aqt-trail

**Purpose.** A tamper-evident audit trail written by a separate process, with verification, external anchors, importers for agent sessions, an ALCOA++ report and a signed, independent audit-trail review.

**Main concepts.** The writer pipeline and protocol (sections 3.2–3.5); checkpoints and anchors (2.7); importers; review queries.

**Commands** (all accept `--state DIR`, `--config FILE`, `--json`; exit 0 ok, 1 check failed or refused, 2 usage or runtime error): `init [--log-id ID]`, `serve`, `status [--test-tsa]`, `append [FILE|-]`, `event --action A …`, `hook claude-code`, `import claude-code|codex|pi PATH… [--dry-run]`, `checkpoint [--anchor] [--tsa URL]`, `head [--export]`, `drain`, `verify […]`, `list [filters]`, `show ID|SEQ`, `report --format md|html`, `export --out DIR [--tar]`, `alcoa`, `review run|sign|list`. `status` reports the last anchor (writer-written RFC 3161; TEST ONLY ones only in test mode) and the last review whose signature is valid, counting a copied statement once. See [`aqt-trail/docs/usage.md`](../aqt-trail/docs/usage.md).

**Files.** State in `$AQT_TRAIL_STATE` or `$XDG_STATE_HOME/aqt/trail/`: `trail.jsonl`, `checkpoints.jsonl`, `trail.json` (`log_id`, `key_id`, `created`), `trail.lock`, `keys/service.key[.pub]`, `reviews/<rv_id>/worksheet.json|.md`, and `test-tsa/` when the test authority is used. Configuration `$XDG_CONFIG_HOME/aqt/trail.toml` (`[writer]`, `[anchor]` with `tsa_url`, `tsa_ca` and `test_tsa`, `[import]`, `[review]`; see `examples/trail.toml`). Note that the code's default review time zone is `UTC`; the example file sets `Europe/Vienna`.

**Records written.** `trail.event` (`service.start`, `service.stop`, `clock.jump`, `log.repaired`, or a user action), `trail.gap`, `trail.refused`, `trail.import`, `trail.anchor` (`rfc3161`, `external-head`), `trail.review` (`review.signed`).

**Verification** (`aqt-trail verify`). It recomputes every hash; checks the service signatures (all keys in `<state>/keys/*.pub`, or only `--pin-key`); checks stored checkpoints, exported heads (`--heads FILE`) and the checkpoints inside RFC 3161 anchors; verifies anchor tokens (the CA from `--tsa-ca`, `[anchor] tsa_ca`, or `--test-tsa`), counting only anchors the writer wrote and TEST ONLY anchors only in test mode; and verifies every detached statement against the signer registry (or `--signers FILE`): the key must belong to the named signer, be backed by the `signoff.key.enrolled` records in the trail as aqt-signoff counts them (section 4.1; without aqt-signoff, a warning that keys rest on `signers.json` alone), be enrolled before `signed_at` and not revoked at it, and the statement must be for the record's type and meaning. A review signed with a key that is only in `signers.json` is a problem; other such signatures are warnings. A key's own enrolment request and revocation are judged by their signature only. A `trail.review` is a problem when it is unsigned, signed by someone other than its actor, not about its own content, with a wrong head, with actors that differ from the trail or include the reviewer, or with profile parameters that do not match its `profile_sha256`; a copy of a review statement already in another record is reported and counts once (`verify.review_statuses`). Malformed anchor and review payloads are problems, never crashes. Lines must be canonical (section 2.3). Without `--pin-key` it warns that a full rewrite under a new key is only caught by external heads or anchors, and it always warns which records no external head or CA-verified anchor covers and how many follow the newest checkpoint. A truncated copy checked against exported heads:

```text
$ aqt-trail verify --trail truncated.jsonl --heads heads.jsonl
chain intact (6 records) but: checkpoint at seq 8 is beyond the head: the trail was truncated
problem: external head at seq 9 is beyond the head: the trail was truncated
```

**Importers** (`importers.py`). The `READERS` dictionary maps `claude-code`, `codex` and `pi` to readers for Claude Code transcripts (`~/.claude/projects/<key>/<uuid>.jsonl`), Codex rollouts (`~/.codex/sessions/YYYY/MM/DD/rollout-….jsonl`) and pi v3 session JSONL. `hook claude-code` reads one hook payload from standard input and always exits 0 so that it never blocks the agent. Import rules:

- only regular files owned by the caller, not symlinks, with one hard link; a partly written last line is left for the next import;
- records carry hashes (`input_sha256`, `prompt_sha256`, `output_sha256`) and excerpts of at most `excerpt_chars` (default 160; 0 disables them) with secrets masked: assignments, `--flag value` pairs and JSON fields whose name contains password, passphrase, secret, token, api-key, access-key, private-key or credential, `Authorization:` headers and bearer tokens, passwords in URLs and `curl -u`, PEM private keys, and token formats such as `sk-…`, `ghp_…`, `github_pat_…`, `AKIA…`, Slack tokens and JWTs. Masking is a safety net; the log cannot be redacted later;
- record IDs are derived from the source time and the source hash (`rec_<12 hex ms><16 hex of the source hash>`), and events whose `source_hash` is already in the trail or the spool are skipped, so re-imports never duplicate.

**Review** (`review.py`). `review run [--since --until --profile FILE --test-tsa]` runs risk queries over the records whose writer time falls in the scope and writes a worksheet. The worksheet shows the profile's parameters and flags those that differ from the built-in defaults (`profile_params`, `profile_differs`, signed with the review); a profile file named `default` may not change parameters. The actors in scope are every non-service actor except on records that are not activity and on a signer's records about their own key (enrolment request, rotation approval, revocation); approving someone else's enrolment, or importing enrolment records, is activity (`scope_actors`; reviews signed with the earlier rule still verify). The queries: `self_approval`, `missing_reason`, `attribution_mismatch`, `gaps`, `out_of_hours`, `repeated_failures`, `time_anomalies`, `actor_changes`, `invalidated_signatures`, `unanchored_head`. Real worksheet excerpt:

```text
- Actors in scope (may not sign this review): agent:claude-code:s-0001, agent:claude-code:unknown, human:alice
| F1 | attribution_mismatch | major | rec_01a1… | claims human human:alice but was sent from inside claude-code (aqt-trail <- bash <- claude <- …) |
| F2 | gaps                 | major | rec_01a1… | 1 record(s) spooled between …; their attribution was not observed |
```

`review sign` recomputes the worksheet's scope, profile, actors and findings from the trail (never from the `trail` path written in the worksheet) and signs only the recomputed values. It refuses (and records `trail.refused`) when the caller fails `require_human`, when the reviewer is not a `human:` ID, when the reviewer was an actor in scope (`not_independent`), when the trail no longer has the worksheet's head (`stale_worksheet`), does not verify up to there (`trail_broken`) or disagrees with the worksheet (`worksheet_mismatch`), and, with a signer registry, when the reviewer is not registered (`unknown_signer`), uses another signer's key (`key_mismatch`), a key that the enrolment records do not back (`unenrolled_key`), a revoked key (`revoked_key`) or one not registered for them (`unknown_key`). A UI binds the worksheet it showed with `worksheet_digest` and `expected_sha256` (`worksheet_changed`). Worksheets go to `review run --out DIR`, else `<state>/reviews`, else `$XDG_STATE_HOME/aqt/trail-reviews` when the state is not writable. Every finding needs a disposition (`ok`, `explained`, `deviation`; the last two need a note). The `trail.review` record carries `meaning: reviewed` and a detached statement whose subject hash is the content hash of `data` without `signature`; `verify` checks both. Findings with disposition `deviation` feed aqt-capa.

**ALCOA++ report** (`alcoa.py`). `aqt-trail alcoa` evaluates the ten attributes (attributable, legible, contemporaneous, original, accurate, complete, consistent, enduring, available, traceable) as `pass`, `warn` or `fail`, each citing `alcoa:<attribute>` and related catalogue IDs. It exits 1 when an attribute fails. It verifies the whole trail with the trust options of `verify`; *original* and *complete* fail on chain, checkpoint, head or anchor problems, *attributable* warns on human claims whose process chain was incomplete and fails on drained human claims an agent pushed, *accurate* warns when signer keys could not be checked against enrolment records, and *enduring* counts only RFC 3161 anchors the writer wrote (TEST ONLY anchors only in test mode) and head copies matched with `verify --heads`, never an exported-head note in the trail. Real output after the spool sequence above:

```text
FAIL  alcoa:attributable       1 record(s) claim a human but came from an agent harness
PASS  alcoa:original           hash chain and service signatures intact
WARN  alcoa:complete           sequence continuous; 1 gap marker(s), 1 spooled record(s)
PASS  alcoa:enduring           2 anchor(s), 1 RFC 3161 token(s) verified to a CA; newest record is 0 h after the last anchor
```

**Export.** `export --out DIR [--tar]` writes `trail.jsonl`, `checkpoints.jsonl`, the service public keys, `signers.json`, the TSA CA when configured, `VERIFY.md` and `MANIFEST.json` (SHA-256 of each file, log ID, head, key IDs). `MANIFEST.json` is not signed, and the copies are for convenience, not trust anchors: `verify --bundle DIR` uses the service key, TSA CA and signer registry the caller passes (`--pin-key`, `--tsa-ca`, `--signers`), the bundle's own keys only without `--pin-key` (with a warning), and its TEST ONLY CA only with `--test-tsa`.

**Separate-user mode.** `scripts/setup-system-user.sh` (run with `sudo`, never by the tests) creates a system user `aqt-trail` and a group `aqt-trail-clients`, writes `/etc/aqt/trail.toml` (state `/var/lib/aqt-trail`, socket `/run/aqt-trail/trail.sock` mode 0660, log mode 0640, your uid in `allowed_uids`) and installs `examples/aqt-trail-system.service` as `/etc/systemd/system/aqt-trail.service`. The unit runs as user `aqt-trail` with `Group=aqt-trail-clients`, so `/run/aqt-trail` (0750), the socket and the log (0640) are reachable for the clients group, while the service key stays 0600. With `ProtectHome=true` the service cannot run an `aqt-trail` (or a Python) inside a home folder; the script refuses such a path, and any part of the installation that is not owned by root or is writable by group or others (`--check` runs only these checks), and `aqt-trail/docs/separate-user.md` shows an install under `/opt`. The aim is that agents running as you can append but can neither edit the log nor read the service key. For user mode, `examples/aqt-trail.service` is a systemd user unit.

### 5.3 aqt-signoff

**Purpose.** Signatures with a stated meaning, bound to exact content, that visibly stop applying when the content changes; and approved actions that run at most once and are never retried blindly.

**Signing.** `sign FILE | --record ID | --hash H --meaning M --reason R [--signer ID] [--author ID]` writes a `signoff.signature` record with the statement in `data.signature` and `data.meaning`. For record subjects it also adds a `signs` link. Before unlocking the key it checks the policy for that meaning (`[policy.<meaning>]`: `min_signatures`, `roles`, `distinct_from_author`); a signer who authored the content cannot approve it when `distinct_from_author` is set (`self_approval` refusal). Authors are the actor of every evidence record whose content hash is the signed hash, `authored` signatures on that hash and `--author`; `sign`, `verify` and `is_approved` use the same rule. Roles for a policy come from the registry and must equal the signed role.

**Verifying.** `verify FILE | --record ID | --hash H [--require MEANING]` finds every signature over the subject in the evidence, verifies each against the registry and computes a status, worst first: `invalid` (also a replayed copy of a statement already in another record) › `unknown-signer` (also a key whose enrolment is pending or not backed by the enrolment evidence) › `revoked` › `invalidated` › `valid`. The first time it sees that signed content has changed, it writes one `signoff.invalidation` record (`action: content-changed`). Signatures are never deleted; a signer can withdraw one with `invalidate SIG --reason R` (`signoff.invalidation`, `action: withdraw`, with the withdrawn statement's digest in the signed `withdraws`). `manifest` renders a signature block (Markdown or HTML) with printed name, ID, role, meaning, local time with zone and UTC, reason, status and content hash.

**Enrolment** (rules in section 4.1). `init --id ID --name N --role R` creates the key and records the enrolment request; it counts at once only for the first signer. `signers approve ID --key KEY [--role ROLE] [--signer YOU]` records an approval signed by the approver, or a role change, and the registry follows it. `init --add-key` is a rotation while the active key counts, otherwise a new request that waits for approval. `signers import [--dry-run]` carries the enrolment and revocation records written before the trail into it once (refused with `sink_not_trail` when records would not reach the trail, and with `already_imported` after the first import). `signers export [FILE]` writes the registry with its enrolment evidence (section 4.1). `rekey` re-encrypts a key file from an earlier version and records a missing request, reporting whether it is `pending`. `signers check` exits 1 unless every key counts and nothing is pending, conflicting or unconfirmed. Every command here except `signers check` is human-only (`require_human` and the passphrase).

**Approved actions.** An action is a command (`argv`, run without a shell), an HTTP call description, or any other effect, plus an optional payload hash.

```mermaid
stateDiagram-v2
    [*] --> prepared: prepare (agent or script)
    prepared --> prepared: prepare --revise (new hash, approvals dropped)
    prepared --> approved: approve --hash H (enough valid signatures)
    prepared --> rejected: reject --hash H
    approved --> claimed: claim / run (atomic, re-verifies approvals)
    claimed --> succeeded: outcome or exit 0
    claimed --> failed: outcome or exit ≠ 0
    claimed --> unknown: timeout, signal, or no outcome within claim_grace_ms
    unknown --> succeeded: resolve --as succeeded (signed)
    unknown --> failed: resolve --as not-applied (signed)
```

- The action ID is `act_` plus 24 hex digits of a hash of the request key, so `prepare` is idempotent per key; a different action under the same key is refused (`request_key_conflict`).
- The action hash covers `{action_id, version, kind, description, spec, payload_sha256, preparer}` (and `revised_by` after a revision), so the author exclusion uses the hashed preparer. Approvals sign that exact hash; a revision changes it.
- `claim` first hashes the stored action again; it succeeds only when `signoff.action.approved` records (subject kind `action`) verify against the registry for that hash, meet `[actions]` policy (default one approval, approver ≠ preparer), have not expired and were not withdrawn. `run` executes that verified body. The claim is an atomic SQLite update guarded by the status and the hash, and a `signoff.action.claimed` record in the evidence refuses a second claim of the same version even after the database was rolled back. With a plain JSONL sink, an agent could delete that record together with the database state; in the trail the deletion is detected. A status in the database is not authority.
- An action that binds a payload needs exactly those bytes at `claim` and `run` (`payload_required` otherwise); `run` passes them on standard input. A command that reads its payload from a file path is not bound.
- A claim with no outcome becomes `unknown` only after the claim grace (`claim_grace_ms`, default 11 minutes), which is never shorter than `run_timeout_ms` (default 10 minutes); `run --timeout` may not exceed it.
- `unknown` is final for automation: nothing retries it. `resolve` records a human `signoff.action.outcome` with `meaning: verified`. A `not-applied` resolution is stored as status `failed` with `data.resolution = "not-applied"`.
- Records: `signoff.action.prepared` (`prepare`, `revise`), `.approved`, `.rejected`, `.claimed`, `.outcome` (`outcome`, `resolve`). `run` exits 0 only for `succeeded`, 1 for failed, unknown or refused, and 2 when the record could not reach the sink (the outcome is kept; run `sync`).

**Files.** Registry and keys (section 4.1). Configuration `$XDG_CONFIG_HOME/aqt/signoff.toml` (`AQT_SIGNOFF_CONFIG`). State `$XDG_STATE_HOME/aqt/signoff/signoff.db` (`AQT_SIGNOFF_STATE`, mode 0600): table `actions` (the action index with the claim lock) and table `pending` (records that could not reach the sink, delivered by `sync`).

**Python API.** `Signoff.open()`, `so.sign(subject, meaning, reason)`, `so.verify_file(path)`, `so.actions.prepare(…)`, `with so.actions.claim(id, hash) as claim: …` (leaving the block without a report records `unknown`), `so.approve_enrolment(signer_id, key_id, role=None, approver_id=…)`, `so.import_preview()` and `so.import_enrolments(signer_id=…)`, `so.export_registry()`, `so.record_enrolment(signer_id, key)` for keys other tools create, plus `verify_subject`, `is_approved` and `check_signers` for other tools (section 6.2).

### 5.4 aqt-change

**Purpose.** Change control for agent work: hash-reconciled plans, verification receipts captured by the runner, reviews bound to a diff, approved-versus-actual scope checks, a crash-safe finish and a derived gate.

**Plans.** Markdown files in the Project Tracker Next sprint format: YAML front matter (`tracker:` with `id`, `kind`, `status` …, plus an optional `aqt:` block with `paths` and `review.min_independence`), `## Tasks` and `## Verification` with stable item IDs, append-only event sections and `## Completion`. A verification item may declare a command as inline code starting with `$ `:

```markdown
- [ ] [V01] Unit tests pass `$ python -m pytest -q`
```

The command is split with `shlex` and run without a shell. The front-matter parser accepts a strict YAML subset only.

**Plan states** (`plan status`): `unregistered`, `clean`, `status_neutral` (only check marks or appended events changed), `unreconciled` (prose or structure changed; needs `reconcile --kind editorial|semantic --reason`), `history_rewritten` (an earlier event entry was edited; always refused), `lifecycle_changed` (status fields edited by hand). Each accepted version is stored by hash, and each acceptance is a `change.plan.reconciled` record (`baseline`, `begin`, `reconcile`) with the before and after basis hashes and an item-level diff.

**Receipts.** `run [--plan P] [--item ID | --all] [--junit FILE] -- CMD…` executes the declared command itself and records `change.receipt` (example in section 2.2): argv, exit code, duration, output hashes and a tail excerpt, parsed pytest/unittest/JUnit counts, Git HEAD, an environment summary (platform, Python version, executable, a hash of the whole environment, never its values, and `python_bytecode: "fresh"`), the plan basis hash and the working-tree fingerprint. A receipt is **fresh** while both hashes match the current state. The fingerprint hashes the content of every tracked file (one `git hash-object` pass, about 0.5 s for 10,000 files; it does not trust `git status`, and Git runs with `core.fsmonitor`, `core.untrackedCache` and relaxed stat checks switched off) and of untracked files that the repository's tracked `.gitignore` files (in HEAD or the index) do not ignore, minus the plan file and the `fingerprint_exclude` globs: from `.aqt/change.toml` any matching file, from the user configuration only untracked files outside the plan's paths. Untracked files that only `.git/info/exclude`, `core.excludesFile` or an untracked `.gitignore` ignore stay in the fingerprint (MANUAL `locally_ignored_files`); the one exception is the `.gitignore` that a tool writes directly into its own `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.venv`, `.tox` or `.nox` folder (`gitio.TOOL_DIRS`). Any later edit makes the receipt stale. Commands run with `PYTHONPYCACHEPREFIX` set to a new temporary folder (removed afterwards), so Python neither reads nor writes `__pycache__/` in the tree; other ignored files that a run may load (extension modules next to the source, `.pyc` files without a source, other tools' build caches, the virtual environment) are not fingerprinted, and a command that clears its children's environment (tox) does not pass the setting on. Receipts also record `tree_fingerprint_before`: a run that changed the fingerprinted tree while it ran does not count by itself (MANUAL `command_modified_worktree`) until a later run of the same check leaves the tree unchanged. `attest --item ID --reason R` records manual evidence (`action: attest`, `meaning: verified`).

**Finish.** `finish PATH --key K --summary S [--path F…]` runs as a phase machine stored in `attempts/<plan>/<key>.json`: preflight (nothing written on failure) → `plan_written_commit_pending` → `commit_created_record_pending` → `completed`. It ticks verified items, sets `status: completed`, commits exactly the plan and the named paths with trailers `AQT-Plan`, `AQT-Task`, `AQT-Receipts`, `AQT-Finish`, verifies the trailers and writes `change.finish`. The preflight also refuses when the commit would not hold the tested tree (`finish_tested_change_not_committed`: a tracked file inside the plan's paths or covered by the fingerprint that differs from HEAD, or an untracked file inside the plan's paths, not named with `--path`), on a hidden change (`finish_hidden_changes`), without a required trail log (`finish_trail_required`), when the plan state's base commit is not one the plan's records name (`finish_plan_base_mismatch`) and when a check's latest run changed the tree (`finish_command_modified_worktree`). Re-running with the same key resumes after a hook failure or crash; the same key with different inputs fails (`idempotency_conflict`). With `lifecycle_owner = "external"`, aqt-change never writes the plan or commits; it only records.

**Gate.** `gate PATH` derives `GO`, `NO-GO` or `MANUAL_VERIFY_REQUIRED` from the records only. NO-GO codes: `plan_unreconciled`, `receipt_missing`, `receipt_stale`, `receipt_failed`, `receipt_unverified` / `review_unverified` (the trail lacks or contradicts the record, its copy is not signed by a pinned key, or the trail is required and no log is found), `trail_required`, `plan_base_mismatch` (the trail log confirms another base commit for the plan than the plan state names), `hidden_worktree_change`, `unapproved_change`, `review_fail`, `not_finished`, and `anti_gaming_warning` when `warnings_block = true`. MANUAL codes include `waiver_present`, `manual_item_agent_attested`, `receipt_unverified` / `review_unverified` (the record came through the spool, or no trail log is readable), `sparse_checkout`, `approval_stale`, `approval_invalid`, `approval_unsigned` / `approval_unverified` (with `require_signed_approval`), `review_concerns`, `review_waived`, `review_independence_below_policy`, `scope_undeclared`, `scope_unverifiable`, `project_settings_changed`, `locally_ignored_files`, `plan_base_mismatch` (only the ledger's copy of the records names another base commit, or a log records several for the plan), `command_modified_worktree`, `allowed_by_user_config` and `tested_change_not_committed`. `--rerun` re-executes the declared commands, in the same working tree, instead of trusting stored receipts.

**Trail confirmation.** `gate`, `finish` and the hooks read receipts and reviews from the ledger's `records.jsonl`, which the agent's user can edit. When a trail is in use (a trail log exists, or `resolve_sink()` names a writer; `AQT_SINK=file:` does not switch this off), a receipt or review counts only if the trail log holds a record with the same ID and content hash that the writer received over its socket (`observed.via = socket`). The log is each `AQT_EVIDENCE` entry named `trail.jsonl`, else `trail.jsonl` in the trail state directory; the sink file and the spool never count. Because that location comes from the caller's environment, two things keep the check on: the project setting `require_trail` (no log found: NO-GO `trail_required`, `finish` refuses, the hooks block and the commit-msg hook rejects `AQT-Receipts`) and, without it, a record in the local copy that came back from a writer (it has a `chain`), which keeps a trail in use (no log found: MANUAL). With `trail_keys`, a log copy confirms a record only when it carries a valid writer signature by a pinned key (public key from `keys/*.pub` next to the log, matched by key ID; `aqt_evidence.verify_record_signatures`), else `unsigned` (NO-GO). The gate JSON reports `trail: {checked, logs, required}`, plus `keys` with `trail_keys`. The local copy still decides which records belong to the plan and in which order, and `change.finish` and the approval target are read from it. A tracked file whose content differs from the index while `git status` does not show it (index flags `skip-worktree` / `assume-unchanged`, or flag `stat-cache` for an fsmonitor hook, relaxed stat settings or edited index data) is a hidden change: NO-GO `hidden_worktree_change`. Real output of the offline quick start (`aqt-change/examples/quickstart.sh`):

```text
completed: s01 record rec_01a163bc4f17… commit 1a983e55… gate GO
AQT-Plan: s01 sha256:35b6b791…
AQT-Task: T01
AQT-Receipts: rec_01a163bc4e5dbbc9a20a667641f8
AQT-Finish: s01/s01-finish
gate: GO
== 5. a later code change makes the receipt stale
gate: NO-GO ['receipt_stale']
```

**Approval.** The approval target is the latest `baseline`, `begin` or semantic `reconcile` record of the plan. A person signs it with aqt-signoff (`--record <id> --meaning approved`). aqt-change asks `aqt_signoff.is_approved(record_content_hash)` when aqt-signoff is installed (`signed` or `invalid`); otherwise it finds matching `signoff.signature` records and reports them as `unverified`.

**Reviews and scope.** `review add --reviewer ID --independence same-session|fresh-context|different-model|human --verdict PASS|CONCERNS|FAIL|WAIVED` records `change.review` bound to the diff hash; independence `human` requires `require_human`. `reconcile-diff` compares the plan's `aqt.paths` with the actual diff since the base commit (`change.reconciliation`). Anti-gaming heuristics flag added `skip`/`xfail`/`only`, removed asserts or tests, deselection configuration and stale JUnit files.

**Hooks.** `hook claude-code` for `TaskCompleted`, `Stop` and `SubagentStop` (exit 2 blocks and shows the reason to the agent; with `stop_hook_active` it reports without blocking a second time). `hook commit-msg FILE` checks trailers; `hooks install-git` installs a shim and never overwrites an existing hook.

**Files.** Ledger in `AQT_CHANGE_STATE`, else `<git-dir>/aqt-change/`, else `$XDG_STATE_HOME/aqt/change/<16 hex of the root path>/`: `plans/<id>.json`, `objects/<sha>` (accepted plan snapshots), `logs/<sha>` (full command output, 0600), `attempts/`, `records.jsonl`. Configuration `$XDG_CONFIG_HOME/aqt/change.toml` (`AQT_CHANGE_CONFIG`): `actor`, `excerpt_lines`, `timeout_seconds`, `fingerprint_exclude`, `lifecycle_owner`, `[gate]`. The library default is `require_signed_approval = false`; the example configuration sets it to `true` for QM use. Project settings `.aqt/change.toml`, committed in the repository (`config.parse_project_settings`): `require_trail`, `trail_keys`, `fingerprint_exclude` and `[gate]` (`require_signed_approval`, `min_review_independence`, `warnings_block`, `always_allowed_paths`). They can only make checks stricter. A setting counts when a copy sets it: the working-tree copy, HEAD's copy, the copy at each base commit of a plan in progress and of the plan being judged (the plan state's `base_commit` and every base commit the plan's `begin`/`baseline` records name, in `records.jsonl` and in the trail log; `Ledger.plan_bases`), and the copy at every commit since such a base that changed the file (an unreadable copy there is left out): `require_trail` and each `[gate]` value at its strictest across those copies and the user configuration (for the independence also the plan's `aqt.review.min_independence`); `trail_keys` only the keys every pinning copy names; `fingerprint_exclude` and `always_allowed_paths` only the globs every copy names. From the user configuration, `fingerprint_exclude` leaves out only untracked files outside the plan's paths and `always_allowed_paths` gives MANUAL (`allowed_by_user_config`). A change to the file inside a plan's diff, or a commit since the base that changed it (also one changed back later), gives MANUAL (`project_settings_changed`, `reconcile-diff`: `settings_changed`); an unreadable copy (except one between a base and HEAD), an unknown key or a wrong value refuses (`config_invalid`). A plan state whose base commit its records do not name gives `plan_base_mismatch` (`Ledger.base_problem`). The gate JSON's `policy` shows the values that applied.

### 5.5 aqt-sensei

**Purpose.** Pair a worker agent with an advisor agent of any vendor. The advisor reads the project but cannot change it, because the operating system mounts the project read-only. The owner controls what passes between them, and every step is a record.

**Components.**

- `aqt-sensei serve`: the bridge daemon, with one backend (`tmux`, `herdr`, or `fake` for tests). It types messages into a pane only when the receiver is idle. Herdr reports agent status directly; tmux uses hook-reported states (`aqt-sensei hook-state working|idle|blocked`) or, without hooks, a screen unchanged for `quiet_seconds` with a visible prompt. An unknown state never receives input.
- Three kinds of Unix sockets in `$XDG_RUNTIME_DIR/aqt-sensei/` (all mode 0600): `owner.sock` for every owner operation; `agent.sock` for `ask` and `status` from workers (the pair is found from the caller's process ancestry); and `pairs/<id>/advisor.sock` for that pair's advisor only (`reply`, `send`, `status`, `worker_log`).
- `aqt-sensei launch --pair ID`: started in the advisor pane; builds the bubblewrap command line and replaces itself with it. Inside, a stdlib-only `sensei` shim talks to the advisor socket.
- `aqt-sensei doctor`: host checks plus a probe inside the exact sandbox.

**Owner authentication.** An owner request must come from the daemon's uid, carry the owner token (`$XDG_CONFIG_HOME/aqt/sensei/owner.token`, compared in constant time), not come from a process below a paired pane, carry no agent markers (read from the caller's `/proc` environment and ancestry), have a terminal, and not share a paired pane's terminal. Refusal codes: `uid`, `token`, `paired-pane`, `agent-session`, `no-terminal`, `paired-terminal`. Every refusal is a `sensei.refused` record.

**Sandbox** (`sandbox.py`, [`aqt-sensei/docs/sandbox.md`](../aqt-sensei/docs/sandbox.md)). `bwrap --unshare-all --die-with-parent` (plus `--share-net` unless `--network none`) and `--clearenv` with an allow-list. System directories and the project are read-only; `/tmp`, `/run` and `/home` are empty; only the platform's private home (`$XDG_STATE_HOME/aqt/sensei/homes/<platform>`) and the scratch folder `<project>/.sensei/<pair>/` are writable. The bridge state, other pairs, the owner token, configuration and sockets are not visible. The sandbox sets `AQT_AGENT_SESSION=1`, so the shared human check recognises the advisor as an agent. Built-in profiles exist for `claude`, `codex` and `pi`; any command line can be an advisor.

**Modes and budgets.** `manual` (nothing reaches an agent until the owner forwards that message), `confirm` (every message waits for `approve`, optionally edited, or `discard`), `auto` (delivered when the receiver is idle). Budgets: `max_exchanges`, `max_messages`, `max_cost` (declared integer minor units, not metered). When auto mode reaches a limit, the pair falls back to confirm and a `sensei.budget reached` record is written. Message states: `queued`, `awaiting_approval`, `held`, `delivered`, `discarded`, `failed`.

**Records.** `sensei.pair` (`attached`, `updated`, `paused`, `resumed`, `ended`, `doctor`), `sensei.message` (`enqueued`, `delivered`, `failed`, `no-reply`; text hash plus an excerpt of at most 280 characters), `sensei.decision` (`approved`, `edited`, `discarded`, `forwarded`; with meaning, reason and before/after hashes for edits), `sensei.budget` (`consumed`, `reached`, `set`, `cost-added`), `sensei.refused`. Owner decisions are record-first: if the sink refuses the record, the decision is not applied. If only the trail socket is unreachable, `SocketSink` spools and the decision proceeds. Automatic events that cannot be written wait in `ledger-spool.jsonl` in the sensei state folder and are retried.

**Files.** Configuration `$XDG_CONFIG_HOME/aqt/sensei.toml` (`AQT_SENSEI_CONFIG`); token (`AQT_SENSEI_TOKEN`); state `$XDG_STATE_HOME/aqt/sensei/` (`AQT_SENSEI_STATE`): `pairs.json`, `messages/<pair>.jsonl`, `ledger-spool.jsonl`, `homes/<platform>/`; runtime `$XDG_RUNTIME_DIR/aqt-sensei/` (`AQT_SENSEI_RUNTIME`).

### 5.6 aqt-quarantine

**Purpose.** Score untrusted inputs to an agent (web pages, search results, MCP tool output), hold risky ones, and release them only on a signed decision by a responsible person.

**Pipeline** (`engine.py`). The text is scored by the configured detectors (`[[detectors]]`, default the built-in `heuristics`), each returning `score_ppm` and evidence spans. The thresholds file decides the band:

- a band fires when the number of detectors whose score is **strictly greater** than their threshold satisfies its `rule` (`"any"` or `{"at_least": k}`);
- `hold` is checked before `warn`;
- a trusted source lowers the band by one step (`trusted_source_policy = "downgrade"`) or passes it (`"pass"`); trusts expire and the content is still scanned and recorded;
- **fail closed:** a detector error, an off-contract answer (float score, span out of range, exception), an unreadable thresholds file, or text above `max_scan_chars` (2,000,000 characters) holds the content. Oversize text is never partly scanned.

| Band | What the agent gets | Record |
|---|---|---|
| pass | The content inside `<untrusted_content source=… tool=…>` with a header saying it is data; fake delimiters inside the content are neutralised | `quarantine.passed` (if `record_passes`) |
| warn | Wrapped content plus a warning banner; a case opens | `quarantine.passed` with `case_id` |
| hold | Only a notice with a case ID; the original goes to `cases/<CASE>/original.txt` | `quarantine.held` |

Case IDs are `Q` plus six characters from a Crockford-style alphabet (`Q7SEGGW`). Case states: `held`, `warned`, `released`, `threat`. A case is what its first opening record (`quarantine.held`, or `quarantine.passed` with a case ID) says; a later opening record for the same case ID changes nothing. Malformed journal lines are skipped, not fatal; skipped lines are listed in `Store.journal_problems` and reported by the commands that read cases, the hook and `doctor`. The `quarantine.held` record (`case_id`, `band`, `score_ppm`, `scores`, `source {tool, ref, domain, …}`, evidence spans with short excerpts, detector versions, and the thresholds `{sha256, version, calibrated}`) is shown in part in section 2.6.

**Decisions** (`decisions.py`). `release CASE --reason R`, `declare-threat CASE --reason R` and `trust-source DOMAIN --reason R --expires DATE [--revoke]` by a responsible person (`[policy] responsible`, empty means every registered signer). Each passes `require_human`, unlocks the person's key with a passphrase and stores a detached statement in `data.signature`. Records: `quarantine.released` (`meaning: released`), `quarantine.threat.declared` (`rejected`), `quarantine.source.trusted` (`trust` with `approved`, `revoke` with `rejected`), `quarantine.refused`. With `require_signed_decisions = true` (the default), the hooks honour only decisions whose signature verifies against the registry, made after the key's enrolment and before its revocation; a forged decision line in the journal is ignored. With aqt-signoff installed, a registry key counts only as aqt-signoff's enrolment check counts it (`enrolment_view`, `verify_decision(..., enrolment=)`), and the decider refuses to sign with a key that does not count (`unenrolled_key`); without aqt-signoff the keys rest on `signers.json` alone (`Decider.enrolment_note`, `doctor`). `release` and `declare-threat` say before the passphrase prompt that the signature covers all N characters of the content. A decision acts only through its signed `data.decision` (case ID and content hash, or domain, subdomain flag and expiry): a record whose unsigned fields differ is `mismatch` and has no effect. A signed statement counts once (a copy is a replay), and decisions take effect in signed order (`signed_at`), not in journal order. `release` refuses when the stored original no longer hashes to the case's content hash; front ends use `Decider.case_content()` and pass `expected_sha256`. Deleting a later decision from the agent-writable journal brings back the earlier one; with aqt-trail as the sink, the deleted record is still in the trail.

**Claude Code adapter** (`adapters/claude_code.py`). `PostToolUse` for `WebFetch`, `WebSearch` and `mcp__.*` returns `hookSpecificOutput.updatedToolOutput`: a deep copy of `tool_response` with only its content-bearing string leaves rewritten (metadata keys such as `url`, `query`, `tool_use_id` stay), plus `additionalContext` for warn and hold. `UserPromptSubmit` delivers released content and threat notes to the session the case came from, once each (`quarantine.delivered`). `hooks print claude-code` also prints `permissions.deny` rules that stop the agent from running decision commands or reading the quarantine state. A generic filter is `aqt-quarantine scan --source URL` (stdin → stdout; exit 1 when held).

**Files.** Configuration `$XDG_CONFIG_HOME/aqt/quarantine.toml` (`AQT_QUARANTINE_CONFIG`; `init` writes a starter file and, with `--id`, creates and enrols a key, or reuses an existing key file of that ID, for example from `aqt-signoff init`). State `$XDG_STATE_HOME/aqt/quarantine/` (`AQT_QUARANTINE_STATE`, mode 0700): `journal.jsonl` (every record this tool wrote; case state is folded from it), `outbox.jsonl` (records the sink did not accept; `flush` sends them), `cases/<CASE>/original.txt` (0600). Thresholds file from `AQT_QUARANTINE_THRESHOLDS` or `[paths] thresholds`, else the packaged uncalibrated defaults (warn above 350,000 ppm, hold above 750,000 ppm), which every record and `doctor` mark as *uncalibrated*.

### 5.7 aqt-validate

**Purpose.** A validation report for an AI control before you trust it: intended use and acceptance criteria fixed in advance, results with exact confidence bounds, deviations, a conclusion, a validity period and requalification triggers.

**Lifecycle.**

1. `protocol init --kind detector|reviewer` prints an annotated TOML protocol (intended use, data, detectors or reviewer argv, bands, criteria, `confidence`, `validity_days`, `requalify_on`).
2. Exploratory runs on the `dev` split need no lock and cannot be qualified.
3. `protocol lock FILE --reason R` records `validate.run` `protocol-locked` with the protocol's SHA-256. A test run requires a lock for the exact file, and each test readout of the same data is counted and reported.
4. `detector run` or `reviewer run` writes a run directory and records `validate.run` `completed` and `validate.report` `issued` (`conclusion`: `meets`, `does-not-meet` or `inconclusive`). Exit 0 means meets.
5. `qualify RUN_DIR --approve|--reject --reason R` is human only (`require_human`) and records `validate.qualification` (`approve`/`reject`, `meaning` approved/rejected, `configuration_hash`, `valid_until`, triggers).
6. `check --protocol P [--thresholds F] [--observed-fp K/N]` exits 1 when a trigger fires (`configuration-changed`, `thresholds-changed`, `expired`, `drift`) and records `validate.requalification` `triggered` once per qualification and set of triggers.

**Detector validation** (`detector.py`). Data are JSONL items `{id, label: benign|attack, text, group?, family?, goal?, …}`; loaders import BIPIA, InjecAgent, LLMail-Inject exports and AgentDojo from paths you provide. Benign items are split by group (session), attacks by goal, and overlaps between splits are counted. Thresholds are calibrated on calibration benign items only, per band at its FPR target; several detectors are fused by max-rank. Results include TPR and FPR with exact two-sided and one-sided Clopper–Pearson bounds, AUROC (Mann–Whitney U), per-family rates, latency and a contamination registry (results for a detector trained on a dataset are reported separately and excluded from criteria). All statistics are standard-library code in `stats.py`; integer ppm bounds are rounded outward. A criterion the sample size cannot demonstrate is *inconclusive* (FPR ≤ 1 % at 95 % confidence needs at least 299 clean items).

**Detector adapters** (`adapters.py`). Exactly one of `command = [argv]` (JSONL in, JSONL `{id, score_ppm}` or `score` in [0, 1] out), `callable = "module:function"`, `plugin = "name"` (the `aqt.detectors` entry-point group, with an `options` table) or `scores = "file.jsonl"`. The configuration hash covers the effective detector versions, code hashes and `model_file` hashes.

**Reviewer qualification** (`reviewer.py`). `reviewer build-cases --repo .` inverts fix commits to recreate seeded defects and adds clean diffs. The reviewer argv (placeholders `{diff}`, `{workdir}`, `{prompt}`) runs N times per case on a snapshot in a temporary directory; findings JSON is matched to the defect by file and line. Rates are per case; agreement and Fleiss' kappa measure repeatability. Failed runs are errors, excluded from rates and cached.

**Files.** Configuration `$XDG_CONFIG_HOME/aqt/validate.toml` (`AQT_VALIDATE_CONFIG`): `actor`, `sink`, `state_dir`, `evidence`. State `$XDG_STATE_HOME/aqt/validate/` (`AQT_VALIDATE_STATE`): `runs/<run>/` (0700; `manifest.json`, `results.json`, `scores.jsonl`, `splits.jsonl`, `report.md`, `report.html`, and `thresholds.json` for detector runs or `outcomes.jsonl` for reviewer runs), `cache/reviewer/`, `tmp/`.

### 5.8 aqt-capa

**Purpose.** Turn agent failures into deviations with a root cause, a corrective or preventive change to the agent's controls under approval, and an effectiveness check decided from later evidence.

**Intake.** `scan` reads the evidence and Git history and proposes **candidates**; it never opens deviations by itself. Source rules: `quarantine-held`, `quarantine-threat`, `receipt-failed`, `finish-not-go`, `review-fail`, `refused` (any `<tool>.refused`), `trail-review-finding` (disposition `deviation`), `action-outcome-unknown`, `git-revert`. A human accepts (`capa.deviation accepted`) or dismisses (`dismissed`) each candidate with a reason. `deviation new` opens one by hand (`opened`).

**Lifecycle.** Deviation: `open` → `investigated` → `actions` → `closed` (final; a recurrence opens a new deviation). Investigation: `investigate DEV --why … --root-cause … --root-category K [--factor CAT:TEXT]` (`capa.investigation` `recorded`, `revised`, or `drafted` for agents). Action: `action plan` (`planned`, with the target file and the effectiveness criterion fixed now) → edit the file → `action implement` (`implemented`, `meaning: authored`, before and after hashes, diff hash and excerpt) → `action approve` (`approved`, bound to the implementation record's content hash; the implementer cannot approve unless `allow_self_approval`) or an aqt-signoff signature over the implementation record → `effectiveness` → `close`.

**Effectiveness.** The default criterion is no recurrence within N agent sessions and/or D days (`--window-sessions`, `--window-days`). Sessions are counted from `actor.agent.session` in later records. The result is `effective` only when the window is complete, no matching deviation occurred after approval, no matching candidate is undecided, no `trail.gap` falls in the window, and the control file still has the approved hash; otherwise `pending` (with reasons) or `not-effective`. `capa.effectiveness` `evaluated` is written only when the result or reasons change.

**Approval states.** `recorded-unsigned` (a recorded human approval), `signed-verified` (aqt-signoff installed and the signature verifies; independence and the `approved` policy are checked on exactly the verified signatures, and an aqt-signoff error is `signature-not-valid`, never an approval), `signed-unverified` (a matching `signoff.signature` record but aqt-signoff is not installed to check it). `action verify` reports `changed-since-approval` when the control file later changes.

**Files.** Configuration `$XDG_CONFIG_HOME/aqt/capa.toml` (`[identity]`, `[evidence]`, `[project]`, `[scan]`, `[due_days]`, `[similarity]`, `[approval]`). State: the SQLite working index `$XDG_STATE_HOME/aqt/capa/capa.db` (`AQT_CAPA_DB` or `[state] db`) and `snapshots/<sha256>` of control files beside it. The index is not evidence; `aqt-capa rebuild` recreates it from the `capa.*` records. Accept, dismiss, classify, investigation, recorded approval, cancel, extend and close are unsigned records, so in a plain JSONL sink `rebuild` replays a forged closure. aqt-capa does not verify chains or signatures of the evidence it reads; run `aqt-trail verify` for that.

---

## 6. Cross-tool interfaces

### 6.1 Who reads what

| Reader | Reads | Produced by | Through |
|---|---|---|---|
| aqt-trail `verify`, `review sign` | `signers.json`, reviewer key `keys/<slug>.key`; the `signoff.key.enrolled` and `signoff.key.revoked` records in the trail | aqt-signoff (or `aqt-quarantine init`) | Direct file read; keys checked with aqt-signoff's enrolment rules when it is installed |
| aqt-trail `review run` | Every record in scope (`meaning`, `reason`, `links`, `observed`, `trail.gap`, `signoff.invalidation`, failed or refused outcomes) | All tools | The trail log |
| aqt-signoff `sign --record`, `verify` | The record to sign or verify (any type); `signoff.*` records | All tools | `iter_evidence` / `--evidence` |
| aqt-change approval | `signoff.signature` over the content hash of `change.plan.reconciled` | aqt-signoff | `aqt_signoff.is_approved`, else evidence files |
| aqt-change `review add --qualification REC` | A `validate.qualification` record ID, stored as a link (not checked) | aqt-validate | Argument |
| aqt-quarantine | `thresholds.json` | aqt-validate | File path (`AQT_QUARANTINE_THRESHOLDS`, `[paths] thresholds`) |
| aqt-quarantine | `signers.json`, key files | aqt-signoff (or its own `init`) | Direct file read; keys checked through `aqt_signoff.Signoff.trust` when aqt-signoff is installed |
| aqt-change `gate`, `finish`, hooks | `.aqt/change.toml` (working tree, HEAD, the plan's base commits and every commit since that changed it); the trail log (receipts, reviews and the plan's `begin` records) and, with `trail_keys`, `keys/*.pub` next to it | You (committed); aqt-trail | File read, `git cat-file` and `git rev-list` |
| aqt-validate | Detector plug-ins (`heuristics`, `onnx`) | aqt-quarantine | Entry points `aqt.detectors` (`[quarantine]` extra) |
| aqt-validate | Benign traffic in the generic JSONL format | You (for example from `aqt-quarantine cases export`) | File |
| aqt-validate `check`, test runs | Its own `validate.run` and `validate.qualification` records | aqt-validate | `iter_evidence` / `--evidence` |
| aqt-capa `scan` | `quarantine.held`, `quarantine.threat.declared`, `change.receipt`, `change.finish`, `change.review`, `*.refused`, `trail.review`, `signoff.action.outcome`; Git reverts | aqt-quarantine, aqt-change, aqt-trail, aqt-signoff, all tools | Evidence files, `git log` |
| aqt-capa `effectiveness` | Later records' `actor.agent.session`, `trail.gap`, `capa.*`, `signoff.signature` | aqt-trail imports and all tools | Evidence files; `aqt_signoff.is_approved` |

The `data` field names that other tools rely on are fixed by spec §11 and the payload schemas:

| Type | Required `data` fields |
|---|---|
| `change.receipt` | `argv`, `exit_code`, `passed`, `plan_basis_hash`, `tree_fingerprint`, `counts` |
| `change.finish` | `plan_ref`, `receipts`, `waivers`, `gate` |
| `change.review` | `verdict`, `independence`, `diff_sha256`, `findings` |
| `trail.review` | `findings` (`[{query, severity, record_ids, disposition}]`), `head` |
| `signoff.signature` | `signature`, `meaning` |
| `signoff.action.outcome` | `outcome`, `action_id` |
| `quarantine.held`, `quarantine.threat.declared` | `case_id`, `band`, `score_ppm`, `source` |
| `sensei.decision` | `decision`, `message_id`, `pair_id` |
| `validate.qualification` / `.requalification` | `configuration_hash`, `valid_until` (+ `trigger`) |
| `capa.action` | `target` (`{path, before_sha256, after_sha256}`), `effectiveness_criterion` |
| `<tool>.refused` | `attempted_action`, `reason_code`, `agent_markers` |

### 6.2 The aqt-signoff API for other tools

```python
from aqt_signoff import verify_subject, is_approved

statuses = verify_subject("sha256:…", meaning=None, sources=None)
# -> list[SignatureStatus]: record_id, record_type, status (valid | invalid | unknown-signer | revoked |
#    invalidated), signer_id, name, role, meaning, subject, …

ok = is_approved("sha256:…", meaning="approved",
                 policy={"min_signatures": 2, "distinct_from_author": True}, sources=None, authors=None)
# -> True when valid signatures with that meaning satisfy the policy
#    (argument, else [policy.<meaning>] in signoff.toml, else one signature);
#    the actors of records with this content hash are always added to authors

check_signers()
# -> {"ok", "registry", "evidence", "keys": [{signer, key_id, state, counts, pending, basis, approvals, roles,
#     stopped_at, unsigned_revocations, problems, notes, …}], "bootstrap", "rebootstrap", "pending", "imports",
#     "problems", "ignored", "unsigned_revocations"}
```

`sources` is a list of JSONL paths; the default is `iter_evidence`'s sources, with the signoff configuration's `[paths] evidence` taking precedence. To sign a record from another tool, use the subject `{"kind": "record", "ref": record["id"], "sha256": aqt_evidence.record_content_hash(record)}`. Consumers import aqt-signoff only when it is installed and otherwise report matching `signoff.signature` records as unverified.

### 6.3 The thresholds file

aqt-validate writes `thresholds.json` into the run directory of a detector run; aqt-quarantine reads it. Schema: `aqt-spec/schemas/thresholds.schema.json`; details in [`aqt-validate/docs/thresholds-file.md`](../aqt-validate/docs/thresholds-file.md). A real file from the demo:

```json
{"aqt_thresholds": "0.1", "calibrated": true,
 "protocol": {"id": "aqt-demo-heuristics", "sha256": "sha256:301c5989…"}, "run": "rec_01a163bac9fad1190ff0b8e8c0af",
 "configuration_hash": "sha256:dac1df71…",
 "detectors": [{"id": "heuristics", "version": "0.1.0+9fa4d49f402b"}],
 "bands": [{"name": "warn", "fpr_target_ppm": 30000, "rule": "any", "thresholds": {"heuristics": 80000}},
           {"name": "hold", "fpr_target_ppm": 10000, "rule": "any", "thresholds": {"heuristics": 150000}}],
 "calibration": {"n": 398, "realised_fpr_ppm": {"hold": 0, "warn": 20101}}}
```

- Thresholds are in the detector's `score_ppm` unit; a detector fires above (strictly greater than) its threshold.
- aqt-quarantine treats the file as calibrated only when `run` is set and `calibration.n > 0`, and records the file's SHA-256 on every scan and decision. `aqt-validate check --thresholds FILE` fires `thresholds-changed` when the file in use differs from the qualified one.
- The detector `version` is the plug-in's own version; aqt-quarantine's heuristics include a hash of their pattern table, so a pattern change changes the configuration hash.
- The uncalibrated defaults shipped with aqt-quarantine (`src/aqt_quarantine/data/thresholds.uncalibrated.json`) have `calibrated: false` and no `protocol`, `run` or `fpr_target_ppm`; they validate against the published schema (tested). aqt-quarantine reads thresholds files with its own loader, which does not validate against the schema. The TEST ONLY `examples/thresholds.hold-everything.json` deliberately uses a threshold of -1, below the schema's range, so that a score of 0 is held too.

### 6.4 Catalogue IDs

Reports cite catalogue items as `<catalogue>:<item>`, where the item is the clause as numbered in the source: `part11:11.50(a)`, `annex11-2025d:12.2`, `gdp-2013:6.3`, `euaiact:12(1)`, `alcoa:attributable`. The suffix `d` marks drafts whose numbering may change. Published catalogues: `alcoa`, `annex11-2011`, `annex11-2025d`, `part11`, `ch4-2025d`, `annex22-2025d`, `gdp-2013`, `iso9001-2015`, `euaiact`, `ichq10`, `ichq9`. Look an item up in Python with `aqt_evidence.catalogues.item("part11:11.70")`; the full mapping is [`aqt-spec/crosswalk.md`](../aqt-spec/crosswalk.md).

### 6.5 Harness hooks

| Tool | Claude Code events | Command | Effect |
|---|---|---|---|
| aqt-trail | `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Stop`, `SessionEnd` | `aqt-trail hook claude-code` | One `trail.import` per event; always exits 0; spools when the writer is down |
| aqt-quarantine | `PostToolUse` (`WebFetch\|WebSearch\|mcp__.*`), `UserPromptSubmit` | `aqt-quarantine hook claude-code` | Replaces held output; delivers released content on the next prompt |
| aqt-change | `TaskCompleted`, `Stop`, `SubagentStop`; Git `commit-msg` | `aqt-change hook claude-code`, `aqt-change hook commit-msg` | Exit 2 blocks "done" without fresh passing receipts; checks trailers |
| aqt-sensei | `UserPromptSubmit`, `Stop`, `Notification` (`permission_prompt`) | `aqt-sensei hook-state working\|idle\|blocked` | Exact pane state for the tmux backend |

Snippets: `aqt-trail/examples/claude-code-hooks.json`, `aqt-quarantine hooks print claude-code`, `aqt-change hooks print`, `aqt-sensei/examples/claude-code-hooks.json`. Hook payload shapes change with Claude Code versions; each package documents a manual check in a real session.

---

## 7. Data locations

Everything the suite writes, with the defaults. "umask" means the file is created without an explicit mode, so the process umask applies (typically 0644 for files and 0755 for directories).

| Path | Written by | Content | Mode |
|---|---|---|---|
| **Configuration** `$XDG_CONFIG_HOME/aqt/` | | | |
| `signers.json` | aqt-signoff, `aqt-quarantine init` | Signer registry (public keys only); replaced atomically | umask |
| `keys/` | aqt-signoff, `aqt-quarantine init` | Key folder | 0700 (set by `aqt-signoff init`, and by `generate_key` when it creates the folder) |
| `keys/<slug>.key` | aqt-signoff, `aqt-quarantine init` | Passphrase-encrypted Ed25519 private key (AQT key format, section 2.6) | 0600 |
| `keys/<slug>.key.pub` | same | Public key | umask |
| `keys/<slug>.<hex>.revoked.key[.pub]` | aqt-signoff `revoke` | Retired key files | as before |
| `trail.toml`, `signoff.toml`, `change.toml`, `quarantine.toml`, `validate.toml`, `capa.toml`, `sensei.toml` | You (`aqt-quarantine init` and `aqt-sensei init` write starter files) | Per-tool configuration | umask |
| `sensei/owner.token` | `aqt-sensei init` | Owner token for the bridge | 0600 |
| **State** `$XDG_STATE_HOME/aqt/` | | | |
| `evidence.jsonl` | Any tool via the default `JsonlSink` | Unchained records | 0600 |
| `spool/spool.jsonl` | `SocketSink`, `aqt-trail` client | Records waiting for the writer | 0600 |
| `trail/` (`AQT_TRAIL_STATE`) | aqt-trail | Trail state directory | 0700 (not changed when `log_mode` is 0640) |
| `trail/trail.jsonl`, `trail/checkpoints.jsonl` | aqt-trail writer | The chained log; signed checkpoints | `log_mode` (0600; 0640 in separate-user mode) |
| `trail/trail.json` | aqt-trail | Log ID, key ID, creation time | umask |
| `trail/trail.lock` | aqt-trail writer | Writer lock | 0600 |
| `trail/keys/service.key`, `.pub` | `aqt-trail init` | Unencrypted service key; public key | 0600; umask |
| `trail/reviews/<rv_id>/worksheet.json`, `.md` | `aqt-trail review run` | Review worksheets (working copies; `review sign` recomputes them) | umask |
| `trail-reviews/<rv_id>/` | `aqt-trail review run`, aqt-ui | Worksheets when the trail state is not writable (separate-user mode) | umask |
| `trail/test-tsa/` | `--tsa test:` | TEST ONLY CA, certificate and key (`tsa.key` 0600) | umask |
| `signoff/signoff.db` (`AQT_SIGNOFF_STATE`) | aqt-signoff | Action index and undelivered records (SQLite) | 0600 |
| `change/<16 hex>/` | aqt-change outside a Git repository | Ledger (as below) | files 0600 |
| `quarantine/` (`AQT_QUARANTINE_STATE`) | aqt-quarantine | `journal.jsonl`, `outbox.jsonl`, `cases/<CASE>/original.txt` | dir 0700, files 0600 |
| `validate/` (`AQT_VALIDATE_STATE`) | aqt-validate | `runs/<run>/`, `cache/reviewer/`, `tmp/` | run and cache dirs 0700 |
| `capa/capa.db` (`AQT_CAPA_DB`), `capa/snapshots/` | aqt-capa | Working index; snapshots of control files | umask |
| `sensei/` (`AQT_SENSEI_STATE`) | aqt-sensei | `pairs.json`, `messages/<pair>.jsonl`, `ledger-spool.jsonl`, `homes/<platform>/` | state dir, `messages/` and each home 0700; files 0600 |
| **Runtime** `$XDG_RUNTIME_DIR/` | | | |
| `aqt/trail.sock` | `aqt-trail serve` | Writer socket | 0600 (0660 in separate-user mode) |
| `aqt-sensei/` (`AQT_SENSEI_RUNTIME`) | `aqt-sensei serve` | `owner.sock`, `agent.sock`, `pairs/<id>/advisor.sock` and shim, `panes/` | dirs 0700, sockets 0600 |
| **Home** | | | |
| `~/aqt-ui-login-*/login.html` | `aqt-ui` | Private page that forwards the browser to the one-time login link; deleted after a login and when the server stops (in `$XDG_RUNTIME_DIR` or the temporary directory without a usable home folder) | dir 0700, file 0600 |
| **Project** | | | |
| `<repository>/.aqt/change.toml` | You (committed) | aqt-change project settings (section 5.4) | as committed |
| `<git-dir>/aqt-change/` (`AQT_CHANGE_STATE`) | aqt-change | `plans/`, `objects/`, `logs/`, `attempts/`, `records.jsonl` | files 0600 |
| `<git-dir>/hooks/commit-msg` | `aqt-change hooks install-git` | Trailer check shim (never overwrites) | executable |
| `<project>/.sensei/<pair>/` | aqt-sensei advisor | The advisor's writable scratch folder | inside the sandbox |
| **Separate-user mode** | | | |
| `/etc/aqt/trail.toml`, `/var/lib/aqt-trail/`, `/run/aqt-trail/trail.sock` | `scripts/setup-system-user.sh` | System configuration, state and socket | see section 5.2 |

Record contents to keep in mind for data protection: actor IDs and display names, signer names, short excerpts (prompt and tool excerpts in `trail.import`, evidence excerpts in `quarantine.held`, message excerpts in `sensei.message`, output tails in receipts), and paths such as the Python executable in a receipt's environment summary.

---

## 8. Security model

### 8.1 Threat assumptions

- **The adversary is an agent**, possibly steered by injected content: a coding agent that claims "done" without evidence, approves its own work, edits records, or follows instructions from a web page. Agents usually run as the same Unix user as the person they work for.
- **Out of scope:** an attacker with the owner's private keys or passphrases, root, a root-equivalent group (`sudo`, `docker`), a modified installation, or kernel escapes. Detector evasion by adaptive prompt injection is also out of scope: detectors are triage.
- **Single user, single host, local use.** The tools are designed for a developer workstation; there are no network listeners, and every socket is a Unix socket.

### 8.2 What each control protects against, and what it does not

| Control | Protects against | Does not protect against |
|---|---|---|
| Separate trail writer with `observed` attribution | An actor claiming another identity unnoticed: the claim and the observed process chain are both stored, review flags mismatches and incomplete chains (`chain_status`), and clients cannot write records in the writer's name | A same-user process that detaches into a new session or is started by a service manager or a terminal server on an agent's request (its chain looks complete); records delivered through the spool (marked `via: spool`, not observed); tools or hooks that never write |
| Hash chain plus writer signature | Unnoticed edits, inserts, deletes and reordering, for a verifier with the writer's public key | Truncation and a full rewrite under a new key, unless the key is pinned and head copies or anchors exist |
| Head copies (`head --export`) and RFC 3161 anchors | Truncation, rollback and rewrite before the anchor's time, as long as the copies are out of the agents' reach; `verify` names the records they do not cover | Changes after the last anchor; a TSA you should not trust (no revocation check). TEST ONLY anchors, which any client may request, count only in test mode |
| Separate-user mode | Agents editing the log or reading the service key | Root and root-equivalent users |
| Detached statements with passphrase keys and counter-signed enrolment | Signing without the passphrase, moving a signature to other content, replaying it in another record, altering the printed name, role, meaning, time or reason; a key, extra key or role that an agent enrols for itself (pending until an enrolled person approves it); offline guessing of a copied key file is slow (scrypt) | An agent that obtains the passphrase (never type it into an agent chat); the first enrolment of an empty store and a re-bootstrap after every key was revoked, which count without approval (a re-bootstrap stays flagged by `signers check`, `verify` and `aqt status`, which also name unsigned revocations before it); reordering of a plain evidence file without a trail; without aqt-signoff installed, keys that only `signers.json` lists, for aqt-trail and aqt-quarantine; old backup copies of PBKDF2 key files |
| `require_human` and per-tool owner checks | Agents deciding by accident or on injected instructions; every attempt is recorded as `<tool>.refused` | A determined same-user process that clears its environment, detaches and fakes a terminal |
| aqt-quarantine detectors and fail-closed bands | Known-style injections reaching the agent through the covered tools | Adaptive attacks; other channels (`curl` in a shell, downloaded files, uncovered tools); content in the warn band, which the model has already seen; a hook that does not run (Claude Code then passes the original) |
| aqt-sensei bubblewrap sandbox | An advisor writing to the project, reading the bridge state, the owner token, sockets, other pairs or the owner's agent homes | Confidentiality: with the network shared (the default) the advisor can send what it reads to the internet; a same-user process outside the panes that reads the token |
| aqt-change receipts and gate | A careless agent claiming "done" without running anything; silent plan changes; stale evidence; with aqt-trail, receipts and reviews forged or edited in the local ledger, and (with `require_trail` and `trail_keys`) a trail check switched off through the environment or answered by a log the agent wrote; changes hidden from `git status`, also behind an untracked `.gitignore`; Python bytecode standing in for the source; tested changes left out of the commit; a user configuration that loosens the gate; project settings dropped by editing a plan's base commit | Without aqt-trail, a forged ledger or plain JSONL sink (use `gate --rerun`); a made-up receipt sent through the writer's socket (the trail keeps the sender's process chain); in user mode, a log re-signed with the real service key; deleting a later failing run from the local ledger; without aqt-trail, a base commit rewritten together with its `begin` record in the ledger; ignored build output a run loads other than Python bytecode (only a clean-checkout run is decisive); local clean filters; a committed `.gitignore` change (visible in the diff); inadequate tests (reviews and aqt-validate address that) |
| aqt-capa | Deviations disappearing as anecdotes; unapproved or reverted changes to agent instructions (hash-bound); an unverified record posing as an independent approval | Failures that no control records; tampered input evidence (aqt-capa does not verify chains); forged unsigned steps such as a closure in a plain JSONL sink |

### 8.3 Where tamper evidence comes from

Tamper evidence is not tamper prevention. A record set is trustworthy to the degree that all of the following hold:

1. records reached the trail through the socket (`observed.via = socket`), not through the spool;
2. the chain verifies and every record is signed by the writer;
3. the verifier pins the writer's public key (`--pin-key`, or `aqt-evidence conform --key`), obtained independently of the log;
4. checkpoints exist **outside the writer's reach**: exported heads on another device, or RFC 3161 tokens from a TSA you trust;
5. human decisions carry detached statements that verify against a registry you trust, made with keys the agents cannot use;
6. in user mode, the agents cannot read the service key; otherwise only separate-user mode or sandboxing makes 2 and 3 meaningful against a same-user agent.

`aqt-evidence conform --level 3` checks 2–4 mechanically for any JSONL file.

### 8.4 Known limitations

- **Security review.** The code had an AI-assisted security review in October 2026, not a professional audit. The [review report](security-review-2026-10.md) lists every finding, its fix and the limits that remain.
- **Linux only.** Attribution needs `SO_PEERCRED` and `/proc`; locking uses `fcntl`; the advisor sandbox needs bubblewrap and unprivileged user namespaces (on Ubuntu, AppArmor can block them; `aqt-sensei doctor` detects that).
- **Time** is the writer's clock unless anchored. Clock jumps are recorded, not prevented.
- **Separate-user mode is scripted but not exercised by the tests.** The units pass `systemd-analyze verify`, but the script itself has not run in CI. Check once that a client user can write through `/run/aqt-trail/trail.sock` and read the log before relying on this mode.
- **The advisor sandbox does not use `bwrap --new-session`.** The advisor runs in the pane's terminal session.
- **Importers** depend on undocumented, changing session formats. Codex's SQLite history store is not imported.
- **Excerpts** can contain personal data; set `excerpt_chars = 0` (aqt-trail) or `excerpt_lines = 0` (aqt-change) where that matters.
- **Default evidence sources** do not include a separate-user log; name it in `AQT_EVIDENCE` (section 3.6).
- **AF_UNIX path length** (about 104 bytes) limits socket locations, including the temporary directories used by tests.
- **Not implemented in 0.1:** an MCP server for approvals, a query service, in-toto or SCITT export, multi-host replication, eIDAS-qualified signatures, PDF signing.

---

## 9. Testing and CI

### 9.1 Suites

Each package has an offline pytest suite in `<package>/tests/` with synthetic fixtures: no network, no real agents or models, no GPU. Counts observed on 2026-10-30 (Python 3.13), after the four fix rounds of the security review:

| Suite | Passed | Skipped | Notes |
|---|---|---|---|
| aqt-spec | 200 | 0 | Vectors, schemas, catalogues (every cited catalogue ID exists), spec documents agree with the code; Hypothesis property tests for canonical JSON, hashing, chain and signature verification |
| aqt-trail | 195 | 0 | Writer, server, tamper cases, TSA and test mode, importers, review and profile parameters, enrolment-backed registry keys, ALCOA++, bundles |
| aqt-signoff | 73 | 0 | Signatures, statuses, replays, counter-signed enrolment (bootstrap, approval, roles, rotation, re-bootstrap and its confirmation, unsigned revocations, replayed requests, one import, export with enrolment evidence), key format, actions, CLI, L1 conformance of its records |
| aqt-change | 122 | 0 | Plan format, reconciliation, receipts, content fingerprint, hidden changes, ignore rules and the fresh bytecode cache, trail confirmation, project settings and the plan's base commit, finish, gate, hooks, quick start |
| aqt-sensei | 55 | 3 | The skipped tests need real tmux and bubblewrap (opt-in) |
| aqt-quarantine | 85 | 0 | Detectors, engine, decisions and their replays, enrolment-checked keys, journal problems, Claude Code adapter, payload conformance of every record type |
| aqt-validate | 110 | 0 | Statistics against reference values, loaders, detector and reviewer runs |
| aqt-capa | 23 | 0 | Units, CLI, end to end, signature-based approval |
| aqt-ui | 93 | 0 | Login, Host, CSRF and Origin, session key, request limits, read-only and peer checks for every decision, substituted content, release only after every page was shown, the record inspector, test mode and review parameters, each decision end to end, German labels, paging and a 50,000-record trail |
| aqt-cli | 28 | 0 | `aqt status` (including the signer check), `aqt setup`, tool pass-through |
| demo | 1 | 0 | `examples/demo/test_demo.py`: the full story, 43 expected outcomes |

In total 985 tests pass: 984 package tests (including the optional aqt-ui and aqt-cli) plus the demo test. Some tests skip themselves when a tool is missing: `openssl` (aqt-trail token cross-check) and `git` (aqt-change quick start).

### 9.2 Running them

```sh
scripts/test_all.sh                 # every package, then the demo; prints a summary table
scripts/test_all.sh aqt-trail       # one or more packages (the demo runs only without arguments)
cd aqt-trail && .venv/bin/python -m pytest -q     # directly, inside a package
```

`scripts/test_all.sh` needs `uv`. It creates a missing `<package>/.venv` (`uv venv`, then `uv pip install -e ../aqt-spec -e ".[test]"`; aqt-validate also gets aqt-quarantine for the plug-in tests) and `examples/demo/.venv` with all eight packages. Each suite runs with:

- throw-away `HOME`, `XDG_STATE_HOME`, `XDG_CONFIG_HOME`, `XDG_CACHE_HOME` and `TMPDIR`, and a short `XDG_RUNTIME_DIR` under `/tmp`;
- every `AQT_*` variable removed from the environment;
- a private Git configuration (`GIT_CONFIG_GLOBAL`, `GIT_CONFIG_NOSYSTEM=1`).

At the end the script fails if `~/.local/state/aqt` or `~/.config/aqt` appeared during the run. Keep `TMPDIR` short or unset: tests create Unix sockets below it, and a long base path exceeds the AF_UNIX limit (`OSError: AF_UNIX path too long`).

**Isolation inside the suites.** Each `conftest.py` points `XDG_STATE_HOME` and `XDG_CONFIG_HOME` at temporary folders (aqt-trail's does this for the whole session in `pytest_configure`), because `SocketSink` spools by default and must never reach the real spool. Tests that call `require_human` inject an empty environment and process chain, since the test runner itself may run inside an agent session.

**Opt-in tests.** `AQT_SENSEI_REAL=1` enables aqt-sensei's tests with real tmux, real sockets and real bubblewrap (`tests/test_tmux_real.py`, `tests/test_e2e_real.py`, one test in `tests/test_doctor.py`). `test_all.sh` removes `AQT_*` variables, so run these with pytest directly inside `aqt-sensei/`. Manual checks that need a real agent session are described in `aqt-quarantine/docs/claude-code.md`, `aqt-change/docs/claude-code.md`, `aqt-sensei/docs/manual-verification.md` and `aqt-validate/docs/usage.md`.

### 9.3 The demo

`examples/demo/run_demo.py` wires all eight packages together offline in about ten seconds. It isolates `HOME`, the XDG directories and `TMPDIR` in a fresh temporary directory, runs `aqt-trail serve` on a temporary socket, sets `AQT_SINK` to it, and drives the tools mostly through their command lines, with the documented test injection for the two simulated people (DEMO ONLY passphrases) and the TEST ONLY time-stamp authority. It exits 0 only when every expected outcome occurred. `--keep` keeps the temporary directory so that you can inspect the trail with `aqt-trail --state <dir>/state/aqt/trail list`; `--out DIR` chooses where readable outputs go (default `examples/demo/output/`, which is git-ignored).

Started from inside an agent session, the demo's ALCOA++ report fails *attributable*: the writer sees the outer agent in the process chain of the simulated humans. The demo expects and reports this.

### 9.4 CI

`.github/workflows/ci.yml` runs on every push and pull request on `ubuntu-latest` with Python 3.11, 3.12 and 3.13. It installs `uv`, `bubblewrap` and `tmux`, then runs `scripts/test_all.sh`; further jobs run `scripts/clean_install_check.sh` and audit the third-party dependencies of all packages with `pip-audit`. The `.github/workflows/ci.yml` files inside the package folders are path-filtered workflows for a package that lives in its own repository; GitHub Actions runs only the root workflow in this monorepo.

---

## 10. Extending the suite

### 10.1 A detector plug-in

A detector is any object with `name`, `version` and `score(text) -> DetectorResult`. The interface lives in `aqt_quarantine.detectors`, which imports only the standard library.

```python
# my_package/detect.py
from aqt_quarantine.detectors import DetectorResult, Span

class KeywordDetector:
    name = "keyword"          # the id used in thresholds files and protocols
    version = "1.0.0"         # change it whenever behaviour changes; it is recorded with every scan

    def __init__(self, **options):            # options come from [[detectors]] or the protocol's options table
        self.words = options.get("words", ["ignore all previous instructions"])

    def score(self, text: str) -> DetectorResult:
        lowered = text.lower()
        spans = [Span(i, i + len(w), "override", "known override phrase")
                 for w in self.words if (i := lowered.find(w)) >= 0]
        return DetectorResult(score_ppm=900_000 if spans else 0, spans=spans)
```

```toml
# my_package's pyproject.toml
[project.entry-points."aqt.detectors"]
keyword = "my_package.detect:KeywordDetector"
```

Contract: `score_ppm` is an integer from 0 to 1,000,000, higher means more suspicious; every span indexes the text that was passed in. Anything else (a float, a span out of range, an exception) is a detector error, and aqt-quarantine holds the content. Use the detector in aqt-quarantine with `[[detectors]] kind = "keyword"` (or `kind = "my_package.detect:KeywordDetector"` without an entry point), and validate it with aqt-validate using `plugin = "keyword"` in the protocol. `aqt-validate detector plugins` lists what is installed. Calibrate a new detector with aqt-validate before using its thresholds; until then, its records say *uncalibrated*. A complete command-line example is `aqt-validate/examples/detectors/keyword_detector.py`.

### 10.2 A record type

- **Outside the suite:** use `x-<org>.<kind>`, for example `x-acme.deploy`. It needs no registration and passes L1; its payload is not schema-checked.
- **Inside the suite:** the source of truth is the `TYPES` table in `aqt-spec/scripts/build_schemas.py`: `type -> (summary, actions, meanings, human_reason, data schema)`. A new tool prefix also needs an entry in `TOOLS`, which gives it a `<tool>.refused` type automatically. Then:
  1. run `python scripts/build_schemas.py` in `aqt-spec/` to regenerate `schemas/registry.json` and `schemas/data/<type>.schema.json`;
  2. add the type to the table in spec §11 (`tests/test_spec_docs.py` checks that every registered type appears there), and, if other tools will read it, its required `data` fields;
  3. if a catalogue feature is evidenced by the type, list it in `catalogues/features.yaml`;
  4. run the aqt-spec tests.

Rules: within 0.1, payload schemas may only add optional fields. Use integer `_ppm` and `_ms` units, never floats. Store hashes and short excerpts instead of large or sensitive texts. A human decision type should set `human_reason`. Changes to types or fields that other tools read need a spec change first (`CONTRIBUTING.md`).

### 10.3 An importer

Importers live in `aqt-trail/src/aqt_trail/importers.py`. There is no plug-in mechanism yet: add a reader function and register it in the module-level `READERS` dictionary; the `aqt-trail import` command takes its choices from that dictionary.

```python
def my_harness_session(path, *, excerpt_chars: int = 160) -> Session:
    session = Session("my-harness-session", "my-harness")    # format, harness name
    for number, line in safe_lines(path):                     # owner, symlink and link-count checks
        entry = json.loads(line)
        ...
        session.id = session.id or entry["session"]
        session.events.append(Event(
            "prompt",                                         # action of the trail.import record
            entry.get("id") or f"line:{number}",              # event id within the source
            _line_hash(line),                                 # source_hash: makes re-imports idempotent
            entry.get("timestamp"),                           # source time (RFC 3339), kept in data.source_time
            {"prompt_sha256": value_hash(entry["text"]),
             "prompt_excerpt": excerpt(entry["text"], excerpt_chars)}))   # masked, length-limited
    return session

READERS["my-harness"] = my_harness_session
```

`to_records` turns a `Session` into `trail.import` records with the actor `agent:<harness>:<session id>`, `data.source = {format, session, event_id}`, `data.source_hash` and a deterministic record ID. Event fields must not use the reserved names `source`, `source_hash` or `source_time`. Never store full texts: use `value_hash` and `excerpt`. Add a synthetic fixture under `aqt-trail/tests/fixtures/` (structure only, no real content) and a test in `tests/test_importers.py`.

### 10.4 A catalogue item

Catalogues are YAML files in `aqt-spec/catalogues/`, licensed CC BY 4.0. Each file has a `source` block (`document`, `version`, `status`, `consulted`, `basis`) and `items`:

```yaml
  - id: part11:11.70                  # <catalogue>:<clause as numbered in the source>
    clause: "11.70"
    title: Signature/record linking
    paraphrase: In your own words, at most two sentences and 400 characters.
    supported_by: [spec.signature, signoff.signature]   # feature IDs from features.yaml
    user_must: What the user still has to do.
    verified: true                    # false needs a note saying what was not checked
```

New features go into `catalogues/features.yaml` (`package`, `description`, `records`, where every record type must be registered). Then run `python scripts/build_crosswalk.py` (needs PyYAML, part of the `test` extra) to regenerate `crosswalk.md` and `catalogues/catalogues.json`. The tests check that the generated files are current, that every feature is cited by some item, that IDs cited by other tools exist, and that no wording claims compliance. A new catalogue also needs its ID in `ORDER` in `build_crosswalk.py` and in the published list of spec §13. Paraphrase in your own words; never copy long quotes; cite the clause as numbered in the source and say which text you checked.

---

## 11. Reference: environment variables and conventions

### 11.1 Environment variables

| Variable | Used by | Meaning |
|---|---|---|
| `AQT_SINK` | All tools | `file:/path.jsonl` or `unix:/path.sock`; unset: the trail writer when one answers or a trail exists, else `$XDG_STATE_HOME/aqt/evidence.jsonl` (section 3.1) |
| `AQT_EVIDENCE` | All readers | Colon-separated JSONL files to read records from; files named `trail.jsonl` are read first (section 3.6) |
| `AQT_ACTOR` | aqt-trail, aqt-signoff, aqt-change, aqt-validate, aqt-capa | Claimed actor ID (never turns an agent context into a human in aqt-change) |
| `AQT_AGENT_SESSION` | Human check; aqt-change, aqt-capa, aqt-validate session IDs | Marks an agent session; set to `1` inside the aqt-sensei sandbox |
| `AQT_TRAIL_STATE` | aqt-trail | Trail state directory |
| `AQT_SIGNERS`, `AQT_KEYS_DIR` | aqt-signoff, aqt-quarantine, aqt-trail | Signer registry and key directory |
| `AQT_SIGNOFF_CONFIG`, `AQT_SIGNOFF_STATE` | aqt-signoff | Configuration file; state directory |
| `AQT_CHANGE_CONFIG`, `AQT_CHANGE_STATE` | aqt-change | Configuration file; ledger directory |
| `AQT_SENSEI_CONFIG`, `AQT_SENSEI_STATE`, `AQT_SENSEI_RUNTIME`, `AQT_SENSEI_TOKEN` | aqt-sensei | Configuration, state, runtime directory, owner token |
| `AQT_SENSEI_SOCKET`, `AQT_SENSEI_ROLE`, `AQT_SENSEI_PAIR` | aqt-sensei sandbox | Set by the bridge for the `sensei` shim |
| `AQT_SENSEI_HERDR_BIN` | aqt-sensei | Path of the Herdr binary |
| `AQT_SENSEI_REAL` | aqt-sensei tests | `1` enables the opt-in tests with real tmux and bubblewrap |
| `AQT_QUARANTINE_CONFIG`, `AQT_QUARANTINE_STATE`, `AQT_QUARANTINE_THRESHOLDS` | aqt-quarantine | Configuration, state, thresholds file |
| `AQT_VALIDATE_CONFIG`, `AQT_VALIDATE_STATE` | aqt-validate | Configuration, state |
| `AQT_CAPA_DB` | aqt-capa | SQLite index path |

### 11.2 Conventions shared by every command

- One console script per package, `argparse` subcommands, `--json` for machine-readable output. Global options such as `--json` and `--config` are accepted before or after the subcommand.
- Exit codes: **0** ok, **1** check failed or refused, **2** usage or runtime error. Hooks follow their harness's protocol instead (for Claude Code, exit 2 blocks).
- Configuration is TOML at `$XDG_CONFIG_HOME/aqt/<tool>.toml`, read with the standard library; every path can be overridden by a flag or an environment variable. Example files are in each package's `examples/`.
- Services listen on Unix sockets only; there are no TCP listeners.
- Network access is off unless the user configures it.
