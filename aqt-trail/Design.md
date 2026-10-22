# aqt-trail — Design

**Status:** target design, MVP built (Phase B), 2026-10-21; adjusted in passing to `planning/04_designs/INTERFACES.md`, which wins where they differ. **Brief:** `planning/04_designs/SUITE_ARCHITECTURE.md` §2.2.
**Shared foundation:** `aqt-spec` (`aqt_evidence` library, record envelope 0.1). This design uses that API and does not copy it.

---

## 1. Introduction

### 1.1 Core idea

`aqt-trail` is a small, local, tamper-evident audit trail for the work of AI coding agents, plus the tools a quality reviewer needs to **verify** it, **review** it and **sign** the review. It applies the audit-trail ideas of EU GMP Annex 11 §12 and 21 CFR Part 11 §11.10(e) to agent sessions on a developer machine:

- every AQT tool, hook or script appends evidence records to **one writer service** that the agents do not run themselves;
- the writer, not the client, decides the time, the sequence and the **observed** attribution (the Unix peer of the socket and its process chain, for example `claude → bash → python3`);
- records are hash-chained and signed, and the chain head is anchored **outside** the writer's reach (exported head copies and RFC 3161 timestamps), so a rewrite after an anchor is always detectable;
- a reviewer who was not involved runs risk queries over a period, works through the findings and signs a `trail.review` record with the meaning *reviewed*.

The hash chain itself is a commodity. What this package adds is the QM layer around it: independent recording, GxP record semantics, honest gap handling, an ALCOA++ check and an audit-trail review workflow with enforced reviewer independence.

### 1.2 Users

- **Solo developers and small teams** who run Claude Code, Codex or pi and want a trustworthy record of what their agents did and what humans decided.
- **The other AQT tools**, which send their records here through `AQT_SINK=unix:…` (`aqt_evidence.open_sink`).
- **Reviewers and auditors** (also people from regulated industries) who receive an export bundle and must check it independently.

### 1.3 Problem

Agent logs today are either plain files the agent can edit, or "signed" logs where the agent process signs its own entries. Neither shows *who really acted* (a claimed `actor` is just a string), neither marks what is missing, and none supports the step a GMP quality manager cares about most: a documented, risk-based, independent **review** of the trail. Annex 11 (draft §12.5) explicitly encourages tools for that review; no open-source one was found (R3 §5).

### 1.4 End-to-end behaviour

1. `aqt-trail init` creates the state directory, a service signing key and a log ID.
2. `aqt-trail serve` listens on a Unix socket. A client (any AQT tool, the Claude Code hook, `aqt-trail append`) sends a record. The writer checks the envelope, refuses records that try to set writer-owned fields, restamps the time, adds `observed` (pid, uid, gid, process chain, client time), links the record into the chain, signs it, appends it to the JSONL log and fsyncs, then returns the stored record.
3. If the writer is down, the client puts the record into a **spool**. When the writer next starts, it writes a `trail.gap` marker that names the outage window and then appends the spooled records, clearly marked as *spooled, attribution not observed*. Nothing is silently lost, and nothing pretends to be observed when it was not.
4. `aqt-trail checkpoint --anchor` signs the current head and, when a TSA URL is configured, obtains an RFC 3161 timestamp over the head hash, stored as a `trail.anchor` record. `aqt-trail head --export` prints the signed head for storage elsewhere (another machine, a phone, a git repo, e-mail to oneself).
5. `aqt-trail import` turns Claude Code hook events and Claude Code, Codex and pi session files into `trail.import` records (hashes and short excerpts, never full texts), idempotently.
6. `aqt-trail verify` reports **intact** or **broken from seq N** with the reason, plus the state of signatures, checkpoints, anchors and external heads.
7. `aqt-trail alcoa` reports per ALCOA++ attribute what the trail demonstrates and where it falls short.
8. `aqt-trail review run` produces a worksheet of risk findings for a period; `aqt-trail review sign` records the reviewer's dispositions as a signed `trail.review` record — refused if the reviewer appears as an actor in the reviewed scope.
9. `aqt-trail export` writes a self-contained bundle (log, checkpoints, anchors, public keys, manifest with checksums, verification instructions) and `aqt-trail report` a legible Markdown/HTML view.

### 1.5 Inputs and outputs

| Inputs | Outputs |
|---|---|
| AQT evidence records over the socket or from stdin | Append-only `trail.jsonl` (chained, signed records) |
| Claude Code hook JSON (stdin); Claude Code / Codex rollout / pi session JSONL files | `trail.import` records; import summary |
| Configuration (TOML), review profile (TOML) | Signed checkpoints, `trail.anchor` records with TSA tokens |
| Optional TSA URL and TSA CA certificate; exported head files | Verification result (text / `--json`), ALCOA++ report, review worksheet, `trail.review` records |
| Reviewer key (Ed25519 PEM, aqt-signoff compatible) | Export bundle; Markdown/HTML report |

### 1.6 Performance intent

Qualitative: an append must be fast enough for a hook that fires on every tool call without the user noticing (one fsync per record; a few milliseconds is the expected order, not a measured target). Verification, review and ALCOA reports read the JSONL linearly and should be comfortable for a personal trail of up to some hundred thousand records; beyond that, a rebuildable SQLite index is a later stage. Hooks must never block the agent for long: a short client timeout, then spool.

### 1.7 Design flexibility

Everything in §2 is a proposal. The implementer may merge or split modules, use another internal structure, replace the hand-written DER code with a permissively licensed library behind an optional extra, change CLI spellings or query parameters, and reorder the work — as long as the core outcomes stay intact: a separate writer that sets time and observed attribution, an append-only chained and signed log, gap markers instead of silent loss, external anchors that make rewrites detectable, idempotent importers, a verifier with a precise "broken from seq N", an ALCOA++ report, and an audit-trail review whose signer is enforced to be independent. Small product adaptations need no approval round; a change to one of these outcomes goes to the lead.

> **Implementation workflow.** All implementation guided by this design uses `lean-vertical-delivery` (small end-to-end slices, proportionate checks, a small completion report; no separate testing or documentation regime). Work is tracked in Project Tracker Next (project "Agent Quality Toolkit", one implementation for this package) through its low-call lifecycle. This package has no interactive UI; if one is added later, it is designed with `ui-studio`. When the same functionality fails repeatedly despite a reassessed approach, consult a Sensei with the intended behaviour, the attempts and the specific help needed.

(For the builder session itself, the common brief applies: no Project Tracker calls and no `git init` by the builder; the lead records tracking.)

---

## 2. Proposed architecture

```mermaid
flowchart LR
    subgraph Clients["Clients (run as the user or as agents)"]
        T1["AQT tools<br/>open_sink(unix:)"]
        H["Claude Code hook<br/>aqt-trail hook claude-code"]
        A["aqt-trail append / event"]
        I["aqt-trail import<br/>claude / codex / pi files"]
    end
    SP[("shared spool<br/>spool.jsonl")]
    subgraph Writer["aqt-trail serve (writer; own user optional)"]
        S["Unix socket 0600/0660<br/>SO_PEERCRED"]
        O["observe: /proc chain,<br/>client time, service time"]
        W["TrailWriter: validate → restamp →<br/>link → sign → append + fsync"]
        D["spool drain → trail.gap"]
    end
    L[("trail.jsonl<br/>+ checkpoints.jsonl")]
    K[("service key<br/>keys/")]
    TSA["RFC 3161 TSA<br/>(optional, configured)"]
    X["External heads<br/>(other device, repo)"]
    subgraph Readers["Readers (anyone with read access)"]
        V["verify"]
        AL["alcoa"]
        R["review run / sign"]
        E["export / report / list"]
    end
    T1 & H & A & I --> S
    T1 & H & A -. writer down .-> SP
    SP --> D --> W
    S --> O --> W
    K --> W
    W --> L
    W -- head hash --> TSA -- token --> W
    L -- head --export --> X
    L --> V & AL & R & E
    X --> V
    R -- trail.review (reviewer key) --> S
```

Arrows: clients only *send*; only `TrailWriter` appends to `trail.jsonl`. Readers never write except through the socket (the signed review is an ordinary append). The writer contacts the TSA only when a URL is configured and only sends a hash.

### Modules (suggested, not binding)

| Module in `src/aqt_trail/` | Role |
|---|---|
| `writer.py` | `TrailWriter`: single-writer lock (`fcntl.flock` on `trail.lock`), open/recover the log (truncate a torn last line, record it as `trail.event action=log.repaired`), restamp, link with `aqt_evidence.link`, sign with the service key, append + fsync, monotonic-clock check |
| `observe.py` | `SO_PEERCRED` → pid/uid/gid; `/proc/<pid>/stat` walk for the process chain (comm, pid, start time; max depth 16); harness detection from the chain |
| `server.py` | `socketserver.ThreadingUnixStreamServer`, one request per connection (protocol of `aqt_evidence.sink`), ops `append`, `head`, `ping`; allowed-uid check |
| `client.py` | `TrailClient` with spool fallback; spool writer (atomic rename, 0600) |
| `anchors.py`, `der.py` | checkpoints, RFC 3161 request/response, minimal DER reader/writer, token verification, test TSA helper |
| `verify.py` | chain + service signatures + checkpoints + anchors + external heads + detached `data.signature` statements → `TrailReport` |
| `importers/` | `claude_hook.py`, `claude_session.py`, `codex_rollout.py`, `pi_session.py`, shared `safe_read.py` |
| `review.py`, `queries.py` | review profile, risk queries, worksheet, independence check, `trail.review` |
| `alcoa.py` | ALCOA++ checks |
| `export.py`, `render.py` | bundle with manifest; Markdown/HTML views (`html.escape`, no template engine) |
| `config.py`, `cli.py` | TOML config and XDG paths; argparse CLI |

### Storage

`$XDG_STATE_HOME/aqt/trail/` (overridable with `--state` / `AQT_TRAIL_STATE`):
`trail.jsonl` (the log, canonical JSON lines), `trail.lock`, `checkpoints.jsonl` (signed heads), `keys/service.key` + `.pub` (0600), `reviews/`; the client spool is the shared `$XDG_STATE_HOME/aqt/spool/spool.jsonl` (I3) and the socket defaults to `$XDG_RUNTIME_DIR/aqt/trail.sock` (short path; AF_UNIX limit), `reviews/<id>/worksheet.{json,md}`. Configuration: `$XDG_CONFIG_HOME/aqt/trail.toml`. The log is never rewritten; a segmented log is a later stage.

**Separate-user mode.** `scripts/setup-system-user.sh` (provided, documented, never run in tests) creates a system user `aqt-trail`, `/var/lib/aqt-trail` for log and key (log 0640 so the clients group can read and verify; key 0600), and `/run/aqt-trail/trail.sock` with mode 0660 and group `aqt-trail-clients` (accepted exception, I12), plus an example systemd unit. Then agents running as the user can append but can neither edit the log nor read the service key. In user mode (the default) the same user owns everything, so integrity rests on the external anchors (§2.4).

### How records are written

1. Client sends `{"op": "append", "record": …}`. The writer rejects (`{"ok": false, "code": …}`, I3 codes): invalid envelope, client-set `sig`, `chain` or `observed`, or a human decision (`meaning` set) without `reason` → `invalid_record`; uid not allowed → `unauthorized`; a different record under an existing id → `duplicate_id` (a re-sent identical record returns the stored one). Refusals are appended as `trail.refused` (I5: `action: refused`, claimed actor, `data = {attempted_action, reason_code, agent_markers, …}`) with the observed peer — attempts are evidence.
2. The writer moves the client's `time` to `observed.client_time`, sets `time` from its own clock, adds `observed`, links (`chain.seq`, `chain.prev`), signs with the service key and appends.
3. The stored record is returned to the client.

### Reuse

| From | What | How |
|---|---|---|
| Agent Platform Next s74 sprint (`docs/implementations/platform-consolidation/sprints/74_TAMPER_EVIDENT_AGENT_AUDIT_TRAIL.md`) | Concept: separate writer, peer attribution, chain + Ed25519, anchors, gap markers, ALCOA+ mapping, tamper tests V01/V02 | Rebuilt from the design (s74 was never implemented) |
| `Agent_Platform_Next/scripts/herdr/claude_history.py` | Claude transcript knowledge: `sessionId` is the only identity (not `session_id`), `continued-in` chains, `tool_use`/`tool_result` pairing, `compact_boundary`, `permission-mode` records, torn last line ignored | Copy + adapt the parsing knowledge only; no paging, branch walking, shells or runtime facts |
| `…/codex_history.py` | Rollout format: `session_meta` header, `turn_context` (model, sandbox, approval policy), `response_item` function/custom/local-shell calls and outputs, `event_msg` turn events, rollback | Copy + adapt for rollout JSONL; SQLite paginated store left for later |
| `…/pi_history.py` | pi v3 session: header `type=session, version=3`, tree via `id`/`parentId`, `message` roles incl. `toolResult`, `model_change`, `compaction` | Copy + adapt |
| shared safety rules of those readers | `O_NOFOLLOW`, regular file, one hard link, owner uid, inode re-check, partial-line tolerance | Copy into `safe_read.py` |
| `aqt-spec` (`aqt_evidence`) | envelope, canonical JSON, `record_hash`, `link`, `verify_chain`, checkpoints, keys, sinks | Dependency |
| Open source | C2SP tlog-checkpoint (spec), Rekor v2 log/TSA split (pattern), eLabFTW RFC 3161 flow (idea only, AGPL), `openssl ts -verify` (independent check documented for users) | Ideas and interoperability only; no code copied |

All copied code loses private paths, hosts and names; origin noted in `NOTICE`. Fixtures are synthetic.

### 2.1 Core concepts

**Claimed versus observed attribution.** `actor` is what the client claims; `observed` is what the writer saw. The writer cannot authenticate a human, but it can see the process that connected. A record that claims `actor.kind = human` while the observed chain contains `claude`, `codex` or `pi` is an **attribution mismatch** — the exact attack of s74 V02 ("an agent appends under the owner's name"). The writer records such records faithfully; the review and the ALCOA report flag them. Proposed `observed` shape (writer-owned):

```json
{"pid": 4242, "uid": 1000, "gid": 1000,
 "process_chain": ["python3", "bash", "claude", "bash", "sshd"],
 "processes": [{"pid": 4242, "comm": "python3", "start": 123456}, "…"],
 "harness": "claude-code", "client_time": "2026-10-21T14:03:12.100000Z",
 "via": "socket"}
```
`via` is `socket` or `spool` (I2; spooled records carry no pid/uid/gid because the sender was never observed); records the writer creates itself have no `via` but `origin: writer`. PIDs are reused, so `start` (from `/proc/<pid>/stat` field 22) makes an entry unambiguous; a process that exited before observation is recorded as `"?"` and the chain marked incomplete.

**Chain and signatures (INTERFACES I1).** The record hash covers everything except `sig`, so chaining and restamping change it. The envelope `sig` belongs to the writer of the stored record — the aqt-trail service — and clients never send one. Human signatures (for example a signed review) travel as a detached statement in `data.signature` (`{statement, alg, key, value}`, aqt-spec `signature.schema.json`); the writer never changes `data`, so they survive storage. A signature over a record uses `record_content_hash`, which excludes `sig`, `chain`, `observed` and `time`. `verify` checks detached statements against the shared signer registry (I9).

**Checkpoints and anchors.** A checkpoint is `aqt_evidence.make_checkpoint(log_id, seq, head)` signed by the service key and appended to `checkpoints.jsonl`. An **anchor** puts evidence of the head outside the writer's reach:
- *RFC 3161:* the message imprint is the 32-byte head hash itself (SHA-256), so a user can check a token independently with `openssl ts -verify -digest <head hex> -in token.tsr -CAfile tsa.pem`. The `trail.anchor` record stores the checkpoint, the DER token (base64), TSA URL, `genTime`, serial and the TSA certificate fingerprint.
- *External heads:* `head --export` prints the signed checkpoint; the user stores it anywhere. `verify --heads FILE` checks every stored head against the trail: missing seq → **truncated**, different hash → **rewritten**.
A full rewrite under a new key still "verifies" as a chain; the anchors and **key pinning** (`verify --pin-key`) are what detect it (the Sasana lesson in R3).

**RFC 3161 verification with `cryptography` only.** `cryptography` has no TSP/CMS verifier, so a small DER module parses `TimeStampResp → SignedData → TSTInfo` and checks: status granted; `messageImprint` equals the head; `messageDigest` signed attribute equals SHA-256 of the TSTInfo; the SignerInfo signature over the DER-encoded signed attributes verifies with the TSA certificate (RSA PKCS#1 v1.5 / ECDSA); the certificate has the `timeStamping` extended key usage; and it chains to the configured CA (`verify_directly_issued_by` walk, validity at `genTime`). No revocation checking (stated as a limit). Tests use an in-process **test TSA** built from the same DER module and a locally generated CA — no network.

**Gaps and honesty.** Three kinds of missing evidence are made visible instead of hidden: spooled records (`trail.gap` with window, count and the spool IDs, followed by the records with `observed.via = "spool"`); writer downtime (`trail.event` `service.start`/`service.stop`, so the window between them is known); and clock problems (`clock.jump` when wall-clock and monotonic time disagree by more than a threshold, `time` never decreasing). Events that happened while nothing was listening and no client spooled them are undetectable — said plainly in the README.

**Imports are retrospective.** An imported session event gets the writer's time (when it was recorded *in the trail*) and keeps its native timestamp in `data.source_time`. The ALCOA report counts them as *not contemporaneous* by design; hook events are near-contemporaneous. Idempotency: `data.source_hash` = SHA-256 of the native line (or hook payload); the importer skips hashes already in the trail. Events seen both by the hook and in the session file are different evidence and both kept; `data.tool_use_id` correlates them.

**Audit-trail review.** A review covers a **scope** (seq range, time range and the head hash at `to_seq`). The profile (TOML) selects queries and parameters. Each finding has an ID, query, severity (info / minor / major), the record IDs and a short explanation. Signing binds the worksheet hash, the profile hash and the scope head; it is refused if the trail at `to_seq` no longer has that head (stale worksheet). **Independence:** the reviewer's ID must not be the `actor.id` of any record in scope (writer and import service records excluded), the reviewer must be `kind: human`, and the signing process chain must not contain an agent harness; the signing process must pass `aqt_evidence.require_human` (I9); a refusal is recorded as `trail.refused` with `attempted_action: review.sign`. Each finding gets a disposition (I6): `ok`, `explained` or `deviation` (the last two need a note; `deviation` is what aqt-capa's `scan` picks up). Keys come from `--key` or the shared key directory and registry (`$XDG_CONFIG_HOME/aqt/keys/<slug>.key`, `signers.json`); revoked or unregistered keys of a registered reviewer are refused.

**Default risk queries** (profile `default`):

| Query | Flags | Basis |
|---|---|---|
| `self_approval` | `meaning` in approved/released/verified/reviewed by the same actor that authored the linked or same-subject record | four-eyes, R-06 |
| `missing_reason` | human records with `meaning` or decision-like `action` and no `reason` (spooled or pre-existing records can lack it) | R-03 |
| `attribution_mismatch` | claimed human but harness in observed chain; claimed agent session but no harness observed | R-02, s74 V02 |
| `gaps` | `trail.gap`, `observed.via = spool`, writer downtime, `log.repaired` | R-04, ALCOA complete |
| `out_of_hours` | human actions outside configured hours, weekdays and zone | R-06 |
| `repeated_failures` | ≥ N failed/refused/unknown outcomes by the same actor on the same action within a window | R-06 |
| `time_anomalies` | client/service skew above a threshold, `clock.jump` | ALCOA contemporaneous |
| `actor_changes` | the same `subject.ref` changed by different actors within a window | R-06 |
| `invalidated_signatures` | `signoff.invalidation` records | R-11 |
| `unanchored_head` | records since the last anchor older than the configured age | enduring |

"Failure" is read generically (`data.outcome` in failed/refused/unknown, `data.exit_code ≠ 0`, `action` ending in `.refused`) plus a small per-type map for known AQT types.

**ALCOA++ checks** (each result cites `alcoa:<attribute>` plus related clause IDs per I11, e.g. `annex11-2025d:12.2`, `part11:11.10(e)`):

| Attribute | Check |
|---|---|
| Attributable | `actor` present and conventional ID; `observed.via = socket`; no attribution mismatch |
| Legible | canonical JSON parses; `report` renders every record |
| Contemporaneous | skew client↔service within threshold; share of imported/spooled records stated |
| Original | chain intact and service signature valid |
| Accurate | client co-signatures valid; content hashes well-formed |
| Complete | no seq gaps; gap markers and downtime windows listed |
| Consistent | time non-decreasing; one log ID; one service key or recorded key changes |
| Enduring | age of last anchor; TSA token present and valid; external heads match |
| Available | an export bundle can be produced and re-verified (dry-run export) |
| Traceable | every `links[].ref` resolves inside the trail, or is listed as external |

### 2.2 Interfaces

**CLI** `aqt-trail` (argparse; `--json` everywhere; global `--state`, `--config`; exit 0 ok, 1 check failed / refused, 2 usage or runtime error):

| Command | Purpose |
|---|---|
| `init [--log-id ID]` | state dir, service key, example config |
| `serve [--socket PATH] [--foreground]` | run the writer; drains the spool at start and periodically |
| `status` | socket reachable, head seq/hash, spool count, last anchor age |
| `append [FILE\|-]` | send one or more records (JSON / JSONL); spool if down |
| `event --action A [--reason R] [--subject KIND:REF] [--data JSON]` | convenience `trail.event` |
| `hook claude-code` | read a hook payload from stdin, append `trail.import`; always exit 0 so the agent is never blocked (failures go to the spool and stderr) |
| `import {claude-code\|codex\|pi} PATH… [--dry-run]` | import session files; prints new / skipped counts |
| `checkpoint [--anchor] [--tsa URL]` | signed head; with `--anchor` an RFC 3161 token and a `trail.anchor` record |
| `head [--export]` | print head; `--export` prints the signed checkpoint |
| `verify [--trail FILE] [--key PEM…] [--pin-key PEM] [--heads FILE] [--tsa-ca PEM] [--bundle DIR]` | intact / broken from seq N; anchors; heads |
| `list [--since --until --actor --type --action --subject --session]` / `show ID` | search and view |
| `report --format md\|html [filters] [--out FILE]` | legible record view |
| `export --out DIR [--tar]` | bundle: `trail.jsonl`, `checkpoints.jsonl`, `keys/*.pub`, `MANIFEST.json` (SHA-256 per file), `VERIFY.md` |
| `alcoa [--since --until] [--format text\|md\|json]` | ALCOA++ report; exit 1 if any attribute fails |
| `review run --since T [--until T] [--profile NAME\|FILE]` | worksheet in `reviews/<id>/` |
| `review sign WORKSHEET --reviewer human:ID [--key PEM] --disposition F1=ok … [--note F2=…] --reason R` | prompts for the key passphrase (re-authentication), appends signed `trail.review` |
| `review list` | past reviews and their scopes |

**Python API** (small, documented): `TrailWriter(state, signer, log_id)`, `TrailClient(socket, spool)` (implements `aqt_evidence.Sink`), `verify_trail(path, *, keys, pin_key=None, heads=None, tsa_ca=None) -> TrailReport`, `import_claude_hook(payload)`, `import_file(kind, path) -> ImportResult`, `run_review(records, profile) -> Worksheet`, `sign_review(worksheet, reviewer, signer, dispositions, reason)`, `alcoa_report(records, …)`, `request_timestamp(url, digest)`, `verify_timestamp(token, digest, ca)`.

**Socket ops** (extends the aqt-spec protocol additively): `append` (fixed), `drain` (spooled records → one `trail.gap` then the records), `checkpoint` (signed head, optional RFC 3161 anchor or external-head note), `head`, `ping`. Commands that need the writer use the socket when it runs and open the writer directly (lock) when it does not.

**Record types and `data` payloads:**

| Type | `action` examples | `data` |
|---|---|---|
| `trail.event` | `service.start`, `service.stop`, `clock.jump`, `log.repaired`, user events | `{event-specific; service.start: version, config_sha256, key_id, log_id}` |
| `trail.gap` | `spool.drained` | `{reason, first_time, last_time, count, spool_ids: [...], source}` |
| `trail.refused` | `refused` | `{attempted_action, reason_code, agent_markers, message, attempted_sha256, attempted_id, attempted_type}` |
| `trail.import` | `prompt`, `tool.call`, `tool.result`, `session.start`, `session.end`, `stop`, `model.change`, `compaction`, `permission.mode` | `{source: {format, session, event_id, line}, source_hash, source_time, tool: {name, use_id, input_sha256, input_excerpt, output_sha256, is_error}, model, harness_version}` |
| `trail.anchor` | `rfc3161`, `external-head` | `{checkpoint, imprint, tsa: {url, token_b64, gen_time, serial, cert_sha256}}` |
| `trail.review` | `review.signed` (`meaning: reviewed`) | `{worksheet, log_id, scope: {from_seq, to_seq, head, since, until, …}, head, profile, profile_sha256, actors_reviewed, findings: [{id, query, severity, record_ids, disposition, note}], conclusion, signer_registered, signature}`; the statement's subject hash is the content hash of `data` without `signature` |

Import actors follow the suite convention `agent:<harness>:<session>` with `actor.agent` fields; `subject` is the session or the tool call. Excerpts are at most 160 characters (configurable, 0 disables), with obvious token patterns masked; full prompts and outputs are only hashed (R3 privacy note).

**Claude Code hook snippet** (`examples/claude-code-hooks.json`): `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Stop`, `SessionEnd` → `aqt-trail hook claude-code`. `SessionStart`/`SessionEnd` are added to the brief's list because they give the access log (R-07) for free.

### 2.3 Stack and method table

| Area | Choice | Why | Trade-offs | Alternative |
|---|---|---|---|---|
| Runtime | Python ≥ 3.11, stdlib + `aqt-spec` + `cryptography` | suite rule; one install | no async framework | — |
| Log store | one append-only canonical JSONL file, flock, fsync per record | readable with `jq`, verifiable in any language, matches aqt-spec | linear scans; no random access | SQLite index (rebuildable) when trails get large |
| Tamper evidence | linear hash chain + per-record Ed25519 + signed checkpoints | simple, already in `aqt_evidence` | no O(log n) inclusion proofs | C2SP tlog-tiles / Tessera (Go) if third parties need proofs |
| Service | `socketserver.ThreadingUnixStreamServer`, one lock around append | stdlib, enough for hooks | not a high-throughput server | systemd socket activation later |
| Attribution | `SO_PEERCRED` + `/proc/<pid>/stat` walk | observed, not claimed; no deps | Linux only (macOS: `LOCAL_PEERCRED` gives uid only → chain empty, documented) | eBPF/auditd: heavy, root |
| Time stamps | RFC 3161 request over `urllib`, DER via own ~200-line module | no new dependency; tokens checkable with `openssl ts` | hand-written ASN.1 needs care; no revocation | optional `rfc3161-client` (Apache-2.0) extra if the DER code proves fragile |
| Certificate chain | `cryptography` `verify_directly_issued_by`, EKU check | already a dependency | simple path only | `cryptography.x509.verification` once it supports timestamping EKU policies cleanly |
| Config | TOML (`tomllib`), XDG paths | suite rule | — | — |
| Reports | Markdown + HTML strings with `html.escape` | no template engine | plain look | — |
| Tests | pytest, temp state dirs, real Unix sockets in tmp, test TSA, synthetic session fixtures | offline, deterministic | `/proc` chain assertions are Linux-only (skipped elsewhere) | — |

### 2.4 QM mapping and threat model

**QM mapping** (R-IDs from R3 §2.2; clause numbers of the July 2025 drafts; "supports", never "meets"):

| Feature | Concept and clause | What the user still must do |
|---|---|---|
| Separate writer, observed attribution, service time | Annex 11 draft §12.1–12.2, Part 11 §11.10(e), ALCOA++ attributable/contemporaneous (R-01, R-02) | route all relevant tools and hooks to the writer |
| Reason required on human decisions | Annex 11 draft §12.2 reason prompt (R-03) | write meaningful reasons |
| Append-only chained log, refused writes logged, config hash and clock events | Annex 11 draft §12.3 locked trail, Part 11 §11.10(c) (R-04) | use separate-user mode; keep admin role apart |
| `list`, `export`, `report` | Annex 11 draft §12.4, §12.9; Part 11 §11.10(b) (R-05) | retain bundles per their retention policy |
| `review run/sign` with independence and signed record | Annex 11 draft §12.5–12.8 audit-trail review (R-06); ISO 9001:2015 9.1.3 analysis, 9.2 internal audit (by analogy) | define a review procedure and frequency; investigate findings |
| Session start/end from hooks | Annex 11 draft §11.9 access log (R-07) | — |
| `agent:<harness>:<session>` IDs, model per event | Annex 11 draft §11.1 unique identities; Ch.4 draft 4.24–4.25 AI-produced records; Annex 22 draft §10 model configuration (R-08, R-22, R-24) | keep the accountable human in the record (aqt-signoff) |
| RFC 3161 anchors with configurable TSA | Annex 11 draft §13.2 trusted services, eIDAS qualified time stamps (R-12) | choose a TSA (qualified if needed) |
| Signed review record, re-authentication by passphrase | Part 11 §11.50, §11.70; Annex 11 draft §13 | key custody |
| Export bundle with manifest and checksums | Annex 11 draft §16–17 archiving, checksum on transfer (R-20) | store and restore-test archives |
| `alcoa` | Ch.4 draft 4.63 ALCOA++, PIC/S PI 041-1 (R-21) | act on failures |
| Logs over the lifetime of the system | EU AI Act Art. 12, 19, 26(6) (R-27) | set retention |
| Findings → `deviation` disposition | ISO 9001:2015 10.2; Annex 11 draft §12.10 | aqt-capa or own CAPA process |

**Threat model.** Protection is against agents, not against the owner or root (s74 owner decision, kept).

| Adversary / event | User mode | Separate-user mode | Detected by |
|---|---|---|---|
| Agent edits, inserts, deletes or reorders records | possible | prevented (no write access) | `verify` (from seq N) |
| Agent truncates the tail / rolls back the file | possible | prevented | external heads, anchors |
| Agent rewrites the whole chain with the service key | possible (key readable) | prevented (key unreadable) | anchors, pinned key, external heads |
| Agent appends under a human's name | possible | possible | `attribution_mismatch` (observed chain) |
| Agent forges spool files | possible | possible | records marked `via=spool`, flagged in review |
| Agent disables its hooks or does not call the sink | possible | possible | not detectable by the trail alone; mitigated by session imports and the `SessionStart` hook config hash (later stage) |
| Agent in the `docker` group / sudo | root-equivalent | root-equivalent | only anchors made before the attack |
| Writer down | spool + gap marker | same | `trail.gap`, downtime windows |
| Local clock wrong | — | — | skew and `clock.jump`; TSA `genTime` |
| TSA compromised or unreachable | anchor missing / false | same | second anchor (external heads); review `unanchored_head` |

**Limits** stated in the README: tamper-evident, not tamper-proof; no protection against root; anchors protect only up to their time; Linux-first attribution; no revocation check for TSA certificates; native session formats are undocumented and change often (the original readers needed eight fixes in 18 days); Codex's SQLite history store is not yet imported; excerpts can still contain personal data.

### 2.5 Novelty and prior art

| Project (R3 §3–4) | What it does | Difference |
|---|---|---|
| Microsoft Agent Governance Toolkit (MIT) | policy, identity, Merkle audit log, AI Act/SOC 2 maps | logs in-process; no Annex 11/Part 11 semantics, no review workflow |
| Pipelock, asqav (Elastic-2.0), Aegis, halo-record, Capsule, Acta | signed/chained receipts, some with RFC 3161 | the agent side signs; no observed attribution, no gap semantics, no review; asqav's licence blocks reuse |
| Sello / "Notarized Agents" | receiver-side recording argument | closest in principle; aqt-trail adds OS-observed process chains, GxP semantics and review |
| agent-custody, Sasana, WitnessKit | chain-of-custody libraries | show why key pinning and anchors matter; no QM layer |
| Trillian Tessera, Rekor v2, C2SP | transparency logs, checkpoints, log/TSA split | stronger proofs for many parties; aqt-trail is a single-host QM tool and may export C2SP checkpoints later |
| eLabFTW (AGPL) | RFC 3161 and signatures in an ELN | same evidence pattern for lab records; idea only |
| Commercial LIMS/CDS audit-trail review | review in vendor systems | no open-source agent equivalent found |
| draft-mih-scitt-checkpointed-local-log | local log with checkpoints | similar mechanism; aqt-trail can align its checkpoint export later |

Honest summary: the cryptography is ordinary. New is the combination of **writer ≠ actor with observed process attribution**, **attribution-mismatch and other GxP risk queries**, a **signed, independence-enforced audit-trail review**, and an **ALCOA++ report**, all on an open record format.

---

## 3. Flexible roadmap

### 3.1 MVP slice (all "Must" items of the brief, built end to end)

Suggested order, each step usable on its own:

1. **Writer core:** `init`, `TrailWriter`, `serve`, `append`, `verify`. Check: a real Unix socket in a temp dir; the stored record carries service time, `observed` with the test process's pid/uid and a non-empty chain; tamper tests (edit, insert, delete, reorder, truncate, forged signature, wrong key, rewrite under a new key with `--pin-key`) each give the right "broken from seq N"; refusals (writer fields, missing reason) are logged as `trail.refused`.
2. **Spool and gaps:** writer stopped → `append` spools → writer starts → `trail.gap` then spooled records with `via=spool`; `service.start/stop` events.
3. **Anchors:** `checkpoint`, `head --export`, `verify --heads` (truncation, rewrite); RFC 3161 against the in-process test TSA, including a token for the wrong digest and a token from an untrusted CA being rejected.
4. **Importers:** hook snippet + `hook claude-code`; Claude, Codex rollout and pi files from synthetic fixtures; re-import adds nothing.
5. **Review and ALCOA:** `review run` on a synthetic trail with planted self-approval, missing reason, attribution mismatch, gap and out-of-hours events finds each; `review sign` succeeds for an independent reviewer and is refused (and logged) for an actor in scope or a stale worksheet; `alcoa` reports pass/fail per attribute.
6. **Export and report:** bundle re-verifies after copying elsewhere; HTML/Markdown render.
7. README (quick start, Mermaid, QM table, threat model, non-compliance statement), `docs/`, `examples/` (config, profile, hook snippet, separate-user script, systemd unit), CHANGELOG, NOTICE, CI file.

Done when one scripted run goes `init → serve → hook/import → checkpoint --anchor (test TSA) → review run → review sign → verify (intact) → alcoa → export`, and the tests pass offline.

### 3.2 Later stages

| Stage | Result | Decision (who, when) | Risk / response |
|---|---|---|---|
| Spec/signoff statement alignment | one statement field set across aqt-spec schema and aqt-signoff | lead | trail follows the aqt-spec schema today |
| Hook-config attestation | `SessionStart` records the hash of the agent's hook settings; review flags changes | builder, after MVP | settings paths differ per harness → per-harness map |
| SQLite index | fast `list`/review on large trails; rebuildable from JSONL | builder, when trails exceed ~100k records | index drift → always rebuildable, never evidence |
| Codex SQLite history | import the paginated store | lead, if Codex users need it | schema changes → read-only, version check |
| Key rotation and log segments | `key.rotated` events, sealed segments with their own heads | lead, before long-term use | verification across keys → keyring in bundle |
| Witness / C2SP export | cosigned checkpoints, signed-note format | lead, if third parties verify | spec churn → export only |
| in-toto / SCITT export | interoperable statements | lead, wave 3+ | fragmented drafts → optional extra |
| aqt-signoff registry | reviewer identities and revocation from aqt-signoff | lead with signoff builder | format coupling → read-only adapter |
| Review desk UI | browse findings, sign in a browser (with `ui-studio`) | owner | scope creep → after CLIs settle |
