# aqt-trail

**A tamper-evident audit trail for AI coding agents, with an ALCOA++ report and an independent audit-trail review.**
Part of the Agent Quality Toolkit (AQT).

> Agent Quality Toolkit supports quality-management practices; it is not a validated system and does not by itself make any process compliant with GMP, GDP, 21 CFR Part 11 or EU Annex 11.

## The problem

Agent logs are usually files the agent itself can edit, or "signed" logs where the agent process signs its own
entries. Neither shows who really acted (a claimed actor is just a string), neither marks what is missing, and none
supports what a GMP quality manager cares about most: a documented, risk-based, independent **review** of the trail
(EU GMP Annex 11, 2025 draft §12.5, explicitly encourages tools for this).

aqt-trail applies audit-trail practice to agent work on a developer machine:

- **One writer, not the actors.** Tools, hooks and scripts send records to a small writer service over a Unix
  socket. The writer sets the time, the sequence and the **observed** attribution: the socket peer's pid, uid and
  gid from the kernel (`SO_PEERCRED`) and its process chain from `/proc`, for example
  `python3 ← bash ← claude`. A record that *claims* a human but was sent from inside an agent is kept and flagged.
- **Tamper-evident.** Records are hash-chained and signed by the writer. Editing, inserting, deleting or reordering
  anything breaks verification from that record on.
- **Anchored outside the writer's reach.** Signed head copies (`head --export`) and RFC 3161 time stamps over the
  head make truncation and full rewrites detectable.
- **Nothing silently lost.** When the writer is down, clients spool; the writer later writes a `trail.gap` marker
  and the spooled records, marked as *not observed*. Writer starts and stops, clock jumps and refused attempts are
  records too.
- **Importers** for Claude Code hooks and session files, Codex rollouts and pi sessions — hashes and short masked
  excerpts, never full texts; re-importing never duplicates.
- **ALCOA++ report** and an **audit-trail review** whose signer is enforced to be independent of the reviewed work.

## 60-second quick start

```sh
uv venv .venv && uv pip install --python .venv/bin/python -e ../aqt-spec -e .
export PATH=$PWD/.venv/bin:$PATH

aqt-trail init                                   # state dir + service key
aqt-trail serve &                                # the writer (Unix socket, 0600); as a service: examples/aqt-trail.service
export AQT_SINK=unix:$XDG_RUNTIME_DIR/aqt/trail.sock   # other AQT tools now write here

aqt-trail event --action release.decided --actor human:alice --reason "plan approved in review"
aqt-trail import claude-code tests/fixtures/claude-session.jsonl   # synthetic example
aqt-trail checkpoint --anchor --tsa test:        # TEST ONLY time-stamp authority, offline
aqt-trail head --export >> ~/trail-heads.jsonl   # keep head copies somewhere else, too

aqt-trail verify --test-tsa --heads ~/trail-heads.jsonl
aqt-trail alcoa --test-tsa                       # fails 'attributable' if an agent claimed to be alice
aqt-trail review run                             # writes a worksheet with findings
aqt-trail review sign <worksheet.json> --reviewer human:dora --key dora.key \
    --disposition all=ok --reason "weekly audit-trail review"
aqt-trail export --out trail-bundle              # self-contained copy with checksums
```

For Claude Code, merge [`examples/claude-code-hooks.json`](examples/claude-code-hooks.json) into your settings:
every prompt, tool call, tool result, stop and session start/end becomes a `trail.import` record. The hook never
blocks the agent (it always exits 0 and spools when the writer is down).

## How it works

```mermaid
flowchart LR
    subgraph Clients["Clients (you, your agents, AQT tools)"]
        T["AQT tools<br/>AQT_SINK=unix:…"]
        H["Claude Code hook"]
        I["aqt-trail import"]
    end
    SP[("shared spool")]
    subgraph Writer["aqt-trail serve"]
        S["Unix socket<br/>SO_PEERCRED"] --> W["validate → restamp → observe →<br/>chain → sign → fsync"]
    end
    L[("trail.jsonl<br/>checkpoints.jsonl")]
    TSA["RFC 3161 TSA"]
    X["head copies elsewhere"]
    T & H & I --> S
    T & H -. writer down .-> SP -. trail.gap .-> W
    W --> L
    W -- head hash --> TSA -- token --> W
    L -- head --export --> X
    L --> V["verify · alcoa · review · export"]
    X --> V
```

- **Records** follow the AQT evidence envelope (aqt-spec 0.1). Clients never send `sig`, `chain` or `observed`;
  the writer refuses such records (`invalid_record`) and records the attempt as `trail.refused`. The client's time
  moves to `observed.client_time`; `time` is the writer's. Appends are idempotent by record id.
- **Human signatures** (for example a signed review) travel as a detached statement in `data.signature`, so they
  survive chaining and re-signing.
- **Verification** recomputes every hash, checks the service signatures, checkpoints, external heads, RFC 3161
  tokens (imprint = the 32-byte head hash; signature, `timeStamping` usage and chain to your TSA CA) and detached
  signatures against the shared signer registry. A token can also be checked independently with
  `openssl ts -verify -digest <head hex> -in token.der -token_in -CAfile tsa-ca.pem`.

Details: [docs/usage.md](docs/usage.md) (commands, records, configuration),
[docs/review.md](docs/review.md) (risk queries and signing), [docs/separate-user.md](docs/separate-user.md).

## QM mapping

Designed along these concepts (clause numbers of the July 2025 drafts may change); "supports", never "meets".

| Feature | Concept and clause | What you still must do |
|---|---|---|
| Separate writer, observed peer attribution, writer time | Annex 11 (2025 draft) §12.1–12.2; 21 CFR 11.10(e); ALCOA++ attributable, contemporaneous | route your tools and hooks to the writer |
| Reason required on human decisions; refused attempts recorded | Annex 11 (2025 draft) §12.2 | give meaningful reasons |
| Append-only chained, signed log; writer start/stop, config hash and clock events | Annex 11 (2025 draft) §12.3; 21 CFR 11.10(c) | use separate-user mode; keep the admin role apart |
| `list`, `report`, `export` | Annex 11 (2025 draft) §12.4, §12.9; 21 CFR 11.10(b) | keep bundles per your retention rules |
| `review run` / `review sign` with enforced independence | Annex 11 (2025 draft) §12.5–12.8 | define review procedure and frequency; investigate findings |
| Session start/end from hooks | Annex 11 (2025 draft) §11.9 (access log) | — |
| Agent identity per session, model per event | EU GMP Ch. 4 (2025 draft) 4.24–4.25; Annex 22 (draft) §10 | keep the accountable human in the record (aqt-signoff) |
| RFC 3161 anchors with a configurable TSA | Annex 11 (2025 draft) §13.2 trusted services | choose a TSA (qualified if needed) |
| Export bundle with manifest checksums | Annex 11 (2025 draft) §16–17 | store and restore-test archives |
| `alcoa` with catalogue IDs `alcoa:*` | EU GMP Ch. 4 (2025 draft) 4.63 ALCOA++ | act on failures |
| Finding disposition `deviation` | ISO 9001:2015 10.2 | run CAPA (aqt-capa or your own) |

## Threat model and limits

Protection is against **agents**, not against the owner or root.

| Attack | User mode (default) | Separate-user mode | Detected by |
|---|---|---|---|
| Edit, insert, delete, reorder records | possible | prevented | `verify` (broken from seq N) |
| Truncate / roll back the log | possible | prevented | head copies, checkpoints, anchors |
| Rewrite everything under a new key | possible (key readable) | prevented | `--pin-key`, head copies, anchors |
| Append under a human's name | possible | possible | `attribution_mismatch` (observed process chain) |
| Forge spooled records | possible | possible | marked `via: spool`, flagged in review |
| Not calling the writer at all / disabling hooks | possible | possible | not by the trail alone; session imports help |
| Agent with root or `docker` group | anything | anything | only anchors made before the attack |

Limits: tamper-evident, not tamper-proof. Attribution needs Linux (`SO_PEERCRED`, `/proc`). No revocation
check for TSA certificates. The agent check before signing a review is a guard against agents deciding for
themselves, not a security boundary. Native session formats are undocumented and change often; Codex's
SQLite history store is not imported yet. Excerpts can still contain personal data (set `excerpt_chars = 0`).
The default socket lives in `$XDG_RUNTIME_DIR`, so one writer per user session. The writer refuses to continue
a log that no longer links; run `verify` and decide.

## Licence

Apache-2.0 (see `LICENSE`). Derived in part from the author's private Agent Platform Next (see `NOTICE`).
