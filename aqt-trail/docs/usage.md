# aqt-trail usage

## Commands

Every command accepts `--state DIR`, `--config FILE` and `--json`. Exit codes: 0 ok, 1 check failed or
refused, 2 usage or runtime error.

| Command | What it does |
|---|---|
| `init [--log-id ID]` | create the state directory, the service key (`keys/service.key`, unencrypted so the writer starts unattended, 0600) and `trail.json` |
| `serve` | run the writer; records `service.start` (version, key, config hash), drains the spool at start and every `drain_interval_s`, records `service.stop` on SIGTERM/SIGINT |
| `status` | writer running, head, spooled count, last anchor |
| `append [FILE\|-]` | send records (JSON object, array or JSON lines) |
| `event --action A [--reason R] [--subject KIND:REF] [--data JSON] [--actor ID]` | a `trail.event` |
| `hook claude-code` | one Claude Code hook payload from stdin → `trail.import`; always exits 0 |
| `import claude-code\|codex\|pi PATH… [--dry-run]` | import session files; already imported events are skipped |
| `checkpoint [--anchor] [--tsa URL]` | sign the head into `checkpoints.jsonl`; with `--anchor` also an RFC 3161 token in a `trail.anchor` record |
| `head [--export]` | print the head; `--export` prints a signed checkpoint (one JSON line) and notes it as `trail.anchor action=external-head` |
| `drain` | send spooled records now (through the socket when the writer runs) |
| `verify [--pin-key PEM] [--key PEM…] [--heads FILE] [--tsa-ca PEM] [--test-tsa] [--signers FILE] [--bundle DIR] [--trail FILE]` | intact / broken from seq N, plus checkpoint, anchor, head, review and detached-signature problems; warnings say which records no external head or CA-verified anchor covers and how many follow the newest checkpoint. With `--bundle` nothing inside the bundle is trusted: its keys are used only without `--pin-key` (with a warning), its `tsa-ca.pem` and `signers.json` never, its TEST ONLY CA only with `--test-tsa` |
| `list [filters]`, `show ID\|SEQ` | search and view; filters `--since --until --actor --type (prefix with *) --action --subject --session`; control and invisible characters a client wrote are shown escaped (`\x1b`) |
| `report --format md\|html [--out FILE] [filters]` | legible record view (client text escaped for Markdown and HTML) |
| `export --out DIR [--tar]` | bundle with `MANIFEST.json` (SHA-256 per file, not signed), keys, signer registry, CA and `VERIFY.md`; the copies are for convenience, not trust anchors |
| `alcoa [--since --until] [--format text\|md\|json] [--pin-key --key --heads --tsa-ca --test-tsa --signers]` | ALCOA++ report over the selection, with the verification of the whole trail (same trust options as `verify`); `original` and `complete` fail on chain, checkpoint, head or anchor problems; exit 1 when an attribute fails |
| `review run [--out DIR]`, `review sign`, `review list` | see [review.md](review.md) |

## Socket protocol

One JSON request per connection; the client closes its write side and reads one JSON response.

| Request | Response |
|---|---|
| `{"op": "append", "record": {…}}` | `{"ok": true, "record": stored, "created": bool}` |
| `{"op": "drain", "records": [...], "source": "…"}` | `{"ok": true, "appended", "already_stored", "refused", "gap"}` |
| `{"op": "checkpoint", "anchor": bool, "export": bool, "tsa_url": "…"}` | `{"ok": true, "checkpoint", "anchor"}`; `tsa_url` may only be empty, the configured `[anchor] tsa_url` or `test:` (the TEST ONLY authority in the writer's state directory); anything else is refused (`unauthorized`) |
| `{"op": "head"}`, `{"op": "ping"}` | head / version |

Errors: `{"ok": false, "code": "invalid_record|unauthorized|duplicate_id|unavailable|internal", "message"}`.
`unavailable` also means the writer could not undo a failed write (disk full, I/O error) and accepts no
records until it is restarted; a failed write is otherwise cut back, so nothing half-written or
unacknowledged stays in the log.

The writer refuses (`invalid_record`, recorded as `trail.refused`) client records that would pass for its own:
the actor `service:aqt-trail`, the types `trail.anchor` and `trail.gap`, and the actions `service.start`,
`service.stop`, `clock.jump` and `log.repaired`. Client `trail.review` records need a human actor and the
payload of `review sign` (`head`, `findings` with `query`, `severity`, `record_ids`, `disposition`, and a
detached `signature` with `statement.signer`, `statement.subject` and `key`); client `trail.refused` records need
`attempted_action`, `reason_code` and `agent_markers`. A drain stores each record id once: a repeat with the
same content counts as already stored, one with other content is refused (`duplicate_id`).
`aqt_evidence.SocketSink` and `aqt_trail.client.TrailClient` both speak it; the client spools to
`$XDG_STATE_HOME/aqt/spool/spool.jsonl` when the socket is unavailable.

## Records written by aqt-trail

| Type | `action` | `data` |
|---|---|---|
| `trail.event` | `service.start`, `service.stop`, `clock.jump`, `log.repaired`, or your own | event-specific (`service.start`: version, log id, key id, pid, socket, config hash) |
| `trail.gap` | `spool.drained` | `reason`, `count`, `first_time`, `last_time`, `spool_ids`, `source` |
| `trail.refused` | `refused` | `attempted_action`, `reason_code`, `agent_markers`, `message`, `attempted_sha256`, `attempted_id`, `attempted_type` |
| `trail.import` | `prompt`, `message`, `tool.call`, `tool.result`, `model.change`, `permission.mode`, `compaction`, `session.start`, `session.end`, `session.continued`, `turn.start`, `turn.end`, `rollback`, `stop` | `source {format, session, event_id}`, `source_hash`, `source_time`, `tool {name, use_id, input_sha256, input_excerpt, output_sha256, is_error}`, `prompt_sha256`, `prompt_excerpt`, `model`, … |
| `trail.anchor` | `rfc3161`, `external-head` | `checkpoint`, `imprint`, `tsa {url, token_b64, gen_time, serial, policy, cert_sha256}`; only anchors the writer wrote itself (`observed.origin: writer`) count, others are a `verify` problem |
| `trail.review` | `review.signed` | see [review.md](review.md) |

`observed` (writer-owned): `pid`, `uid`, `gid`, `process_chain` (nearest first), `processes`
(`{pid, comm, start_time}`), `harness`, `client_time`, `via` (`socket` or `spool`; spooled records carry no
pid/uid/gid because the sender was never observed), and `chain_status`, how far the observed chain goes:

| `chain_status` | When |
|---|---|
| `complete` | the chain was read up to init and nothing below applies |
| `partial` | an ancestor exited during the walk; more than 16 ancestors; a parent started after its child (pid reused); or a process belongs to a session whose leader is not among its ancestors, i.e. it was reparented to init or a subreaper such as the systemd user manager after its parent exited, so whoever started it is no longer visible |
| `unavailable` | no peer pid; the sender's own `/proc` entry could not be read; or the sender had exited before the walk ended (checked with `SO_PEERPIDFD`, Linux >= 6.5) |

`chain_detail` says why a chain is not `complete`; `chain_complete: false` (kept for older readers) marks a
walk that did not reach init. A missing agent marker means little unless the chain is `complete`, and even then
it is a heuristic: a process that detaches into a new session (`setsid`) or is started by a service manager or
an existing terminal server on an agent's request looks `complete`. The writer's own records have no `via` but
`origin: writer`. Records sent through the `drain` op carry `drained_by`, the observation of the client that
sent them; the `trail.gap` before them carries it as its own `observed`. The gap's `reason`,
`first_time` and `last_time` come from the spooled records, so they are the client's account.
Review and `alcoa` count a record that claims a human as attributed only with `complete` and no agent marker. Older records have no `chain_status`; there `chain_complete: false` marked a chain with a process that had already exited.

## Importers

| Source | File | Identity |
|---|---|---|
| Claude Code hooks | hook JSON on stdin | `session_id` |
| Claude Code transcripts | `~/.claude/projects/<key>/<uuid>.jsonl` | `sessionId` only (never `session_id`); a transcript mixing sessions is refused |
| Codex rollouts | `~/.codex/sessions/YYYY/MM/DD/rollout-….jsonl` | `session_meta.id` (first line) |
| pi | pi v3 session JSONL | header `type=session`, `version=3` |

Files must be regular, owned by you, not symlinks, single-linked. A partly written last line is left for the next
import. Excerpts are at most `excerpt_chars` characters with obvious secrets masked: assignments, `--flag value`
pairs and JSON fields whose name contains password, passphrase, secret, token, api-key, access-key, private-key or
credential (`DB_PASSWORD=…`, `GITHUB_TOKEN=…`, `"password": "…"`, `--password …`), `Authorization:` headers and
bearer tokens, passwords in URLs and `curl -u`, PEM private keys, and token formats such as `sk-…`, `gh?_…`,
`github_pat_…`, `glpat-…`, `hf_…`, `AKIA…`, `xox?-…`, `AIza…`, `npm_…`, `pypi-…`, Stripe keys and JWTs. Masking is a
safety net, not a guarantee, and the log cannot be redacted later: set `excerpt_chars = 0` to keep no excerpts. Record ids are derived from the source time and the source hash, so re-sending is idempotent.

## Configuration

See [`examples/trail.toml`](../examples/trail.toml). Paths: state `$AQT_TRAIL_STATE` or
`$XDG_STATE_HOME/aqt/trail`; config `$XDG_CONFIG_HOME/aqt/trail.toml`; socket from `[writer] socket`,
`AQT_SINK=unix:…`, `$XDG_RUNTIME_DIR/aqt/trail.sock`, or `<state>/aqt-trail.sock`, in that order.
AF_UNIX paths are limited to about 104 bytes. Signer registry `$AQT_SIGNERS` or `$XDG_CONFIG_HOME/aqt/signers.json`;
reviewer keys in `$AQT_KEYS_DIR` or `$XDG_CONFIG_HOME/aqt/keys/`.

To run the writer as a systemd **user** service, copy [`examples/aqt-trail.service`](../examples/aqt-trail.service)
to `~/.config/systemd/user/`, set `ExecStart` to your `aqt-trail`, then
`systemctl --user daemon-reload && systemctl --user enable --now aqt-trail`. Separate-user mode has its own system
unit, [`examples/aqt-trail-system.service`](../examples/aqt-trail-system.service); see
[separate-user.md](separate-user.md).

## RFC 3161

`[anchor] tsa_url` names a TSA you trust; only the 32-byte head hash leaves the machine. `tsa_ca` is used by
`verify`; every issuer on the path to it must be a CA certificate (`basicConstraints cA`, `keyCertSign`, path
length), and the TSA certificate must carry `timeStamping` as its only, critical extended key usage. Use your TSA's
own CA, not a broad root. `test:` uses a built-in authority whose CA lives in `<state>/test-tsa/` and is named TEST
ONLY — use it for demos and tests, never as evidence of time. Manual check against a real TSA (not part of the tests):

```sh
aqt-trail checkpoint --anchor --tsa https://your-tsa.example/tsr
aqt-trail show <anchor id> | python3 -c 'import json,sys,base64; r=json.load(sys.stdin); \
  open("token.der","wb").write(base64.b64decode(r["data"]["tsa"]["token_b64"])); print(r["data"]["imprint"][7:])'
openssl ts -verify -digest <printed hex> -in token.der -token_in -CAfile tsa-ca.pem
aqt-trail verify --tsa-ca tsa-ca.pem
```
