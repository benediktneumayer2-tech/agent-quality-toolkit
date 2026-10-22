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
| `verify [--pin-key PEM] [--key PEM…] [--heads FILE] [--tsa-ca PEM] [--test-tsa] [--bundle DIR] [--trail FILE]` | intact / broken from seq N, plus checkpoint, anchor, head and detached-signature problems |
| `list [filters]`, `show ID\|SEQ` | search and view; filters `--since --until --actor --type (prefix with *) --action --subject --session` |
| `report --format md\|html [--out FILE] [filters]` | legible record view |
| `export --out DIR [--tar]` | bundle with `MANIFEST.json` (SHA-256 per file), keys, signer registry, CA and `VERIFY.md` |
| `alcoa [--since --until] [--format text\|md\|json]` | ALCOA++ report; exit 1 when an attribute fails |
| `review run`, `review sign`, `review list` | see [review.md](review.md) |

## Socket protocol

One JSON request per connection; the client closes its write side and reads one JSON response.

| Request | Response |
|---|---|
| `{"op": "append", "record": {…}}` | `{"ok": true, "record": stored, "created": bool}` |
| `{"op": "drain", "records": [...], "source": "…"}` | `{"ok": true, "appended", "already_stored", "refused", "gap"}` |
| `{"op": "checkpoint", "anchor": bool, "export": bool, "tsa_url": "…"}` | `{"ok": true, "checkpoint", "anchor"}` |
| `{"op": "head"}`, `{"op": "ping"}` | head / version |

Errors: `{"ok": false, "code": "invalid_record|unauthorized|duplicate_id|unavailable|internal", "message"}`.
`aqt_evidence.SocketSink` and `aqt_trail.client.TrailClient` both speak it; the client spools to
`$XDG_STATE_HOME/aqt/spool/spool.jsonl` when the socket is unavailable.

## Records written by aqt-trail

| Type | `action` | `data` |
|---|---|---|
| `trail.event` | `service.start`, `service.stop`, `clock.jump`, `log.repaired`, or your own | event-specific (`service.start`: version, log id, key id, pid, socket, config hash) |
| `trail.gap` | `spool.drained` | `reason`, `count`, `first_time`, `last_time`, `spool_ids`, `source` |
| `trail.refused` | `refused` | `attempted_action`, `reason_code`, `agent_markers`, `message`, `attempted_sha256`, `attempted_id`, `attempted_type` |
| `trail.import` | `prompt`, `message`, `tool.call`, `tool.result`, `model.change`, `permission.mode`, `compaction`, `session.start`, `session.end`, `session.continued`, `turn.start`, `turn.end`, `rollback`, `stop` | `source {format, session, event_id}`, `source_hash`, `source_time`, `tool {name, use_id, input_sha256, input_excerpt, output_sha256, is_error}`, `prompt_sha256`, `prompt_excerpt`, `model`, … |
| `trail.anchor` | `rfc3161`, `external-head` | `checkpoint`, `imprint`, `tsa {url, token_b64, gen_time, serial, policy, cert_sha256}` |
| `trail.review` | `review.signed` | see [review.md](review.md) |

`observed` (writer-owned): `pid`, `uid`, `gid`, `process_chain` (nearest first), `processes`
(`{pid, comm, start_time}`), `harness`, `client_time`, `via` (`socket` or `spool`; spooled records carry no
pid/uid/gid because the sender was never observed). The writer's own records have no `via` but
`origin: writer`. `chain_complete: false` marks a chain with a process that had already exited.

## Importers

| Source | File | Identity |
|---|---|---|
| Claude Code hooks | hook JSON on stdin | `session_id` |
| Claude Code transcripts | `~/.claude/projects/<key>/<uuid>.jsonl` | `sessionId` only (never `session_id`); a transcript mixing sessions is refused |
| Codex rollouts | `~/.codex/sessions/YYYY/MM/DD/rollout-….jsonl` | `session_meta.id` (first line) |
| pi | pi v3 session JSONL | header `type=session`, `version=3` |

Files must be regular, owned by you, not symlinks, single-linked. A partly written last line is left for the next
import. Excerpts are at most `excerpt_chars` characters with obvious secrets masked (`sk-…`, `ghp_…`, `AKIA…`,
JWTs, `password=…`). Record ids are derived from the source time and the source hash, so re-sending is idempotent.

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
`verify`. `test:` uses a built-in authority whose CA lives in `<state>/test-tsa/` and is named TEST ONLY — use it
for demos and tests, never as evidence of time. Manual check against a real TSA (not part of the tests):

```sh
aqt-trail checkpoint --anchor --tsa https://your-tsa.example/tsr
aqt-trail show <anchor id> | python3 -c 'import json,sys,base64; r=json.load(sys.stdin); \
  open("token.der","wb").write(base64.b64decode(r["data"]["tsa"]["token_b64"])); print(r["data"]["imprint"][7:])'
openssl ts -verify -digest <printed hex> -in token.der -token_in -CAfile tsa-ca.pem
aqt-trail verify --tsa-ca tsa-ca.pem
```
