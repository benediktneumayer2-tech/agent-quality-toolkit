# `aqt_evidence` API

The 0.1.0 API is stable; later changes are additive and backwards compatible. Everything below is importable from `aqt_evidence` unless a module is named.

## Records

| Name | Purpose |
|---|---|
| `new_record(type, actor, action, *, subject, reason, meaning, before, after, links, data, tz, time)` | Create and validate a record (raises `ValueError` when invalid) |
| `actor(kind, id, *, role, display, harness, model, version, session)` | Build `actor`; agent details go into `actor.agent` |
| `subject(kind, ref, *, sha256)` | Build `subject` |
| `validate_record(record) -> list[str]` | Envelope check with the types of `envelope.schema.json` (`null` is not a value for optional members), whole-string patterns, real dates; empty list means valid |
| `record_hash(record)` | `sha256:` over the canonical record without `sig` (identity as stored) |
| `record_content_hash(record)` | `sha256:` without `sig`, `chain`, `observed`, `time` (use as `subject.sha256` when signing a record) |
| `new_id()`, `utc_now()`, `unsigned(record)` | Helpers |
| `SPEC_VERSION`, `ACTOR_KINDS`, `MEANINGS` | Constants |

## Canonical JSON and parsing

| Name | Purpose |
|---|---|
| `canonical_json(value) -> bytes` | AQT canonical JSON (raises `CanonicalError`) |
| `content_hash(value)`, `bytes_hash(data)`, `sha256_hex(data)` | Hashes |
| `parse_record(text)`, `parse_json(text)` | Strict parsing: rejects duplicate keys, floats, NaN, lone surrogates, invalid UTF-8, nesting too deep for the parser (`CanonicalError`) |
| `parse_canonical_line(line)` | For log verifiers: `parse_record`, and the line (without one final `\n`) must be exactly the canonical form (`CanonicalError`). `read_jsonl(path, strict=True)` applies it to a file |

## Keys and signatures

| Name | Purpose |
|---|---|
| `generate_key(path, *, passphrase)` | Write `path` (0600; with a passphrase the AQT key format: scrypt + AES-256-GCM, else unencrypted PKCS#8 PEM) and `path.pub`; returns the key ID |
| `load_signer(path, *, passphrase)`, `load_public_key(path)` | Load keys, AQT key format or PKCS#8 (`(key_id, public_key)` for public keys) |
| `crypto.key_file_format(path)`, `crypto.upgrade_key(path, passphrase)` | `aqt-key`, `pkcs8-encrypted` or `pkcs8`; re-encrypt an earlier PKCS#8 key in the AQT key format |
| `signer_from_seed(seed)`, `public_key_from_raw(raw)` | Keys from raw bytes (test vectors, fixtures) |
| `key_id(public_key)`, `Signer` | Key IDs and the signer object |
| `sign_record(record, signer)` | Append an envelope signature to `sig` (the writer's signature) |
| `verify_record_signatures(record, keys) -> [(key_id, True/False/None)]` | `None` = key not pinned |
| `sign_statement(statement, signer)` | Detached signed statement `{statement, alg, key, value}` for `data.signature` |
| `verify_statement(signed, keys) -> True/False/None` | Check a detached statement against pinned keys |

## Chains and checkpoints

| Name | Purpose |
|---|---|
| `link(record, *, seq, prev)`, `GENESIS` | Place a record in a chain (drops old signatures) |
| `verify_chain(records, *, keys, require_signature, start_prev, start_seq) -> ChainResult` | `ok`, `count`, `head_seq`, `head_hash`, `first_bad_seq`, `reason`, `warnings`, `summary()`. `require_signature=True` without `keys` fails (it never checks nothing) |
| `make_checkpoint(*, log_id, seq, head, signer, time)`, `verify_checkpoint(cp, keys)`, `checkpoint_matches(cp, records)` | Signed heads. `verify_checkpoint` is `False` for anything that is not a well-formed checkpoint (`checkpoint_problems(cp)` lists why) |

## Sinks and reading

| Name | Purpose |
|---|---|
| `open_sink(spec=None)` | `spec`, else the route of `resolve_sink()`: `JsonlSink` (`file:`) or `SocketSink` (`unix:`). Pings only when that decides the route |
| `resolve_sink(environ=None) -> dict` | Where records go: `kind` (`file`/`unix`), `target` (path), `source` (`env` = `AQT_SINK`, `discovered` = aqt-trail socket, `default` = fallback file), `writer` (a ping was answered: `True`/`False`; `None` when not asked) and `warning` (`None` or why records may be missing from the trail). Order: `AQT_SINK`; the default aqt-trail socket when a writer answers or a trail is initialised (spooled while the writer is down); `$XDG_STATE_HOME/aqt/evidence.jsonl`. Raises `SinkError` for a malformed `AQT_SINK` (spec §10.1) |
| `JsonlSink(path).append(record)` | Locked, fsynced, mode 0600 |
| `SocketSink(path, *, timeout=5.0, spool=True, spool_path=None).append(record)` | aqt-trail client. When the socket is unreachable the record is spooled to `spool_file()` and `last_spooled` is `True`; `spool=False` raises `SinkUnavailable`. Spooling prints one warning per process on stderr. Refusals (`ok: false`) raise `SinkError` and are never spooled |
| `spool_file()`, `state_dir()` | `$XDG_STATE_HOME/aqt/spool/spool.jsonl`, `$XDG_STATE_HOME/aqt` |
| `ERROR_CODES` | `invalid_record`, `unauthorized`, `duplicate_id`, `unavailable`, `internal` |
| `read_jsonl(path, *, strict=False)` | Yield records; lenient JSON for consumers, `strict=True` (canonical lines, `parse_canonical_line`) for verifiers. A bad line raises `RecordLineError` (a `SinkError` with `path`, `line`, `reason`) |
| `evidence_sources(environ=None)`, `iter_evidence(paths=None, *, conflicts=None)` | `AQT_EVIDENCE`, or the trail log, the sink file and the spool; deduplicated by id. Trail logs (`trail.jsonl`) are read first whatever the order of `paths`; a later copy of an id with other content is not used and is reported as `{id, kept, dropped}` in `conflicts` (or once on stderr) |
| `SinkError`, `SinkUnavailable`, `RecordLineError` | Errors (both are `SinkError`s) |

## Human check

`detect_agent_context(environ=None, *, chain=None) -> AgentContext`, `require_human(...)` (raises `HumanCheckError`), `process_chain(pid=None)`. A guard, not a security boundary.

## Conformance

`conformance(records, level=1, *, keys=None, checkpoints=None, check_payloads=True, parse_problems=None) -> ConformanceResult` with `target`, `level` (highest reached), `ok`, `problems`, `warnings`, `payloads_checked`, `anchored_seq` and `unanchored` (L3: the newest matching checkpoint's seq and the number of records after it), `summary()`, `as_dict()`. L1 also applies the envelope schema when `jsonschema` is installed. `aqt_evidence.conformance.read_strict(path) -> (records, parse_problems)`.

## Schemas (`aqt_evidence.schemas`)

`registry()`, `registered_types()`, `is_registered(type)`, `load_schema(name)`, `schema_for(type)`, `schema_dir()`. Validation needs `jsonschema` (`[schema]` extra): `validate_schema(instance, name) -> list[str]`, `validate_payload(record) -> list[str]`. Names: `envelope`, `observed`, `signature`, `checkpoint`, `thresholds`, `signers`, `common`, or a record type.

## Catalogues (`aqt_evidence.catalogues`)

Standard library only: `load()`, `catalogue_ids()`, `item(id)`, `items(catalogue=None)`, `features()`, `supporting(feature)`, `ALCOA` (the ten attribute names).

## Vectors (`aqt_evidence.vectors`)

`vector_dir()`, `load_keys()`, `load_vectors()`, `run_vector(vector, keys) -> VectorResult`, `run_all(dir=None)`.

## CLI `aqt-evidence`

| Command | Purpose |
|---|---|
| `validate FILE` | Strict parse and envelope check per record |
| `hash FILE` | Record ID and hash per line |
| `verify FILE [--key PEM]… [--require-signature] [--json]` | Canonical lines (strict), chain and signatures; `--require-signature` needs `--key` |
| `keygen PATH [--passphrase]` | Ed25519 key pair |
| `conform FILE [--level 1\|2\|3] [--key PEM]… [--checkpoint FILE]… [--no-payloads] [--json]` | Highest conformance level reached |
| `vectors [DIR] [--json]` | Run the test vectors against this library |

Exit codes: 0 ok, 1 check failed, 2 usage or runtime error.
