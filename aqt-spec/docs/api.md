# `aqt_evidence` API

The 0.1.0 API is stable; later changes are additive and backwards compatible. Everything below is importable from `aqt_evidence` unless a module is named.

## Records

| Name | Purpose |
|---|---|
| `new_record(type, actor, action, *, subject, reason, meaning, before, after, links, data, tz, time)` | Create and validate a record (raises `ValueError` when invalid) |
| `actor(kind, id, *, role, display, harness, model, version, session)` | Build `actor`; agent details go into `actor.agent` |
| `subject(kind, ref, *, sha256)` | Build `subject` |
| `validate_record(record) -> list[str]` | Envelope check; empty list means valid |
| `record_hash(record)` | `sha256:` over the canonical record without `sig` (identity as stored) |
| `record_content_hash(record)` | `sha256:` without `sig`, `chain`, `observed`, `time` (use as `subject.sha256` when signing a record) |
| `new_id()`, `utc_now()`, `unsigned(record)` | Helpers |
| `SPEC_VERSION`, `ACTOR_KINDS`, `MEANINGS` | Constants |

## Canonical JSON and parsing

| Name | Purpose |
|---|---|
| `canonical_json(value) -> bytes` | AQT canonical JSON (raises `CanonicalError`) |
| `content_hash(value)`, `bytes_hash(data)`, `sha256_hex(data)` | Hashes |
| `parse_record(text)`, `parse_json(text)` | Strict parsing: rejects duplicate keys, floats, NaN, lone surrogates, invalid UTF-8 (`CanonicalError`). `read_jsonl` stays lenient; use `conformance.read_strict` for files |

## Keys and signatures

| Name | Purpose |
|---|---|
| `generate_key(path, *, passphrase)` | Write `path` (PKCS#8 PEM, 0600) and `path.pub`; returns the key ID |
| `load_signer(path, *, passphrase)`, `load_public_key(path)` | Load keys (`(key_id, public_key)` for public keys) |
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
| `verify_chain(records, *, keys, require_signature, start_prev, start_seq) -> ChainResult` | `ok`, `count`, `head_seq`, `head_hash`, `first_bad_seq`, `reason`, `warnings`, `summary()` |
| `make_checkpoint(*, log_id, seq, head, signer, time)`, `verify_checkpoint(cp, keys)`, `checkpoint_matches(cp, records)` | Signed heads |

## Sinks and reading

| Name | Purpose |
|---|---|
| `open_sink(spec=None)` | `AQT_SINK` → `JsonlSink` (`file:`) or `SocketSink` (`unix:`); default `$XDG_STATE_HOME/aqt/evidence.jsonl` |
| `JsonlSink(path).append(record)` | Locked, fsynced, mode 0600 |
| `SocketSink(path, *, timeout=5.0, spool=True, spool_path=None).append(record)` | aqt-trail client. When the socket is unreachable the record is spooled to `spool_file()` and `last_spooled` is `True`; `spool=False` raises `SinkUnavailable`. Refusals (`ok: false`) raise `SinkError` and are never spooled |
| `spool_file()`, `state_dir()` | `$XDG_STATE_HOME/aqt/spool/spool.jsonl`, `$XDG_STATE_HOME/aqt` |
| `ERROR_CODES` | `invalid_record`, `unauthorized`, `duplicate_id`, `unavailable`, `internal` |
| `read_jsonl(path)` | Yield records (lenient JSON) |
| `evidence_sources()`, `iter_evidence(paths=None)` | `AQT_EVIDENCE` or default sink + trail log, deduplicated by id |
| `SinkError`, `SinkUnavailable` | Errors (`SinkUnavailable` is a `SinkError`) |

## Human check

`detect_agent_context(environ=None, *, chain=None) -> AgentContext`, `require_human(...)` (raises `HumanCheckError`), `process_chain(pid=None)`. A guard, not a security boundary.

## Conformance

`conformance(records, level=1, *, keys=None, checkpoints=None, check_payloads=True, parse_problems=None) -> ConformanceResult` with `target`, `level` (highest reached), `ok`, `problems`, `warnings`, `payloads_checked`, `summary()`, `as_dict()`. `aqt_evidence.conformance.read_strict(path) -> (records, parse_problems)`.

## Schemas (`aqt_evidence.schemas`)

`registry()`, `registered_types()`, `is_registered(type)`, `load_schema(name)`, `schema_for(type)`, `schema_dir()`. Validation needs `jsonschema` (`[schema]` extra): `validate_schema(instance, name) -> list[str]`, `validate_payload(record) -> list[str]`. Names: `envelope`, `observed`, `signature`, `checkpoint`, `thresholds`, `signers`, `common`, or a record type.

## Catalogues (`aqt_evidence.catalogues`)

Standard library only: `load()`, `catalogue_ids()`, `item(id)`, `items(catalogue=None)`, `features()`, `supporting(feature)`, `ALCOA` (the ten attribute names).

## Vectors (`aqt_evidence.vectors`)

`vector_dir()`, `load_keys()`, `load_vectors()`, `run_vector(vector, keys) -> VectorResult`, `run_all(dir=None)`.

## CLI `aqt-evidence`

| Command | Purpose |
|---|---|
| `validate FILE` | Envelope check per record |
| `hash FILE` | Record ID and hash per line |
| `verify FILE [--key PEM]… [--require-signature] [--json]` | Chain and signatures |
| `keygen PATH [--passphrase]` | Ed25519 key pair |
| `conform FILE [--level 1\|2\|3] [--key PEM]… [--checkpoint FILE]… [--no-payloads] [--json]` | Highest conformance level reached |
| `vectors [DIR] [--json]` | Run the test vectors against this library |

Exit codes: 0 ok, 1 check failed, 2 usage or runtime error.
