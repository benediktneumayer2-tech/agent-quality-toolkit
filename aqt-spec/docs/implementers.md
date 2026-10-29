# Implementing Evidence Records in another language

You need: a JSON parser that can report duplicate keys and tell integers from floats, SHA-256, Ed25519 (RFC 8032) and Base64. An RFC 8785 (JCS) library helps but is not required.

## Steps

1. **Strict parsing** (spec §4). Reject duplicate keys, numbers with a fraction or exponent (also `1.0`), integers beyond ±(2^53 − 1), unpaired surrogates and invalid UTF-8. Use the strict parser everywhere you verify a log, not only for conformance (vectors `tampered/log-*`).
2. **Canonical form.** Sort keys (ASCII only), no whitespace, RFC 8785 string escaping, plain integers. Vectors `canonical/*` give the exact expected strings and hashes.
3. **Envelope validation** (spec §3). `schemas/envelope.schema.json` covers the structure. Strict parsing covers what JSON Schema cannot, and so must a date check (`2026-02-30` matches the pattern). Match patterns against the whole string: in some regex engines (Python's `re`) `$` also matches before a final newline.
4. **Hashes.** `record_hash` over the record without `sig`; `record_content_hash` also without `chain`, `observed` and `time`.
5. **Signatures.** Ed25519 over the same canonical bytes as the record hash; detached statements sign `canonical(statement)`. Key ID = `ed25519:` + first 16 hex of SHA-256(raw public key).
6. **Chains and checkpoints** (spec §7, §8). Report the first broken `seq` exactly as the vectors expect.

## Running the vectors

`vectors/index.json` lists every vector. Each file has:

| Member | Meaning |
|---|---|
| `kind` | `canonical`, `record`, `chain`, `log`, `checkpoint` or `statement` |
| `input` / `input_text` | Parsed input, or raw JSON text for parse-level cases |
| `pinned_keys` | Names from `vectors/keys.json` to trust (others count as unknown) |
| `expect` | Expected results (see below) |

Expectations by kind:

- `canonical`: `error` (true when strict parsing must fail), otherwise `canonical` (string) and `sha256`.
- `record`: `valid`; `schema_valid` when the envelope schema alone gives a definite answer (it can differ from `valid`, e.g. for floats); for valid records `record_hash`, `content_hash`, `canonical` and, if present, `signatures` as `[[key_id, true | false | null]]`.
- `chain`: `ok`, `first_bad_seq`, `require_signature`, and `head_seq`/`head_hash` when intact. Signatures required with no pinned key must give `ok: false`.
- `log`: `input_text` is a stored JSON-lines log. Parse each non-empty line strictly, stop at the first line that fails (`first_bad_line`, 1-based, else `null`), verify the chain of the lines before it with `require_signature`; `ok` is true only when every line parsed and the chain verified (then `head_hash`).
- `checkpoint`: `valid` (well formed as in `schemas/checkpoint.schema.json` and signed by a pinned key) and `matches` (record at `seq` has hash `head`).
- `statement`: `valid` (`true`, `false` or `null` for an unpinned key), and `target_matches` / `stored_target_matches` (does `record_content_hash` of the given record equal the statement's subject hash).

The Python reference runs them with `aqt-evidence vectors`; `src/aqt_evidence/vectors.py` (about 150 lines) is a readable model for your own runner.

## Test keys

`vectors/keys.json` holds the RFC 8032 §7.1 TEST 1 and TEST 2 seeds and public keys. They are public. Use them only in tests.
