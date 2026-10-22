# Changelog

## 0.1.0 — 2026-10-21

First version of the Agent Quality Toolkit evidence model.

### Added
- Specification `spec/evidence-records-0.1.md`: envelope, canonical JSON, record and content hashes, record signatures and detached signed statements, chain, checkpoints, conformance levels L1–L3, sink and trail socket protocol (spool, idempotent appends, error codes), record-type registry, shared files, catalogue IDs, security considerations.
- JSON Schemas (draft 2020-12) for the envelope, `observed`, signed statements, checkpoints, the thresholds file, the signer registry and the `data` payload of all 46 registered record types; `schemas/registry.json`.
- 57 conformance test vectors in six categories with the RFC 8032 test keys.
- GxP catalogues (11 catalogues, 118 items) with `features.yaml` and the generated `crosswalk.md`.
- Library: `parse_record`/`parse_json` (strict parsing), `SocketSink` spooling (`spool`, `spool_path`, `last_spooled`, `spool_file`, `SinkUnavailable`, `ERROR_CODES`), `sign_statement`/`verify_statement`, `signer_from_seed`/`public_key_from_raw`, `conformance`, modules `schemas`, `catalogues` and `vectors`.
- CLI: `aqt-evidence conform` and `aqt-evidence vectors`.
- Wave-0 core (by the lead): records, canonical JSON, Ed25519 keys and signatures, chains, checkpoints, JSONL and socket sinks, `record_content_hash`, `iter_evidence`, agent-context check; CLI `validate`, `hash`, `verify`, `keygen`.

### Changed
- `SocketSink` now spools by default when the socket is unreachable (INTERFACES I3); pass `spool=False` for the earlier hard failure.

### Fixed
- GxP catalogues checked against the source texts on 2026-10-22 (eCFR, EudraLex, the July 2025 consultation drafts, OJ texts, ICH): corrected paraphrases and clause ranges (among others Chapter 4 draft 4.70 and 4.77, Annex 11 draft 3.1, 6.1 and 13.9, Annex 22 draft 8 and 9, Annex 11 (2011) 4.1 and 4.7), updated every `source` block, and added `verified` per item (`note` required when false). The ALCOA++ report in aqt-trail now cites only catalogue IDs that exist.
- A lone surrogate in a string now gives a validation problem (`CanonicalError`) instead of an uncaught `UnicodeEncodeError`.
