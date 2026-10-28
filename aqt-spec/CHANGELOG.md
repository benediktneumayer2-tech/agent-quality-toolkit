# Changelog

## Unreleased

### Added
- Sink discovery (spec §10.1): without `AQT_SINK`, `open_sink()` finds the aqt-trail writer socket at its
  default place (`[writer] socket` in `trail.toml`, `$XDG_RUNTIME_DIR/aqt/trail.sock`). An initialised trail
  whose writer is down gets the records through the spool; the fallback file is used only when no trail is
  found. `resolve_sink()` reports the route (`kind`, `target`, `source`, `writer`, `warning`).

### Changed
- `SocketSink` prints one warning per process on stderr when it spools.
- `evidence_sources()` also reads the spool, and finds the trail log under `AQT_TRAIL_STATE` or `[trail] state`.

### Fixed
- Registry aligned with what the 0.1 tools write: actions `signoff.action.prepared` `revise`,
  `signoff.invalidation` `content-changed`/`withdraw`, `sensei.budget` `set`, `validate.report` `issued`,
  `validate.qualification` `approve`/`reject`, `validate.requalification` `triggered`; meanings
  `quarantine.source.trusted` `rejected` (revocation) and `capa.action` `authored` (implementation).
- Payload schemas: `quarantine.source.trusted` `expires` is a calendar date (`common#/$defs/date`);
  `quarantine.delivered` accepts the modes `command` and `failed`, a null `session`, and lists `kind` and
  `decision`; a quarantine `source` may have a null `ref` or `domain`. Real aqt-quarantine records now pass
  `aqt-evidence conform` with payload checks.
- A test keeps the spec's registry table in step with `registry.json` (actions and meanings).
- Catalogues: Annex 22 draft items `annex22-2025d:3` (intended use), `:4` (acceptance criteria) and `:7` (test
  execution) added, checked against the July 2025 consultation draft (121 items). The undocumented `r3`
  cross-reference field was removed. A new test fails when any package cites a catalogue ID that does not exist.

## 0.1.0 — 2026-10-21

First version of the Agent Quality Toolkit evidence model.

### Added
- Specification `spec/evidence-records-0.1.md`: envelope, canonical JSON, record and content hashes, record signatures and detached signed statements, chain, checkpoints, conformance levels L1–L3, sink and trail socket protocol (spool, idempotent appends, error codes), record-type registry, shared files, catalogue IDs, security considerations.
- JSON Schemas (draft 2020-12) for the envelope, `observed`, signed statements, checkpoints, the thresholds file, the signer registry and the `data` payload of all 46 registered record types; `schemas/registry.json`.
- 57 conformance test vectors in six categories with the RFC 8032 test keys.
- GxP catalogues (11 catalogues, 118 items) with `features.yaml` and the generated `crosswalk.md`.
- Library: `parse_record`/`parse_json` (strict parsing), `SocketSink` spooling (`spool`, `spool_path`, `last_spooled`, `spool_file`, `SinkUnavailable`, `ERROR_CODES`), `sign_statement`/`verify_statement`, `signer_from_seed`/`public_key_from_raw`, `conformance`, modules `schemas`, `catalogues` and `vectors`.
- CLI: `aqt-evidence conform` and `aqt-evidence vectors`.
- Core: records, canonical JSON, Ed25519 keys and signatures, chains, checkpoints, JSONL and socket sinks, `record_content_hash`, `iter_evidence`, agent-context check; CLI `validate`, `hash`, `verify`, `keygen`.

### Changed
- `SocketSink` now spools by default when the socket is unreachable (spec §10.4); pass `spool=False` for the earlier hard failure.

### Fixed
- GxP catalogues checked against the source texts on 2026-10-22 (eCFR, EudraLex, the July 2025 consultation drafts, OJ texts, ICH): corrected paraphrases and clause ranges (among others Chapter 4 draft 4.70 and 4.77, Annex 11 draft 3.1, 6.1 and 13.9, Annex 22 draft 8 and 9, Annex 11 (2011) 4.1 and 4.7), updated every `source` block, and added `verified` per item (`note` required when false). The ALCOA++ report in aqt-trail now cites only catalogue IDs that exist.
- A lone surrogate in a string now gives a validation problem (`CanonicalError`) instead of an uncaught `UnicodeEncodeError`.
