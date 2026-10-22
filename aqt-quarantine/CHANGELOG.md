# Changelog

## Unreleased

- Fix: `init --id` no longer crashes when the key file exists (for example after `aqt-signoff init`). It reuses
  that key: an enrolled key is reported, an unenrolled one is enrolled after its passphrase unlocks it.
- Fix: the shipped thresholds files validate against aqt-spec's `thresholds.schema.json` (optional fields are left
  out instead of `null`; `calibrated: false`). A test checks the packaged default.
- Records conform to the aqt-spec payload schemas (the schemas were corrected in aqt-spec); a test writes every
  `quarantine.*` type and checks it with payload validation. `jsonschema` joins the `[test]` extra.
- README: the quick-start injection example is one that the shipped thresholds really hold.
- `examples/quarantine.toml`: the commented trail sink is the writer's default socket `$XDG_RUNTIME_DIR/aqt/trail.sock`.

## 0.1.0 — 2026-10-21

First MVP.

- Detector plugin interface `aqt_quarantine.detectors` (entry-point group `aqt.detectors`, scores in ppm),
  built-in heuristics (EN/DE, hidden and encoded text) and an optional ONNX detector (`[hf]` extra).
- Bands pass / warn / hold from an aqt-validate thresholds file (uncalibrated defaults shipped); fail closed on
  detector errors, unreadable thresholds and oversize text.
- Claude Code hooks: `PostToolUse` replaces results shape-preservingly; `UserPromptSubmit` delivers releases and
  threat notes.
- Generic `scan` filter.
- Signed human decisions (`release`, `trust-source`, `declare-threat`) with the agent-session guard; refusals
  recorded.
- Case files: `cases list | show [--html] | export`, `sources list`, `doctor`, `flush`.
- Records: `quarantine.passed`, `.held`, `.released`, `.source.trusted`, `.threat.declared`, `.refused`,
  `.delivered`.
