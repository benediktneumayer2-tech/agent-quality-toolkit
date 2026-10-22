# Changelog

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
