# Changelog

## Unreleased

- Security fix: a signed decision acts only through its signed `data.decision`. A record whose unsigned fields
  (case id, content hash, overrule, domain, subdomains, expiry, action, subject) differ from it is `mismatch`
  and has no effect, so a signature can no longer be copied onto another case or domain, and a signed revocation
  can no longer be turned into a trust.
- Security fix: a signed statement counts once (later copies are reported as replays), and decisions take effect
  in signed order (`signed_at`), so replaying an old trust or release does not undo a later revocation or threat.
- Security fix: a signature made before its key was enrolled is `unknown-signer`, as in aqt-signoff; enrolment and
  revocation times are compared as timestamps.
- Security fix: `release` refuses to sign when the stored original no longer hashes to the case's content hash,
  and `cases show` does not display such a file. New API for front ends: `Decider.case_content(case_id)` returns
  `CaseContent(case_id, content_sha256, text, error)`, with `text` only when it hashes to `content_sha256`;
  `release()` and `declare_threat()` take `expected_sha256` and refuse when the case is not the one shown.
- Source decisions that are not honoured are kept in `Store.ignored_sources` and reported by `sources list`;
  a trust without a valid expiry date is not honoured.
- Security fix: a case is what its first opening record (`quarantine.held`, or `quarantine.passed` with a
  case id) says. A later opening record for the same case id no longer replaces it, so an appended line
  cannot change a case's band, evidence spans or excerpts. A malformed line (data not an object, no valid
  case id, evidence or source of the wrong shape, ...) is skipped instead of crashing every reader of the
  journal, so the hook no longer withholds all tool output because of one bad line. Skipped lines are
  listed in `Store.journal_problems` (`JournalProblem(line, record_id, case_id, message)`, journal text
  made inert) and reported on stderr by the commands that read cases and by the hook, and as a warning
  by `doctor`.
- `release` and `declare-threat` say before the passphrase prompt that the signature covers all N characters
  of the content (with its hash) and that `cases show CASE --full` shows all of it.
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
