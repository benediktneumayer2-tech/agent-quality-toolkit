# Changelog

## Unreleased

- Reports cite only catalogue IDs that exist: `annex22-2025d:6.2` and `annex22-2025d:10` instead of
  sub-clauses that the catalogue groups, and `iso9001-2015:7.1.5` instead of 7.1.5.1/7.1.5.2.

## 0.1.0 — 2026-10-21

First MVP.

- Statistics (standard library): exact Clopper–Pearson bounds (two- and one-sided), AUROC with ties, Fleiss' kappa, nearest-rank percentiles, minimum n for a zero-failure bound.
- Data: generic JSONL format, loaders for BIPIA, InjecAgent, LLMail-Inject exports and AgentDojo (ast), payload composition into benign hosts, session/goal-disjoint hash splits with an overlap check.
- Detector validation: protocol and lock, command/callable/plugin/score-file adapters, max-rank "any" and `at_least` band calibration, contamination registry, criteria with inconclusive detection, Markdown/HTML report, `thresholds.json` (shared schema, ppm).
- Reviewer qualification: seeded defects from fix commits, clean diffs and user defects; snapshot runner with cache and error accounting; location matching; detection, false-alarm, agreement and kappa metrics.
- Human-only qualification (`aqt_evidence.require_human`, refusals recorded) and `check` with configuration, thresholds, expiry and drift triggers.
- The configuration hash, thresholds file and report use the detector that actually runs: a plug-in's loaded version (a pinned protocol version must match), command/callable code hashes. `--json` works before or after the subcommand.
- Records: `validate.run`, `validate.report`, `validate.qualification`, `validate.requalification`, `validate.refused`.
