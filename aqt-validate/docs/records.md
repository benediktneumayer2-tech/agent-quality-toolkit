# Evidence records written by aqt-validate

All records follow aqt-spec 0.1 and go to `aqt_evidence.open_sink()` (`AQT_SINK`: `file:` or `unix:` for aqt-trail). Numbers are integers: rates and bounds in ppm, durations in ms. Rate objects look like `{"k", "n", "rate_ppm", "lo_ppm", "hi_ppm", "lower1_ppm", "upper1_ppm"}`. `lo/hi` are the two-sided Clopper–Pearson interval; `lower1/upper1` are the one-sided bounds at the protocol's confidence.

| Type | Action | Actor | Main `data` fields |
|---|---|---|---|
| `validate.run` | `protocol-locked` | invoker; `reason` given | `kind`, `protocol {id, sha256}`, `subject_id`, `configuration_hash`, `criteria` (count) |
| `validate.run` | `completed` | invoker | `kind`, `protocol`, `subject_id`, `configuration_hash`, `datasets [{name, sha256, items}]`, `data_sha256`, `split_read` (`dev`/`test`), `test_readouts`, `results_sha256`, `conclusion`, `headline`, `errors`, `run_id`; link `protocol-lock` |
| `validate.report` | `issued` | invoker; subject = report.md hash | `run`, `conclusion` (`meets`/`does-not-meet`/`inconclusive`), `criteria [...]`, `deviations [...]`, `configuration_hash`, `thresholds_sha256` (detector), `html_sha256` |
| `validate.qualification` | `approve` / `reject` | human only; `meaning` approved/rejected; `reason` | `configuration_hash`, `valid_until` (INTERFACES I6), `valid_from`, `kind`, `subject_id`, `report`, `run`, `conclusion`, `decision`, `triggers`, `accepted_deviation`, `thresholds_sha256` and `expected_fpr_upper_ppm` (detector) |
| `validate.requalification` | `triggered` | invoker | `configuration_hash` (current), `valid_until`, `trigger` (first fired; I6), `fired [{trigger, detail}]`, `qualification`, `configuration_hash_qualified` |
| `validate.refused` | `refused` | the claimed (invoking) actor | `attempted_action` (`qualify`), `reason_code` (`agent-context` / `no-terminal`), `agent_markers` (I5) |

Triggers: `configuration-changed`, `thresholds-changed`, `expired`, `drift`. One requalification record is written per qualification and set of triggers; later checks still exit 1 until a new qualification exists.

Reading records: commands take `--evidence PATH` (repeatable); the default is `AQT_EVIDENCE` or the default sink file plus the aqt-trail log (INTERFACES I4).
