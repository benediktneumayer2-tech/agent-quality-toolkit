# Thresholds file (`thresholds.json`, schema 0.1)

Written by `aqt-validate detector run` into the run directory; read by aqt-quarantine. The shared contract is INTERFACES I8; aqt-spec publishes it as `schemas/thresholds.schema.json`. All scores and thresholds are integers in parts per million (ppm, 0–1,000,000), per INTERFACES I7.

```json
{
  "aqt_thresholds": "0.1",
  "calibrated": true,
  "protocol": {"id": "web-guard-detectors-2026-10", "sha256": "sha256:..."}, "run": "rec_...",
  "configuration_hash": "sha256:...",
  "detectors": [{"id": "heuristics", "version": "1.0", "sha256": "sha256:..."}],
  "bands": [
    {"name": "warn", "fpr_target_ppm": 30000, "rule": "any", "thresholds": {"heuristics": 412000}},
    {"name": "hold", "fpr_target_ppm": 10000, "rule": {"at_least": 2},
     "thresholds": {"heuristics": 655000, "other": 870000}}
  ],
  "calibration": {"n": 400, "realised_fpr_ppm": {"warn": 27500, "hold": 5000}}
}
```

| Field | Meaning |
|---|---|
| `aqt_thresholds` | Schema version (string) |
| `calibrated` | `true` when produced by a validation run; hand-written defaults use `false` |
| `protocol` | Protocol id and SHA-256 the thresholds were calibrated under |
| `run` | The `validate.run` record id of the calibration run. aqt-quarantine treats the file as calibrated only when `run` is set and `calibration.n > 0` |
| `configuration_hash` | Hash of the detector configuration (ids, versions, adapters, model file hashes) |
| `detectors[]` | Detectors the thresholds apply to. `version` is the version that actually ran (a plug-in's own `version`, e.g. aqt-quarantine heuristics with its pattern-table hash); `sha256` is the model file hash when the protocol names one; `code_sha256` hashes a command detector's argv and script files, or a callable's module source |
| `bands[]` | Least to most severe. The most severe band that fires wins |
| `bands[].thresholds` | A detector fires for the band when its `score_ppm` is **strictly greater** than its threshold |
| `bands[].rule` | `"any"`: the band fires when any listed detector fires. `{"at_least": k}`: when at least k fire |
| `bands[].fpr_target_ppm` | The false-positive target used for calibration |
| `calibration` | Number of calibration benign items and the realised calibration FPR per band (ppm) |

The file's SHA-256 is stored in the `validate.report` record (`thresholds_sha256`) and in the qualification; the file names its run record, so the run record cannot carry the file hash itself. `aqt-validate check --thresholds FILE` fires `thresholds-changed` when the file in use differs. aqt-quarantine records the same hash with each decision.

How "any" thresholds are computed: each detector's score is ranked against its own calibration benign scores, and the fused rank is the maximum. The smallest rank level whose calibration FPR is within the target gives one threshold per detector, at that same level. A single detector reduces to the usual rule "smallest *t* with #(s > t) ≤ ⌊α·n⌋".
