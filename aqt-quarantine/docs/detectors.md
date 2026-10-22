# Detectors and thresholds

## Plugin interface (shared with aqt-validate)

```python
from aqt_quarantine.detectors import DetectorResult, Span

class MyDetector:
    name = "my-detector"          # the id used in the thresholds file
    version = "1.2.0"             # recorded with every scan

    def __init__(self, **options):  # options come from the [[detectors]] table
        ...

    def score(self, text: str) -> DetectorResult:
        return DetectorResult(score_ppm=123_456, spans=[Span(10, 42, "override", "why this matched")])
```

The contract:

- `score_ppm` is an integer from 0 to 1,000,000, and higher means more suspicious.
- Each `Span(start, end, label, reason)` indexes the `text` that was passed in.
- Anything off-contract is a detector error, and a detector error holds the content (fail closed). That covers a float score, an out-of-range span or an exception.

There are three ways to make a detector available:

1. **Entry point (installed package):** in `pyproject.toml`,

   ```toml
   [project.entry-points."aqt.detectors"]
   my-detector = "my_package.detect:MyDetector"
   ```

   Then use `[[detectors]] kind = "my-detector"`.
2. **Import path:** `[[detectors]] kind = "my_package.detect:MyDetector"`.
3. **Built-ins:** `heuristics` and `onnx`.

`aqt_quarantine.detectors` imports only the standard library, so aqt-validate can load detectors without the evidence or crypto stack. `aqt_quarantine.detectors.available()` lists the loadable kinds, and `load_detector(kind, **options)` creates one.

## Built-in heuristics

The heuristics are explainable regular-expression pattern groups in English and German:

- `override`, `addressed`, `framing`, `toolcall`, `exfil`, `secret`;
- plus `hidden`: Unicode tag characters (decoded), three or more zero-width or bidi characters, HTML comments and CSS-hidden text;
- plus `encoded`: base64 blobs whose decoded text matches a group.

The score is a noisy-OR of the per-hit weights. **It is uncalibrated and easy to evade**; treat it as a triage signal and calibrate it with aqt-validate. The version string contains a hash of the pattern table, so any change of patterns or weights shows up in the records.

## ONNX detector (`pip install 'aqt-quarantine[hf]'`)

The ONNX detector loads a local export (`model.onnx` and `tokenizer.json`) of a sequence-classification model, for example Horizon prompt-injection-guard, Wolf Defender, PIGuard or deepset deberta-v3-base-injection. Nothing is downloaded; check each model's licence and card. The text is split into overlapping token windows, and the score is the highest positive-class probability, in ppm. Each call loads the model, which costs seconds on CPU; a persistent detector service is on the roadmap.

## Thresholds file

The format is defined by aqt-validate (its `Design.md` §2.2), with ppm values:

```json
{"aqt_thresholds": "0.1", "protocol": {"id": "...", "sha256": "sha256:..."}, "run": "rec_...",
 "detectors": [{"id": "heuristics", "version": "..."}],
 "bands": [{"name": "warn", "fpr_target_ppm": 30000, "rule": "any", "thresholds": {"heuristics": "412000"}},
           {"name": "hold", "fpr_target_ppm": 10000, "rule": {"at_least": 1}, "thresholds": {"heuristics": 655000}}],
 "calibration": {"n": 300, "realised_fpr_ppm": {"warn": 26000, "hold": 9000}}}
```

How the bands are applied:

- A band fires when a score is **strictly greater** than its threshold.
- `rule` is either `"any"` or `{"at_least": k}`, the number of detectors that must exceed their own threshold.
- Hold is checked before warn.
- The file counts as calibrated when it names a `run` and `calibration.n > 0`. Otherwise `doctor`, `cases show` and every record say *uncalibrated*.
- Every record carries the file's SHA-256, so a threshold change is visible in the evidence.
