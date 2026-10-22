# Validation report: aqt-demo-heuristics

Detector validation. Conclusion: MEETS (split read: test; confidence 95%).

Agent Quality Toolkit supports quality-management practices; it is not a validated system and does not by itself make any process compliant with GMP, GDP, 21 CFR Part 11 or EU Annex 11.

## 1. Intended use

DEMO: triage of synthetic web results before a coding agent reads them.

## 2. Configuration under test

| Detector | Version (as loaded) | Model SHA-256 | Code SHA-256 |
|---|---|---|---|
| heuristics | 0.1.0+9fa4d49f402b | – | – |

- Subject: aqt-quarantine heuristics
- Protocol: detector.toml (sha256:0da8f47a46d0f4512d77e0ab1ceeed05519069b95076dd12701a7ad4bdfc245b)
- Protocol lock record: rec_01a1649d36a0f75a35b6adbb19c1
- Configuration hash: sha256:dac1df7102b15c21423d3fc08fef90859697d67a4caeb34f361927aad3656b00
- Run record: rec_01a1649d37220c3d04e5696ff714
- Thresholds file: thresholds.json (names run record rec_01a1649d37220c3d04e5696ff714)
- Run: 20261022T171627Z-79c8e2

## 3. Data

| Dataset | SHA-256 | Items |
|---|---|---|
| benign.jsonl | sha256:fbd6befb85e9146d2340c94725a39727e8105b5cb446757b17d234cc41c6d630 | 760 |
| attacks.jsonl | sha256:8cad03e31a094cae2aee216236c1279565aaee4ae923c8534b4fdd3db8c0507e | 96 |

- Calibration benign: 398; held-out benign: 362 (hard: 29); attacks read (test): 68 (0 contaminated)
- Split salt: demo; overlaps: goal_overlap=0, payload_overlap=15, attack_host_in_calib=0
- Test readouts of this data (including this one): 1
- Items not scored (errors): 0

## 4. Acceptance criteria and results

| ID | Metric | Scope | Bound | Target | Value used | Observed (95% CI) | Result |
|---|---|---|---|---|---|---|---|
| C1 | tpr | band=warn | lower | >= 60.00 % | 95.69 % | 68/68 = 100.0 % [94.7 %, 100.0 %] | PASS |
| C2 | fpr | band=hold, split=heldout | upper | <= 3.00 % | 0.82 % | 0/362 = 0.0 % [0.0 %, 1.0 %] | PASS |
| E0 | errors | – | point | <= 0 | 0 | 0 | PASS |

## 5. Results by band

### Band warn (target FPR 3.00 %, rule any)

| Detector | Threshold (ppm) |
|---|---|
| heuristics | 80000 |

| Measure | Rate [95% two-sided CI] | One-sided bound |
|---|---|---|
| FPR calibration benign | 8/398 = 2.0 % [0.9 %, 3.9 %] | 3.60 % |
| FPR held-out benign | 4/362 = 1.1 % [0.3 %, 2.8 %] | 2.51 % |
| FPR hard benign (held-out) | 4/29 = 13.8 % [3.9 %, 31.7 %] | 28.84 % |
| Detection, all clean attacks | 68/68 = 100.0 % [94.7 %, 100.0 %] | 95.69 % |
| Detection, family demo-0 | 20/20 = 100.0 % [83.2 %, 100.0 %] | 86.09 % |
| Detection, family demo-1 | 17/17 = 100.0 % [80.5 %, 100.0 %] | 83.84 % |
| Detection, family demo-2 | 15/15 = 100.0 % [78.2 %, 100.0 %] | 81.90 % |
| Detection, family demo-3 | 16/16 = 100.0 % [79.4 %, 100.0 %] | 82.92 % |
| Detection, category agent_action | 68/68 = 100.0 % [94.7 %, 100.0 %] | 95.69 % |

### Band hold (target FPR 1.00 %, rule any)

| Detector | Threshold (ppm) |
|---|---|
| heuristics | 150000 |

| Measure | Rate [95% two-sided CI] | One-sided bound |
|---|---|---|
| FPR calibration benign | 0/398 = 0.0 % [0.0 %, 0.9 %] | 0.75 % |
| FPR held-out benign | 0/362 = 0.0 % [0.0 %, 1.0 %] | 0.82 % |
| FPR hard benign (held-out) | 0/29 = 0.0 % [0.0 %, 11.9 %] | 9.81 % |
| Detection, all clean attacks | 68/68 = 100.0 % [94.7 %, 100.0 %] | 95.69 % |
| Detection, family demo-0 | 20/20 = 100.0 % [83.2 %, 100.0 %] | 86.09 % |
| Detection, family demo-1 | 17/17 = 100.0 % [80.5 %, 100.0 %] | 83.84 % |
| Detection, family demo-2 | 15/15 = 100.0 % [78.2 %, 100.0 %] | 81.90 % |
| Detection, family demo-3 | 16/16 = 100.0 % [79.4 %, 100.0 %] | 82.92 % |
| Detection, category agent_action | 68/68 = 100.0 % [94.7 %, 100.0 %] | 95.69 % |

## 6. Separation and latency

| Score | AUROC (held-out benign vs clean attacks) |
|---|---|
| fused | 1.000 |
| heuristics | 1.000 |

| Detector | p50 ms | p95 ms | max ms | n |
|---|---|---|---|---|
| heuristics | 0 | 0 | 0 | 828 |
| fused | 0 | 0 | 0 | 828 |

AUROC is context only: it does not describe the operating point.

## 7. Deviations

- payload overlap: 15 (leakage between splits)

## 8. Limits

- Results hold for the static payloads tested; adaptive attackers defeat every detector. Claim risk reduction at the stated operating point only, and pair detectors with capability limits.
- Calibration is only as representative as the benign data; recalibrate when traffic changes.
- Contamination is user-declared; unknown training data may inflate detection.
- Bounds assume independent items; near-duplicate items make them optimistic.

## 9. Conclusion, validity and requalification

Conclusion: meets. Proposed validity: 90 days after qualification. Requalify on: configuration-changed, thresholds-changed, expired, drift. Qualification is a separate, human decision (`aqt-validate qualify`).

## References

- annex22-2025d:3, annex22-2025d:4 (intended use, acceptance criteria)
- annex22-2025d:6.2, annex22-2025d:6.3 (test-data independence and use)
- annex22-2025d:7 (test execution), annex22-2025d:10.1-10.4 (change control, monitoring)
- iso9001-2015:7.1.5.1, iso9001-2015:7.1.5.2 (monitoring and measuring resources)
