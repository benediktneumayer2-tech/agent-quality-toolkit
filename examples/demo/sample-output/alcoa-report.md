| Attribute | Catalogue | Status | Detail |
|---|---|---|---|
| attributable | `alcoa:attributable` | fail | 17 record(s) claim a human but came from an agent harness |
| legible | `alcoa:legible` | pass | all records are canonical JSON with a valid envelope and render in the report |
| contemporaneous | `alcoa:contemporaneous` | pass | writer time on every record; 0 with client skew > 5000 ms, 0 clock jump(s); 6 retrospective import(s) keep their source time in data.source_time |
| original | `alcoa:original` | pass | hash chain and service signatures intact |
| accurate | `alcoa:accurate` | pass | 5 detached signature(s) verified; verification re-computes every hash |
| complete | `alcoa:complete` | pass | sequence continuous; 0 gap marker(s), 0 spooled record(s) |
| consistent | `alcoa:consistent` | pass | 1 service key(s); writer time went backwards 0 time(s) |
| enduring | `alcoa:enduring` | pass | 2 anchor(s), 1 RFC 3161 token(s) verified to a CA; newest record is 0 h after the last anchor |
| available | `alcoa:available` | pass | export bundle re-verifies: intact: 51 records, head seq 50 sha256:2f2fcbe36a534237ce75e7e4531b27fd3a589586a47b9684d32ec28da9e6df9d |
| traceable | `alcoa:traceable` | pass | 0 record link(s) point outside this trail; 13 external reference(s) |
