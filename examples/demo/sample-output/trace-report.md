# Change report: s01

## Summary

- **Plan:** s01 — Subtraction
- **File:** plans/s01.md
- **Status:** completed
- **Ledger state:** clean
- **Accepted version:** sha256:ee8e7ad0a385ae6ad4ebcbd27a761d686bedc95c10ff50ea7ff3c9ce91c70eae
- **Base commit:** fd9d81a462c62a6a83fd462c0c1a22ca97503e08
- **Approval:** signed (rec_01a164d4023d376fd0d3039b28e3)
- **Gate:** GO

## Gate reasons

No open reasons.

## Tasks

| ID | Done | Task | Commits |
|---|---|---|---|
| T01 | x | Implement sub | 7d9c4b086c14 |

## Verification

| ID | Item | Command | State | Result | Receipt |
|---|---|---|---|---|---|
| V01 | Unit tests pass `$ python -m pytest -q -p no:cacheprovider` | python -m pytest -q -p no:cacheprovider | ok | 2/2 passed | rec_01a164d40491f9b5613d0a9c8f67 |

## Reviews

| Record | Reviewer | Independence | Verdict | Findings | Summary |
|---|---|---|---|---|---|
| rec_01a164d404d02fbf6bcce2c605b7 | agent:demo-reviewer:review-1 | different-model | PASS | 0 | sub() is correct and tested |

## Sign-offs

| Signature | Signs record | Meaning | Signer | Time |
|---|---|---|---|---|
| rec_01a164d40258f039097967917a6c | rec_01a164d4023d376fd0d3039b28e3 | approved | human:qm-demo | 2026-10-22T18:16:18.265045Z |

## Plan history

| Record | Action | Kind | Actor | Reason | Items changed |
|---|---|---|---|---|---|
| rec_01a164d401aa0737589eb15729b1 | baseline | baseline | agent:demo-agent:worker-1 |  |  |
| rec_01a164d401edce33fadedb60a2ff | reconcile | semantic | agent:demo-agent:worker-1 | define task and check | added: T01, V01 |
| rec_01a164d4023d376fd0d3039b28e3 | begin | baseline | agent:demo-agent:worker-1 | start subtraction |  |

## Approved scope versus actual diff

| Path | Change | Approved |
|---|---|---|
| src/calc.py | M | yes |

Declared paths: src/**, tests/**. Result: clean.

## Deviations, failures and blockers

None recorded in the plan.

## Waivers

No waivers.

## Anti-gaming warnings

No warnings.

## Finish

- **Record:** rec_01a164d40535fc04ddf4ab5d41d5
- **Commit:** 7d9c4b086c14c3f60a36b9cef683169ff0d6f0b1
- **Gate at finish:** GO

---

*Agent Quality Toolkit supports quality-management practices; it is not a validated system and does not by itself make any process compliant with GMP, GDP, 21 CFR Part 11 or EU Annex 11.*
