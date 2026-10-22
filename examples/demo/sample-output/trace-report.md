# Change report: s01

## Summary

- **Plan:** s01 — Subtraction
- **File:** plans/s01.md
- **Status:** completed
- **Ledger state:** clean
- **Accepted version:** sha256:28272e73631d6df12d733f7038c927d3007fde4f72fa5a15dd4fee71d23988d9
- **Base commit:** de13384f27bb1af5829a28bf343b55dd1f109b92
- **Approval:** signed (rec_01a1649d2f3130c1e6e37dcaa4b2)
- **Gate:** GO

## Gate reasons

No open reasons.

## Tasks

| ID | Done | Task | Commits |
|---|---|---|---|
| T01 | x | Implement sub | f631b3dd6fda |

## Verification

| ID | Item | Command | State | Result | Receipt |
|---|---|---|---|---|---|
| V01 | Unit tests pass `$ python -m pytest -q -p no:cacheprovider` | python -m pytest -q -p no:cacheprovider | ok | 2/2 passed | rec_01a1649d3176479bae4895df6a1b |

## Reviews

| Record | Reviewer | Independence | Verdict | Findings | Summary |
|---|---|---|---|---|---|
| rec_01a1649d31aed99f63dbaff49b51 | agent:demo-reviewer:review-1 | different-model | PASS | 0 | sub() is correct and tested |

## Sign-offs

| Signature | Signs record | Meaning | Signer | Time |
|---|---|---|---|---|
| rec_01a1649d2f4a4c704b0f6acbfc3a | rec_01a1649d2f3130c1e6e37dcaa4b2 | approved | human:qm-demo | 2026-10-22T17:16:25.290733Z |

## Plan history

| Record | Action | Kind | Actor | Reason | Items changed |
|---|---|---|---|---|---|
| rec_01a1649d2ea930d62cea8afa24b2 | baseline | baseline | agent:demo-agent:worker-1 |  |  |
| rec_01a1649d2ee9815f4cb15ac07f07 | reconcile | semantic | agent:demo-agent:worker-1 | define task and check | added: T01, V01 |
| rec_01a1649d2f3130c1e6e37dcaa4b2 | begin | baseline | agent:demo-agent:worker-1 | start subtraction |  |

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

- **Record:** rec_01a1649d321428c474576cc4573a
- **Commit:** f631b3dd6fda880026599647cd8464b9b9e5923a
- **Gate at finish:** GO

---

*Agent Quality Toolkit supports quality-management practices; it is not a validated system and does not by itself make any process compliant with GMP, GDP, 21 CFR Part 11 or EU Annex 11.*
