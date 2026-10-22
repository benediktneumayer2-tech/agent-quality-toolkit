# Sample output of the demo

These files were written by `examples/demo/run_demo.py` on 22 October 2026 and copied here unchanged, so you can see the results without installing anything. All people, passphrases and data are made up (DEMO ONLY); the time stamp comes from a local test authority (TEST ONLY).

| File | What it shows | Who reads it |
|---|---|---|
| [release-manifest.md](release-manifest.md) | The signature that released the change: printed name, role, meaning, date and time, reason, and whether it still matches the content | Quality managers, auditors |
| [alcoa-report.md](alcoa-report.md) | The audit trail checked against the ten ALCOA++ attributes of trustworthy records | Quality managers, auditors |
| [capa-DEV-0001.md](capa-DEV-0001.md) | One deviation from detection to closure: root cause, corrective action, approval, effectiveness check | Quality managers |
| [validation-report.md](validation-report.md) | The injection detector tested against criteria fixed in advance, with exact confidence bounds | Validation specialists |
| [trace-report.md](trace-report.md) | One change from approved plan to test receipts, review and gate | Developers, reviewers |

**Why "attributable" fails in `alcoa-report.md`:** this run was started from inside an AI agent session. The audit trail saw that an agent, not a person, sent the decisions of the simulated quality manager, and said so. Run from your own terminal, all ten attributes pass.
