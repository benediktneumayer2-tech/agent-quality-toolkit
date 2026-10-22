# Integration demo

One offline command that walks through all eight Agent Quality Toolkit packages with synthetic data and ends in a verified audit trail, a signed audit-trail review and a signed release record.

> Agent Quality Toolkit supports quality-management practices; it is not a validated system and does not by itself make any process compliant with GMP, GDP, 21 CFR Part 11 or EU Annex 11.

## Run it

```sh
# once, from the suite root: one venv with all eight packages (editable) plus pytest
uv venv examples/demo/.venv
uv pip install --python examples/demo/.venv/bin/python -e "aqt-spec[schema]" -e aqt-trail -e aqt-signoff \
    -e aqt-change -e aqt-sensei -e aqt-quarantine -e aqt-validate -e aqt-capa pytest

examples/demo/.venv/bin/python examples/demo/run_demo.py      # about 5 seconds
```

Options: `--out DIR` (default `examples/demo/output/`, which is emptied first), `--keep` (keep the temporary directory and print its path, so that you can run `aqt-trail list` and the other tools on it), `--quiet` (summary only). The exit code is 0 only when every expected outcome occurred. The script restarts itself with `examples/demo/.venv` if another Python starts it.

Test: `examples/demo/.venv/bin/python -m pytest -q examples/demo/test_demo.py`. The whole suite: `scripts/test_all.sh`.

## Isolation

- A fresh temporary directory holds everything: `HOME`, `XDG_STATE_HOME`, `XDG_CONFIG_HOME`, `XDG_RUNTIME_DIR` and `TMPDIR` point into it. Git uses a private global config. Nothing is written to `~/.local/state/aqt` or `~/.config/aqt`; the test checks that.
- No network (proxy variables are removed, the time stamp authority is aqt-trail's built-in `test:` authority), no real agents or models, no GPU. The "agents" are the demo script acting with the shared agent marker `AQT_AGENT_SESSION`.
- **DEMO ONLY:** the two people have fixed demo passphrases. Their decisions go through the packages' documented test injection: `aqt_signoff.StaticPassphrase`, a passphrase callback for aqt-quarantine, and an injected agent check for aqt-quarantine, aqt-capa, aqt-validate and the review signature. The real command-line tools read passphrases at a terminal and refuse to decide inside an agent session. Never use this pattern for real decisions.
- **TEST ONLY:** the RFC 3161 time stamps come from aqt-trail's test authority. They are not evidence of time.

## The story

| Step | What happens | Packages | Records | QM concept |
|---|---|---|---|---|
| a | `aqt-trail serve` runs on a temporary socket; `AQT_SINK` points every tool at it. A quality manager (`human:qm-demo`) and a developer (`human:dev-demo`) are enrolled | aqt-trail, aqt-signoff | `trail.event`, `signoff.key.enrolled` | one independent record writer; personal signature keys |
| b | A synthetic web page with a hidden injection arrives through the Claude Code `PostToolUse` hook and is **held**. The agent's attempt to release it is **refused**. The quality manager releases it with a reason and a signed statement; the next prompt delivers it, wrapped as untrusted data | aqt-quarantine | `quarantine.held`, `.refused`, `.released`, `.delivered` | GDP quarantine and release by a responsible person; segregation of duties |
| c | The worker agent asks an advisor through the sensei bridge on a fake terminal host; the developer approves each message | aqt-sensei | `sensei.pair`, `.message`, `.decision`, `.budget` | independent second opinion under human control |
| d | Toy git project, plan `s01` with a declared pytest check. The quality manager signs the plan's `begin` record (`require_signed_approval = true`). A first run fails (`sub()` missing), the second passes, an agent reviewer of another model records PASS, `finish` commits with trailers and the gate is **GO**. An edit afterwards makes the receipt stale: **NO-GO** | aqt-change, aqt-signoff | `change.plan.reconciled`, `change.receipt` (failed and passed), `change.review`, `change.finish`, `signoff.signature` | change control with an approved plan; objective evidence of verification |
| e | `scan` finds the failing receipt, the held case and the refusal. The developer dismisses the first two with reasons and accepts the refusal as `DEV-0001`, investigates (5 whys, factors). The agent plans and implements a corrective action on `AGENTS.md` (hash-bound) and is refused when it tries to approve it. The quality manager signs the implementation record. Effectiveness is **pending**, then **effective** after two later agent sessions and an injected clock eight days ahead; the deviation is closed | aqt-capa, aqt-signoff, aqt-trail (hook import) | `capa.deviation`, `.investigation`, `.action`, `.refused`, `.effectiveness`, `.closure`, `trail.import` | deviation, root cause, CAPA, effectiveness check |
| f | aqt-validate runs aqt-quarantine's heuristics detector (entry-point plug-in) on 760 synthetic benign and 96 synthetic attack texts under a locked protocol: conclusion **meets**, `thresholds.json` written. The quality manager qualifies it; `check` says no requalification is needed. aqt-quarantine then scans a benign page with these thresholds | aqt-validate, aqt-quarantine | `validate.run`, `.report`, `.qualification`, `quarantine.passed` | validation protocol, method performance with bounds, qualified status |
| g | Checkpoint with a TEST ONLY time stamp; `aqt-trail verify` → **intact**; `aqt-evidence conform --level 3` with the pinned service key and an exported checkpoint; ALCOA++ report. A review of the whole trail cannot be signed by the quality manager because the quality manager decided things in it (**not_independent**, recorded). A review of the implementation period of `s01` (receipts to finish, only agents acted) is signed by the quality manager | aqt-trail, aqt-spec | `trail.anchor`, `trail.refused`, `trail.review` | independent audit-trail review; ALCOA++; trusted time stamps |
| h | Gate GO again; the quality manager signs the `change.finish` record with meaning **released**; the manifest prints name, role, meaning, time with zone, reason and content hash. A final checkpoint, `verify` and an export bundle that re-verifies on its own close the story | aqt-signoff, aqt-trail | `signoff.signature` (released), `trail.anchor` | release by an authorised person; signature manifestation; archive |

## Outputs (`examples/demo/output/`)

| File | Content |
|---|---|
| `release-manifest.md` | aqt-signoff manifest of the `change.finish` record with the quality manager's `released` signature |
| `alcoa-report.md` | ALCOA++ report with catalogue IDs |
| `review-worksheet.md`, `review-signed.json` | worksheet of the signed period review and the stored `trail.review` record |
| `review-worksheet-full-trail.md` | worksheet of the whole trail (not signable by the quality manager) |
| `trace-report.md`, `gate-after-edit.json` | aqt-change trace report after finish; gate verdict after the unverified edit |
| `capa-DEV-0001.md`, `capa-trends.md` | deviation timeline and the CAPA trend review |
| `validation-report.md`, `thresholds.json` | detector validation report and the qualified thresholds file |
| `trail-report.md`, `bundle-MANIFEST.json`, `record-types.json` | readable view of every record, the export bundle's checksums, record counts per type |

## When an agent starts the demo

The trail writer observes the real process ancestry of every client. If the demo is started from inside an agent session (for example by Claude Code), the records of the simulated humans are sent from a process below that agent. The ALCOA++ report then fails `attributable` and the full-trail worksheet lists `attribution_mismatch` findings. That is the tool working as designed, and the demo says so instead of hiding it. Started from your own terminal, every ALCOA++ attribute passes and the period review shows only minor "agent claimed but not observed" findings, because the demo's agents are simulated.

## Friction found while building the demo

These were worked around in the demo; the packages are unchanged.

- **aqt-trail `importers.claude_hook`:** a hook payload's top-level `source` string (Claude Code sends `"source": "startup"` on `SessionStart`) is copied into `fields["source"]` and then overwrites `data.source` (`{format, session, event_id}`) in `records_for`. The stored `trail.import` record fails the aqt-spec payload schema (`data/source: 'startup' is not of type 'object'`), so `aqt-evidence conform` stops at L0. The demo sends `UserPromptSubmit` and `Stop` events instead.
- **aqt-validate `protocol.detector_components` / `detector.py`:** for `plugin = "…"` detectors the configuration hash and the thresholds file use only the `version` written in the protocol, not the plug-in's own `version` (which for aqt-quarantine's heuristics contains a hash of the pattern table). Without a pinned version, a changed detector does not trigger `configuration-changed`. The demo pins the plug-in's current version in the protocol.
- Changing an agent instruction file inside the project tree after `aqt-change finish` makes the receipts stale and shows up as `unapproved_change`. The demo keeps `AGENTS.md` in a separate agent-instructions folder (like `~/.codex/AGENTS.md`).
