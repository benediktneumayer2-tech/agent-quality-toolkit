# aqt-capa usage

## Global options

`aqt-capa [--config FILE] [--db FILE] [--evidence PATH]... [--root DIR] [--repo PATH]... [--json] COMMAND`

| Option | Default |
|---|---|
| `--config` | `$XDG_CONFIG_HOME/aqt/capa.toml` (missing file = defaults) |
| `--db` | `AQT_CAPA_DB`, config `[state] db`, else `$XDG_STATE_HOME/aqt/capa/capa.db` |
| `--evidence` | config `[evidence] paths`, else `AQT_EVIDENCE`, else the default sink file plus the aqt-trail log. A configured file that does not exist yet is read as empty (with a note on stderr) |
| `--root` | config `[project] root`, else the current directory |
| `--repo` | config `[scan] repos` |
| Writing | `AQT_SINK` (`file:…` or `unix:…` for aqt-trail), default `$XDG_STATE_HOME/aqt/evidence.jsonl` |

The actor is taken from config `[identity] id` or `AQT_ACTOR`. When the shared agent check fires, commands that agents may run are recorded as `agent:<harness>:<AQT_AGENT_SESSION or unknown>`.

**Exit codes:**
- 0: ok.
- 1: check failed, refused, or precondition not met. This covers `close` before effectiveness, a `verify` mismatch, `effectiveness --check` with a result that is not effective, and a human-only command run from an agent context.
- 2: usage or runtime error, including unknown IDs and a sink refusal.

## Commands

| Command | Who | Records |
|---|---|---|
| `scan` | anyone | none (candidates live in the index) |
| `candidate list [--all]` | anyone | — |
| `candidate accept C --reason R [--severity] [--category] [--title] [--description]` | human | `capa.deviation` `accepted` |
| `candidate dismiss C --reason R` | human | `capa.deviation` `dismissed` |
| `deviation new --title T --severity S [--category K] [--description] [--subject REF] [--link REL=REF]` | human or agent | `capa.deviation` `opened` |
| `deviation classify DEV --reason R [--severity] [--category] [--recurrence-of DEV2]` | human | `capa.deviation` `classified` |
| `investigate DEV --why … --root-cause … --root-category K [--factor CAT:TEXT] [--impact] [--evidence-ref REC] [--draft]` | human; agent with `--draft` | `capa.investigation` `recorded` / `revised` / `drafted` |
| `action plan DEV --kind corrective\|preventive --target PATH --description D [--window-sessions N] [--window-days D] [--max N] [--match-category K] [--match-source TYPE]` | human or agent | `capa.action` `planned` |
| `action implement A` | human or agent | `capa.action` `implemented` |
| `action approve A --reason R` | human (not the implementer unless `allow_self_approval`) | `capa.action` `approved` |
| `action cancel A --reason R` | human | `capa.action` `cancelled` |
| `action verify [A]` | anyone | — |
| `effectiveness [DEV\|A] [--check]` | anyone | `capa.effectiveness` `evaluated` (only when the result or reasons changed) |
| `effectiveness --extend A --reason R --window-sessions N --window-days D` | human | `capa.effectiveness` `extended` |
| `close DEV --reason R [--no-action]` | human | `capa.closure` `closed` |
| `list [--open] [--overdue]`, `show DEV [--markdown]` | anyone | — |
| `trends [--since 90d\|12w\|DATE] [--by month\|week] [--format md\|json]` | anyone | — |
| `rebuild` | anyone | — |

Factor categories (Ishikawa, adapted): `method`, `machine`, `material`, `measurement`, `people`, `environment`.
Deviation categories: `instructions`, `missing-context`, `tool`, `model`, `task-specification`, `environment`, `security`, `unclassified`.

## Lifecycle rules

- A deviation's states are `open`, then `investigated`, then `actions`, then `closed`. `closed` is final, and a recurrence opens a new deviation.
- Closing needs a recorded investigation. Then one of two rules applies:
  - **With actions:** every non-cancelled action has a decided result (`effective` or `not-effective`), and the most recent action is `effective`.
  - **`--no-action`:** the deviation has no actions and is not critical.
- Implementing an action again (after a further edit) clears the earlier approval.
- An extension replaces the action's window with a new one. Its reason and the previous window are recorded.

## Source rules

| Rule | Record (INTERFACES I5/I6 fields) | Suggested |
|---|---|---|
| `quarantine-held` | `quarantine.held` (skipped when the same `case_id` was declared a threat) | minor / security |
| `quarantine-threat` | `quarantine.threat.declared` | major / security |
| `receipt-failed` | `change.receipt` with `passed: false` or `exit_code != 0` | minor / tool; major when listed in a `change.finish` `receipts` |
| `finish-not-go` | `change.finish` with `gate` other than `GO`, or non-empty `waivers` | minor (major on `NO-GO`) / task-specification |
| `review-fail` | `change.review` with `verdict: FAIL` | major / model |
| `refused` | any `<tool>.refused` | minor / instructions |
| `trail-review-finding` | `trail.review` finding with `disposition: deviation` (one per finding) | from the finding severity / unclassified |
| `action-outcome-unknown` | `signoff.action.outcome` with `outcome: unknown` | minor / environment |
| `git-revert` | commits with `This reverts commit <sha>` or subject `Revert "…"` (optionally only reverts of commits matching `agent_commit_patterns`) | major / unclassified |

## Record payloads (`data`)

| Type / action | Fields |
|---|---|
| `capa.deviation` `opened` / `accepted` | `dev_id`, `title`, `severity`, `category`, `due`, `similar [{dev_id, score_ppm}]`, `description` + `description_sha256`, `source {type, ref, rule}`, `candidate {…}`, `subject_ref`, `suggested_severity` |
| `capa.deviation` `dismissed` | `candidate {candidate_id, key, rule, source_type, source_ref, time, title, severity, category, session}` |
| `capa.deviation` `classified` | `dev_id`, `before`, `after` (`{severity, category}`), `recurrence_of []` |
| `capa.investigation` | `dev_id`, `whys []`, `factors [{category, text}]`, `root_cause`, `root_category`, `impact` |
| `capa.action` (all) | `action_id`, `dev_id`, `target {path, before_sha256, after_sha256, project?}`, `effectiveness_criterion {type, match, window, max}`; `planned` adds `kind`, `description`; `implemented` adds `diff_sha256`, `diff_excerpt`; `approved` adds `approves`, `approves_sha256` |
| `capa.effectiveness` `evaluated` | `action_id`, `dev_id`, `result`, `reasons []`, `counts {recurrences, undecided, sessions, days, gaps}`, `approval`, `start`, `window`, `target_hash_ok`, `recurrences []`, `undecided []` |
| `capa.effectiveness` `extended` | `action_id`, `dev_id`, `window`, `previous_window` |
| `capa.closure` `closed` | `dev_id`, `basis` (`effective` / `no-action`), `actions [{action_id, result}]` |
| `capa.refused` | `attempted_action`, `reason_code` (`agent-context` / `no-tty`), `agent_markers []` |

To sign an approval with aqt-signoff, sign the **implementation record**. Its `subject.sha256` must be `aqt_evidence.record_content_hash(implemented_record)`, which `action implement` prints as the record id to sign.
