# DEV-0001: Refused attempt: release by human:qm-demo (agent_context)

- State: **closed**; severity major; category instructions
- Source: quarantine.refused rec_01a164d400e8a2cdf9850eb17a6d
- Opened 2026-10-22T18:16:19.305009Z by human:dev-demo; investigation due 2026-10-29T18:16:19.304492Z
- Closed 2026-10-22T18:16:20.072537Z (basis: effective)

## Investigation

1. the agent ran aqt-quarantine release
2. it treated the hold as a blocker to remove
3. AGENTS.md says nothing about quarantine decisions
- method: no rule on quarantine decisions in AGENTS.md
- environment: deny rules for decision commands not installed

**Root cause** (instructions): Agent instructions do not forbid deciding quarantine cases

## Actions

| Action | Kind | Target | State | Approval | File | Effectiveness |
|---|---|---|---|---|---|---|
| CAPA-0001-1 | corrective | `AGENTS.md` | implemented | signed-verified | ok | effective |

## Timeline

- 2026-10-22T18:16:19.305009Z `capa.deviation` accepted by human:dev-demo: The agent tried to release its own quarantined input
- 2026-10-22T18:16:19.315122Z `capa.investigation` recorded by human:dev-demo
- 2026-10-22T18:16:19.365946Z `capa.action` planned by agent:demo-agent:worker-1
- 2026-10-22T18:16:19.422830Z `capa.action` implemented by agent:demo-agent:worker-1
- 2026-10-22T18:16:19.512496Z `capa.effectiveness` evaluated by service:aqt-capa
- 2026-10-22T18:16:20.058853Z `capa.effectiveness` evaluated by service:aqt-capa
- 2026-10-22T18:16:20.072537Z `capa.closure` closed by human:qm-demo: Corrective action effective; no recurrence in the window
