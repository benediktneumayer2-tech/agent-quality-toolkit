---
tracker:
  schema: 1
  kind: sprint
  id: calc-s01
  implementation: calculator
  status: planned
aqt:
  paths:
    - src/**
    - tests/**
  review:
    min_independence: fresh-context
---

# Calculator: subtraction

## Outcome

`calc.sub(a, b)` exists and is tested.

## Scope

Only `src/calc.py` and its tests.

## Tasks

- [ ] [T01] Implement `sub`
- [ ] [T02] Add tests for `sub`

## Verification

- [ ] [V01] Unit tests pass `$ python -m pytest -q`
- [ ] [V02] README example checked by a person

## Progress Log

## Blockers

## Deviations

## Failures And Learnings

## Decisions

## Linked Git Changes

## Completion
