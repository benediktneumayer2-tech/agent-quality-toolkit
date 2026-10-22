import pytest

from aqt_change import frontmatter
from aqt_change.plan import basis_hash, item_diff, parse_plan, structure, tick_items, set_tracker, append_completion
from conftest import PLAN

PTN_FRONT = """tracker:
  schema: 1
  kind: sprint
  id: s94
  implementation: platform-consolidation
  sequence: 94
  status: completed
  started_at: '2026-10-21T06:00:28+00:00'
  git:
    base_commit: 9d50a037cc8aace035b21fdc00cba9b7762a88e5
    branches:
      - main
  completed_at: 2026-10-21T06:35:10+00:00
  depends_on: [s93, "s92"]
# a comment
"""


def test_frontmatter_reads_ptn_subset():
    data = frontmatter.parse(PTN_FRONT)
    tracker = data["tracker"]
    assert tracker["sequence"] == 94
    assert tracker["started_at"] == "2026-10-21T06:00:28+00:00"
    assert tracker["completed_at"] == "2026-10-21T06:35:10+00:00"
    assert tracker["git"] == {"base_commit": "9d50a037cc8aace035b21fdc00cba9b7762a88e5", "branches": ["main"]}
    assert tracker["depends_on"] == ["s93", "s92"]


def test_frontmatter_roundtrip():
    data = frontmatter.parse(PTN_FRONT)
    assert frontmatter.parse(frontmatter.dump(data)) == data


@pytest.mark.parametrize("bad", ["a: {b: 1}\n", "a: |\n  x\n", "a:\n  - b: 1\n", "a: 1\na: 2\n", "a: 'x\n"])
def test_frontmatter_refuses_unsupported(bad):
    with pytest.raises(frontmatter.FrontMatterError):
        frontmatter.parse(bad)


def test_parse_items_commands_and_events():
    text = PLAN.replace("## Deviations\n", "## Deviations\n\n### 2026-10-21T10:00:00Z — Scope cut\n\nDropped X.\n")
    plan = parse_plan(text)
    assert plan.errors == []
    assert plan.id == "s01" and plan.status == "planned" and plan.title == "Demo change"
    assert [i.id for i in plan.tasks] == ["T01", "T02"]
    v1, v2 = plan.verification
    assert v1.commands and v1.commands[0][1] == "tests/check.py"
    assert v2.manual
    assert plan.declared_paths == ["src/**", "tests/**"]
    assert len(plan.events) == 1 and plan.events[0].category == "deviation"
    assert plan.events[0].body == "Dropped X."


def test_items_need_stable_unique_ids():
    plan = parse_plan(PLAN.replace("[T02] Document", "Document").replace("[V02]", "[V01]"))
    assert any("stable ID" in e for e in plan.errors)
    assert any("duplicate" in e for e in plan.errors)


def test_items_inside_code_fences_are_ignored():
    plan = parse_plan(PLAN.replace("## Tasks\n", "## Tasks\n\n```\n- [ ] [T09] example\n```\n"))
    assert "T09" not in [i.id for i in plan.items]


def test_basis_ignores_status_neutral_edits():
    plan = parse_plan(PLAN)
    base = basis_hash(plan)
    ticked = tick_items(PLAN, {"T01", "V01"})
    ticked = set_tracker(ticked, status="in_progress", started_at="2026-10-21T10:00:00+00:00",
                         git={"base_commit": "a" * 40, "branches": ["main"]})
    ticked = ticked.replace("## Progress Log\n", "## Progress Log\n\n### 2026-10-21T10:00:00Z — Started\n\nOK\n")
    ticked = append_completion(ticked, "### 2026-10-21T11:00:00Z — Completed\n\nDone.")
    after = parse_plan(ticked)
    assert after.errors == []
    assert [i.checked for i in after.items] == [True, False, True, False]
    assert basis_hash(after) == base
    assert structure(after) == structure(plan)


def test_basis_changes_on_text_edits():
    plan = parse_plan(PLAN)
    prose = parse_plan(PLAN.replace("Add a calculator.", "Add a small calculator."))
    item = parse_plan(PLAN.replace("Implement add", "Implement add and sub"))
    assert basis_hash(prose) != basis_hash(plan)
    assert structure(prose) == structure(plan)          # editorial is possible
    assert structure(item) != structure(plan)           # semantic
    assert item_diff(plan, item) == {"added": [], "removed": [], "changed": ["T01"]}
