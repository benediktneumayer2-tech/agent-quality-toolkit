import pytest
from aqt_evidence import read_jsonl, validate_record

from aqt_change import plans
from aqt_change.errors import ChangeError
from conftest import edit, git, read

P = "plans/s01.md"


def codes(fn, *args, **kwargs):
    with pytest.raises(ChangeError) as info:
        fn(*args, **kwargs)
    return info.value.code


def test_add_status_and_records(ledger, project, evidence_file):
    assert plans.status(ledger, P)["state"] == "unregistered"
    result = plans.add(ledger, P)
    assert result["result"] == "registered"
    assert plans.add(ledger, P)["result"] == "already_registered"
    assert plans.status(ledger, P)["state"] == "clean"
    records = list(read_jsonl(evidence_file))
    assert len(records) == 1 and validate_record(records[0]) == []
    record = records[0]
    assert record["type"] == "change.plan.reconciled" and record["action"] == "baseline"
    assert record["subject"] == {"kind": "plan", "ref": "s01", "sha256": result["accepted_raw"]}
    assert record["actor"]["kind"] == "human"


def test_status_neutral_edits_need_no_reconciliation(ledger, project):
    plans.add(ledger, P)
    edit(project / P, "- [ ] [T01]", "- [x] [T01]")
    edit(project / P, "## Progress Log\n", "## Progress Log\n\n### 2026-10-21T10:00:00Z — Note\n\nfine\n")
    assert plans.status(ledger, P)["state"] == "status_neutral"


def test_text_edit_is_unreconciled_until_reconciled(ledger, project, evidence_file):
    plans.add(ledger, P)
    edit(project / P, "Add a calculator.", "Add a tiny calculator.")
    assert plans.status(ledger, P)["state"] == "unreconciled"
    result = plans.reconcile(ledger, P, "editorial", None)
    assert result["result"] == "reconciled"
    assert plans.status(ledger, P)["state"] == "clean"
    record = list(read_jsonl(evidence_file))[-1]
    assert record["data"]["kind"] == "editorial" and record["before"]["sha256"] != record["after"]["sha256"]


def test_editorial_refused_when_structure_changed(ledger, project):
    plans.add(ledger, P)
    edit(project / P, "- [ ] [T02] Document add", "- [ ] [T02] Document add\n- [ ] [T03] Release")
    assert codes(plans.reconcile, ledger, P, "editorial", "typo") == "plan_editorial_structure_changed"
    assert codes(plans.reconcile, ledger, P, "semantic", None) == "plan_reason_required"
    result = plans.reconcile(ledger, P, "semantic", "add release task")
    assert result["items"]["added"] == ["T03"]


def test_scope_change_is_semantic(ledger, project):
    plans.add(ledger, P)
    edit(project / P, "    - tests/**\n", "    - tests/**\n    - docs/**\n")
    assert codes(plans.reconcile, ledger, P, "editorial", "x") == "plan_editorial_structure_changed"


def test_expect_hash_guards_against_concurrent_edits(ledger, project):
    plans.add(ledger, P)
    edit(project / P, "Add a calculator.", "Add a calculator!")
    assert codes(plans.reconcile, ledger, P, "editorial", None, "sha256:" + "0" * 64) == "source_conflict"


def test_event_history_is_append_only(ledger, project):
    edit(project / P, "## Decisions\n", "## Decisions\n\n### 2026-10-20T10:00:00Z — Use stdlib\n\nNo deps.\n")
    plans.add(ledger, P)
    edit(project / P, "No deps.", "Some deps.")
    assert plans.status(ledger, P)["state"] == "history_rewritten"
    assert codes(plans.reconcile, ledger, P, "semantic", "x") == "plan_event_history_changed"


def test_appended_event_is_ratcheted(ledger, project):
    plans.add(ledger, P)
    edit(project / P, "## Decisions\n", "## Decisions\n\n### 2026-10-20T10:00:00Z — Use stdlib\n\nNo deps.\n")
    assert plans.status(ledger, P)["state"] == "status_neutral"
    edit(project / P, "No deps.", "Some deps.")
    assert plans.status(ledger, P)["state"] == "history_rewritten"


def test_identity_and_lifecycle_are_protected(ledger, project):
    plans.add(ledger, P)
    edit(project / P, "implementation: demo", "implementation: other")
    assert codes(plans.reconcile, ledger, P, "semantic", "x") == "plan_identity_changed"
    edit(project / P, "implementation: other", "implementation: demo")
    edit(project / P, "status: planned", "status: completed")
    assert plans.status(ledger, P)["state"] == "lifecycle_changed"
    assert codes(plans.reconcile, ledger, P, "editorial", "x") == "plan_lifecycle_changed"


def test_begin_writes_lifecycle_and_base(ledger, project):
    result = plans.begin(ledger, P)
    assert result["result"] == "started"
    head = git(project, "rev-parse", "HEAD").strip()
    assert result["base_commit"] == head
    text = read(project / P)
    assert "status: in_progress" in text and f"base_commit: {head}" in text
    assert plans.status(ledger, P)["state"] == "clean"
    assert plans.begin(ledger, P)["result"] == "unchanged"


def test_active_plan_keeps_completed_items_and_needs_reasons(ledger, project):
    plans.begin(ledger, P)
    edit(project / P, "- [ ] [T01]", "- [x] [T01]")
    edit(project / P, "Add a calculator.", "Add a calculator now.")
    assert codes(plans.reconcile, ledger, P, "editorial", None) == "plan_reason_required"
    plans.reconcile(ledger, P, "editorial", "wording")
    edit(project / P, "- [x] [T01] Implement add", "- [x] [T01] Implement add and multiply")
    assert codes(plans.reconcile, ledger, P, "semantic", "grow") == "plan_checked_item_changed"


def test_terminal_plan_refuses_semantic_change(ledger, project):
    edit(project / P, "status: planned", "status: cancelled")
    plans.add(ledger, P)
    edit(project / P, "Implement add", "Implement sub")
    assert codes(plans.reconcile, ledger, P, "semantic", "x") == "terminal_plan_semantic_change"
    edit(project / P, "Implement sub", "Implement add")
    edit(project / P, "Only the calculator.", "Only the calculator module.")
    assert codes(plans.reconcile, ledger, P, "editorial", None) == "plan_reason_required"
    assert plans.reconcile(ledger, P, "editorial", "clarify")["result"] == "reconciled"


def test_new_plan_from_template(ledger, project):
    result = plans.new(ledger, "plans/s02.md", "s02", "Follow-up", "demo", follows="s01")
    assert result["result"] == "created"
    assert "Follow-up of `s01`" in read(project / "plans/s02.md")
    assert plans.status(ledger, "plans/s02.md")["state"] == "clean"
