"""Message codes next to the English sentences: verify summary, policy note, signature rows, actions,
refusals. The English stays as it was."""

import pytest

from aqt_evidence import actor, coded
from aqt_signoff import Conflict, Refused
from aqt_signoff.core import policy_note

AGENT = actor("agent", "agent:test:s1", harness="test")


@pytest.mark.parametrize("others,roles,code,english", [
    ([], (), "signoff.policy.needs_more", "needs 2 more valid signature(s)"),
    (["human:bob"], (), "signoff.policy.needs_more_other", "needs 2 more valid signature(s) from someone other than "
                                                           "human:bob"),
    ([], ("qa", "qm"), "signoff.policy.needs_more_role", "needs 2 more valid signature(s) with role qa or qm"),
    (["human:bob", "human:eve"], ("qa",), "signoff.policy.needs_more_other_role",
     "needs 2 more valid signature(s) from someone other than human:bob, human:eve with role qa"),
])
def test_policy_note_variants(others, roles, code, english):
    note = policy_note(2, others, roles)
    assert note == english and note.code == code


def test_verify_summary_rows_and_policy_carry_codes(people, make, isolated, tmp_path):
    cfg = tmp_path / "policy.toml"
    cfg.write_text('[signoff]\ntz = "UTC"\n[policy.approved]\nmin_signatures = 2\ndistinct_from_author = true\n',
                   encoding="utf-8")
    alice, bob = make("human:alice", config_path=cfg), make("human:bob", config_path=cfg)
    doc = isolated / "report.md"
    doc.write_text("# Report\n")
    bob.sign(bob.file_subject(doc), "authored", "I wrote it")
    with pytest.raises(Refused) as refused:
        bob.sign(bob.file_subject(doc), "approved", "my own work")
    assert refused.value.code == "self_approval"
    assert coded(refused.value) == {"code": "signoff.refused.author",
                                    "args": {"signer": "human:bob", "meaning": "'approved'"}}
    assert str(refused.value) == "human:bob is an author of this content and may not sign it as 'approved'"
    alice.sign(alice.file_subject(doc), "approved", "checked")
    report = alice.verify_file(doc, required=["approved"])
    assert report.summary().code == "signoff.verify.policy_not_met"
    assert report.as_dict()["summary"] == "POLICY NOT MET: approved"
    note = report.policies["approved"].note
    assert note.code == "signoff.policy.needs_more_other" and note == ("needs 1 more valid signature(s) from someone "
                                                                         "other than human:bob")
    doc.write_text("# Report\nedited\n")
    report = alice.verify_file(doc, required=["approved"], record_invalidations=False)
    assert report.summary().code == "signoff.verify.unsigned"
    row = report.signatures[0]
    assert row.detail.code == "signoff.signature.content_changed" and row.as_dict()["detail"].code == row.detail.code


def test_prepared_action_details_and_conflicts_carry_codes(people):
    alice = people["human:alice"]
    view = alice.actions.prepare("command", "k-msg", {"argv": ["true"]}, who=AGENT)
    with pytest.raises(Conflict) as conflict:
        alice.actions.approve(view["id"], "sha256:" + "0" * 64, "looks fine")
    assert conflict.value.code == "hash_mismatch" and coded(conflict.value)["code"] == "signoff.error.hash_mismatch"
    with pytest.raises(Refused) as refused:
        alice.actions.claim(view["id"], view["action_sha256"])
    assert refused.value.code == "not_approved"
    assert coded(refused.value)["args"]["why"] == {"code": "signoff.refused.why_no_approval", "args": {}}
    assert str(refused.value) == f"{view['id']}: no valid approval for this exact action"
