"""Approval with the real aqt-signoff: independence and policy are checked on the very signatures that
verify, and the approval is attributed to them (AQT-EI-011, KEYS-07). Uses the installed aqt-signoff, else
the monorepo's ``aqt-signoff/src``; skipped when neither exists."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from aqt_evidence import actor, subject

from conftest import rec, sessions

PASSPHRASE = "a-long-test-passphrase"


@pytest.fixture
def signoff(monkeypatch):
    for name in ("AQT_SIGNERS", "AQT_KEYS_DIR", "AQT_SIGNOFF_STATE", "AQT_SIGNOFF_CONFIG"):
        monkeypatch.delenv(name, raising=False)
    before = set(sys.modules)
    try:
        import aqt_signoff
    except ImportError:
        src = Path(__file__).resolve().parents[2] / "aqt-signoff" / "src"
        if not (src / "aqt_signoff").is_dir():
            pytest.skip("aqt-signoff is not available")
        monkeypatch.syspath_prepend(str(src))
        import aqt_signoff
    yield aqt_signoff
    for name in set(sys.modules) - before:       # leave the other tests without aqt-signoff
        if name.split(".")[0] == "aqt_signoff":
            del sys.modules[name]


def person(aqt_signoff, env, signer_id: str):
    settings = aqt_signoff.load_settings(sink=f"file:{env.others}", evidence=[env.others, env.sink_path])
    so = aqt_signoff.Signoff(settings, authenticator=aqt_signoff.StaticPassphrase(PASSPHRASE), environ={}, chain=[],
                             require_tty=False)
    enrolled = so.init_signer(signer_id, signer_id.split(":")[1].title(), "quality")
    first = so.check_signers()["bootstrap"]["signer"]
    if first != signer_id:                  # every later enrolment counts after an enrolled signer approves it
        approver = aqt_signoff.Signoff(settings, authenticator=aqt_signoff.StaticPassphrase(PASSPHRASE), environ={},
                                       chain=[], require_tty=False)
        approver.approve_enrolment(signer_id, enrolled["data"]["key_id"], approver_id=first)
    return so


def implemented_by_alice(env, **config):
    capa = env.capa(identity_id="human:alice", **config)
    dev = capa.new_deviation(title="t", description=None, severity="minor", category="tool")["data"]["dev_id"]
    aid = capa.plan(dev, kind="corrective", target="AGENTS.md", description="d", window_sessions=1)["data"]["action_id"]
    (env.root / "AGENTS.md").write_text("new rule\n")
    capa.implement(aid)
    act = capa.store.action(aid)
    assert act["implementer"] == "human:alice"
    return capa, aid, act


def approve(so, act, signer_id: str) -> dict:
    target = {"kind": "record", "ref": act["implemented_record"], "sha256": act["implemented_hash"]}
    return so.sign(target, "approved", "clear, testable rule", signer_id=signer_id)


def test_unsigned_independent_claim_does_not_combine_with_a_self_approval(env, signoff):
    capa, aid, act = implemented_by_alice(env)
    alice = person(signoff, env, "human:alice")
    approve(alice, act, "human:alice")                         # genuine, but by the implementer
    assert capa.approval(act)["status"] == "awaiting-approval"
    forged = rec("signoff.signature", "sign", who=actor("human", "human:bob"), meaning="approved", reason="ok",
                 subject=subject("record", act["implemented_record"], sha256=act["implemented_hash"]),
                 data={"meaning": "approved"})
    env.add([forged])
    status = capa.approval(act)
    assert not status["approved"] and status["status"] == "signature-not-valid" and status["record"] == forged["id"]
    env.add(sessions(1))
    assert capa.evaluate(aid)["result"] == "pending"


def test_an_independent_verified_signature_approves_and_is_the_one_attributed(env, signoff):
    capa, aid, act = implemented_by_alice(env)
    alice, bob = person(signoff, env, "human:alice"), person(signoff, env, "human:bob")
    approve(alice, act, "human:alice")
    signed = approve(bob, act, "human:bob")
    status = capa.approval(act)
    assert status["approved"] and status["status"] == "signed-verified"
    assert (status["by"], status["record"]) == ("human:bob", signed["id"])
    assert status["at"] == signed["data"]["signature"]["statement"]["signed_at"]
    env.add(sessions(1))
    assert capa.evaluate(aid)["result"] == "effective"


def test_self_approval_counts_only_when_allowed(env, signoff):
    capa, _, act = implemented_by_alice(env, allow_self_approval=True)
    signed = approve(person(signoff, env, "human:alice"), act, "human:alice")
    status = capa.approval(act)
    assert status["status"] == "signed-verified" and (status["by"], status["record"]) == ("human:alice", signed["id"])


def test_a_verification_failure_never_approves(env, signoff):
    capa, _, act = implemented_by_alice(env)
    approve(person(signoff, env, "human:bob"), act, "human:bob")
    assert capa.approval(act)["approved"]
    (env.root.parent / "config" / "aqt" / "signers.json").write_text("not json")
    status = capa.approval(act)
    assert not status["approved"] and status["status"] == "signature-not-valid" and "could not verify" in status["note"]
