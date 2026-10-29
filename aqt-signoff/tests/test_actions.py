import sys
import threading

import pytest

from aqt_evidence import SinkError, actor, read_jsonl, validate_record
from aqt_signoff import AlreadyClaimed, Conflict, Refused

AGENT = actor("agent", "agent:test:s1", harness="test")


def records(make, type_=None):
    return [r for r in read_jsonl(make.sink) if type_ is None or r["type"] == type_]


def counter_action(so, tmp_path, key="count-1"):
    out = tmp_path / "count.txt"
    argv = [sys.executable, "-c", f"open({str(out)!r}, 'a').write('x\\n')"]
    view = so.actions.prepare("command", key, {"argv": argv}, description="append one line", who=AGENT)
    return view, out


def test_prepare_is_idempotent_and_conflicts_on_other_spec(people):
    so = people["human:alice"]
    first = so.actions.prepare("command", "k1", {"argv": ["true"]}, who=AGENT)
    again = so.actions.prepare("command", "k1", {"argv": ["true"]}, who=AGENT)
    assert first["id"] == again["id"] and first["action_sha256"] == again["action_sha256"]
    with pytest.raises(Conflict) as conflict:
        so.actions.prepare("command", "k1", {"argv": ["false"]}, who=AGENT)
    assert conflict.value.code == "request_key_conflict"


def test_approve_exact_hash_then_run_once(people, make, tmp_path):
    alice = people["human:alice"]
    view, out = counter_action(alice, tmp_path)
    with pytest.raises(Conflict):
        alice.actions.approve(view["id"], "sha256:" + "0" * 64, "looks fine")
    with pytest.raises(Refused):           # not approved yet
        alice.actions.claim(view["id"], view["action_sha256"])
    approved = alice.actions.approve(view["id"], view["action_sha256"], "argv reviewed")
    assert approved["status"] == "approved"
    result = alice.actions.run(view["id"])
    assert result["data"]["outcome"] == "succeeded" and result["data"]["exit_code"] == 0
    assert out.read_text() == "x\n"
    with pytest.raises(AlreadyClaimed):
        alice.actions.run(view["id"])
    assert out.read_text() == "x\n"
    assert alice.actions.show(view["id"])["status"] == "succeeded"
    types = [r["type"] for r in records(make) if r["type"].startswith("signoff.action")]
    assert types == ["signoff.action.prepared", "signoff.action.approved", "signoff.action.claimed",
                     "signoff.action.outcome"]
    assert all(not validate_record(r) for r in records(make))


def test_preparer_cannot_approve_own_action(people):
    alice = people["human:alice"]
    view = alice.actions.prepare("command", "self", {"argv": ["true"]},
                                 who=actor("human", "human:alice"))
    with pytest.raises(Refused) as refused:
        alice.actions.approve(view["id"], view["action_sha256"], "mine")
    assert refused.value.code == "self_approval"


def test_concurrent_claims_only_one_wins(people, make, tmp_path):
    alice = people["human:alice"]
    view, _ = counter_action(alice, tmp_path)
    alice.actions.approve(view["id"], view["action_sha256"], "ok")
    workers = [make("human:alice") for _ in range(6)]
    results, barrier = [], threading.Barrier(len(workers))

    def attempt(so):
        barrier.wait()
        try:
            results.append(so.actions.claim(view["id"], view["action_sha256"], who=AGENT).claim_id)
        except AlreadyClaimed:
            results.append(None)

    threads = [threading.Thread(target=attempt, args=(so,)) for so in workers]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len([r for r in results if r]) == 1
    assert len(records(make, "signoff.action.claimed")) == 1


def test_crash_after_claim_is_unknown_until_human_resolves(people, make, clock, tmp_path):
    alice = people["human:alice"]
    view, out = counter_action(alice, tmp_path)
    alice.actions.approve(view["id"], view["action_sha256"], "ok")
    alice.actions.claim(view["id"], view["action_sha256"], who=AGENT)   # executor "crashes" here
    assert alice.actions.show(view["id"])["status"] == "claimed"
    with pytest.raises(Refused) as refused:
        alice.actions.resolve(view["id"], "not-applied", "checked")
    assert refused.value.code == "claim_in_progress"
    clock.advance(minutes=12)                  # default grace: run timeout (10 min) + 1 min
    status = alice.actions.show(view["id"])
    assert status["status"] == "unknown" and "no outcome" in status["detail"]
    with pytest.raises(AlreadyClaimed):
        alice.actions.run(view["id"])
    assert not out.exists()
    resolved = alice.actions.resolve(view["id"], "not-applied", "Checked: nothing was written")
    assert resolved["status"] == "failed" and "not-applied" in resolved["detail"]
    record = records(make, "signoff.action.outcome")[-1]
    assert record["data"]["outcome"] == "failed" and record["data"]["resolution"] == "not-applied"
    assert record["meaning"] == "verified" and record["data"]["signature"]["statement"]["outcome"] == "failed"
    with pytest.raises(Conflict):
        alice.actions.resolve(view["id"], "succeeded", "again")


def test_failed_command_needs_new_version_and_approval(people, make, tmp_path):
    alice = people["human:alice"]
    view = alice.actions.prepare("command", "fails", {"argv": [sys.executable, "-c", "raise SystemExit(3)"]},
                                 who=AGENT)
    alice.actions.approve(view["id"], view["action_sha256"], "ok")
    result = alice.actions.run(view["id"])
    assert result["data"]["outcome"] == "failed" and result["data"]["exit_code"] == 3
    revised = alice.actions.prepare("command", "", {"argv": ["true"]}, revise=view["id"], who=AGENT)
    assert revised["version"] == 2 and revised["status"] == "prepared"
    assert revised["action_sha256"] != view["action_sha256"]
    with pytest.raises(Refused):
        alice.actions.claim(view["id"], revised["action_sha256"])
    alice.actions.approve(view["id"], revised["action_sha256"], "v2 ok")
    assert alice.actions.run(view["id"])["data"]["outcome"] == "succeeded"
    assert records(make, "signoff.action.prepared")[-1]["data"]["supersedes"] == view["action_sha256"]


def test_database_flag_is_not_authority(people, tmp_path):
    alice = people["human:alice"]
    view, out = counter_action(alice, tmp_path)
    alice.store.db.execute("UPDATE actions SET status='approved' WHERE id=?", (view["id"],))
    with pytest.raises(Refused) as refused:
        alice.actions.run(view["id"])
    assert refused.value.code == "not_approved" and not out.exists()


def test_forged_approval_in_database_is_rejected(people, tmp_path):
    alice = people["human:alice"]
    view, out = counter_action(alice, tmp_path)
    alice.actions.approve(view["id"], view["action_sha256"], "ok")
    import json
    row = alice.store.action(view["id"])
    forged = row["approvals"]
    forged[0]["data"]["signature"]["statement"]["reason"] = "edited"
    alice.store.db.execute("UPDATE actions SET approvals=? WHERE id=?", (json.dumps(forged), view["id"]))
    with pytest.raises(Refused):
        alice.actions.run(view["id"])
    assert not out.exists()


def test_payload_hash_is_checked_at_claim(people):
    alice = people["human:alice"]
    view = alice.actions.prepare("http", "upload", {"method": "PUT", "url": "https://example.invalid/x"},
                                 payload=b"approved bytes", who=AGENT)
    alice.actions.approve(view["id"], view["action_sha256"], "ok")
    with pytest.raises(Refused) as refused:
        alice.actions.claim(view["id"], view["action_sha256"], payload=b"other bytes", who=AGENT)
    assert refused.value.code == "payload_mismatch"
    with alice.actions.claim(view["id"], view["action_sha256"], payload=b"approved bytes", who=AGENT) as claim:
        claim.succeeded({"http_status": 201})
    assert alice.actions.show(view["id"])["status"] == "succeeded"


def test_exception_inside_claim_block_records_unknown(people):
    alice = people["human:alice"]
    view = alice.actions.prepare("other", "manual", {"text": "rotate the certificate"}, who=AGENT)
    alice.actions.approve(view["id"], view["action_sha256"], "ok")
    with pytest.raises(RuntimeError):
        with alice.actions.claim(view["id"], view["action_sha256"], who=AGENT):
            raise RuntimeError("connection reset")
    view = alice.actions.show(view["id"])
    assert view["status"] == "unknown" and view["outcome"]["basis"] == "executor-exception"


def test_approval_expiry(people, clock):
    alice = people["human:alice"]
    view = alice.actions.prepare("command", "exp", {"argv": ["true"]}, who=AGENT)
    alice.actions.approve(view["id"], view["action_sha256"], "ok for an hour", valid_for_ms=3_600_000)
    clock.advance(hours=2)
    assert alice.actions.show(view["id"])["status"] == "expired"
    with pytest.raises(Refused):
        alice.actions.claim(view["id"], view["action_sha256"], who=AGENT)


def test_two_approvals_policy(people, make, tmp_path):
    cfg = tmp_path / "two.toml"
    cfg.write_text("[actions]\nmin_signatures = 2\n", encoding="utf-8")
    alice, carol = make("human:alice", config_path=cfg), make("human:carol", config_path=cfg)
    view = alice.actions.prepare("command", "two", {"argv": ["true"]}, who=AGENT)
    assert alice.actions.approve(view["id"], view["action_sha256"], "first")["status"] == "prepared"
    with pytest.raises(Conflict):
        alice.actions.approve(view["id"], view["action_sha256"], "first again")
    assert carol.actions.approve(view["id"], view["action_sha256"], "second")["status"] == "approved"


def test_outcome_waits_for_sync_when_sink_is_down(people, make):
    alice = people["human:alice"]
    view = alice.actions.prepare("other", "sync", {"text": "x"}, who=AGENT)
    alice.actions.approve(view["id"], view["action_sha256"], "ok")
    claim = alice.actions.claim(view["id"], view["action_sha256"], who=AGENT)
    real = alice.sink

    class Down:
        def append(self, record):
            raise SinkError("socket unavailable")

    alice._sink = Down()
    result = claim.succeeded()
    assert result["_delivered"] is False
    assert alice.actions.show(view["id"])["status"] == "succeeded"   # the fact is kept locally
    assert not records(make, "signoff.action.outcome")
    assert alice.sync()["failed"]
    alice._sink = real
    assert alice.sync()["delivered"] == [result["id"]]
    assert records(make, "signoff.action.outcome")[0]["id"] == result["id"]


def test_claim_is_released_when_its_record_cannot_be_written(people):
    alice = people["human:alice"]
    view = alice.actions.prepare("other", "release", {"text": "x"}, who=AGENT)
    alice.actions.approve(view["id"], view["action_sha256"], "ok")
    real = alice.sink

    class Down:
        def append(self, record):
            raise SinkError("socket unavailable")

    alice._sink = Down()
    with pytest.raises(SinkError):
        alice.actions.claim(view["id"], view["action_sha256"], who=AGENT)
    alice._sink = real
    assert alice.actions.show(view["id"])["status"] == "approved"
    alice.actions.claim(view["id"], view["action_sha256"], who=AGENT).succeeded()
