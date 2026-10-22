"""Advice ledger: valid records, no full texts, record-first owner decisions, spooling."""

import pytest

from aqt_evidence import validate_record
from aqt_sensei.bridge import BridgeError
from aqt_sensei.ledger import LedgerError, excerpt, text_hash

from conftest import make_bridge, pair_up, records

LONG = "secret plan detail " * 100


def test_every_record_is_valid_and_carries_no_full_text(bridge, host, project, sink_path):
    pair = pair_up(bridge, project, mode="auto", max_exchanges=3)
    bridge.tick()
    host.set_status("%1", "working"); bridge.tick(); host.set_status("%1", "idle"); bridge.tick()
    bridge.agent_op("worker", bridge.pairs[pair["id"]], {"op": "ask", "text": LONG}, None)
    bridge.tick()
    all_records = records(sink_path)
    assert {r["type"] for r in all_records} >= {"sensei.pair", "sensei.message", "sensei.budget"}
    for record in all_records:
        assert validate_record(record) == []
        assert "observed" not in record and "sig" not in record and "chain" not in record
        assert LONG not in str(record)
    message = [r for r in records(sink_path, "sensei.message") if r["data"]["kind"] == "ask"][-1]
    assert message["subject"]["sha256"] == text_hash(LONG)
    assert len(message["data"]["excerpt"]) <= 280
    assert message["actor"]["id"] == f"agent:pi:{pair['id']}-worker" and message["actor"]["role"] == "worker"
    delivered = [r for r in records(sink_path, "sensei.message") if r["action"] == "delivered"][-1]
    assert delivered["data"]["rendered_sha256"].startswith("sha256:")


def test_owner_decision_not_applied_when_sink_refuses(paths, config, host, project, clock, tmp_path):
    bridge = make_bridge(paths, config, host, clock)
    pair = pair_up(bridge, project)
    bridge.tick()
    out = bridge.agent_op("worker", bridge.pairs[pair["id"]], {"op": "ask", "text": "q"}, None)
    bridge.ledger.sink_spec = f"file:{tmp_path / 'missing-dir-file' / 'x.jsonl'}"
    (tmp_path / "missing-dir-file").write_text("a file, so the sink path cannot be created")
    with pytest.raises(LedgerError):
        bridge.owner_op({"op": "approve", "message_id": out["message_id"], "reason": "ok"}, None)
    assert bridge.messages[out["message_id"]]["state"] == "awaiting_approval"


def test_automatic_events_spool_and_drain(paths, config, host, project, clock, tmp_path, sink_path):
    bridge = make_bridge(paths, config, host, clock)
    pair = pair_up(bridge, project, mode="auto", max_exchanges=3)
    good = bridge.ledger.sink_spec
    blocker = tmp_path / "blocker"
    blocker.write_text("x")
    bridge.ledger.sink_spec = f"file:{blocker / 'x.jsonl'}"
    bridge.tick()  # intro delivered; its record cannot be written
    assert bridge.ledger.pending() >= 1
    listed = bridge.owner_op({"op": "list"}, None)
    assert listed["ledger_pending"] >= 1
    bridge.ledger.sink_spec = good
    bridge.tick()
    assert bridge.ledger.pending() == 0
    assert any(r["action"] == "delivered" for r in records(sink_path, "sensei.message"))


def test_excerpt_is_bounded():
    assert len(excerpt("x" * 1000)) == 280
    assert excerpt("a\n\nb") == "a b"
