"""Pairs, the owner gate per mode, budgets, delivery rules and persisted turns."""

import pytest

from aqt_sensei.bridge import Bridge, BridgeError, Refused, independence

from conftest import make_bridge, pair_up, records


def ask(bridge, pair, text="tests fail after two approaches"):
    return bridge.agent_op("worker", bridge.pairs[pair["id"]], {"op": "ask", "text": text}, None)


def reply(bridge, pair, text="root cause is X", op="reply"):
    return bridge.agent_op("advisor", bridge.pairs[pair["id"]], {"op": op, "text": text}, None)


def advisor_pane(pair):
    return pair["advisor"]["pane_id"]


def settle(bridge, host, pane):
    """The receiver worked on the delivered message and is idle again."""
    host.set_status(pane, "working")
    bridge.tick()
    host.set_status(pane, "idle")
    bridge.tick()


def test_pair_splits_launches_and_introduces(bridge, host, project, sink_path):
    pair = pair_up(bridge, project)
    assert pair["state"] == "starting" and pair["scratch_dir"].startswith(str(project))
    assert host.store[advisor_pane(pair)].commands == [bridge.launcher_argv(pair["id"])]
    assert (bridge.paths.pair_runtime(pair["id"]) / "bin" / "sensei").exists()
    assert pair["independence"] == "different-vendor"
    bridge.tick()  # advisor pane has an agent: active; intro delivered to the idle worker
    assert bridge.pairs[pair["id"]]["state"] == "active"
    assert host.store["%1"].received[0].startswith("[Bridge → Worker · intro]")
    attached = records(sink_path, "sensei.pair")[0]
    assert attached["action"] == "attached" and attached["actor"]["id"] == "human:alice"
    assert attached["reason"] == "test pair" and attached["data"]["sandbox_argv_sha256"].startswith("sha256:")


def test_pair_requires_reason_and_existing_pane(bridge, project):
    with pytest.raises(BridgeError, match="reason"):
        bridge.owner_op({"op": "pair", "worker": "%1", "advisor": "claude", "project": str(project)}, None)
    with pytest.raises(BridgeError, match="not found"):
        bridge.owner_op({"op": "pair", "worker": "%9", "advisor": "claude", "project": str(project),
                         "reason": "x"}, None)


def test_confirm_mode_waits_for_approval_and_records_the_decision(bridge, host, project, sink_path):
    pair = pair_up(bridge, project, mode="confirm")
    bridge.tick()
    out = ask(bridge, pair)
    assert out["state"] == "awaiting_approval" and "owner's approval" in out["output"]
    bridge.tick()
    assert host.store[advisor_pane(pair)].received == []
    with pytest.raises(BridgeError, match="reason"):
        bridge.owner_op({"op": "approve", "message_id": out["message_id"]}, None)
    bridge.owner_op({"op": "approve", "message_id": out["message_id"], "reason": "clear question"}, None)
    bridge.tick()
    delivered = host.store[advisor_pane(pair)].received
    assert len(delivered) == 1 and delivered[0].startswith("[Worker → Sensei · 1]")
    decision = records(sink_path, "sensei.decision")[0]
    assert decision["data"] == {"decision": "approve", "message_id": out["message_id"], "pair_id": pair["id"],
                                "kind": "ask", "from": "worker", "to": "advisor"}
    assert decision["meaning"] == "approved" and decision["reason"] == "clear question"


def test_edit_keeps_original_and_records_before_after(bridge, host, project, sink_path):
    pair = pair_up(bridge, project)
    bridge.tick()
    out = ask(bridge, pair, "original question")
    bridge.owner_op({"op": "approve", "message_id": out["message_id"], "text": "clearer question",
                     "reason": "sharpened"}, None)
    shown = bridge.owner_op({"op": "show", "message_id": out["message_id"]}, None)
    assert shown["versions"][0] == "original question" and shown["versions"][-1] == "clearer question"
    decision = records(sink_path, "sensei.decision")[0]
    assert decision["action"] == "edited" and decision["data"]["decision"] == "edit"
    assert decision["before"]["sha256"] != decision["after"]["sha256"]
    bridge.tick()
    assert "clearer question" in host.store[advisor_pane(pair)].received[0]


def test_manual_mode_never_delivers_without_forward(bridge, host, project, sink_path):
    pair = pair_up(bridge, project, mode="manual")
    bridge.tick()
    out = ask(bridge, pair)
    assert out["state"] == "held"
    with pytest.raises(BridgeError, match="forward"):
        bridge.owner_op({"op": "approve", "message_id": out["message_id"], "reason": "x"}, None)
    bridge.owner_op({"op": "mode", "pair_id": pair["id"], "mode": "auto", "reason": "speed up"}, None)
    bridge.tick()
    assert host.store[advisor_pane(pair)].received == []  # mode changes never release held messages
    assert bridge.messages[out["message_id"]]["state"] == "held"
    bridge.owner_op({"op": "forward", "message_id": out["message_id"], "reason": "fine"}, None)
    bridge.tick()
    assert len(host.store[advisor_pane(pair)].received) == 1
    assert records(sink_path, "sensei.decision")[-1]["meaning"] == "released"


def test_switch_to_auto_releases_waiting_messages(bridge, host, project):
    pair = pair_up(bridge, project, mode="confirm")
    bridge.tick()
    out = ask(bridge, pair)
    bridge.owner_op({"op": "mode", "pair_id": pair["id"], "mode": "auto", "reason": "trust it"}, None)
    bridge.tick()
    assert bridge.messages[out["message_id"]]["state"] == "delivered"


def test_auto_exchange_and_budget_fallback_to_confirm(bridge, host, project, sink_path):
    pair = pair_up(bridge, project, mode="auto", max_exchanges=1)
    bridge.tick()  # intro to worker
    settle(bridge, host, "%1")
    out = ask(bridge, pair)
    assert out["state"] == "queued"
    bridge.tick()
    assert host.store[advisor_pane(pair)].received[0].startswith("[Worker → Sensei · 1/1]")
    reply(bridge, pair)
    settle(bridge, host, advisor_pane(pair))  # reply delivered to the worker; last exchange used
    assert host.store["%1"].received[-1].startswith("[Sensei → Worker · 1/1]")
    live = bridge.pairs[pair["id"]]
    assert live["mode"] == "confirm" and "Budget reached" in live["note"]
    assert any(r["action"] == "reached" for r in records(sink_path, "sensei.budget"))
    assert host.notifications
    settle(bridge, host, "%1")
    second = ask(bridge, pair, "one more")
    assert second["state"] == "awaiting_approval"


def test_max_messages_limit(bridge, host, project):
    pair = pair_up(bridge, project, mode="auto", max_messages=1)
    bridge.tick()
    settle(bridge, host, "%1")
    ask(bridge, pair)
    bridge.tick()
    out = reply(bridge, pair)
    assert out["state"] == "awaiting_approval"  # one agent message delivered, limit reached
    assert bridge.pairs[pair["id"]]["mode"] == "confirm"


def test_auto_mode_gets_default_budget(bridge, project):
    pair = pair_up(bridge, project, mode="auto")
    assert pair["budget"]["max_exchanges"] == 8


def test_never_delivers_to_busy_blocked_or_unknown(bridge, host, project):
    pair = pair_up(bridge, project, mode="auto", max_exchanges=5)
    bridge.tick()
    settle(bridge, host, "%1")
    out = ask(bridge, pair)
    for status in ("working", "blocked", "unknown"):
        host.set_status(advisor_pane(pair), status)
        bridge.tick()
        assert bridge.messages[out["message_id"]]["state"] == "queued"
    host.set_status(advisor_pane(pair), "idle")
    bridge.tick()
    assert bridge.messages[out["message_id"]]["state"] == "delivered"


def test_failed_delivery_after_five_attempts(bridge, host, project, sink_path):
    pair = pair_up(bridge, project, mode="auto", max_exchanges=5)
    bridge.tick()
    settle(bridge, host, "%1")
    out = ask(bridge, pair)
    host.fail_deliveries = 5
    for _ in range(5):
        bridge.tick()
    assert bridge.messages[out["message_id"]]["state"] == "failed"
    assert any(r["action"] == "failed" for r in records(sink_path, "sensei.message"))


def test_no_reply_notice_survives_restart(paths, config, host, project, clock, sink_path):
    first = make_bridge(paths, config, host, clock)
    pair = pair_up(first, project, mode="auto", max_exchanges=5)
    first.tick()
    settle(first, host, "%1")
    ask(first, pair)
    first.tick()  # delivered to the advisor; the turn is open
    host.set_status(advisor_pane(pair), "working")
    first.tick()
    second = make_bridge(paths, config, host, clock)  # the bridge restarts mid-turn
    assert advisor_pane(pair) in second.pairs[pair["id"]]["turns"]
    host.set_status(advisor_pane(pair), "idle")
    second.tick()  # turn ended without `sensei reply`
    live = second.pairs[pair["id"]]
    assert live["open_ask"] is None and "without replying" in live["note"]
    second.tick()
    assert host.store["%1"].received[-1].startswith("[Bridge → Worker · notice]")
    assert any(r["action"] == "no-reply" for r in records(sink_path, "sensei.message"))


def test_pane_gone_pauses_pair(bridge, host, project, sink_path):
    pair = pair_up(bridge, project)
    bridge.tick()
    host.close("%1")
    bridge.tick()
    assert bridge.pairs[pair["id"]]["state"] == "paused"
    assert records(sink_path, "sensei.pair")[-1]["action"] == "paused"


def test_end_discards_pending_and_closes_advisor(bridge, host, project):
    pair = pair_up(bridge, project)
    bridge.tick()
    out = ask(bridge, pair)
    bridge.owner_op({"op": "end", "pair_id": pair["id"], "reason": "done"}, None)
    assert bridge.messages[out["message_id"]]["state"] == "discarded"
    assert advisor_pane(pair) not in host.store
    with pytest.raises(BridgeError):
        ask(bridge, pair)


def test_role_limits(bridge, project):
    pair = pair_up(bridge, project)
    with pytest.raises(Refused):
        bridge.agent_op("advisor", bridge.pairs[pair["id"]], {"op": "ask", "text": "x"}, None)
    with pytest.raises(Refused):
        bridge.agent_op("worker", bridge.pairs[pair["id"]], {"op": "reply", "text": "x"}, None)
    with pytest.raises(Refused):
        bridge.agent_op("worker", bridge.pairs[pair["id"]], {"op": "worker_log"}, None)


def test_worker_log_and_digest_come_from_the_worker_pane(bridge, host, project):
    host.store["%1"].screen = ["\x1b[31mError: boom\x1b[0m", "> "]
    pair = pair_up(bridge, project, mode="auto", max_exchanges=5)
    out = ask(bridge, pair)
    assert "Error: boom" in bridge.messages[out["message_id"]]["digest"]
    assert "\x1b" not in bridge.messages[out["message_id"]]["digest"]
    log = bridge.agent_op("advisor", bridge.pairs[pair["id"]], {"op": "worker_log", "last": 50}, None)
    assert "Error: boom" in log["output"]


def test_budget_set_and_cost(bridge, project, sink_path):
    pair = pair_up(bridge, project)
    bridge.owner_op({"op": "budget", "pair_id": pair["id"], "max_cost": 100, "add_cost": 30,
                     "reason": "set cap"}, None)
    live = bridge.pairs[pair["id"]]
    assert live["budget"]["max_cost"] == 100 and live["used"]["cost"] == 30
    record = records(sink_path, "sensei.budget")[-1]
    assert record["actor"]["kind"] == "human" and record["data"]["added_cost"] == 30


def test_worker_resolution_by_ancestry(bridge, project):
    pair = pair_up(bridge, project)
    bridge.tick()
    assert bridge.worker_for([9999, 4100, 1], None)["id"] == pair["id"]
    with pytest.raises(Refused):
        bridge.worker_for([9999, 1], "%1")  # a declared pane alone is not enough
    with pytest.raises(Refused):
        bridge.worker_for([9999, 4100, 1], "%2")


def test_independence_classes():
    assert independence({"platform": "claude", "model": "m1"}, {"platform": "claude", "model": "m1"}) == "same-model"
    assert independence({"platform": "claude"}, {"platform": "claude"}) == "same-vendor"
    assert independence({"platform": "pi", "model": "openai/x"}, {"platform": "codex"}) == "same-vendor"
    assert independence({"platform": "codex"}, {"platform": "claude"}) == "different-vendor"
    assert independence({}, {"platform": "claude"}) == "unknown"
