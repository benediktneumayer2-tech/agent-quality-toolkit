"""Offline demo: one confirm-mode exchange on a fake terminal host, then the advice ledger.

    python examples/demo_offline.py [OUTPUT_DIR]

No tmux, Herdr, bubblewrap, network or model is used. The ledger records go to
OUTPUT_DIR/evidence.jsonl (default: a temporary folder), so the integration
demo can feed them into aqt-trail.
"""

import json
import shutil
import sys
import tempfile
from pathlib import Path

from aqt_evidence import read_jsonl
from aqt_sensei.bridge import Bridge
from aqt_sensei.config import Config, Paths, create_token
from aqt_sensei.hosts import FakeHost
from aqt_sensei.ledger import Ledger


def main(out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    project = out / "project"
    project.mkdir(exist_ok=True)
    (project / "calc.py").write_text("def add(a, b):\n    return a - b\n")
    paths = Paths(config_file=out / "sensei.toml", token_file=out / "owner.token", state=out / "state",
                  runtime=Path(tempfile.mkdtemp(prefix="aqs-demo-", dir="/tmp")))
    create_token(paths.token_file)
    sink = out / "evidence.jsonl"
    config = Config(owner_id="demo-owner", owner_display="Demo Owner", sink=f"file:{sink}")
    host = FakeHost()
    worker = host.add("%1", status="idle", root_pid=1001)
    ledger = Ledger(sink_spec=config.sink, spool=paths.state / "spool.jsonl", owner_id=config.owner_actor_id,
                    owner_display=config.owner_display)
    bridge = Bridge(paths=paths, config=config, host=host, ledger=ledger, resolve=lambda name: (f"/usr/bin/{name}", []))

    pair = bridge.owner_op({"op": "pair", "worker": worker, "advisor": "claude", "project": str(project),
                            "mode": "confirm", "max_exchanges": 3, "worker_platform": "pi",
                            "worker_model": "acme/small", "reason": "worker stuck on a failing test"}, None)["pair"]
    advisor = pair["advisor"]["pane_id"]
    host.store[advisor].info.agent, host.store[advisor].info.status = True, "idle"
    bridge.tick()                                   # pair active, intro delivered to the worker
    host.set_status(worker, "working"); bridge.tick(); host.set_status(worker, "idle"); bridge.tick()

    live = bridge.pairs[pair["id"]]
    ask = bridge.agent_op("worker", live, {"op": "ask", "text": "test_add fails: add(2, 2) returns 0. Why?"}, None)
    print("worker:", ask["output"])
    print("owner sees:\n" + bridge.owner_op({"op": "show", "message_id": ask["message_id"]}, None)["rendered"])
    bridge.owner_op({"op": "approve", "message_id": ask["message_id"], "reason": "clear, bounded question"}, None)
    bridge.tick()                                   # delivered to the advisor
    answer = bridge.agent_op("advisor", live, {"op": "reply", "text": "calc.py line 2 subtracts; use a + b."}, None)
    bridge.owner_op({"op": "approve", "message_id": answer["message_id"], "reason": "correct diagnosis"}, None)
    host.set_status(advisor, "working"); bridge.tick(); host.set_status(advisor, "idle"); bridge.tick()
    print("worker received:", host.store[worker].received[-1].splitlines()[0:2])
    bridge.owner_op({"op": "end", "pair_id": pair["id"], "reason": "question answered"}, None)

    print(f"\nadvice ledger ({sink}):")
    for record in read_jsonl(sink):
        print(f"  {record['type']:<16} {record['action']:<10} {record['actor']['id']:<38} "
              f"{record.get('reason') or ''}")
    print(json.dumps({"pair_id": pair["id"], "records": sum(1 for _ in read_jsonl(sink))}))
    shutil.rmtree(paths.runtime, ignore_errors=True)
    return 0


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(tempfile.mkdtemp(prefix="aqt-sensei-demo-"))
    raise SystemExit(main(target))
