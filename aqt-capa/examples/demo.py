"""Offline demo of the aqt-capa loop on synthetic evidence, in a temporary directory.

Run:  .venv/bin/python examples/demo.py

DEMO ONLY: this script injects a stub for the human check so it can run unattended
(also from inside an agent session). The real CLI always uses
``aqt_evidence.require_human()`` for human-only decisions and records refusals.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from aqt_evidence import AgentContext, JsonlSink, actor, new_record

from aqt_capa import Capa, Config, Store, render_markdown, trends

AGENT = actor("agent", "agent:claude-code:demo-1", harness="claude-code", session="demo-1")
HUMAN_STUB = lambda: AgentContext(False)  # noqa: E731 - demo stub, see module docstring


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        root = tmp / "project"
        root.mkdir()
        (root / "AGENTS.md").write_text("# Rules\n\n- Run the tests.\n")
        others, sink = tmp / "tools.jsonl", tmp / "capa.jsonl"
        JsonlSink(others).append(new_record("change.receipt", AGENT, "run", data={
            "argv": ["pytest", "-q"], "exit_code": 1, "passed": False, "plan_basis_hash": "sha256:" + "0" * 64,
            "tree_fingerprint": "sha256:" + "1" * 64, "counts": {"failed": 3}}))
        sink.touch()
        cfg = Config(identity_id="human:qa-lead", project_root=root, db_path=tmp / "capa.db",
                     evidence_paths=[others, sink])
        agent_mode = {"on": False}
        context = lambda: AgentContext(True, "claude-code", ["demo"]) if agent_mode["on"] else AgentContext(False)  # noqa: E731
        capa = Capa(cfg, store=Store(cfg.db_path), sink=JsonlSink(sink), evidence=cfg.evidence_paths,
                    guard=HUMAN_STUB, context=context)

        cand = capa.scan()[0]
        print("candidate:", cand["candidate_id"], cand["title"])
        dev = capa.accept(cand["candidate_id"], category="instructions", reason="agent reported done with red tests")
        dev_id = dev["data"]["dev_id"]
        print("opened:", dev_id)
        capa.investigate(dev_id, whys=["tests failed", "agent reported done", "no completion rule"],
                         factors=["method:no completion rule in AGENTS.md"],
                         root_cause="completion criteria missing", root_category="instructions")
        agent_mode["on"] = True  # the agent proposes and implements the fix
        aid = capa.plan(dev_id, kind="corrective", target="AGENTS.md", description="require green receipts",
                        window_sessions=2)["data"]["action_id"]
        (root / "AGENTS.md").write_text("# Rules\n\n- Run the tests.\n- Never report done with failing tests.\n")
        capa.implement(aid)
        agent_mode["on"] = False  # the human approves
        capa.approve(aid, reason="clear, testable rule")
        print("effectiveness:", capa.effectiveness(aid)[0]["reasons"])
        for i in range(2):
            JsonlSink(others).append(new_record("trail.import", actor(
                "agent", f"agent:claude-code:demo-{i + 2}", harness="claude-code", session=f"demo-{i + 2}"),
                "import", data={"tool": "Bash"}))
        print("effectiveness:", capa.effectiveness(aid)[0]["result"])
        print("closed:", capa.close(dev_id, reason="no recurrence in 2 sessions")["data"]["basis"])
        print()
        print(render_markdown(trends(capa)))


if __name__ == "__main__":
    main()
