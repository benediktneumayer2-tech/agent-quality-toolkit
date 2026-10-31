"""Message codes next to the English sentences: candidate titles (one per rule), effectiveness reasons and
decision errors. Stored titles stay the English text."""

import pytest

from aqt_evidence import coded

from aqt_capa import sources
from aqt_capa.capa import Blocked
from conftest import rec, sessions


def test_candidate_titles_carry_the_code_of_their_rule():
    failed = rec("change.receipt", "run", data={"argv": ["make", "test"], "exit_code": 2, "passed": False})
    finish = rec("change.finish", "finish", data={"plan_ref": "plans/s1.md", "receipts": [failed["id"]],
                                                  "waivers": [], "gate": "NO-GO"})
    held = rec("quarantine.held", "hold", data={"case_id": "QC-9", "band": "hold", "source": {}})
    out = {c.rule: c.title for c in sources.from_records([failed, finish, held])}
    assert out["receipt-failed"] == "Failed verification receipt: make test (exit 2) — referenced by a finish"
    assert out["receipt-failed"].code == "capa.candidate.receipt_failed_finish"
    assert out["finish-not-go"].code == "capa.candidate.finish_not_go"
    assert out["quarantine-held"] == "Input held in quarantine: case QC-9 (unknown source, band hold)"
    assert coded(out["quarantine-held"])["args"]["source"] == {"code": "capa.candidate.unknown_source", "args": {}}
    long = rec("change.receipt", "run", data={"argv": ["x" * 300], "exit_code": 1})
    assert not hasattr(sources.from_records([long])[0].title, "code")      # shortened: the code no longer fits


def test_effectiveness_reasons_and_close_errors_carry_codes(env):
    capa = env.capa()
    dev = capa.new_deviation(title="t", description=None, severity="minor", category="tool")["data"]["dev_id"]
    with pytest.raises(Blocked) as raised:
        capa.close(dev, reason="x", no_action=True)
    assert coded(raised.value) == {"code": "capa.blocked.no_investigation", "args": {"dev": dev}}
    assert str(raised.value) == f"{dev} has no recorded investigation"
    env.is_agent = True
    planned = capa.plan(dev, kind="corrective", target="AGENTS.md", description="d", window_sessions=50)
    aid = planned["data"]["action_id"]
    (env.root / "AGENTS.md").write_text("changed\n")
    capa.implement(aid)
    env.is_agent = False
    capa.approve(aid, reason="ok")
    env.add(sessions(1) + [rec("trail.gap", "gap", data={"from_seq": 3, "count": 2})])
    reasons = capa.effectiveness(aid)[0]["reasons"]
    assert [r.code for r in reasons] == ["capa.effectiveness.gaps", "capa.effectiveness.sessions"]
    assert reasons == ["1 trail gap(s) in the window", f"{reasons[1].args['n']}/50 agent sessions observed"]
