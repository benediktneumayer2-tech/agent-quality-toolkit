"""Gate reason details carry message codes; the gate JSON adds detail_code / detail_args beside them."""

import json

from aqt_evidence import coded

from aqt_change import plans, receipts
from aqt_change.cli import main
from aqt_change.config import PROJECT_FILE
from aqt_change.gate import gate, public
from conftest import edit
from test_trail_evidence import P, _agent_env, _require_trail


def test_gate_details_carry_codes_and_the_json_adds_them_beside(ledger, project, tmp_path, monkeypatch, capsys):
    _require_trail(project)
    _agent_env(monkeypatch, tmp_path)
    plans.begin(ledger, P)
    edit(project / P, "- [ ] [V01]", "- [x] [V01]")
    [receipt] = receipts.run(ledger, [], plan_path=P, item="V01", echo=False)
    result = gate(ledger, P)
    details = {r["code"]: r.get("detail") for r in result["reasons"]}
    assert details["trail_required"].code == "change.gate.trail_required"
    assert details["trail_required"].args == {"file": PROJECT_FILE}
    trust = coded(details["receipt_unverified"])
    assert trust["code"] == "aqt.join" and trust["args"]["items"][0]["code"] == "change.gate.receipt_trust"
    assert trust["args"]["items"][0]["args"]["receipt"] == receipt["id"]
    assert trust["args"]["items"][0]["args"]["trust"]["code"] == "change.trust.required"
    assert details["receipt_unverified"] == f"{receipt['id']} cannot be checked: {details['trail_required']}"
    assert not any("detail_code" in r for r in result["reasons"])     # finish records keep their shape

    shown = public(result)
    for plain, reason in zip(result["reasons"], shown["reasons"]):
        assert reason.get("detail") == plain.get("detail")
        found = coded(plain.get("detail"))
        assert (reason.get("detail_code"), reason.get("detail_args")) == \
            ((found["code"], found["args"]) if found else (None, None))
    assert main(["gate", P]) == 1
    printed = json.loads(capsys.readouterr().out)
    by_code = {r["code"]: r for r in printed["reasons"]}
    assert by_code["trail_required"]["detail"] == str(details["trail_required"])
    assert by_code["trail_required"]["detail_code"] == "change.gate.trail_required"
    assert by_code["trail_required"]["detail_args"] == {"file": PROJECT_FILE}
    assert "detail_code" not in by_code["not_finished"]
