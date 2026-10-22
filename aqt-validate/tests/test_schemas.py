"""Outputs against the schemas published by aqt-spec (thresholds file and record payloads)."""
import json

import pytest

pytest.importorskip("jsonschema")

from aqt_evidence import JsonlSink  # noqa: E402
from aqt_evidence.schemas import validate_payload, validate_schema  # noqa: E402
from aqt_validate import evidence  # noqa: E402
from aqt_validate.config import records  # noqa: E402
from aqt_validate.decisions import check, qualify  # noqa: E402
from aqt_validate.detector import run_detector  # noqa: E402
from aqt_validate.protocol import load_protocol  # noqa: E402
from conftest import HUMAN, detector_project, read_records  # noqa: E402

ACTOR = {"kind": "human", "id": "human:tester"}


def test_thresholds_and_records_match_published_schemas(aqt_env):
    protocol = load_protocol(detector_project(aqt_env.tmp / "p", hold_rule="at_least = 1"))
    sink = JsonlSink(aqt_env.sink)
    evidence.emit(sink, evidence.RUN, ACTOR, "protocol-locked", reason="t",
                  data={"kind": "detector", "protocol": protocol.ref, "subject_id": protocol.subject})
    result = run_detector(protocol, split="test", state_dir=aqt_env.state, sink=sink, records=records({}), actor=ACTOR)
    thresholds = json.loads((result.run_dir / "thresholds.json").read_text())
    assert validate_schema(thresholds, "thresholds") == []
    assert thresholds["run"] == result.run_record["id"]
    assert result.report_record["data"]["thresholds_sha256"].startswith("sha256:")
    qualify(result.run_dir, decision="approve", reason="ok", sink=sink, records=records({}), human=ACTOR,
            claimed_actor=ACTOR, **HUMAN)
    edited = aqt_env.tmp / "t.json"
    thresholds["bands"][0]["thresholds"]["marker"] += 1
    edited.write_text(json.dumps(thresholds))
    assert check(protocol, records=records({}), sink=sink, actor=ACTOR, thresholds=edited).status == "requalify"
    try:
        qualify(result.run_dir, decision="approve", reason="ok", sink=sink, records=records({}), human=ACTOR,
                claimed_actor=ACTOR, environ={"CLAUDECODE": "1"}, chain=[], stdin=HUMAN["stdin"])
    except PermissionError:
        pass
    recs = read_records(aqt_env.sink)
    assert {r["type"] for r in recs} >= {"validate.run", "validate.report", "validate.qualification",
                                         "validate.requalification", "validate.refused"}
    for record in recs:
        assert validate_payload(record) == [], record["type"]
