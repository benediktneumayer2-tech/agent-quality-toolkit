"""The offline demo (used by the suite's integration demo) runs and writes valid records."""

import importlib.util
from pathlib import Path

from aqt_evidence import read_jsonl, validate_record


def test_offline_demo(tmp_path, capsys):
    spec = importlib.util.spec_from_file_location("demo", Path(__file__).parents[1] / "examples" / "demo_offline.py")
    demo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo)
    assert demo.main(tmp_path) == 0
    found = list(read_jsonl(tmp_path / "evidence.jsonl"))
    assert all(validate_record(r) == [] for r in found)
    assert [r["action"] for r in found if r["type"] == "sensei.decision"] == ["approved", "approved"]
    assert "calc.py line 2 subtracts" in capsys.readouterr().out
