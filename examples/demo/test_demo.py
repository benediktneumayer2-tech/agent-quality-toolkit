"""Runs the integration demo in a subprocess and checks its outcome and key outputs.

    examples/demo/.venv/bin/python -m pytest -q examples/demo/test_demo.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REAL_HOME = Path(os.path.expanduser("~"))
REAL_DIRS = (REAL_HOME / ".local" / "state" / "aqt", REAL_HOME / ".config" / "aqt")

OUTPUTS = ("alcoa-report.md", "review-worksheet.md", "review-worksheet-full-trail.md", "review-signed.json",
           "trace-report.md", "capa-trends.md", "capa-DEV-0001.md", "validation-report.md", "thresholds.json",
           "release-manifest.md", "trail-report.md", "bundle-MANIFEST.json", "gate-after-edit.json", "record-types.json")


def test_demo_runs_offline_and_reaches_every_expected_outcome(tmp_path):
    before = {path: path.exists() for path in REAL_DIRS}
    out = tmp_path / "output"
    done = subprocess.run([sys.executable, str(HERE / "run_demo.py"), "--out", str(out)], capture_output=True,
                          text=True, timeout=300)
    assert done.returncode == 0, done.stdout[-3000:] + done.stderr[-3000:]
    summary = next(line for line in done.stdout.splitlines() if line.startswith("== Summary:"))
    passed, total = summary.split()[2].split("/")
    assert passed == total and int(total) >= 35, summary

    for name in OUTPUTS:
        assert (out / name).is_file() and (out / name).stat().st_size > 0, name

    assert "Conclusion: MEETS" in (out / "validation-report.md").read_text()
    assert (out / "capa-DEV-0001.md").read_text().startswith("# DEV-0001:")
    manifest = (out / "release-manifest.md").read_text()
    assert "| released |" in manifest and "human:qm-demo" in manifest and "valid" in manifest
    review = json.loads((out / "review-signed.json").read_text())
    assert review["type"] == "trail.review" and review["actor"]["id"] == "human:qm-demo"
    assert "human:qm-demo" not in review["data"]["actors_reviewed"]
    gate = json.loads((out / "gate-after-edit.json").read_text())
    assert gate["decision"] == "NO-GO" and "receipt_stale" in [r["code"] for r in gate["reasons"]]
    types = json.loads((out / "record-types.json").read_text())
    for prefix in ("trail.", "signoff.", "change.", "sensei.", "quarantine.", "validate.", "capa."):
        assert any(name.startswith(prefix) for name in types), prefix
    for kind in ("quarantine.refused", "change.finish", "capa.closure", "validate.qualification", "trail.review",
                 "trail.anchor"):
        assert types.get(kind), kind

    # Nothing may appear in the real user's AQT directories.
    for path, existed in before.items():
        assert path.exists() == existed, f"{path} was created by the demo"
