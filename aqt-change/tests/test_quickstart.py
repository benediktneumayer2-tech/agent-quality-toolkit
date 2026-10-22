"""The documented quick start runs offline end to end (GO, then NO-GO after a code change)."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(shutil.which("git") is None or shutil.which("python3") is None, reason="needs git and python3")
def test_quickstart_script(tmp_path):
    exe = Path(sys.executable).with_name("aqt-change")
    if not exe.exists():
        pytest.skip("aqt-change console script not installed in this environment")
    env = {**os.environ, "AQT_CHANGE": str(exe), "TMPDIR": str(tmp_path),
           "GIT_CONFIG_GLOBAL": str(tmp_path / "gitconfig"), "GIT_CONFIG_NOSYSTEM": "1"}
    for name in ("AQT_ACTOR", "AQT_EVIDENCE", "AQT_CHANGE_STATE", "AQT_CHANGE_CONFIG"):
        env.pop(name, None)
    result = subprocess.run(["sh", str(ROOT / "examples/quickstart.sh")], env=env, capture_output=True,
                            text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "gate: GO" in result.stdout
    assert "gate: NO-GO ['receipt_stale']" in result.stdout
