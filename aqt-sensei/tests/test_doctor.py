"""The sandbox probe detects failures; the real bwrap check is opt-in (AQT_SENSEI_REAL=1)."""

import json
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from aqt_sensei.config import Config
from aqt_sensei.doctor import PROBE, doctor_profile, sandbox_probe

from conftest import pair_up


def run_probe(spec):
    done = subprocess.run([sys.executable, "-I", "-c", PROBE, json.dumps(spec)], capture_output=True, text=True,
                          timeout=30, env={"PATH": "/usr/bin:/bin", "LEAK": "1"})
    return {c["name"]: c for c in json.loads(done.stdout)}


def test_probe_reports_an_unsandboxed_process_as_failing(tmp_path):
    project, scratch, secret = tmp_path / "p", tmp_path / "s", tmp_path / "token"
    project.mkdir(); scratch.mkdir(); secret.write_text("x")
    checks = run_probe({"project": str(project), "scratch": str(scratch), "hidden": [str(secret)],
                        "env_allowed": ["PATH"], "pair_id": "sp-1", "pairs_dir": None, "socket": None})
    assert checks["project is read-only"]["passed"] is False
    assert checks["scratch folder is writable"]["passed"] is True
    assert checks[f"hidden: {secret}"]["passed"] is False
    assert checks["environment limited to the allow-list"]["passed"] is False
    assert "LEAK" in checks["environment limited to the allow-list"]["detail"]


def test_probe_runs_inside_the_pairs_argv(bridge, project, paths, config):
    pair = pair_up(bridge, project)
    seen = []

    def runner(argv, **kwargs):
        seen.append(argv)
        if "-c" in argv:
            spec = json.loads(argv[-1])
            assert spec["project"] == pair["project_root"] and "AQT_AGENT_SESSION" in spec["env_allowed"]
            return SimpleNamespace(returncode=0, stdout=json.dumps([{"name": "x", "passed": True, "detail": ""}]),
                                   stderr="")
        return SimpleNamespace(returncode=0, stdout="claude 9.9", stderr="")

    checks = sandbox_probe(bridge.pairs[pair["id"]], paths=paths, config=config, runner=runner,
                           resolve=lambda name: (f"/usr/bin/{name}", []))
    assert all(c["passed"] for c in checks)
    assert seen[0][0] == config.bwrap and "--clearenv" in seen[0]
    assert seen[1][-1] == "--version"


@pytest.mark.skipif(os.environ.get("AQT_SENSEI_REAL") != "1", reason="opt-in: runs the real bubblewrap")
def test_real_bwrap_sandbox(paths, tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "README").write_text("x")
    paths.ensure()
    result = doctor_profile("python3", str(project), paths=paths, config=Config(), backend="tmux")
    failed = [c for c in result["checks"] if not c["passed"] and c["name"] not in ("tmux installed",)]
    assert not failed, failed
    assert not list(project.glob(".aqt-sensei-probe"))
