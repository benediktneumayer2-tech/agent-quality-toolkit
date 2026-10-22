"""The spec text stays in step with the registry and the vectors."""

import json
import re
from pathlib import Path

from aqt_evidence import schemas
from aqt_evidence.vectors import vector_dir

ROOT = Path(__file__).resolve().parents[1]
SPEC = (ROOT / "spec" / "evidence-records-0.1.md").read_text()


def test_every_registered_type_is_in_the_spec_table():
    for type_ in schemas.registered_types():
        assert f"| `{type_}` |" in SPEC, type_


def test_worked_example_matches_its_vector():
    vector = json.loads((vector_dir() / "valid" / "minimal.json").read_text())
    assert vector["expect"]["record_hash"] in SPEC
    assert vector["expect"]["canonical"] in SPEC


def test_error_codes_match_library():
    from aqt_evidence import ERROR_CODES
    for code in ERROR_CODES:
        assert f"| `{code}` |" in SPEC


def test_readme_carries_statement_and_quick_start_commands_exist():
    readme = (ROOT / "README.md").read_text()
    assert "it is not a validated system and does not by itself make any process compliant" in readme
    for command in re.findall(r"aqt-evidence (\w+)", readme):
        assert command in {"validate", "hash", "verify", "keygen", "conform", "vectors"}, command


def test_quickstart_example_reaches_level_3(tmp_path):
    import subprocess
    import sys
    run = subprocess.run([sys.executable, str(ROOT / "examples" / "quickstart.py"), str(tmp_path / "demo")],
                         capture_output=True, text=True)
    assert run.returncode == 0 and "L3 reached" in run.stdout, run.stdout + run.stderr
