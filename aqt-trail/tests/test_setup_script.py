"""The installation checks of scripts/setup-system-user.sh, in --check mode only (it changes nothing
and needs no root). A fake installation in /tmp stands in for a root-owned virtual environment;
--owner-uid accepts the test user as owner. The real setup is never run by the tests."""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "setup-system-user.sh"
pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux") or not shutil.which("sh"),
                                reason="separate-user mode is Linux only")


@pytest.fixture
def install():
    """A minimal installation (mode 0755/0644) whose fake interpreter prints where it loads code from."""
    root = Path(tempfile.mkdtemp(prefix="aqtsetup", dir="/tmp"))  # /tmp: root-owned and sticky
    venv = root / "venv"
    for folder in ("bin", "lib/site/aqt_trail", "lib/site/aqt_evidence", "std"):
        (venv / folder).mkdir(parents=True)
    python = venv / "bin" / "python"
    lines = [venv, venv / "std", venv / "lib/site", venv / "lib/site/aqt_trail", venv / "lib/site/aqt_evidence"]
    python.write_text("#!/bin/sh\n" + "".join(f"echo '{line}'\n" for line in lines))
    script = venv / "bin" / "aqt-trail"
    script.write_text(f"#!{python}\nfrom aqt_trail.cli import main\n")
    (venv / "lib/site/aqt_trail/__init__.py").write_text("")
    for path in [root, *root.rglob("*")]:
        os.chmod(path, 0o755 if path.is_dir() or path == python else 0o644)
    yield script
    shutil.rmtree(root, ignore_errors=True)


def check(script, *extra, owner=True):
    argv = ["sh", str(SCRIPT), "--check", *(["--owner-uid", str(os.getuid())] if owner else []), *extra, str(script)]
    return subprocess.run(argv, capture_output=True, text=True, timeout=60)


def test_a_clean_installation_passes(install):
    result = check(install)
    assert result.returncode == 0, result.stderr
    assert "installation check passed" in result.stdout


def test_files_owned_by_a_user_are_refused_without_owner_uid(install):
    result = check(install, owner=False)
    assert result.returncode == 2 and "not by root" in result.stderr


@pytest.mark.parametrize("target", ["lib/site/aqt_trail/__init__.py", "lib/site/aqt_evidence", "bin/python", "std", "."])
def test_group_or_world_writable_parts_are_refused(install, target):
    path = install.parents[1] / target
    os.chmod(path, os.stat(path).st_mode | 0o020)
    result = check(install)
    assert result.returncode == 2 and "writable by group or others" in result.stderr
    assert str(path.resolve()) in result.stderr


def test_a_missing_package_is_refused(install):
    python = install.parent / "python"
    python.write_text(python.read_text().replace(f"echo '{install.parents[1]}/lib/site/aqt_evidence'",
                                                 "echo 'MISSING aqt_evidence'"))
    result = check(install)
    assert result.returncode == 2 and "cannot find aqt_evidence" in result.stderr


def test_the_test_users_own_virtual_environment_is_refused():
    script = Path(sys.executable).parent / "aqt-trail"
    result = check(script if script.exists() else Path(sys.executable), owner=False)
    assert result.returncode == 2 and "refused" in result.stderr


def test_owner_uid_needs_check_mode(install):
    result = subprocess.run(["sh", str(SCRIPT), "--owner-uid", "1000", str(install)], capture_output=True, text=True)
    assert result.returncode == 2 and "only accepted with --check" in result.stderr
