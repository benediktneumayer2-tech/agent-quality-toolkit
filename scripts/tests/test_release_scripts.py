"""Tests for the release helpers: pypi_readmes.py, check_versions.py and release_notes.py."""

from __future__ import annotations

import importlib.util
import textwrap
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent
BLOB = "https://github.com/benediktneumayer2-tech/agent-quality-toolkit/blob/v9.9.9"
TREE = "https://github.com/benediktneumayer2-tech/agent-quality-toolkit/tree/v9.9.9"
RAW = "https://raw.githubusercontent.com/benediktneumayer2-tech/agent-quality-toolkit/v9.9.9"


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


readmes, versions, notes = load("pypi_readmes"), load("check_versions"), load("release_notes")


def package(root: Path, folder: str, name: str, version: str = "0.2.0", readme: str = "", changelog: str = "",
            readme_field: str = '"README.md"') -> Path:
    pkg = root / folder
    (pkg / "docs").mkdir(parents=True)
    (pkg / "docs" / "usage.md").write_text("usage\n")
    (pkg / "docs" / "shot.png").write_bytes(b"png")
    (pkg / "pyproject.toml").write_text(f'[project]\nname = "{name}"\nversion = "{version}"\nreadme = {readme_field}\n')
    (pkg / "README.md").write_text(textwrap.dedent(readme))
    (pkg / "CHANGELOG.md").write_text(textwrap.dedent(changelog))
    return pkg


# ---- pypi_readmes ---------------------------------------------------------------------------------------

def test_links_and_images_become_absolute_and_code_stays(tmp_path):
    (tmp_path / "LICENSES").mkdir()
    (tmp_path / "LICENSES" / "Apache-2.0.txt").write_text("licence\n")
    pkg = package(tmp_path, "aqt-a", "aqt-a", readme="""\
        # aqt-a
        Part of the [toolkit](../) and [the other part](../aqt-b), see [usage](docs/usage.md#options "Usage")
        and the [licence](/LICENSES/Apache-2.0.txt).
        ![shot](docs/shot.png) and a linked image [![shot](docs/shot.png)](docs/usage.md).
        [web](https://example.org/x.md), [mail](mailto:someone@example.org), [same page](#usage).
        [ref]: docs/usage.md
        [pic]: <docs/shot.png>
        <img src="docs/shot.png" alt="shot"> <a href='docs/usage.md'>usage</a>
        Inline `[not](docs/missing.md)` and ``a `[nested](docs/missing.md)` span``.

        ```bash
        echo "[not a link](docs/missing.md)"
        ```

        - In a list:
            ~~~
            ![no](docs/missing.png)
            ~~~
        """)
    package(tmp_path, "aqt-b", "aqt-b")
    assert readmes.main(["--ref", "v9.9.9", "--root", str(tmp_path)]) == 0
    text = (pkg / "README.md").read_text()
    assert f"[toolkit]({TREE})" in text
    assert f"[the other part]({TREE}/aqt-b)" in text
    assert f'[usage]({BLOB}/aqt-a/docs/usage.md#options "Usage")' in text
    assert f"[licence]({BLOB}/LICENSES/Apache-2.0.txt)" in text
    assert f"![shot]({RAW}/aqt-a/docs/shot.png) and a linked image [![shot]({RAW}/aqt-a/docs/shot.png)]" \
           f"({BLOB}/aqt-a/docs/usage.md)" in text
    assert "[web](https://example.org/x.md), [mail](mailto:someone@example.org), [same page](#usage)" in text
    assert f"[ref]: {BLOB}/aqt-a/docs/usage.md" in text
    assert f"[pic]: <{RAW}/aqt-a/docs/shot.png>" in text
    assert f'<img src="{RAW}/aqt-a/docs/shot.png" alt="shot"> <a href=\'{BLOB}/aqt-a/docs/usage.md\'>' in text
    assert "`[not](docs/missing.md)`" in text and "`[nested](docs/missing.md)`" in text
    assert 'echo "[not a link](docs/missing.md)"' in text and "![no](docs/missing.png)" in text
    # a second run finds nothing left to do
    assert readmes.main(["--ref", "v9.9.9", "--root", str(tmp_path), "--check"]) == 0
    assert (pkg / "README.md").read_text() == text


def test_check_writes_nothing(tmp_path, capsys):
    pkg = package(tmp_path, "aqt-a", "aqt-a", readme="See [usage](docs/usage.md).\n")
    assert readmes.main(["--ref", "v9.9.9", "--root", str(tmp_path), "--check"]) == 0
    assert (pkg / "README.md").read_text() == "See [usage](docs/usage.md).\n"
    assert "would rewrite 1 link" in capsys.readouterr().out


@pytest.mark.parametrize("link, problem", [("docs/gone.md", "missing file"), ("../../outside.md", "outside")])
def test_a_link_that_cannot_be_rewritten_fails_and_nothing_is_written(tmp_path, capsys, link, problem):
    good = package(tmp_path, "aqt-a", "aqt-a", readme="See [usage](docs/usage.md).\n")
    bad = package(tmp_path, "aqt-b", "aqt-b", readme=f"See [this]({link}).\n")
    for args in (["--check"], []):
        assert readmes.main(["--ref", "v9.9.9", "--root", str(tmp_path), *args]) == 1
    assert problem in capsys.readouterr().err
    assert (good / "README.md").read_text() == "See [usage](docs/usage.md).\n"
    assert (bad / "README.md").read_text() == f"See [this]({link}).\n"


def test_the_readme_named_in_pyproject_is_used(tmp_path):
    pkg = package(tmp_path, "aqt-a", "aqt-a", readme_field='{ file = "docs/INTRO.md", content-type = "text/markdown" }')
    (pkg / "docs" / "INTRO.md").write_text("See [usage](usage.md).\n")
    assert readmes.main(["--ref", "v9.9.9", "--root", str(tmp_path)]) == 0
    assert (pkg / "docs" / "INTRO.md").read_text() == f"See [usage]({BLOB}/aqt-a/docs/usage.md).\n"
    assert (pkg / "README.md").read_text() == ""


def test_the_real_readmes_can_be_rewritten():
    assert readmes.main(["--ref", "v0.0.0", "--check"]) == 0


# ---- check_versions -------------------------------------------------------------------------------------

def test_versions_agree_and_match_the_tag(tmp_path, capsys):
    package(tmp_path, "aqt-a", "aqt-a")
    package(tmp_path, "aqt-cli", "agent-quality-toolkit")
    assert versions.main(["--root", str(tmp_path)]) == 0
    assert versions.main(["--root", str(tmp_path), "--tag", "v0.2.0"]) == 0
    assert capsys.readouterr().out.split() == ["0.2.0", "0.2.0"]
    assert versions.main(["--root", str(tmp_path), "--tag", "v0.2.1"]) == 1
    assert versions.main(["--root", str(tmp_path), "--tag", "0.2.0"]) == 1
    assert "expected tag v0.2.0" in capsys.readouterr().err


def test_citation_file_carries_the_version_and_on_a_tag_the_date(tmp_path, capsys):
    package(tmp_path, "aqt-a", "aqt-a")
    cff = tmp_path / "CITATION.cff"
    cff.write_text('cff-version: 1.2.0\nversion: "0.2.1"\n')
    assert versions.main(["--root", str(tmp_path)]) == 1
    assert "CITATION.cff 0.2.1" in capsys.readouterr().err
    cff.write_text("cff-version: 1.2.0\nversion: 0.2.0\n")
    assert versions.main(["--root", str(tmp_path)]) == 0
    assert versions.main(["--root", str(tmp_path), "--tag", "v0.2.0"]) == 1
    assert "no date-released" in capsys.readouterr().err
    cff.write_text("cff-version: 1.2.0\nversion: 0.2.0\ndate-released: 2026-11-13\n")
    assert versions.main(["--root", str(tmp_path), "--tag", "v0.2.0"]) == 0


def test_the_real_citation_file_matches_the_packages():
    assert versions.main([]) == 0


def test_different_versions_fail(tmp_path, capsys):
    package(tmp_path, "aqt-a", "aqt-a")
    package(tmp_path, "aqt-b", "aqt-b", version="0.2.0.dev0")
    assert versions.main(["--root", str(tmp_path)]) == 1
    assert "aqt-b 0.2.0.dev0" in capsys.readouterr().err


# ---- release_notes --------------------------------------------------------------------------------------

CHANGELOG = """\
    # Changelog

    ## 0.2.0.dev1 — unreleased
    - not this one

    ## 0.2.0 — 2026-11-12

    ### Added
    - the thing

    ## 0.1.0 — 2026-10-22
    - older
    """


def test_notes_take_each_packages_section(tmp_path, capsys):
    package(tmp_path, "aqt-a", "aqt-a", changelog=CHANGELOG)
    package(tmp_path, "aqt-cli", "agent-quality-toolkit", changelog="## [0.2.0] — 2026-11-12\nFirst version.\n")
    assert notes.main(["0.2.0", "--root", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert out.index("## agent-quality-toolkit 0.2.0") < out.index("## aqt-a 0.2.0")   # the umbrella first
    assert "#### Added\n- the thing" in out and "First version." in out
    assert "not this one" not in out and "older" not in out


def test_notes_need_a_dated_section(tmp_path, capsys):
    package(tmp_path, "aqt-a", "aqt-a", changelog="## 0.2.0 — unreleased\n- soon\n")
    package(tmp_path, "aqt-b", "aqt-b", changelog="## Unreleased\n- soon\n")
    assert notes.main(["0.2.0", "--root", str(tmp_path)]) == 1
    err = capsys.readouterr().err
    assert "aqt-a/CHANGELOG.md: the 0.2.0 section is still marked unreleased" in err
    assert "aqt-b/CHANGELOG.md: no section for 0.2.0" in err
    (tmp_path / "aqt-b" / "CHANGELOG.md").write_text("## 0.2.0 — unreleased\n- soon\n")
    assert notes.main(["0.2.0", "--root", str(tmp_path), "--allow-unreleased"]) == 0
