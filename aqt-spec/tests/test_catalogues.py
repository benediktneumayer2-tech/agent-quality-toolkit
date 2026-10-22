"""Catalogues are consistent, the crosswalk is generated and up to date, IDs are stable."""

import subprocess
import sys
from pathlib import Path

from aqt_evidence import catalogues, schemas

ROOT = Path(__file__).resolve().parents[1]
I11 = ["alcoa", "annex11-2011", "annex11-2025d", "part11", "ch4-2025d", "annex22-2025d", "gdp-2013",
       "iso9001-2015", "euaiact", "ichq10", "ichq9"]


def test_crosswalk_and_json_are_up_to_date():
    run = subprocess.run([sys.executable, str(ROOT / "scripts" / "build_crosswalk.py"), "--check"],
                         capture_output=True, text=True)
    assert run.returncode == 0, run.stdout + run.stderr


def test_published_catalogue_list_and_alcoa_ids():
    assert catalogues.catalogue_ids() == I11
    assert [entry["id"] for entry in catalogues.items("alcoa")] == [f"alcoa:{a}" for a in catalogues.ALCOA]


def test_ids_cited_by_other_tools_exist():
    for item_id in ("part11:11.10(e)", "part11:11.50(a)", "part11:11.70", "annex11-2025d:12.2",
                    "annex11-2025d:12.5", "annex11-2011:9", "gdp-2013:6.3", "iso9001-2015:10.2",
                    "euaiact:12(1)", "ichq10:3.2.2", "annex22-2025d:1", "ch4-2025d:4.24"):
        assert catalogues.item(item_id)["paraphrase"]


def test_features_resolve_to_registered_record_types():
    for name, feature in catalogues.features().items():
        for record_type in feature["records"]:
            assert record_type == "*" or schemas.is_registered(record_type), (name, record_type)
        assert catalogues.supporting(name), f"{name} supports nothing"


def test_wording_never_claims_compliance():
    text = (ROOT / "crosswalk.md").read_text().lower()
    statement = catalogues.load()["statement"].lower()
    assert statement in text
    rest = text.replace(statement, "")
    assert "compliant" not in rest and "compliance" not in rest
    for claim in ("aqt is validated", "aqt is certified", "is part 11 ready", "meets the requirement"):
        assert claim not in rest, claim
