"""The reference library agrees with every conformance vector; vectors are reproducible."""

import subprocess
import sys
from pathlib import Path

import pytest

from aqt_evidence.vectors import load_keys, load_vectors, run_vector, vector_dir

ROOT = Path(__file__).resolve().parents[1]
VECTORS = load_vectors()
KEYS = load_keys()


def test_vector_set_is_complete():
    categories = {v["category"] for v in VECTORS}
    assert categories == {"canonical", "valid", "invalid", "chained", "tampered", "signed"}
    assert len(VECTORS) >= 50
    assert "TEST ONLY" in (vector_dir() / "keys.json").read_text()


@pytest.mark.parametrize("vector", VECTORS, ids=[v["_file"] for v in VECTORS])
def test_library_agrees(vector):
    result = run_vector(vector, KEYS)
    assert result.ok, result.mismatches


def test_rfc8032_test_key_is_the_published_one():
    test1 = KEYS["rfc8032-test1"]
    assert test1["public_hex"] == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    from aqt_evidence import signer_from_seed
    signer = signer_from_seed(bytes.fromhex(test1["seed_hex"]))
    # RFC 8032 7.1 TEST 1: the signature of the empty message
    expected = ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46b"
                "d25bf5f0595bbe24655141438e7a100b")
    assert signer.private_key.sign(b"").hex() == expected


def test_vectors_and_schemas_are_up_to_date():
    for script in ("gen_vectors.py", "build_schemas.py"):
        run = subprocess.run([sys.executable, str(ROOT / "scripts" / script), "--check"], capture_output=True, text=True)
        assert run.returncode == 0, run.stdout + run.stderr
