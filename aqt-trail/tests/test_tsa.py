import base64
import hashlib
import shutil
import subprocess

import pytest

from aqt_trail import anchors, tsa
from aqt_trail.state import open_writer, read_records, service_keys
from aqt_trail.verify import verify_trail

from conftest import event, observed_stub

DIGEST = hashlib.sha256(b"head").digest()


@pytest.fixture(scope="module")
def authority():
    return tsa.TestTSA()


def test_token_verifies(authority):
    token = tsa.request_timestamp("test:", DIGEST, transport=authority.transport)
    check = tsa.verify_token(token, DIGEST, ca_certs=[authority.ca_cert])
    assert check.ok and check.chain_checked and check.policy == tsa.TEST_POLICY
    assert check.cert_sha256.startswith("sha256:")


def test_wrong_digest_untrusted_ca_and_tampering(authority):
    token = tsa.request_timestamp("test:", DIGEST, transport=authority.transport)
    assert "imprint" in tsa.verify_token(token, hashlib.sha256(b"other").digest()).problems[0]
    other = tsa.TestTSA()
    assert any("chain" in p for p in tsa.verify_token(token, DIGEST, ca_certs=[other.ca_cert]).problems)
    tampered = bytearray(token)
    tampered[-5] ^= 0xFF  # inside the signature
    assert not tsa.verify_token(bytes(tampered), DIGEST, ca_certs=[authority.ca_cert]).ok


def test_certificate_without_timestamping_usage_is_rejected(authority):
    from cryptography.hazmat.primitives.asymmetric import ec
    token = authority.token(DIGEST, cert=authority.ca_cert, key=authority.ca_key)
    problems = tsa.verify_token(token, DIGEST, ca_certs=[authority.ca_cert]).problems
    assert any("timeStamping" in p for p in problems)
    assert ec  # keep import for clarity of the key type used above


def test_nonce_mismatch_is_rejected(authority):
    def replay(_url, _body, _timeout):
        from aqt_trail import der
        return der.seq(der.seq(der.integer(0)), authority.token(DIGEST, nonce=12345))
    with pytest.raises(tsa.TsaError, match="nonce"):
        tsa.request_timestamp("test:", DIGEST, transport=replay)


def test_refused_status(authority):
    from aqt_trail import der
    with pytest.raises(tsa.TsaError, match="refused"):
        tsa.request_timestamp("test:", DIGEST, transport=lambda *a: der.seq(der.seq(der.integer(2))))


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")
def test_openssl_accepts_our_tokens(authority, tmp_path):
    """Independent check: the documented `openssl ts -verify` command accepts the token."""
    token = tsa.request_timestamp("test:", DIGEST, transport=authority.transport)
    (tmp_path / "token.der").write_bytes(token)
    (tmp_path / "ca.pem").write_bytes(authority.ca_pem)
    result = subprocess.run(["openssl", "ts", "-verify", "-digest", DIGEST.hex(), "-in", str(tmp_path / "token.der"),
                             "-token_in", "-CAfile", str(tmp_path / "ca.pem")], capture_output=True, text=True)
    assert "Verification: OK" in result.stdout, result.stderr


def test_anchor_record_in_trail_verifies(config):
    w = open_writer(config)
    w.append(event(), observed_stub())
    point, anchor = anchors.checkpoint(w, tsa_url="test:", test_dir=config.state / "test-tsa")
    w.close()
    assert anchor["type"] == "trail.anchor" and anchor["data"]["imprint"] == point["head"]
    assert anchor["data"]["tsa"]["url"] == "test:"
    ca = tsa.load_ca(config.state / "test-tsa" / "ca.pem")
    report = verify_trail(config.trail_path, keys=service_keys(config), checkpoints=config.checkpoints_path, tsa_ca=ca)
    assert report.ok and report.anchors == 1 and report.anchors_verified == 1
    unverified = verify_trail(config.trail_path, keys=service_keys(config))
    assert unverified.ok and any("not checked" in w for w in unverified.warnings)
    token = base64.b64decode(read_records(config.trail_path)[-1]["data"]["tsa"]["token_b64"])
    assert tsa.parse_token(token).imprint == bytes.fromhex(point["head"][7:])
