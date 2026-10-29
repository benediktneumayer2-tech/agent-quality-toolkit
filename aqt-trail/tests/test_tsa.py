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


# -- C-8, AQT-EI-009: every issuer on the TSA's path must be a CA ------------------------------------------
def _cert(subject_cn, issuer_cn, public, signing_key, *, ca, path_length=None, key_cert_sign=None, eku=None,
          eku_critical=True):
    from datetime import UTC, datetime, timedelta
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID
    now = datetime.now(UTC) - timedelta(hours=1)
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
               .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
               .public_key(public).serial_number(x509.random_serial_number())
               .not_valid_before(now).not_valid_after(now + timedelta(days=30))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True))
    if key_cert_sign is not None:
        builder = builder.add_extension(x509.KeyUsage(True, False, False, False, False, key_cert_sign, key_cert_sign,
                                                      False, False), critical=True)
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=eku_critical)
    return builder.sign(signing_key, hashes.SHA256())


@pytest.fixture(scope="module")
def pki():
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID
    keys = {name: ec.generate_private_key(ec.SECP256R1()) for name in ("root", "mid", "leaf", "tsa")}
    stamp = [ExtendedKeyUsageOID.TIME_STAMPING]
    root = _cert("Root", "Root", keys["root"].public_key(), keys["root"], ca=True, key_cert_sign=True)
    strict_root = _cert("Strict Root", "Strict Root", keys["root"].public_key(), keys["root"], ca=True, path_length=0,
                        key_cert_sign=True)
    return {
        "keys": keys, "root": root, "strict_root": strict_root,
        # an ordinary end-entity certificate (for example a TLS server) under the root
        "leaf": _cert("Some server", "Root", keys["leaf"].public_key(), keys["root"], ca=False,
                      eku=[ExtendedKeyUsageOID.SERVER_AUTH]),
        "mid": _cert("Mid CA", "Root", keys["mid"].public_key(), keys["root"], ca=True, key_cert_sign=True),
        "mid_strict": _cert("Mid CA", "Strict Root", keys["mid"].public_key(), keys["root"], ca=True,
                            key_cert_sign=True),
        "mid_no_sign": _cert("Mid CA", "Root", keys["mid"].public_key(), keys["root"], ca=True, key_cert_sign=False),
        "tsa_under_leaf": _cert("Fake TSA", "Some server", keys["tsa"].public_key(), keys["leaf"], ca=False, eku=stamp),
        "tsa_under_mid": _cert("TSA", "Mid CA", keys["tsa"].public_key(), keys["mid"], ca=False, eku=stamp),
    }


def test_end_entity_certificate_cannot_issue_a_tsa_certificate(pki):
    from datetime import UTC, datetime
    reason = tsa._chain(pki["tsa_under_leaf"], [pki["leaf"]], [pki["root"]], datetime.now(UTC))
    assert reason and "not a CA" in reason


def test_ca_constraints_on_the_path(pki):
    from datetime import UTC, datetime
    now = datetime.now(UTC)
    assert tsa._chain(pki["tsa_under_mid"], [pki["mid"]], [pki["root"]], now) is None          # a proper path
    assert "keyCertSign" in tsa._chain(pki["tsa_under_mid"], [pki["mid_no_sign"]], [pki["root"]], now)
    assert "path length" in tsa._chain(pki["tsa_under_mid"], [pki["mid_strict"]], [pki["strict_root"]], now)


def test_tsa_certificate_needs_a_sole_critical_timestamping_usage(authority, pki):
    from cryptography.x509.oid import ExtendedKeyUsageOID
    loose = _cert("Loose TSA", "AQT TEST TSA ROOT - TEST ONLY", pki["keys"]["tsa"].public_key(), authority.ca_key,
                  ca=False, eku=[ExtendedKeyUsageOID.TIME_STAMPING, ExtendedKeyUsageOID.SERVER_AUTH],
                  eku_critical=False)
    token = authority.token(DIGEST, cert=loose, key=pki["keys"]["tsa"])
    check = tsa.verify_token(token, DIGEST, ca_certs=[authority.ca_cert])
    assert not check.ok and any("timeStamping only and critical" in p for p in check.problems)


def test_garbage_certificates_in_a_token_are_a_problem_not_a_crash(authority):
    from cryptography.hazmat.primitives.serialization import Encoding
    from aqt_trail import der
    token = authority.token(DIGEST)
    good = authority.cert.public_bytes(Encoding.DER)
    broken = token.replace(good, der.seq(der.integer(1)) + b"\x00" * (len(good) - 5))
    check = tsa.verify_token(broken, DIGEST, ca_certs=[authority.ca_cert])
    assert not check.ok and check.problems
