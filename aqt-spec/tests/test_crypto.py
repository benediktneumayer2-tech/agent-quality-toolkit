"""Passphrase-protected key files: memory-hard KDF, earlier PKCS#8 keys, modes."""

import base64
import json
import os
import stat

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aqt_evidence import crypto, generate_key, key_id, load_signer

PASS = b"correct horse battery"


def _legacy_key(path):
    """A key as earlier versions wrote it: PKCS#8 with BestAvailableEncryption (PBKDF2, 2048 rounds)."""
    private = Ed25519PrivateKey.generate()
    path.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.BestAvailableEncryption(PASS)))
    os.chmod(path, 0o600)
    return key_id(private.public_key())


def _body(path):
    return json.loads(base64.b64decode("".join(path.read_text().splitlines()[1:-1])))


def _rewrite(path, body):
    lines = path.read_text().splitlines()
    path.write_text(f"{lines[0]}\n{base64.b64encode(json.dumps(body).encode()).decode()}\n{lines[-1]}\n")


def test_new_key_uses_scrypt_and_aes_gcm(tmp_path):
    path = tmp_path / "keys" / "human-alice.key"
    kid = generate_key(path, passphrase=PASS)
    data = path.read_bytes()
    assert data.startswith(b"-----BEGIN AQT ENCRYPTED PRIVATE KEY-----")
    assert b"ENCRYPTED" in data            # aqt-trail and aqt-ui ask for a passphrase on this marker
    assert crypto.key_file_format(path) == "aqt-key"
    body = _body(path)
    assert body["kdf"] == {**body["kdf"], "name": "scrypt", "n": 2**17, "r": 8, "p": 1}
    assert body["cipher"]["name"] == "aes-256-gcm" and body["key_id"] == kid
    assert load_signer(path, passphrase=PASS).key_id == kid
    with pytest.raises(ValueError):
        load_signer(path, passphrase=b"wrong passphrase!")
    with pytest.raises(TypeError):
        load_signer(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700


def test_unprotected_service_key_stays_pkcs8(tmp_path):
    path = tmp_path / "writer.key"
    kid = generate_key(path)
    assert crypto.key_file_format(path) == "pkcs8"
    assert load_signer(path).key_id == kid


def test_tampered_parameters_are_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(crypto, "SCRYPT_N", 2**10)       # cheap for this test; the file records its cost
    path = tmp_path / "k.key"
    generate_key(path, passphrase=PASS)
    body = _body(path)
    body["kdf"]["n"] = 2**11                             # changed cost: authenticated, so decryption fails
    _rewrite(path, body)
    with pytest.raises(ValueError):
        load_signer(path, passphrase=PASS)
    body["kdf"]["n"] = 2**30                             # would allocate 1 TiB: refused before deriving
    _rewrite(path, body)
    with pytest.raises(ValueError, match="parameters"):
        load_signer(path, passphrase=PASS)


def test_earlier_pkcs8_key_loads_and_upgrades_in_place(tmp_path):
    path = tmp_path / "old.key"
    kid = _legacy_key(path)
    assert crypto.key_file_format(path) == "pkcs8-encrypted"
    assert load_signer(path, passphrase=PASS).key_id == kid
    with pytest.raises(ValueError):
        crypto.upgrade_key(path, b"wrong passphrase!")
    assert crypto.key_file_format(path) == "pkcs8-encrypted"
    assert crypto.upgrade_key(path, PASS) is True
    assert crypto.key_file_format(path) == "aqt-key"
    assert load_signer(path, passphrase=PASS).key_id == kid
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert crypto.upgrade_key(path, PASS) is False
    assert sorted(p.name for p in tmp_path.iterdir()) == ["old.key"]   # no temporary file left


def test_record_signature_is_not_a_statement(tmp_path):
    from aqt_evidence import actor, new_record, sign_record, sign_statement, signer_from_seed, verify_statement
    from aqt_evidence.crypto import signing_bytes
    signer = signer_from_seed(bytes(range(32)))
    keys = {signer.key_id: signer.public_key}
    record = sign_record(new_record("x.y", actor("human", "human:alice"), "act"), signer)
    unsigned_record = {key: value for key, value in record.items() if key != "sig"}
    assert signing_bytes(record) == crypto.canonical_json(unsigned_record)
    disguised = {"statement": unsigned_record, "alg": "ed25519", "key": signer.key_id, "value": record["sig"][0]["value"]}
    assert verify_statement(disguised, keys) is False          # same key, same bytes, but not a statement
    statement = {"aqt_signature": "0.1", "signer": {"id": "human:alice", "name": "Alice"}, "key": signer.key_id,
                 "meaning": "approved", "signed_at": "2026-10-21T12:00:00Z",
                 "subject": {"kind": "hash", "ref": "x", "sha256": "sha256:" + "0" * 64}}
    assert verify_statement(sign_statement(statement, signer), keys) is True
    other_key = sign_statement({**statement, "key": "ed25519:" + "0" * 16}, signer)
    assert verify_statement(other_key, keys) is False           # statement.key must be the signing key


def test_malformed_sig_is_a_clean_failure():
    from aqt_evidence import actor, new_record, verify_record_signatures
    record = new_record("x.y", actor("human", "human:alice"), "act")
    for bad in (None, "text", [None], [{"key": 1, "value": "x"}]):
        assert verify_record_signatures({**record, "sig": bad}, {}) == [(None, False)], bad
    assert verify_record_signatures(record, {}) == []
