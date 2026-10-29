"""RFC 3161 time stamps: request, parse and verify tokens; a local test TSA.

``cryptography`` has no TSP/CMS verifier, so the token structure is read with
the small DER module and the checks are done here:

1. the message imprint is the expected SHA-256 digest (the trail head);
2. the signed ``messageDigest`` attribute equals the digest of the TSTInfo;
3. the SignerInfo signature over the signed attributes verifies with the TSA
   certificate (RSA PKCS#1 v1.5, ECDSA or Ed25519);
4. the signed ``signingCertificate`` (v1 or v2) attribute names the signer
   certificate, and that certificate has exactly one, critical extended key usage:
   ``timeStamping`` (RFC 3161 §2.3, as ``openssl ts -verify`` requires);
5. the certificate chains to a configured CA, each certificate valid at
   ``genTime``; every issuer on the path is a CA (``basicConstraints cA``, with
   ``keyCertSign`` when it has a key usage, path length respected), as in RFC 5280
   §6.1.4 (no revocation checking).

A token can also be checked independently:
``openssl ts -verify -digest <head hex> -in token.tsr -token_in -CAfile tsa-ca.pem``.

``TestTSA`` is a self-contained time-stamp authority for tests and offline
demos. Its certificates say TEST ONLY and must never be trusted for real use.
"""

from __future__ import annotations

import base64
import hashlib
import os
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from . import der

SHA256, SHA384, SHA512 = "2.16.840.1.101.3.4.2.1", "2.16.840.1.101.3.4.2.2", "2.16.840.1.101.3.4.2.3"
HASHES = {SHA256: hashes.SHA256, SHA384: hashes.SHA384, SHA512: hashes.SHA512}
HASHLIB = {SHA256: "sha256", SHA384: "sha384", SHA512: "sha512"}
SIGNED_DATA, TST_INFO = "1.2.840.113549.1.7.2", "1.2.840.113549.1.9.16.1.4"
ATTR_CONTENT_TYPE, ATTR_MESSAGE_DIGEST = "1.2.840.113549.1.9.3", "1.2.840.113549.1.9.4"
ATTR_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"
ATTR_SIGNING_CERT = "1.2.840.113549.1.9.16.2.12"   # v1: SHA-1 certificate hash
RSA_OIDS = {"1.2.840.113549.1.1.1": None, "1.2.840.113549.1.1.11": SHA256, "1.2.840.113549.1.1.12": SHA384,
            "1.2.840.113549.1.1.13": SHA512}
ECDSA_OIDS = {"1.2.840.10045.4.3.2": SHA256, "1.2.840.10045.4.3.3": SHA384, "1.2.840.10045.4.3.4": SHA512}
ED25519_OID = "1.3.101.112"
TEST_POLICY = "1.3.6.1.4.1.32473.1.1"  # under the documentation-only enterprise number 32473 (RFC 5612)


class TsaError(RuntimeError):
    pass


@dataclass
class TokenCheck:
    ok: bool
    gen_time: str | None = None
    serial: int | None = None
    policy: str | None = None
    cert_sha256: str | None = None
    chain_checked: bool = False
    problems: list[str] = field(default_factory=list)


def _alg(node: der.Node) -> str:
    return node.child(0).as_oid()


@dataclass
class Token:
    raw: bytes
    econtent: bytes
    digest_alg: str
    hash_alg: str
    imprint: bytes
    policy: str
    serial: int
    gen_time: datetime
    nonce: int | None
    certificates: list[bytes]
    sid_issuer: bytes | None
    sid_serial: int | None
    signer_digest_alg: str
    signed_attrs: der.Node | None
    signature_alg: str
    signature: bytes


def parse_token(token: bytes) -> Token:
    """Parse a TimeStampToken (CMS ContentInfo with SignedData)."""
    try:
        info = der.parse(token)
        if info.child(0).as_oid() != SIGNED_DATA:
            raise TsaError("token is not CMS SignedData")
        signed = info.child(1).child(0)
        parts = signed.children()
        encap = parts[2]
        if encap.child(0).as_oid() != TST_INFO:
            raise TsaError("token does not contain a TSTInfo")
        econtent = encap.child(1).child(0).content
        certificates, signer_infos = [], None
        for node in parts[3:]:
            if node.tag == 0xA0:
                certificates = [cert.raw for cert in node.children()]
            elif node.tag == der.SET:
                signer_infos = node
        if signer_infos is None or not signer_infos.children():
            raise TsaError("token has no SignerInfo")
        signer = signer_infos.child(0).children()
        sid, sid_issuer, sid_serial = signer[1], None, None
        if sid.tag == der.SEQUENCE:
            sid_issuer, sid_serial = sid.child(0).raw, sid.child(1).as_int()
        rest = signer[3:]
        signed_attrs = rest.pop(0) if rest and rest[0].tag == 0xA0 else None
        signature_alg, signature = _alg(rest[0]), rest[1].content
        tst = der.parse(econtent).children()
        imprint = tst[2]
        nonce = None
        for node in tst[5:]:
            if node.tag == der.INTEGER:
                nonce = node.as_int()
        return Token(token, econtent, _alg(parts[1].child(0)), _alg(imprint.child(0)), imprint.child(1).content,
                     tst[1].as_oid(), tst[3].as_int(), tst[4].as_time(), nonce, certificates, sid_issuer,
                     sid_serial, _alg(signer[2]), signed_attrs, signature_alg, signature)
    except (der.DerError, IndexError, UnicodeDecodeError, ValueError) as error:
        raise TsaError(f"unreadable time-stamp token: {error}") from error


def _attributes(node: der.Node | None) -> dict[str, list[der.Node]]:
    attributes = {}
    for attribute in node.children() if node else []:
        attributes[attribute.child(0).as_oid()] = attribute.child(1).children()
    return attributes


def _verify_signature(cert: x509.Certificate, token: Token, data: bytes) -> None:
    public = cert.public_key()
    if isinstance(public, rsa.RSAPublicKey):
        digest = RSA_OIDS.get(token.signature_alg, "unknown") or token.signer_digest_alg
        if digest not in HASHES:
            raise TsaError(f"unsupported RSA signature algorithm {token.signature_alg}")
        public.verify(token.signature, data, padding.PKCS1v15(), HASHES[digest]())
    elif isinstance(public, ec.EllipticCurvePublicKey):
        digest = ECDSA_OIDS.get(token.signature_alg)
        if digest is None:
            raise TsaError(f"unsupported ECDSA signature algorithm {token.signature_alg}")
        public.verify(token.signature, data, ec.ECDSA(HASHES[digest]()))
    elif isinstance(public, ed25519.Ed25519PublicKey):
        public.verify(token.signature, data)
    else:
        raise TsaError("unsupported TSA key type")


def _signer_cert(token: Token, extra: list[x509.Certificate]) -> x509.Certificate | None:
    candidates = [x509.load_der_x509_certificate(raw) for raw in token.certificates] + extra
    for cert in candidates:
        if token.sid_serial is not None and cert.serial_number == token.sid_serial and \
                cert.issuer.public_bytes() == token.sid_issuer:
            return cert
    return candidates[0] if len(candidates) == 1 else None


def _valid_at(cert: x509.Certificate, moment: datetime) -> bool:
    return cert.not_valid_before_utc <= moment <= cert.not_valid_after_utc


def _issuer_problem(issuer: x509.Certificate, below: int, anchor: bool) -> str | None:
    """Why ``issuer`` may not issue the certificate under it (``below`` CA certificates lie between them and the
    TSA certificate), or None. A trust anchor without a basicConstraints extension (a v1 root) is accepted."""
    name = issuer.subject.rfc4514_string()
    try:
        constraints = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        constraints = None
    if constraints is None and not anchor or constraints is not None and not constraints.ca:
        return f"certificate {name} is not a CA but issued a certificate on the TSA's path"
    if constraints is not None and constraints.path_length is not None and below > constraints.path_length:
        return f"certificate {name} allows a path length of {constraints.path_length}, the TSA's path is longer"
    try:
        usage = issuer.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        usage = None
    if usage is not None and not usage.key_cert_sign:
        return f"certificate {name} may not sign certificates (keyUsage without keyCertSign)"
    return None


def _chain(cert: x509.Certificate, pool: list[x509.Certificate], anchors: list[x509.Certificate],
           moment: datetime) -> str | None:
    """None when ``cert`` chains to an anchor through CA certificates, else the reason."""
    anchor_prints = {a.fingerprint(hashes.SHA256()) for a in anchors}
    current, seen, below = cert, set(), 0
    for _ in range(8):
        if not _valid_at(current, moment):
            return f"certificate {current.subject.rfc4514_string()} not valid at genTime"
        if current.fingerprint(hashes.SHA256()) in anchor_prints:
            return None
        seen.add(current.fingerprint(hashes.SHA256()))
        issuer = None
        for candidate in anchors + pool:
            if candidate.subject == current.issuer and candidate.fingerprint(hashes.SHA256()) not in seen:
                try:
                    current.verify_directly_issued_by(candidate)
                except (ValueError, TypeError, InvalidSignature):
                    continue
                issuer = candidate
                break
        if issuer is None:
            return "TSA certificate does not chain to the configured CA"
        if current is not cert and current.subject != current.issuer:
            below += 1                       # a (non-self-issued) intermediate CA between the issuer and the TSA
        problem = _issuer_problem(issuer, below, issuer.fingerprint(hashes.SHA256()) in anchor_prints)
        if problem:
            return problem
        current = issuer
    return "certificate chain too long"


def _signing_cert_problem(attributes: dict[str, list[der.Node]], cert: x509.Certificate) -> str | None:
    """The ESS signingCertificate(V2) attribute must name the certificate the token was verified with."""
    try:
        if ATTR_SIGNING_CERT_V2 in attributes:
            first = attributes[ATTR_SIGNING_CERT_V2][0].child(0).child(0)   # SigningCertificateV2.certs[0]
            parts = first.children()
            algorithm = SHA256
            if parts[0].tag == der.SEQUENCE:                                  # hashAlgorithm (DEFAULT sha256)
                algorithm, parts = _alg(parts[0]), parts[1:]
            if algorithm not in HASHES:
                return "signingCertificateV2 uses an unsupported hash"
            expected = cert.fingerprint(HASHES[algorithm]())
        elif ATTR_SIGNING_CERT in attributes:
            parts = attributes[ATTR_SIGNING_CERT][0].child(0).child(0).children()
            expected = cert.fingerprint(hashes.SHA1())
        else:
            return "token has no signingCertificate attribute"
        if parts[0].tag != der.OCTET_STRING or parts[0].content != expected:
            return "signingCertificate does not name the signer certificate"
    except (der.DerError, IndexError, ValueError):
        return "signingCertificate attribute unreadable"
    return None


def _usage_problem(cert: x509.Certificate) -> str | None:
    try:
        extension = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except x509.ExtensionNotFound:
        return "certificate lacks the timeStamping key usage"
    if ExtendedKeyUsageOID.TIME_STAMPING not in extension.value:
        return "certificate lacks the timeStamping key usage"
    if list(extension.value) != [ExtendedKeyUsageOID.TIME_STAMPING] or not extension.critical:
        return "TSA certificate's extended key usage must be timeStamping only and critical (RFC 3161 2.3)"
    return None


def verify_token(token_der: bytes, digest: bytes, *, ca_certs: list[x509.Certificate] | None = None) -> TokenCheck:
    """Check a token against the expected SHA-256 ``digest``; see the module docstring. Never raises."""
    try:
        token = parse_token(token_der)
    except TsaError as error:
        return TokenCheck(False, problems=[str(error)])
    try:
        return _verify_parsed(token, digest, ca_certs)
    except (ValueError, TypeError, IndexError, der.DerError) as error:
        return TokenCheck(False, problems=[f"unreadable time-stamp token: {error}"])


def _verify_parsed(token: Token, digest: bytes, ca_certs) -> TokenCheck:
    check = TokenCheck(True, token.gen_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), token.serial, token.policy)
    if token.hash_alg != SHA256 or token.imprint != digest:
        check.problems.append("message imprint does not match the head")
    attributes = _attributes(token.signed_attrs)
    if token.signed_attrs is None:
        check.problems.append("token has no signed attributes")
    else:
        content_type = attributes.get(ATTR_CONTENT_TYPE)
        if not content_type or content_type[0].as_oid() != TST_INFO:
            check.problems.append("signed contentType is not TSTInfo")
        message_digest = attributes.get(ATTR_MESSAGE_DIGEST)
        algorithm = HASHLIB.get(token.signer_digest_alg)
        if not message_digest or not algorithm or \
                message_digest[0].content != hashlib.new(algorithm, token.econtent).digest():
            check.problems.append("messageDigest does not match the TSTInfo")
    cert = _signer_cert(token, list(ca_certs or []))
    if cert is None:
        check.problems.append("signer certificate not found in the token")
    else:
        check.cert_sha256 = "sha256:" + cert.fingerprint(hashes.SHA256()).hex()
        if token.signed_attrs is not None:
            try:
                _verify_signature(cert, token, b"\x31" + token.signed_attrs.raw[1:])
            except (InvalidSignature, TsaError, ValueError) as error:
                check.problems.append(f"token signature invalid ({error or 'bad signature'})")
            problem = _signing_cert_problem(attributes, cert)
            if problem:
                check.problems.append(problem)
        problem = _usage_problem(cert)
        if problem:
            check.problems.append(problem)
        if ca_certs:
            pool = [x509.load_der_x509_certificate(raw) for raw in token.certificates]
            reason = _chain(cert, pool, list(ca_certs), token.gen_time)
            if reason:
                check.problems.append(reason)
            else:
                check.chain_checked = True
    check.ok = not check.problems
    return check


def load_ca(path: str | os.PathLike) -> list[x509.Certificate]:
    return x509.load_pem_x509_certificates(Path(path).read_bytes())


# -- requesting ----------------------------------------------------------------
def build_request(digest: bytes, nonce: int) -> bytes:
    return der.seq(der.integer(1), der.seq(der.seq(der.oid(SHA256), der.null()), der.octets(digest)),
                   der.integer(nonce), der.boolean(True))


def _http(url: str, body: bytes, timeout: float) -> bytes:
    request = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/timestamp-query", "Accept": "application/timestamp-reply"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - user-configured URL
        return response.read()


def request_timestamp(url: str, digest: bytes, *, timeout: float = 10, transport=None,
                      test_dir: str | os.PathLike | None = None) -> bytes:
    """Ask a TSA for a token over ``digest``; returns the token DER (not the whole response).

    ``url`` may be ``test:<dir>`` for the local TEST ONLY authority.
    """
    nonce = int.from_bytes(os.urandom(8), "big") >> 1
    body = build_request(digest, nonce)
    if transport is None:
        if url.startswith("test:"):
            transport = TestTSA(url[5:] or test_dir).transport
        elif url.startswith(("http://", "https://")):
            transport = _http
        else:
            raise TsaError("TSA URL must be http(s):// or test:<dir>")
    response = der.parse(transport(url, body, timeout))
    status = response.child(0).child(0).as_int()
    if status not in (0, 1):
        raise TsaError(f"TSA refused the request (status {status})")
    token = response.child(1).raw
    if parse_token(token).nonce != nonce:
        raise TsaError("TSA response nonce does not match the request")
    return token


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# -- test authority --------------------------------------------------------------
class TestTSA:
    """A local RFC 3161 authority with a generated CA. TEST ONLY."""

    __test__ = False  # not a pytest test class

    def __init__(self, directory: str | os.PathLike | None = None, *, clock=None):
        self.clock = clock or (lambda: datetime.now(UTC))
        self.directory = Path(directory) if directory else None
        if self.directory and (self.directory / "tsa.key").exists():
            self._load()
        else:
            self._create()
            if self.directory:
                self._save()
        self._serial = int.from_bytes(os.urandom(6), "big")

    def _create(self):
        now = datetime.now(UTC) - timedelta(days=1)
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AQT TEST TSA ROOT - TEST ONLY")])
        self.ca_cert = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
                        .public_key(self.ca_key.public_key()).serial_number(x509.random_serial_number())
                        .not_valid_before(now).not_valid_after(now + timedelta(days=3650))
                        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                                       critical=True)
                        .sign(self.ca_key, hashes.SHA256()))
        self.key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AQT TEST TSA - TEST ONLY")])
        self.cert = (x509.CertificateBuilder().subject_name(name).issuer_name(ca_name)
                     .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
                     .not_valid_before(now).not_valid_after(now + timedelta(days=3650))
                     .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                     .add_extension(x509.KeyUsage(True, True, False, False, False, False, False, False, False),
                                    critical=True)
                     .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
                     .sign(self.ca_key, hashes.SHA256()))

    def _save(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        pem = serialization.Encoding.PEM
        (self.directory / "ca.pem").write_bytes(self.ca_cert.public_bytes(pem))
        (self.directory / "tsa.pem").write_bytes(self.cert.public_bytes(pem))
        fd = os.open(self.directory / "tsa.key", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(self.key.private_bytes(pem, serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption()))

    def _load(self):
        self.ca_cert = x509.load_pem_x509_certificate((self.directory / "ca.pem").read_bytes())
        self.cert = x509.load_pem_x509_certificate((self.directory / "tsa.pem").read_bytes())
        self.key = serialization.load_pem_private_key((self.directory / "tsa.key").read_bytes(), password=None)

    @property
    def ca_pem(self) -> bytes:
        return self.ca_cert.public_bytes(serialization.Encoding.PEM)

    def token(self, digest: bytes, *, nonce: int | None = None, cert=None, key=None) -> bytes:
        cert, key = cert or self.cert, key or self.key
        self._serial += 1
        fields = [der.integer(1), der.oid(TEST_POLICY),
                  der.seq(der.seq(der.oid(SHA256), der.null()), der.octets(digest)),
                  der.integer(self._serial), der.generalized_time(self.clock())]
        if nonce is not None:
            fields.append(der.integer(nonce))
        tst_info = der.seq(*fields)
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        issuer_serial = der.seq(cert.issuer.public_bytes(), der.integer(cert.serial_number))
        attributes = [
            der.seq(der.oid(ATTR_CONTENT_TYPE), der.set_of(der.oid(TST_INFO))),
            der.seq(der.oid(ATTR_MESSAGE_DIGEST), der.set_of(der.octets(hashlib.sha256(tst_info).digest()))),
            der.seq(der.oid(ATTR_SIGNING_CERT_V2), der.set_of(der.seq(der.seq(der.seq(
                der.octets(hashlib.sha256(cert_der).digest())))))),
        ]
        signed_attrs = der.set_of(*attributes)
        signature = key.sign(signed_attrs, ec.ECDSA(hashes.SHA256()))
        signer_info = der.seq(der.integer(1), issuer_serial, der.seq(der.oid(SHA256), der.null()),
                              der.implicit(0, signed_attrs), der.seq(der.oid("1.2.840.10045.4.3.2")),
                              der.octets(signature))
        signed_data = der.seq(der.integer(3), der.set_of(der.seq(der.oid(SHA256), der.null())),
                              der.seq(der.oid(TST_INFO), der.explicit(0, der.octets(tst_info))),
                              der.implicit(0, der.set_of(cert_der)), der.set_of(signer_info))
        return der.seq(der.oid(SIGNED_DATA), der.explicit(0, signed_data))

    def respond(self, request: bytes) -> bytes:
        parsed = der.parse(request).children()
        digest = parsed[1].child(1).content
        nonce = next((node.as_int() for node in parsed[2:] if node.tag == der.INTEGER), None)
        return der.seq(der.seq(der.integer(0)), self.token(digest, nonce=nonce))

    def transport(self, _url: str, body: bytes, _timeout: float) -> bytes:
        return self.respond(body)
