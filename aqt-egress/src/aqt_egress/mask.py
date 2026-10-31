"""Masking of credentials in what is recorded or stored, and credential fingerprints.

Masking is a small set of rules for common credential shapes (bearer tokens, API keys of the
large providers, JWTs, private key blocks, ``password=``-style pairs). It keeps records and
stored bodies from carrying credentials in plain text; it is not a leak detector (that is a later
stage). Credential headers are never recorded with their value: a record holds only the header
name, the scheme and a keyed fingerprint (HMAC-SHA256 with a per-installation key, cut to 16 hex
digits), so the same key gives the same fingerprint across sessions without being guessable from
the trail.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from pathlib import Path

MASK = "[masked]"

CREDENTIAL_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key", "x-goog-api-key",
    "x-auth-token", "private-token", "x-amz-security-token", "x-csrf-token", "x-xsrf-token", "openai-api-key",
    "anthropic-api-key", "x-functions-key", "ocp-apim-subscription-key",
})

_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)", re.S), MASK),
    (re.compile(r"\b(bearer|basic|digest)(\s+)[A-Za-z0-9._~+/=-]{8,}", re.I), rf"\1\2{MASK}"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), MASK),          # JWT
    (re.compile(r"\b(sk|rk|pk)-(ant-|proj-|live-|test-)?[A-Za-z0-9_-]{16,}"), MASK),             # OpenAI, Anthropic, Stripe
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,})"), MASK),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), MASK),                                       # Slack
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), MASK),                                          # AWS key id
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}"), MASK),                                              # Google API key
    (re.compile(r"\bhf_[A-Za-z0-9]{30,}"), MASK),                                                # Hugging Face
    (re.compile(r"(?i)(\\?\"?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|"
                r"secret[_-]?key|secret|password|passwd|pwd|token|auth)\\?\"?\s*[:=]\s*\\?\"?)([^\"\\&\s,;}]{4,})"),
     rf"\1{MASK}"),
    (re.compile(r"(?i)(://[^/\s:@]+:)[^/\s@]+@"), rf"\1{MASK}@"),                                # user:password@ in URLs
]


def mask_text(text: str) -> str:
    for pattern, replacement in _RULES:
        text = pattern.sub(replacement, text)
    return text


def excerpt(data: bytes, chars: int) -> str | None:
    """A masked text excerpt of at most ``chars`` characters, or None for binary data or ``chars == 0``."""
    if chars <= 0 or not data:
        return None
    text = data[: chars * 4 + 256].decode("utf-8", errors="replace")
    sample = text[: chars + 64]
    odd = sum(1 for ch in sample if ch == "�" or (ord(ch) < 32 and ch not in "\t\r\n"))
    if sample and odd * 10 > len(sample):
        return None
    # mask before cutting, so a credential cut at the edge is still recognised
    return mask_text(text)[:chars]


def load_key(path: Path) -> bytes:
    """The per-installation fingerprint key (32 random bytes, 0600), created on first use."""
    try:
        return path.read_bytes()
    except FileNotFoundError:
        key = os.urandom(32)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(key)
        return key


def fingerprint(value: str, key: bytes) -> str:
    return "hmac-sha256:" + hmac.new(key, value.encode("utf-8", "surrogateescape"), hashlib.sha256).hexdigest()[:16]


def credential(name: str, value: str, key: bytes) -> dict:
    """What a record keeps of a credential header: name, scheme (if any) and fingerprint."""
    entry = {"header": name.lower()}
    scheme, _, rest = value.strip().partition(" ")
    if rest and scheme.isalpha() and len(scheme) <= 16:
        entry["scheme"] = scheme
        entry["fingerprint"] = fingerprint(rest.strip(), key)
    else:
        entry["fingerprint"] = fingerprint(value.strip(), key)
    return entry


def headers_summary(fields, key: bytes) -> tuple[list[str], list[dict]]:
    """(header names in order, lower case, without repeats; credential entries) for ``(name, value)`` pairs."""
    names, credentials = [], []
    for name, value in fields:
        lower = name.lower()
        if lower not in names:
            names.append(lower)
        if lower in CREDENTIAL_HEADERS:
            credentials.append(credential(lower, value, key))
    return names, credentials


def masked_headers(fields) -> list[list[str]]:
    """Headers for the body store: credential headers masked entirely, others through the rules."""
    return [[name, MASK if name.lower() in CREDENTIAL_HEADERS else mask_text(value)] for name, value in fields]


TEXT_ARG_CHARS = 40


def _arg(arg: str, each: int) -> str:
    """Free text in a command line (a prompt for ``claude -p``, a ``sh -c`` script) is not kept: only its
    length and a short hash, so that the records do not store prompts (spec section 3.5)."""
    if len(arg) > TEXT_ARG_CHARS and any(ch.isspace() for ch in arg):
        return f"[text {len(arg)} chars sha256:{hashlib.sha256(arg.encode('utf-8', 'surrogateescape')).hexdigest()[:12]}]"
    return mask_text(arg)[:each]


def masked_argv(argv: list[str], *, limit: int = 12, each: int = 200) -> list[str]:
    out = [_arg(arg, each) for arg in argv[:limit]]
    if len(argv) > limit:
        out.append(f"... ({len(argv) - limit} more)")
    return out
