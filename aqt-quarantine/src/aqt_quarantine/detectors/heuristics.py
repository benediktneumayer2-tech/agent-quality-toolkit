"""Built-in, explainable injection heuristics (English and German).

Pattern groups describe *categories* of text that tries to steer a tool-using
agent; they are keyword patterns written for this package, not copied attack
sentences. The score is a deterministic noisy-OR of per-hit weights, reported
in ppm. It is **uncalibrated**: use aqt-validate to set thresholds on your own
benign traffic. Easy to evade by an adaptive attacker; it is a triage signal.

Before matching, the text is normalised (NFKC per character), invisible
characters (zero-width, bidi controls, soft hyphen) are dropped and counted,
and Unicode tag characters (U+E0020..U+E007E, "ASCII smuggling") are decoded
to the ASCII they hide. Spans are mapped back to offsets in the input text.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import unicodedata
from dataclasses import dataclass

from . import DetectorResult, Span

FLAGS = re.IGNORECASE | re.MULTILINE
_AGENT = r"(?:ai|a\.i\.|assistant|agent|llm|language model|chat ?bot|claude|gpt|gemini|copilot|coding agent)"

# group -> (weight per hit, max counted hits, plain-language reason, patterns)
GROUPS: dict[str, tuple[float, int, str, list[str]]] = {
    "override": (0.40, 2, "tries to override the agent's instructions", [
        r"\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}?\b(?:previous|prior|above|earlier|preceding|"
        r"original|all|any|your|system)\b[^.\n]{0,30}?\b(?:instructions?|prompts?|rules|directions|guidelines|tasks?)\b",
        r"\b(?:new|updated|real|actual|hidden|secret)\s+(?:instructions?|task|directive|orders)\b",
        r"\bfrom now on\b",
        r"\b(?:do not|don't|never)\s+(?:tell|inform|notify|mention|alert)\b[^.\n]{0,30}\b(?:user|owner|human|anyone)\b",
        r"\bwithout (?:asking|telling|informing|notifying|confirmation|permission)\b",
        r"\b(?:ignoriere|vergiss|missachte|übergehe)\b[^.\n]{0,40}?\b(?:vorherigen?|bisherigen?|obigen?|alle[nm]?|"
        r"deine[nm]?)\b[^.\n]{0,30}?\b(?:anweisungen|anweisung|befehle|regeln|vorgaben|aufgaben?)\b",
        r"\bneue\s+(?:anweisung(?:en)?|aufgabe|befehle)\b",
        r"\bab (?:jetzt|sofort) (?:bist|sollst|musst|gilt)\b",
        r"\bohne (?:nachzufragen|rückfrage|zu fragen|bestätigung|erlaubnis)\b",
    ]),
    "addressed": (0.15, 3, "addresses the AI agent directly", [
        rf"\b(?:dear|hey|hello|attention|note to|message (?:to|for))\s+(?:the\s+)?{_AGENT}s?\b",
        rf"\b(?:if you are|you are|as) an? {_AGENT}\b",
        rf"\b{_AGENT}s?\s+(?:reading|processing|summari[sz]ing|browsing)\s+(?:this|these)\b",
        r"\byou (?:must|should now|need to|have to|are (?:required|instructed) to|will now)\b",
        r"\byour (?:new |real |actual |primary |true )?(?:task|goal|instructions?|objective|mission)\b",
        r"\b(?:liebe[rs]?|hallo|achtung)\s+(?:ki|assistent(?:in)?|agent|sprachmodell)\b",
        r"\bdu (?:musst|sollst)\b",
        r"\bdeine (?:neue |eigentliche |wahre )?(?:aufgabe|anweisung|mission)\b",
        r"\bwenn du (?:eine ki|ein (?:ki-)?(?:assistent|agent|sprachmodell)) bist\b",
    ]),
    "framing": (0.25, 2, "fakes a system, role or document boundary", [
        r"<\|?\s*/?\s*(?:system|assistant|user|im_start|im_end|endoftext|eot_id|start_header_id)\s*\|?>",
        r"\[/?\s*(?:INST|SYS|SYSTEM)\s*\]",
        r"</?\s*(?:system|instructions?|tool_?(?:result|output|response)|function_?(?:results?|calls?)|admin)\s*>",
        r"(?:^|\n)\s*#{0,4}\s*(?:system|assistant)\s*(?:message|prompt)?\s*:\s",
        r"\b(?:important|urgent|critical)\s+(?:system\s+)?(?:message|notice|instructions?|update)\b",
        r"\b(?:end|begin) of (?:the )?(?:document|search results?|tool (?:output|result)|context|untrusted content)\b",
        r"\b(?:wichtige|dringende)\s+(?:system)?(?:nachricht|anweisung|mitteilung)\b",
    ]),
    "toolcall": (0.20, 2, "tells the agent to call tools or run commands", [
        r"\b(?:use|call|invoke|run|execute) (?:the )?[`'\"]?[\w.-]+[`'\"]? (?:tool|function)\b",
        r"\"(?:function_call|tool_calls?|tool_use)\"\s*:",
        r"<\s*(?:tool_call|function_call|invoke)\b",
        r"\b(?:curl|wget)\b[^\n]{0,120}?(?:\s-d\b|--data|-X\s*(?:POST|PUT)|--upload-file|-T\s)",
        r"\|\s*(?:sudo\s+)?(?:ba|z)?sh\b",
        r"\brm\s+-[rf]{1,2}\s+[~/]",
        r"\b(?:rufe|nutze|verwende)\b[^.\n]{0,30}\b(?:tool|werkzeug|funktion)\b[^.\n]{0,20}\bauf\b",
        r"\bführe\b[^.\n]{0,40}\b(?:befehl|kommando|skript)\b[^.\n]{0,30}\baus\b",
    ]),
    "exfil": (0.35, 2, "asks to send data somewhere", [
        r"https?://[^\s\"')\]]*[?&][\w.-]+=(?:\{|\$|%7B|<|\[)",
        r"!\[[^\]]{0,80}\]\(\s*https?://[^)\s]*\?[^)\s]+\)",
        r"\b(?:send|forward|e-?mail|upload|post|transfer|leak|exfiltrate)\b[^.\n]{0,60}\b(?:passwords?|credentials?|"
        r"keys?|tokens?|secrets?|files?|history|conversation|contents?|data)\b[^.\n]{0,60}\b(?:to|at)\s+(?:https?://|[\w.+-]+@)",
        r"\b(?:sende|schicke|übermittle|lade)\b[^.\n]{0,60}\b(?:passw[öo]rter|passwort|zugangsdaten|schlüssel|tokens?|"
        r"geheimnisse|dateien|inhalte?|daten|verlauf)\b[^.\n]{0,60}\b(?:an|nach|hoch)\b",
    ]),
    "secret": (0.08, 2, "names secrets or credential files", [
        r"~/\.ssh\b|\bid_(?:rsa|ed25519|ecdsa)\b|\.aws/credentials|(?<![\w.])\.env\b|\.netrc\b|/etc/shadow\b|"
        r"\.kube/config|\.docker/config\.json|\bauth\.json\b",
        r"(?-i:\b[A-Z][A-Z0-9]*_(?:API_?KEY|TOKEN|SECRET|PASSWORD|ACCESS_KEY|PRIVATE_KEY)\b)",
        r"\b(?:api[ _-]?keys?|access[ _-]?tokens?|private keys?|credentials|recovery (?:codes?|phrase)|seed phrase)\b",
        r"\b(?:zugangsdaten|api-?schlüssel|privaten? schlüssel)\b",
    ]),
}
HIDDEN_REASON = "hides text from human readers"
HIDDEN_TAGS = HIDDEN_REASON + " (Unicode tag characters)"
HIDDEN_INVISIBLE = HIDDEN_REASON + " ({n} zero-width or bidi characters)"
HIDDEN_MARKUP = HIDDEN_REASON + " (HTML comment or CSS-hidden element)"
ENCODED_REASON = "carries an encoded payload with instructions"
# Message codes of the reasons, for aqt-ui's catalogue (plain strings: this module imports nothing heavy). Records
# keep only the English reason; a reader finds the code by the span's label and, for "hidden", by the text.
REASON_CODES = {**{f"quarantine.detector.{group}": spec[2] for group, spec in GROUPS.items()},
                "quarantine.detector.hidden_tags": HIDDEN_TAGS, "quarantine.detector.hidden_invisible": HIDDEN_INVISIBLE,
                "quarantine.detector.hidden_markup": HIDDEN_MARKUP, "quarantine.detector.encoded": ENCODED_REASON}
W_TAG_CHARS = 0.50          # any Unicode tag characters (invisible ASCII)
W_INVISIBLE = 0.30          # three or more zero-width / bidi characters
W_HIDDEN_MARKUP = 0.20      # HTML comment or CSS-hidden element containing words
W_ENCODED_HIT = 0.35        # decoded base64 matches a pattern group
MAX_SPANS = 50
MAX_BLOBS = 20

INVISIBLE = frozenset(
    [0x00AD, 0x180E, 0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF]
    + list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A)))
_COMPILED = {group: [re.compile(p, FLAGS) for p in spec[3]] for group, spec in GROUPS.items()}
_HIDDEN_MARKUP = [
    re.compile(r"<!--(?=[^>]{0,2000}?[A-Za-zÄÖÜäöü]{3}).{1,2000}?-->", re.DOTALL),
    re.compile(r"<[a-z][^>]{0,200}style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|"
               r"font-size\s*:\s*0(?:px|pt|em)?\s*[;\"']|opacity\s*:\s*0(?:\.0+)?\s*[;\"'])[^>]*>[^<]{3,}", FLAGS),
]
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
VERSION = "0.1.0+" + hashlib.sha256(repr(sorted((g, s[0], s[1], tuple(s[3])) for g, s in GROUPS.items())).encode()
                                    ).hexdigest()[:12]


@dataclass
class Normalised:
    text: str
    index: list[int]        # index[i] = offset in the input of normalised char i
    invisible: list[int]    # input offsets of dropped invisible characters
    tags: list[int]         # input offsets of decoded tag characters


def normalise(text: str) -> Normalised:
    out: list[str] = []
    index: list[int] = []
    invisible: list[int] = []
    tags: list[int] = []
    for offset, char in enumerate(text):
        code = ord(char)
        if code in INVISIBLE:
            invisible.append(offset)
            continue
        if 0xE0000 <= code <= 0xE007F:
            tags.append(offset)
            if 0xE0020 <= code <= 0xE007E:
                out.append(chr(code - 0xE0000))
                index.append(offset)
            continue
        for piece in unicodedata.normalize("NFKC", char):
            out.append(piece)
            index.append(offset)
    return Normalised("".join(out), index, invisible, tags)


def _map(norm: Normalised, start: int, end: int, length: int) -> tuple[int, int]:
    if not norm.index:
        return 0, min(1, length)
    a = norm.index[min(start, len(norm.index) - 1)]
    b = norm.index[min(max(end - 1, start), len(norm.index) - 1)] + 1
    return a, max(b, a + 1)


def _group_hits(text: str) -> dict[str, list[tuple[int, int]]]:
    hits: dict[str, list[tuple[int, int]]] = {}
    for group, patterns in _COMPILED.items():
        spans = sorted({m.span() for rx in patterns for m in rx.finditer(text) if m.end() > m.start()})
        if spans:
            hits[group] = spans
    return hits


def _decoded_blobs(text: str) -> list[tuple[int, int, str]]:
    blobs = []
    for match in _BASE64.finditer(text):
        if len(blobs) >= MAX_BLOBS:
            break
        raw = match.group(0)
        try:
            decoded = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True).decode("utf-8")
        except (binascii.Error, ValueError):
            continue
        printable = sum(ch.isprintable() or ch in "\n\t" for ch in decoded)
        if decoded and printable >= 0.9 * len(decoded):
            blobs.append((match.start(), match.end(), decoded))
    return blobs


class HeuristicsDetector:
    """Built-in detector. Options: none (the weights are part of the version)."""

    name = "heuristics"
    version = VERSION

    def __init__(self, **_options):
        pass

    def score(self, text: str) -> DetectorResult:
        norm = normalise(text)
        survive = 1.0
        spans: list[Span] = []

        def add(start: int, end: int, label: str, reason: str, *, mapped: bool = False) -> None:
            if len(spans) >= MAX_SPANS:
                return
            a, b = (start, end) if mapped else _map(norm, start, end, len(text))
            if 0 <= a < b <= len(text):
                spans.append(Span(a, b, label, reason))

        for group, found in _group_hits(norm.text).items():
            weight, cap, reason, _ = GROUPS[group]
            survive *= (1 - weight) ** min(len(found), cap)
            for start, end in found:
                add(start, end, group, reason)
        if norm.tags:
            survive *= 1 - W_TAG_CHARS
            add(norm.tags[0], norm.tags[-1] + 1, "hidden", HIDDEN_TAGS, mapped=True)
        if len(norm.invisible) >= 3:
            survive *= 1 - W_INVISIBLE
            add(norm.invisible[0], norm.invisible[0] + 1, "hidden", HIDDEN_INVISIBLE.format(n=len(norm.invisible)),
                mapped=True)
        markup = [m.span() for rx in _HIDDEN_MARKUP for m in rx.finditer(norm.text)]
        if markup:
            survive *= 1 - W_HIDDEN_MARKUP
            for start, end in markup[:5]:
                add(start, end, "hidden", HIDDEN_MARKUP)
        encoded = 0
        for start, end, decoded in _decoded_blobs(norm.text):
            if _group_hits(decoded):
                encoded += 1
                add(start, end, "encoded", ENCODED_REASON)
        if encoded:
            survive *= (1 - W_ENCODED_HIT) ** min(encoded, 2)
        score = int(round((1 - survive) * 1_000_000))
        spans.sort(key=lambda span: (span.start, span.end))
        return DetectorResult(max(0, min(score, 1_000_000)), spans)
