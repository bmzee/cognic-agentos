from __future__ import annotations

import dataclasses
import re
from pathlib import Path
from typing import Protocol

#: Mirror of cli/_governance_vocab.RESTRICTED_DATA_CLASSES (no runtime core->cli import).
DLP_RESTRICTED_CLASSES: frozenset[str] = frozenset(
    {"customer_pii", "payment_data", "credentials", "regulator_communication"}
)


@dataclasses.dataclass(frozen=True, slots=True)
class RedactionSpan:
    data_class: str
    start: int
    end: int


@dataclasses.dataclass(frozen=True, slots=True)
class DLPVerdict:
    detected_classes: frozenset[str]
    redaction_spans: tuple[RedactionSpan, ...]
    confidence: float


class DLPScanner(Protocol):
    def scan(self, value: object) -> DLPVerdict: ...


def _luhn_ok(digits: str) -> bool:
    s, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        s += d
        alt = not alt
    return s % 10 == 0


def _iban_ok(iban: str) -> bool:
    s = iban[4:] + iban[:4]
    n = "".join(str(ord(c) - 55) if c.isalpha() else c for c in s)
    return int(n) % 97 == 1


_PAN_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
_SWIFT_RE = re.compile(r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b")
_SWIFT_CUE_RE = re.compile(r"\b(?:BIC|SWIFT)\b", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_PHONE_RE = re.compile(r"(?<!\w)\+\d{8,15}(?!\w)")
_REGULATORS: frozenset[str] = frozenset(
    Path(__file__).with_name("_regulators.txt").read_text().split()
)


class ChecksumRegexGazetteerScanner:
    """Real, deterministic DLP seed — no model deps. Free-text person names /
    addresses / contextual-org detection are DEFERRED to Presidio (Sprint 13.5);
    the DLPScanner Protocol makes Presidio a drop-in adapter there."""

    def scan(self, value: object) -> DLPVerdict:
        text = value if isinstance(value, str) else repr(value)
        classes: set[str] = set()
        spans: list[RedactionSpan] = []
        for m in _PAN_RE.finditer(text):
            digits = re.sub(r"[ -]", "", m.group())
            if 13 <= len(digits) <= 19 and _luhn_ok(digits):
                classes.add("payment_data")
                spans.append(RedactionSpan("payment_data", m.start(), m.end()))
        for m in _IBAN_RE.finditer(text):
            if _iban_ok(m.group()):
                classes.add("payment_data")
                spans.append(RedactionSpan("payment_data", m.start(), m.end()))
        for m in _SWIFT_RE.finditer(text):
            if _SWIFT_CUE_RE.search(text[max(0, m.start() - 12) : m.start()]):
                classes.add("payment_data")
                spans.append(RedactionSpan("payment_data", m.start(), m.end()))
        for rx, cls in ((_EMAIL_RE, "customer_pii"), (_PHONE_RE, "customer_pii")):
            for m in rx.finditer(text):
                classes.add(cls)
                spans.append(RedactionSpan(cls, m.start(), m.end()))
        for m in re.finditer(r"\b\w+\b", text):
            if m.group() in _REGULATORS:
                classes.add("regulator_communication")
                spans.append(RedactionSpan("regulator_communication", m.start(), m.end()))
        return DLPVerdict(
            detected_classes=frozenset(classes),
            redaction_spans=tuple(spans),
            confidence=1.0 if classes else 0.0,
        )
