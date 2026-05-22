"""Sprint 9 T9 — ISO 42001 control-tagging coverage: 3 implemented + 5 deferred."""

from __future__ import annotations

import re
from pathlib import Path

import cognic_agentos
from cognic_agentos.compliance.iso42001.controls import (
    ISO42001_CONTROLS,
    audit_coverage,
    control_ids,
)

#: The installed `src/cognic_agentos/` package root — this test reads the
#: real governance emission-site source files.
_SRC = Path(cognic_agentos.__file__).resolve().parent

#: The emission-site files the T8 audit named for the 3 `implemented`
#: controls. The observed canonical-emission set is built by scanning
#: THESE files' source — NOT by re-reading the registry — so a raw-form
#: regression at any site is caught.
_EMISSION_SITES = (
    "llm/gateway.py",  # A.9.2
    "core/guardrails.py",  # A.7.4
    "core/policy/engine.py",  # A.7.4
    "protocol/trust_gate.py",  # A.7.4 (T9-reconciled)
    "protocol/plugin_registry.py",  # A.7.4 (T9-reconciled)
    "sandbox/audit.py",  # A.6.2.5 (T9-reconciled)
)

#: The 3 files T9 reconciles raw -> canonical; none may keep a raw tag.
_RECONCILED_SITES = (
    "sandbox/audit.py",
    "protocol/trust_gate.py",
    "protocol/plugin_registry.py",
)

#: A canonical ID inside an `iso_controls=(...)` tuple literal.
_CANONICAL_RE = re.compile(r'iso_controls\s*=\s*\(\s*"(ISO42001\.A\.[0-9.]+)"')
#: A raw (un-prefixed) `A.x.y` code inside an `iso_controls=(...)` tuple.
_RAW_RE = re.compile(r'iso_controls\s*=\s*\(\s*"(A\.[0-9.]+)"')

_IMPLEMENTED = {"ISO42001.A.9.2", "ISO42001.A.7.4", "ISO42001.A.6.2.5"}


def _observed_canonical_ids() -> set[str]:
    observed: set[str] = set()
    for rel in _EMISSION_SITES:
        text = (_SRC / rel).read_text(encoding="utf-8")
        observed |= set(_CANONICAL_RE.findall(text))
    return observed


def test_implemented_controls_emit_canonically() -> None:
    coverage = audit_coverage(_observed_canonical_ids())
    for record in coverage.values():
        if record.hook_status == "implemented":
            assert record.emitted is True, record.control_id
            assert record.deferred_reason == "", record.control_id


def test_deferred_controls_recorded_with_reasons() -> None:
    coverage = audit_coverage(_observed_canonical_ids())
    for record in coverage.values():
        if record.hook_status == "deferred":
            assert record.emitted is False, record.control_id
            assert record.deferred_reason != "", record.control_id


def test_registry_holds_all_eight_with_three_implemented() -> None:
    assert len(ISO42001_CONTROLS) == 8
    assert len(control_ids()) == 8
    implemented = {e.control_id for e in ISO42001_CONTROLS if e.hook_status == "implemented"}
    deferred = {e.control_id for e in ISO42001_CONTROLS if e.hook_status == "deferred"}
    assert implemented == _IMPLEMENTED
    assert len(deferred) == 5
    assert implemented | deferred == control_ids()


def test_no_raw_form_survives_at_reconciled_sites() -> None:
    """The 3 T9-reconciled files must carry NO raw `("A.x.y",)` ADR-006
    tag — only the canonical `ISO42001.`-prefixed form."""
    for rel in _RECONCILED_SITES:
        text = (_SRC / rel).read_text(encoding="utf-8")
        raw = _RAW_RE.findall(text)
        assert raw == [], f"{rel} still emits raw ADR-006 tags: {raw}"
