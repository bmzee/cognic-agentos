"""Sprint 12 (ADR-010) — ISO 42001 control-tagging coverage: 8 implemented + 0 deferred.

Sprint 9 shipped the registry with 3 implemented + 5 deferred. Sprint 9.5
A6 promoted 4 deferred controls to ``implemented`` because the model
registry primitive (per ADR-013) creates a real ``model.lifecycle.*``
chain emission surface tagging them:

* ``A.6.2.6`` — Roles and responsibilities
* ``A.8.2``   — Data quality for AI systems
* ``A.8.5``   — AI system development
* ``A.10.2``  — Stakeholder transparency

``A.7.4`` (AI system impact assessment) was already implemented at Sprint
9 (gateway / guardrails / policy / trust-gate / plugin-registry sites);
the model registry also tags it but no flip is needed.

``A.7.6`` (AI system risk evaluation) was the SOLE remaining deferred
control at Sprint 9.5. Sprint 12 (ADR-010) flips it to ``implemented``
because the bulk evaluation harness lands the real ``eval.bulk_run``
emission surface tagging it (the harness IS an AI-system risk-evaluation
surface). The same hook also tags ``A.9.2`` (system and operational
logging). The deferred set is now empty.
"""

from __future__ import annotations

import re
from pathlib import Path

import cognic_agentos
from cognic_agentos.compliance.iso42001.controls import (
    ISO42001_CONTROLS,
    audit_coverage,
    control_ids,
)
from cognic_agentos.models.registry import MODEL_LIFECYCLE_ISO_CONTROLS

#: The installed `src/cognic_agentos/` package root — this test reads the
#: real governance emission-site source files.
_SRC = Path(cognic_agentos.__file__).resolve().parent

#: The emission-site files the Sprint-9 T8 audit named for the 3
#: originally-implemented controls. The observed canonical-emission set
#: is built by scanning THESE files' source — NOT by re-reading the
#: registry — so a raw-form regression at any site is caught.
_EMISSION_SITES = (
    "llm/gateway.py",  # A.9.2
    "core/guardrails.py",  # A.7.4
    "core/policy/engine.py",  # A.7.4
    "protocol/trust_gate.py",  # A.7.4 (T9-reconciled)
    "protocol/plugin_registry.py",  # A.7.4 (T9-reconciled)
    "sandbox/audit.py",  # A.6.2.5 (T9-reconciled)
)

#: The 3 files Sprint-9 T9 reconciles raw -> canonical; none may keep a
#: raw tag.
_RECONCILED_SITES = (
    "sandbox/audit.py",
    "protocol/trust_gate.py",
    "protocol/plugin_registry.py",
)

#: Sprint 9.5 A6 — the model registry emits 5 canonical ISO controls on
#: every ``model.lifecycle.*`` chain row via the
#: ``MODEL_LIFECYCLE_ISO_CONTROLS`` constant in ``models/registry.py``.
#: The scan is **constant-anchored**: we extract the tuple body via
#: :data:`_MODEL_CONSTANT_RE` first and then apply
#: :data:`_CANONICAL_LITERAL_RE` to the body only — never to the whole
#: file. This defends against future docstring / comment additions that
#: might mention an ``"ISO42001.A.x.y"`` literal (false-positive guard
#: per the user-locked Sprint-9.5 A6 invariant: scan the model emission
#: source without false positives or brittle substring matching).
_MODEL_EMISSION_SITES = ("models/registry.py",)
_MODEL_CONSTANT_RE = re.compile(r"MODEL_LIFECYCLE_ISO_CONTROLS:[^=]*=\s*\(([^)]*)\)")

#: Sprint 12 (ADR-010) — the bulk eval harness emits 2 canonical ISO
#: controls (A.7.6 + A.9.2) on every ``eval.bulk_run`` chain row via the
#: ``_EVAL_ISO_CONTROLS`` constant in ``evaluation/storage.py``. This is
#: the real emission surface that makes the Sprint-12 A.7.6 flip from
#: ``deferred`` to ``implemented`` honest. Scanned constant-anchored,
#: identically to the model-registry constant above (extract the tuple
#: body via :data:`_EVAL_CONSTANT_RE`, then apply
#: :data:`_CANONICAL_LITERAL_RE` to the body only — never the whole file).
_EVAL_EMISSION_SITES = ("evaluation/storage.py",)
_EVAL_CONSTANT_RE = re.compile(r"_EVAL_ISO_CONTROLS:[^=]*=\s*\(([^)]*)\)")

#: A canonical ID inside an ``iso_controls=(...)`` tuple literal
#: (Sprint-9 emission-site convention).
_CANONICAL_RE = re.compile(r'iso_controls\s*=\s*\(\s*"(ISO42001\.A\.[0-9.]+)"')
#: A raw (un-prefixed) ``A.x.y`` code inside an ``iso_controls=(...)``
#: tuple — used by the no-raw-form regression at the reconciled sites.
_RAW_RE = re.compile(r'iso_controls\s*=\s*\(\s*"(A\.[0-9.]+)"')
#: A canonical ID literal — applied ONLY against the matched tuple body
#: of :data:`_MODEL_CONSTANT_RE`, never the whole file.
_CANONICAL_LITERAL_RE = re.compile(r'"(ISO42001\.A\.[0-9.]+)"')

_IMPLEMENTED = {
    "ISO42001.A.6.2.5",
    "ISO42001.A.6.2.6",
    "ISO42001.A.7.4",
    "ISO42001.A.7.6",
    "ISO42001.A.8.2",
    "ISO42001.A.8.5",
    "ISO42001.A.9.2",
    "ISO42001.A.10.2",
}


def _scan_constant_for_canonical_ids(rel: str, constant_re: re.Pattern[str]) -> set[str]:
    """Extract canonical ISO IDs from the tuple body matched by
    ``constant_re`` in ``rel`` — NOT from the whole file. Returns the set
    of canonical IDs declared inside the constant's parentheses.
    """
    text = (_SRC / rel).read_text(encoding="utf-8")
    match = constant_re.search(text)
    if match is None:
        return set()
    return set(_CANONICAL_LITERAL_RE.findall(match.group(1)))


def _scan_model_constant_for_canonical_ids(rel: str) -> set[str]:
    """Extract canonical ISO IDs from the
    ``MODEL_LIFECYCLE_ISO_CONTROLS`` tuple body in ``rel`` — NOT from
    the whole file. Returns the set of canonical IDs declared inside
    the constant's parentheses.
    """
    return _scan_constant_for_canonical_ids(rel, _MODEL_CONSTANT_RE)


def _observed_canonical_ids() -> set[str]:
    observed: set[str] = set()
    for rel in _EMISSION_SITES:
        text = (_SRC / rel).read_text(encoding="utf-8")
        observed |= set(_CANONICAL_RE.findall(text))
    for rel in _MODEL_EMISSION_SITES:
        observed |= _scan_model_constant_for_canonical_ids(rel)
    for rel in _EVAL_EMISSION_SITES:
        observed |= _scan_constant_for_canonical_ids(rel, _EVAL_CONSTANT_RE)
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


def test_registry_holds_all_eight_all_implemented() -> None:
    assert len(ISO42001_CONTROLS) == 8
    assert len(control_ids()) == 8
    implemented = {e.control_id for e in ISO42001_CONTROLS if e.hook_status == "implemented"}
    deferred = {e.control_id for e in ISO42001_CONTROLS if e.hook_status == "deferred"}
    assert implemented == _IMPLEMENTED
    assert deferred == set()
    assert implemented | deferred == control_ids()


def test_no_raw_form_survives_at_reconciled_sites() -> None:
    """The 3 Sprint-9 T9-reconciled files must carry NO raw
    ``("A.x.y",)`` ADR-006 tag — only the canonical
    ``ISO42001.``-prefixed form.
    """
    for rel in _RECONCILED_SITES:
        text = (_SRC / rel).read_text(encoding="utf-8")
        raw = _RAW_RE.findall(text)
        assert raw == [], f"{rel} still emits raw ADR-006 tags: {raw}"


def test_model_emission_scan_matches_runtime_constant() -> None:
    """Source-scan of ``models/registry.py`` returns EXACTLY the values
    in :data:`MODEL_LIFECYCLE_ISO_CONTROLS` — no extras (false-positive
    guard against future docstring / comment IDs), no missing (regex
    sanity check that we actually find + parse the constant block).

    Pins the user-locked Sprint-9.5 A6 invariant: scans the model
    emission source without false positives or brittle substring
    matching.
    """
    scanned: set[str] = set()
    for rel in _MODEL_EMISSION_SITES:
        scanned |= _scan_model_constant_for_canonical_ids(rel)
    assert scanned == set(MODEL_LIFECYCLE_ISO_CONTROLS)


def test_eval_emission_scan_matches_runtime_constant() -> None:
    """Source-scan of ``evaluation/storage.py`` returns EXACTLY the
    values in the runtime ``_EVAL_ISO_CONTROLS`` constant — the real
    ``eval.bulk_run`` emission surface that makes the Sprint-12 (ADR-010)
    A.7.6 flip to ``implemented`` honest. No extras (false-positive
    guard against future docstring / comment IDs), no missing (regex
    sanity check that we actually find + parse the constant block).
    """
    from cognic_agentos.evaluation.storage import _EVAL_ISO_CONTROLS

    scanned: set[str] = set()
    for rel in _EVAL_EMISSION_SITES:
        scanned |= _scan_constant_for_canonical_ids(rel, _EVAL_CONSTANT_RE)
    assert scanned == set(_EVAL_ISO_CONTROLS)


def test_a76_flipped_to_implemented_with_empty_reason() -> None:
    """A.7.6 (AI system risk evaluation) flips from ``deferred`` to
    ``implemented`` at Sprint 12 (ADR-010): the bulk evaluation harness
    lands the real ``eval.bulk_run`` emission surface tagging it, so the
    last remaining deferred control is now implemented and — per the
    registry invariant that every implemented control carries an empty
    ``deferred_reason`` — its reason is cleared.
    """
    a76 = next(e for e in ISO42001_CONTROLS if e.control_id == "ISO42001.A.7.6")
    assert a76.hook_status == "implemented"
    assert a76.deferred_reason == ""
