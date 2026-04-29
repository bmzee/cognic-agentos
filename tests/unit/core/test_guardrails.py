"""Sprint 2.5 Task 5 — guardrail Protocol + result dataclasses
+ pipeline shell.

T5 lands the SHAPES — runtime-checkable ``Guardrail`` Protocol,
frozen+slotted ``GuardrailResult`` / ``PipelineResult``, and the
``GuardrailDirection`` StrEnum. The pipeline's ``check()`` body
+ audit emission lands in T7; bundled regex filters land in T6.

**Critical-controls module.** Per AGENTS.md + the Sprint 2.5 plan
(merged at PR #7 / commit ``4733b52``): ≥95% line + ≥90% branch
coverage, halt-before-commit per edit.

Tests cover:

  - ``Guardrail`` Protocol is ``runtime_checkable``; a class with
    ``name: str`` + ``check(content) -> GuardrailResult`` passes
    ``isinstance(x, Guardrail)``; a class missing ``check`` fails.
  - ``GuardrailResult`` + ``PipelineResult`` are frozen + slotted;
    attribute mutation raises ``FrozenInstanceError``.
  - ``GuardrailDirection`` StrEnum has exactly INPUT + OUTPUT; the
    values are lowercase strings (canonical-form invariant from
    Sprint 2 R3 — only string-valued enums round-trip cleanly).
  - ``GuardrailPipeline`` constructor stores its guardrails tuple +
    AuditStore reference; ``check()`` shell raises ``NotImplementedError``
    until T7 wires the body.
"""

from __future__ import annotations

import dataclasses

import pytest

from cognic_agentos.core.guardrails import (
    Guardrail,
    GuardrailDirection,
    GuardrailPipeline,
    GuardrailResult,
    PipelineResult,
)


class TestGuardrailDirectionEnum:
    """StrEnum with exactly INPUT + OUTPUT, both lowercase strings."""

    def test_values_match_contract(self) -> None:
        assert GuardrailDirection.INPUT.value == "input"
        assert GuardrailDirection.OUTPUT.value == "output"

    def test_two_members_exact(self) -> None:
        assert {d.value for d in GuardrailDirection} == {"input", "output"}

    def test_str_enum_is_str_subclass(self) -> None:
        # canonical-form serializer relies on this; mirrors SLAStatus
        # + EscalationState shape from T1 / T3.
        assert isinstance(GuardrailDirection.INPUT, str)
        assert str(GuardrailDirection.INPUT) == "input"


class TestGuardrailResultDataclass:
    """GuardrailResult is frozen + slotted; mutation raises;
    matches/detail defaults match contract."""

    def _sample(self) -> GuardrailResult:
        return GuardrailResult(
            guardrail_name="canary",
            passed=True,
        )

    def test_minimal_construction(self) -> None:
        r = self._sample()
        assert r.guardrail_name == "canary"
        assert r.passed is True
        assert r.matches == ()  # default empty tuple
        assert r.detail is None  # default None

    def test_full_construction(self) -> None:
        r = GuardrailResult(
            guardrail_name="pii.regex",
            passed=False,
            matches=("credit_card", "email"),
            detail="2 patterns tripped",
        )
        assert r.passed is False
        assert r.matches == ("credit_card", "email")
        assert r.detail == "2 patterns tripped"

    def test_matches_is_tuple_not_list(self) -> None:
        # Tuple is the canonical-form-safe shape (lists are mutable;
        # canonical_bytes accepts both, but tuple matches the
        # iso_controls pattern from Sprint 2 — immutable diagnostic
        # collection).
        r = self._sample()
        assert isinstance(r.matches, tuple)

    def test_frozen_rejects_mutation(self) -> None:
        r = self._sample()
        with pytest.raises(dataclasses.FrozenInstanceError):
            r.passed = False  # type: ignore[misc]


class TestPipelineResultDataclass:
    """PipelineResult is frozen + slotted; aggregate over the
    pipeline's per-guardrail results."""

    def _sample(self) -> PipelineResult:
        return PipelineResult(
            direction=GuardrailDirection.INPUT,
            passed=True,
            results=(
                GuardrailResult(guardrail_name="g1", passed=True),
                GuardrailResult(guardrail_name="g2", passed=True),
            ),
        )

    def test_construction(self) -> None:
        p = self._sample()
        assert p.direction == GuardrailDirection.INPUT
        assert p.passed is True
        assert len(p.results) == 2

    def test_results_is_tuple(self) -> None:
        # Same rationale as GuardrailResult.matches — tuple is the
        # immutable-aggregate shape.
        p = self._sample()
        assert isinstance(p.results, tuple)

    def test_frozen_rejects_mutation(self) -> None:
        p = self._sample()
        with pytest.raises(dataclasses.FrozenInstanceError):
            p.passed = False  # type: ignore[misc]


class TestGuardrailProtocol:
    """``Guardrail`` is a runtime-checkable Protocol; ``isinstance``
    is the structural-typing test for caller-supplied filters."""

    def test_class_with_name_and_check_passes_isinstance(self) -> None:
        class _GoodGuardrail:
            name: str = "good"

            def check(self, content: str) -> GuardrailResult:
                return GuardrailResult(guardrail_name=self.name, passed=True)

        assert isinstance(_GoodGuardrail(), Guardrail)

    def test_class_missing_check_fails_isinstance(self) -> None:
        class _NoCheck:
            name: str = "missing-check"

        # Protocol's runtime_checkable looks for the attribute; missing
        # `check` → not a structural match.
        assert not isinstance(_NoCheck(), Guardrail)

    def test_class_missing_name_attribute_fails_isinstance(self) -> None:
        class _NoName:
            def check(self, content: str) -> GuardrailResult:
                return GuardrailResult(guardrail_name="x", passed=True)

        assert not isinstance(_NoName(), Guardrail)

    def test_check_returns_guardrail_result(self) -> None:
        # Sanity: a structurally-conforming filter returns a
        # GuardrailResult that the pipeline can aggregate. T6 will
        # land bundled filters; T7 will wire the pipeline check.
        class _Stub:
            name: str = "stub"

            def check(self, content: str) -> GuardrailResult:
                return GuardrailResult(
                    guardrail_name=self.name,
                    passed=not bool(content),  # trips on non-empty input
                )

        s = _Stub()
        assert isinstance(s, Guardrail)
        r1 = s.check("")
        r2 = s.check("anything")
        assert r1.passed is True
        assert r2.passed is False


class TestGuardrailPipelineShell:
    """T5 lands the pipeline constructor + the placeholder check()
    that raises NotImplementedError until T7 wires the body. Tests
    pin the shell shape so T7 can extend without breaking the
    stored-state contract."""

    def test_constructor_stores_guardrails_and_audit_store(self) -> None:
        # The pipeline accepts a tuple of guardrails + an AuditStore
        # reference. We don't actually need a real AuditStore for
        # the shell-shape test — a sentinel object is enough to
        # confirm the constructor binds it.
        sentinel_store = object()

        class _G:
            name: str = "g"

            def check(self, content: str) -> GuardrailResult:
                return GuardrailResult(guardrail_name=self.name, passed=True)

        g = _G()
        pipeline = GuardrailPipeline(
            guardrails=(g,),
            audit_store=sentinel_store,  # type: ignore[arg-type]
        )
        # Stored references are accessible via the conventional
        # private-attribute names (this is testing the shell only;
        # T7 may rename if needed).
        assert pipeline._guardrails == (g,)
        assert pipeline._audit_store is sentinel_store

    def test_check_raises_not_implemented_until_t7(self) -> None:
        # The shell's check() raises NotImplementedError so callers
        # can't accidentally use a half-built pipeline. T7 replaces
        # the body with the actual run-all-guardrails + emit-on-trip
        # logic.
        sentinel_store = object()
        pipeline = GuardrailPipeline(
            guardrails=(),
            audit_store=sentinel_store,  # type: ignore[arg-type]
        )

        import asyncio

        with pytest.raises(NotImplementedError):
            asyncio.run(
                pipeline.check(
                    "content",
                    direction=GuardrailDirection.INPUT,
                    request_id="req-shell-1",
                )
            )
