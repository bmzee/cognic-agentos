"""Sprint-7A2 T2 — `agentos_sdk.Hook` base-class regressions.

Mirrors the Sprint-7A T2 ``Tool`` / ``Skill`` test pattern: pin the
template-method seam, the ``__init_subclass__`` mixin guard, the
``HookContext`` / ``HookResult`` frozen+slotted invariants, and the
context / payload / result validation surfaces. Every test pinpoints
a specific contract the SDK base owes pack authors.

Per Doctrine Decision E: this surface is public API; halt-before-
commit on every change.
"""

from __future__ import annotations

import dataclasses
from typing import Any, ClassVar

import pytest

from cognic_agentos.cli._governance_vocab import HookPhase
from cognic_agentos.sdk.hook import (
    Hook,
    HookContext,
    HookContextError,
    HookContractError,
    HookError,
    HookPayloadError,
    HookResult,
    HookResultShapeError,
)

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _ctx(**overrides: Any) -> HookContext:
    """Build a HookContext with sensible defaults; overrides land via
    kwargs. Keeps individual tests focused on the field under test."""
    defaults: dict[str, Any] = {
        "hook_id": "redact_pii_in_input",
        "phase": "dlp_pre",
        "pack_id": "cognic-tool-example",
        "tenant_id": "tenant-1",
        "request_id": "req-123",
        "trace_id": None,
        "parent_trace_id": None,
        "manifest_data_classes": ("public",),
        "manifest_purpose": "operational_telemetry",
    }
    defaults.update(overrides)
    return HookContext(**defaults)


class _PassHook(Hook):
    """Inert pass-through hook used as the canonical happy-path
    fixture across tests."""

    hook_id: ClassVar[str] = "redact_pii_in_input"
    phase: ClassVar[HookPhase] = "dlp_pre"

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        return HookResult(decision="pass", redacted_payload=None, policy_reason=None)


# ---------------------------------------------------------------------------
# HookContext invariants
# ---------------------------------------------------------------------------


def test_hook_context_is_frozen() -> None:
    """Pack-author hooks must not mutate the context across the
    dispatch chain — frozen=True guarantees AttributeError on assign."""
    ctx = _ctx()
    with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
        ctx.hook_id = "different"  # type: ignore[misc]


def test_hook_context_has_slots() -> None:
    """slots=True suppresses __dict__ — hooks can't smuggle extra
    attributes through the context. Pinning this catches a future
    drift to a non-slotted dataclass."""
    ctx = _ctx()
    assert not hasattr(ctx, "__dict__")


def test_hook_context_payload_field_does_not_exist() -> None:
    """Payload-contents-never-logged invariant (Doctrine Lock E):
    HookContext MUST NOT carry payload bytes. Pinned here at the
    SDK boundary; runtime AST-walk regression at
    tests/architecture/test_hook_payload_never_logged.py (Sprint-7A2
    T7) carries the dispatch-side check."""
    ctx = _ctx()
    assert not hasattr(ctx, "payload")
    assert not hasattr(ctx, "payload_bytes")
    assert not hasattr(ctx, "input_payload")
    assert not hasattr(ctx, "raw_bytes")


# ---------------------------------------------------------------------------
# HookResult invariants
# ---------------------------------------------------------------------------


def test_hook_result_is_frozen() -> None:
    """Mirrors HookContext frozen invariant: dispatch chain cannot
    mutate the result the hook returned."""
    result = HookResult(decision="pass", redacted_payload=None, policy_reason=None)
    with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
        result.decision = "refuse"  # type: ignore[misc]


def test_hook_result_has_slots() -> None:
    result = HookResult(decision="pass", redacted_payload=None, policy_reason=None)
    assert not hasattr(result, "__dict__")


def test_hook_result_audit_metadata_defaults_to_empty_dict() -> None:
    """Optional field; default empty dict so simple hooks don't
    have to remember to populate it."""
    result = HookResult(decision="pass", redacted_payload=None, policy_reason=None)
    assert result.audit_metadata == {}


# ---------------------------------------------------------------------------
# Hook abstract / ClassVar contract
# ---------------------------------------------------------------------------


def test_hook_invoke_is_abstract() -> None:
    """Cannot instantiate Hook directly — abstract _invoke."""
    with pytest.raises(TypeError):
        Hook()  # type: ignore[abstract]


def test_hook_subclass_with_invoke_override_only_succeeds() -> None:
    """Happy path: overriding _invoke is the supported pattern."""
    inst = _PassHook()
    assert isinstance(inst, Hook)


# ---------------------------------------------------------------------------
# Template-method invoke() — context / payload / result validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_invoke_passes_through_happy_path() -> None:
    inst = _PassHook()
    result = await inst.invoke(_ctx(), b"payload")
    assert result.decision == "pass"
    assert result.redacted_payload is None
    assert result.policy_reason is None


@pytest.mark.asyncio
async def test_invoke_raises_hook_context_error_when_context_is_none() -> None:
    inst = _PassHook()
    with pytest.raises(HookContextError):
        await inst.invoke(None, b"payload")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_invoke_raises_hook_context_error_when_context_is_wrong_type() -> None:
    inst = _PassHook()
    with pytest.raises(HookContextError):
        await inst.invoke({"hook_id": "x"}, b"payload")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_invoke_raises_hook_payload_error_when_payload_is_none() -> None:
    inst = _PassHook()
    with pytest.raises(HookPayloadError):
        await inst.invoke(_ctx(), None)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_invoke_raises_hook_payload_error_when_payload_is_str() -> None:
    inst = _PassHook()
    with pytest.raises(HookPayloadError):
        await inst.invoke(_ctx(), "string-not-bytes")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_invoke_raises_hook_result_shape_error_when_invoke_returns_dict() -> None:
    """Pack-author bug: _invoke returned a dict instead of HookResult.
    SDK refuses with HookResultShapeError instead of letting the
    bad shape leak past the boundary."""

    class _BadShape(Hook):
        hook_id: ClassVar[str] = "bad"
        phase: ClassVar[HookPhase] = "dlp_pre"

        async def _invoke(self, context: HookContext, payload: bytes) -> Any:
            return {"decision": "pass"}

    with pytest.raises(HookResultShapeError):
        await _BadShape().invoke(_ctx(), b"payload")


@pytest.mark.asyncio
async def test_invoke_raises_when_pass_decision_has_redacted_payload() -> None:
    """Decision-↔-fields invariant: pass + redacted_payload is
    contradictory."""

    class _ContradictoryPass(Hook):
        hook_id: ClassVar[str] = "x"
        phase: ClassVar[HookPhase] = "dlp_pre"

        async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
            return HookResult(
                decision="pass",
                redacted_payload=b"unexpectedly modified",
                policy_reason=None,
            )

    with pytest.raises(HookResultShapeError):
        await _ContradictoryPass().invoke(_ctx(), b"payload")


@pytest.mark.asyncio
async def test_invoke_raises_when_redact_decision_has_no_redacted_payload() -> None:
    """Decision-↔-fields invariant: redact requires redacted_payload
    to be bytes."""

    class _RedactWithoutPayload(Hook):
        hook_id: ClassVar[str] = "x"
        phase: ClassVar[HookPhase] = "dlp_pre"

        async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
            return HookResult(decision="redact", redacted_payload=None, policy_reason=None)

    with pytest.raises(HookResultShapeError):
        await _RedactWithoutPayload().invoke(_ctx(), b"payload")


@pytest.mark.asyncio
async def test_invoke_raises_when_redact_decision_has_string_redacted_payload() -> None:
    """Decision-↔-fields invariant: redacted_payload MUST be bytes,
    not str."""

    class _RedactWithStr(Hook):
        hook_id: ClassVar[str] = "x"
        phase: ClassVar[HookPhase] = "dlp_pre"

        async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
            return HookResult(
                decision="redact",
                redacted_payload="should-be-bytes",  # type: ignore[arg-type]
                policy_reason=None,
            )

    with pytest.raises(HookResultShapeError):
        await _RedactWithStr().invoke(_ctx(), b"payload")


@pytest.mark.asyncio
async def test_invoke_raises_when_refuse_decision_has_no_policy_reason() -> None:
    """Decision-↔-fields invariant: refuse requires non-empty
    policy_reason for the audit row."""

    class _RefuseWithoutReason(Hook):
        hook_id: ClassVar[str] = "x"
        phase: ClassVar[HookPhase] = "dlp_pre"

        async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
            return HookResult(decision="refuse", redacted_payload=None, policy_reason=None)

    with pytest.raises(HookResultShapeError):
        await _RefuseWithoutReason().invoke(_ctx(), b"payload")


@pytest.mark.asyncio
async def test_invoke_raises_when_refuse_decision_has_whitespace_policy_reason() -> None:
    """Whitespace-only policy_reason is rejected — the dispatcher
    needs a non-empty closed-enum string."""

    class _RefuseWithWhitespace(Hook):
        hook_id: ClassVar[str] = "x"
        phase: ClassVar[HookPhase] = "dlp_pre"

        async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
            return HookResult(decision="refuse", redacted_payload=None, policy_reason="   ")

    with pytest.raises(HookResultShapeError):
        await _RefuseWithWhitespace().invoke(_ctx(), b"payload")


@pytest.mark.asyncio
async def test_invoke_raises_when_pass_decision_carries_policy_reason() -> None:
    """Decision-↔-fields invariant: only refuse carries policy_reason."""

    class _PassWithReason(Hook):
        hook_id: ClassVar[str] = "x"
        phase: ClassVar[HookPhase] = "dlp_pre"

        async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
            return HookResult(
                decision="pass",
                redacted_payload=None,
                policy_reason="unexpected_reason",
            )

    with pytest.raises(HookResultShapeError):
        await _PassWithReason().invoke(_ctx(), b"payload")


@pytest.mark.asyncio
async def test_invoke_redact_with_bytes_payload_succeeds() -> None:
    """Happy path: redact decision returns modified bytes; SDK
    accepts and the dispatcher will carry the modified payload
    forward."""

    class _RedactHook(Hook):
        hook_id: ClassVar[str] = "x"
        phase: ClassVar[HookPhase] = "dlp_pre"

        async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
            return HookResult(
                decision="redact",
                redacted_payload=b"[REDACTED]",
                policy_reason=None,
            )

    result = await _RedactHook().invoke(_ctx(), b"original")
    assert result.decision == "redact"
    assert result.redacted_payload == b"[REDACTED]"
    assert result.policy_reason is None


@pytest.mark.asyncio
async def test_invoke_refuse_with_policy_reason_succeeds() -> None:
    """Happy path: refuse decision with a non-empty policy_reason."""

    class _RefuseHook(Hook):
        hook_id: ClassVar[str] = "x"
        phase: ClassVar[HookPhase] = "dlp_pre"

        async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
            return HookResult(
                decision="refuse",
                redacted_payload=None,
                policy_reason="customer_consent_missing",
            )

    result = await _RefuseHook().invoke(_ctx(), b"payload")
    assert result.decision == "refuse"
    assert result.policy_reason == "customer_consent_missing"


# ---------------------------------------------------------------------------
# __init_subclass__ — invoke template-method seam guard (mirrors Tool R8 P2 #1)
# ---------------------------------------------------------------------------


def test_subclass_overriding_invoke_raises_at_class_creation() -> None:
    """Direct override of invoke() bypasses the SDK's validation
    seam. __init_subclass__ refuses at class-definition time
    (NOT at instantiation; pack authors get the error early)."""
    with pytest.raises(TypeError, match=r"resolves Hook\.invoke"):

        class _BadDirectOverride(Hook):
            hook_id: ClassVar[str] = "x"
            phase: ClassVar[HookPhase] = "dlp_pre"

            async def invoke(  # type: ignore[misc]
                self, context: HookContext, payload: bytes
            ) -> HookResult:
                # bypasses input/output validation
                return HookResult(decision="pass", redacted_payload=None, policy_reason=None)

            async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
                return HookResult(decision="pass", redacted_payload=None, policy_reason=None)


def test_mixin_smuggled_invoke_raises_at_class_creation() -> None:
    """A sibling class defining invoke ahead of Hook in MRO bypasses
    the validation seam unless __init_subclass__ walks the MRO. Pinned
    by the same R8 P2 #1 doctrine that Tool uses."""

    class _BypassMixin:
        async def invoke(self, context: HookContext, payload: bytes) -> HookResult:
            return HookResult(decision="pass", redacted_payload=None, policy_reason=None)

    with pytest.raises(TypeError, match=r"resolves Hook\.invoke"):

        class _MixinSmuggled(_BypassMixin, Hook):  # type: ignore[misc]
            hook_id: ClassVar[str] = "x"
            phase: ClassVar[HookPhase] = "dlp_pre"

            async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
                return HookResult(decision="pass", redacted_payload=None, policy_reason=None)


def test_mixin_bypass_via_multi_level_inheritance_raises() -> None:
    """Multi-level: Subclass → IntermediateMixin (defines invoke) →
    Hook. The MRO walk catches it because IntermediateMixin sits in
    cls.__mro__ between Subclass and Hook."""

    class _IntermediateMixin:
        async def invoke(self, context: HookContext, payload: bytes) -> HookResult:
            return HookResult(decision="pass", redacted_payload=None, policy_reason=None)

    with pytest.raises(TypeError, match=r"resolves Hook\.invoke"):

        class _MultiLevelMixin(_IntermediateMixin, Hook):  # type: ignore[misc]
            hook_id: ClassVar[str] = "x"
            phase: ClassVar[HookPhase] = "dlp_pre"

            async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
                return HookResult(decision="pass", redacted_payload=None, policy_reason=None)


# ---------------------------------------------------------------------------
# Exception hierarchy invariants
# ---------------------------------------------------------------------------


def test_hook_contract_error_subclasses_hook_error() -> None:
    """The runtime dispatcher's single ``except HookError`` MUST
    catch every contract violation. Pin the hierarchy."""
    assert issubclass(HookContractError, HookError)


def test_hook_context_error_subclasses_hook_contract_error() -> None:
    assert issubclass(HookContextError, HookContractError)


def test_hook_payload_error_subclasses_hook_contract_error() -> None:
    assert issubclass(HookPayloadError, HookContractError)


def test_hook_result_shape_error_subclasses_hook_contract_error() -> None:
    assert issubclass(HookResultShapeError, HookContractError)


def test_every_contract_error_is_caught_by_hook_error() -> None:
    """Smoke check the dispatcher's catch surface: every contract-
    error sub-case routes through HookError."""
    for cls in (HookContextError, HookPayloadError, HookResultShapeError):
        try:
            raise cls("test")
        except HookError:
            pass
        else:  # pragma: no cover — defensive; the raise above always fires
            raise AssertionError(f"{cls.__name__} not caught by HookError")
