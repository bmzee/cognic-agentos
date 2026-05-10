"""Sprint-7A2 T7 — :mod:`cognic_agentos.packs.hooks.dispatcher` regression suite.

The dispatcher is the FIRST runtime execution path for hooks; under
review-watchpoint scrutiny per Sprint-7A2 plan-of-record:

* Dispatcher must not log or store raw payload bytes (companion AST
  regression at ``tests/architecture/test_hook_payload_never_logged.py``).
* Hook load + call bounded by timeout (``min(entry.timeout_seconds,
  runtime_ceiling)``) via :func:`asyncio.wait_for`.
* Deterministic ordering MUST come from the registry snapshot — the
  dispatcher reads :meth:`HookRegistry.get_phase_hooks` exactly once
  at dispatch entry and iterates the local tuple thereafter.
* Fail-closed is the default outcome for every non-pass path
  (timeout / exception / malformed result / refuse / payload-unscannable).
* Fail-open requires the declaration's ``fail_policy="fail_open"`` AND
  the raised exception's class name (walked through ``__mro__``) to
  match the declaration's ``fail_open_exception``. Any other exception
  is fail-closed regardless.
* Five closed-enum failure modes per Doctrine Lock E:
  ``hook_timeout`` / ``hook_exception`` / ``hook_malformed_result`` /
  ``hook_policy_refused`` / ``hook_payload_unscannable``.
* Snapshot semantics: a hook that mutates the registry mid-dispatch
  cannot affect the current dispatch's iteration target.

Critical-controls T12 promotion: this module joins the gate alongside
``packs/hooks/registry.py``. The 95/90 floor lives at T12; this suite
is the regression spine.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
from typing import ClassVar

import pytest

from cognic_agentos.cli._governance_vocab import HookPhase
from cognic_agentos.packs.hooks.dispatcher import (
    HookDispatcher,
    HookDispatchOutcome,
    HookDispatchResult,
    HookFailureMode,
)
from cognic_agentos.packs.hooks.registry import (
    HookDeclaration,
    HookRegistry,
    VerifiedHookPack,
)
from cognic_agentos.sdk.hook import (
    Hook,
    HookContext,
    HookDecision,
    HookResult,
)

# ---------------------------------------------------------------------------
# Test fixtures — Hook subclasses + context builder + registry seeder
# ---------------------------------------------------------------------------


def _ctx_template(
    *,
    phase: HookPhase = "dlp_pre",
    pack_id: str = "calling-pack",
    tenant_id: str = "tenant-1",
    request_id: str = "req-1",
    trace_id: str | None = "trace-1",
    parent_trace_id: str | None = None,
    manifest_data_classes: tuple[str, ...] = ("pii",),
    manifest_purpose: str = "advisory",
) -> HookContext:
    """Build a HookContext with hook_id="" sentinel — the dispatcher
    fills hook_id per-hook via ``dataclasses.replace``."""
    return HookContext(
        hook_id="",
        phase=phase,
        pack_id=pack_id,
        tenant_id=tenant_id,
        request_id=request_id,
        trace_id=trace_id,
        parent_trace_id=parent_trace_id,
        manifest_data_classes=manifest_data_classes,
        manifest_purpose=manifest_purpose,
    )


class _PassHook(Hook):
    hook_id: ClassVar[str] = "pass_hook"
    phase: ClassVar[HookPhase] = "dlp_pre"

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        return HookResult(decision="pass", redacted_payload=None, policy_reason=None)


class _RedactHook(Hook):
    hook_id: ClassVar[str] = "redact_hook"
    phase: ClassVar[HookPhase] = "dlp_pre"

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        return HookResult(decision="redact", redacted_payload=b"REDACTED", policy_reason=None)


class _MaskHook(Hook):
    hook_id: ClassVar[str] = "mask_hook"
    phase: ClassVar[HookPhase] = "dlp_post"

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        return HookResult(decision="mask", redacted_payload=b"MASKED", policy_reason=None)


class _RefuseHook(Hook):
    hook_id: ClassVar[str] = "refuse_hook"
    phase: ClassVar[HookPhase] = "dlp_pre"

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        return HookResult(
            decision="refuse", redacted_payload=None, policy_reason="data_class_blocked"
        )


class _RaiseHook(Hook):
    """Raises a custom exception class. Used to test fail-open carve-out."""

    hook_id: ClassVar[str] = "raise_hook"
    phase: ClassVar[HookPhase] = "dlp_pre"

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        raise RecoverableHookError("simulated recoverable failure")


class _RaiseGenericHook(Hook):
    hook_id: ClassVar[str] = "raise_generic_hook"
    phase: ClassVar[HookPhase] = "dlp_pre"

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        raise RuntimeError("simulated unrecoverable failure")


class _MalformedResultHook(Hook):
    hook_id: ClassVar[str] = "malformed_result_hook"
    phase: ClassVar[HookPhase] = "dlp_pre"

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        # Decision says "redact" but no redacted_payload — invariant
        # violation. The Hook.invoke() seam raises HookResultShapeError,
        # which the dispatcher routes to ``hook_malformed_result``.
        return HookResult(decision="redact", redacted_payload=None, policy_reason=None)


class _SlowHook(Hook):
    hook_id: ClassVar[str] = "slow_hook"
    phase: ClassVar[HookPhase] = "dlp_pre"

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        # Sleep beyond the test's runtime ceiling.
        await asyncio.sleep(10.0)
        return HookResult(decision="pass", redacted_payload=None, policy_reason=None)


class _TrackingHook(Hook):
    """Records every (context, payload) the dispatcher passes in.
    Test fixture — class-level state for inspection."""

    hook_id: ClassVar[str] = "tracking_hook"
    phase: ClassVar[HookPhase] = "dlp_pre"
    invocations: ClassVar[list[tuple[HookContext, bytes]]] = []

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        type(self).invocations.append((context, payload))
        return HookResult(decision="pass", redacted_payload=None, policy_reason=None)


class RecoverableHookError(Exception):
    """Custom exception class for the fail-open carve-out test. Lives
    at module top-level so its ``__name__`` is stable for the
    declaration's ``fail_open_exception`` matcher."""


def _seed_registry(
    *,
    hook_class: type[Hook],
    phase: HookPhase = "dlp_pre",
    ordering_class: str = "input_redaction",
    timeout_seconds: float = 1.0,
    fail_policy: str = "fail_closed",
    fail_open_exception: str | None = None,
    distribution_name: str = "cognic-hook-test",
    distribution_version: str = "0.1.0",
    signature_digest: str = "sha256:" + "a" * 64,
    max_timeout_seconds: float = 30.0,
) -> HookRegistry:
    registry = HookRegistry(max_timeout_seconds=max_timeout_seconds)
    decl = HookDeclaration(
        hook_id=hook_class.hook_id,
        phase=phase,
        ordering_class=ordering_class,  # type: ignore[arg-type]
        timeout_seconds=timeout_seconds,
        fail_policy=fail_policy,  # type: ignore[arg-type]
        fail_open_exception=fail_open_exception,
        callable_loader=lambda: hook_class,
    )
    pack = VerifiedHookPack(
        distribution_name=distribution_name,
        distribution_version=distribution_version,
        signature_digest=signature_digest,
        declarations=(decl,),
    )
    registry.register_pack(pack)
    return registry


# ---------------------------------------------------------------------------
# Empty-phase + happy-path dispatch
# ---------------------------------------------------------------------------


class TestDispatcherEmptyPhase:
    """No hooks registered for the phase → outcome="passed", payload
    untouched, digest computed against the original payload."""

    @pytest.mark.asyncio
    async def test_no_hooks_returns_passed(self) -> None:
        registry = HookRegistry(max_timeout_seconds=30.0)
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        result = await dispatcher.dispatch(
            phase="dlp_pre",
            payload=b"hello",
            context_template=_ctx_template(),
        )
        assert result.outcome == "passed"
        assert result.final_payload == b"hello"
        assert result.failure_mode is None
        assert result.failed_hook_id is None
        assert result.policy_reason is None
        # Digest computed against the original payload.
        assert result.policy_input_digest == hashlib.sha256(b"hello").hexdigest()


class TestDispatcherSingleHook:
    @pytest.mark.asyncio
    async def test_single_pass_hook(self) -> None:
        registry = _seed_registry(hook_class=_PassHook)
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        result = await dispatcher.dispatch(
            phase="dlp_pre",
            payload=b"original",
            context_template=_ctx_template(),
        )
        assert result.outcome == "passed"
        assert result.final_payload == b"original"
        assert result.failure_mode is None

    @pytest.mark.asyncio
    async def test_single_redact_hook_replaces_payload(self) -> None:
        registry = _seed_registry(hook_class=_RedactHook)
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        result = await dispatcher.dispatch(
            phase="dlp_pre",
            payload=b"original_with_pii",
            context_template=_ctx_template(),
        )
        assert result.outcome == "passed"
        assert result.final_payload == b"REDACTED"

    @pytest.mark.asyncio
    async def test_single_mask_hook_replaces_payload(self) -> None:
        registry = _seed_registry(
            hook_class=_MaskHook,
            phase="dlp_post",
            ordering_class="output_masking",
        )
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        result = await dispatcher.dispatch(
            phase="dlp_post",
            payload=b"output_with_account_numbers",
            context_template=_ctx_template(phase="dlp_post"),
        )
        assert result.outcome == "passed"
        assert result.final_payload == b"MASKED"


class TestDispatcherChainTransformation:
    """Multi-hook chains — payload transformation persists across the
    chain; later hooks see the transformed payload."""

    @pytest.mark.asyncio
    async def test_two_hooks_pass_then_redact(self) -> None:
        # Two packs, two declarations; deterministic order means
        # _PassHook (input_validation rank 10) runs before _RedactHook
        # (input_redaction rank 30).
        registry = HookRegistry(max_timeout_seconds=30.0)
        registry.register_pack(
            VerifiedHookPack(
                distribution_name="cognic-hook-pass",
                distribution_version="0.1.0",
                signature_digest="sha256:" + "a" * 64,
                declarations=(
                    HookDeclaration(
                        hook_id=_PassHook.hook_id,
                        phase="dlp_pre",
                        ordering_class="input_validation",
                        timeout_seconds=1.0,
                        fail_policy="fail_closed",
                        fail_open_exception=None,
                        callable_loader=lambda: _PassHook,
                    ),
                ),
            )
        )
        registry.register_pack(
            VerifiedHookPack(
                distribution_name="cognic-hook-redact",
                distribution_version="0.1.0",
                signature_digest="sha256:" + "b" * 64,
                declarations=(
                    HookDeclaration(
                        hook_id=_RedactHook.hook_id,
                        phase="dlp_pre",
                        ordering_class="input_redaction",
                        timeout_seconds=1.0,
                        fail_policy="fail_closed",
                        fail_open_exception=None,
                        callable_loader=lambda: _RedactHook,
                    ),
                ),
            )
        )
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        result = await dispatcher.dispatch(
            phase="dlp_pre",
            payload=b"original",
            context_template=_ctx_template(),
        )
        assert result.outcome == "passed"
        assert result.final_payload == b"REDACTED"
        # Original-payload digest, not transformed-payload digest.
        assert result.policy_input_digest == hashlib.sha256(b"original").hexdigest()

    @pytest.mark.asyncio
    async def test_tracking_hook_sees_transformed_payload(self) -> None:
        """If hook A redacts, hook B sees the redacted payload — chain
        transformation is forward-propagating."""
        # Reset class-level state.
        _TrackingHook.invocations = []

        # _RedactHook (rank 30) runs before _TrackingHook (rank 40
        # via input_normalization).
        registry = HookRegistry(max_timeout_seconds=30.0)
        registry.register_pack(
            VerifiedHookPack(
                distribution_name="cognic-hook-redact",
                distribution_version="0.1.0",
                signature_digest="sha256:" + "a" * 64,
                declarations=(
                    HookDeclaration(
                        hook_id=_RedactHook.hook_id,
                        phase="dlp_pre",
                        ordering_class="input_redaction",
                        timeout_seconds=1.0,
                        fail_policy="fail_closed",
                        fail_open_exception=None,
                        callable_loader=lambda: _RedactHook,
                    ),
                ),
            )
        )
        registry.register_pack(
            VerifiedHookPack(
                distribution_name="cognic-hook-tracking",
                distribution_version="0.1.0",
                signature_digest="sha256:" + "b" * 64,
                declarations=(
                    HookDeclaration(
                        hook_id=_TrackingHook.hook_id,
                        phase="dlp_pre",
                        ordering_class="input_normalization",
                        timeout_seconds=1.0,
                        fail_policy="fail_closed",
                        fail_open_exception=None,
                        callable_loader=lambda: _TrackingHook,
                    ),
                ),
            )
        )
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        result = await dispatcher.dispatch(
            phase="dlp_pre",
            payload=b"original_with_pii",
            context_template=_ctx_template(),
        )
        assert result.outcome == "passed"
        # _TrackingHook saw the REDACTED payload, not the original.
        assert len(_TrackingHook.invocations) == 1
        _, observed_payload = _TrackingHook.invocations[0]
        assert observed_payload == b"REDACTED"


# ---------------------------------------------------------------------------
# Refuse decision halts the chain
# ---------------------------------------------------------------------------


class TestDispatcherRefuseHalts:
    @pytest.mark.asyncio
    async def test_refuse_returns_refused_with_policy_reason(self) -> None:
        registry = _seed_registry(hook_class=_RefuseHook)
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        result = await dispatcher.dispatch(
            phase="dlp_pre",
            payload=b"forbidden",
            context_template=_ctx_template(),
        )
        assert result.outcome == "refused"
        assert result.failure_mode == "hook_policy_refused"
        assert result.policy_reason == "data_class_blocked"
        assert result.failed_hook_id == "refuse_hook"
        # final_payload is the LAST seen payload — the original since
        # refuse was the first hook and didn't redact.
        assert result.final_payload == b"forbidden"

    @pytest.mark.asyncio
    async def test_refuse_halts_subsequent_hooks(self) -> None:
        """Hook A refuses; hook B (lower rank, runs later) MUST NOT be
        invoked."""
        _TrackingHook.invocations = []

        registry = HookRegistry(max_timeout_seconds=30.0)
        registry.register_pack(
            VerifiedHookPack(
                distribution_name="cognic-hook-refuse",
                distribution_version="0.1.0",
                signature_digest="sha256:" + "a" * 64,
                declarations=(
                    HookDeclaration(
                        hook_id=_RefuseHook.hook_id,
                        phase="dlp_pre",
                        ordering_class="input_validation",  # rank 10 — runs first
                        timeout_seconds=1.0,
                        fail_policy="fail_closed",
                        fail_open_exception=None,
                        callable_loader=lambda: _RefuseHook,
                    ),
                ),
            )
        )
        registry.register_pack(
            VerifiedHookPack(
                distribution_name="cognic-hook-tracking",
                distribution_version="0.1.0",
                signature_digest="sha256:" + "b" * 64,
                declarations=(
                    HookDeclaration(
                        hook_id=_TrackingHook.hook_id,
                        phase="dlp_pre",
                        ordering_class="input_redaction",  # rank 30 — runs after
                        timeout_seconds=1.0,
                        fail_policy="fail_closed",
                        fail_open_exception=None,
                        callable_loader=lambda: _TrackingHook,
                    ),
                ),
            )
        )
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        result = await dispatcher.dispatch(
            phase="dlp_pre",
            payload=b"forbidden",
            context_template=_ctx_template(),
        )
        assert result.outcome == "refused"
        # _TrackingHook MUST NOT have been invoked.
        assert _TrackingHook.invocations == []


# ---------------------------------------------------------------------------
# Exception → hook_exception fail-closed (default)
# ---------------------------------------------------------------------------


class TestDispatcherExceptionFailClosed:
    @pytest.mark.asyncio
    async def test_generic_exception_routes_to_hook_exception(self) -> None:
        registry = _seed_registry(hook_class=_RaiseGenericHook)
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        result = await dispatcher.dispatch(
            phase="dlp_pre",
            payload=b"data",
            context_template=_ctx_template(),
        )
        assert result.outcome == "failed"
        assert result.failure_mode == "hook_exception"
        assert result.failed_hook_id == "raise_generic_hook"
        # No policy_reason on hook_exception (it's an SDK / pack
        # author bug, not a policy decision).
        assert result.policy_reason is None

    @pytest.mark.asyncio
    async def test_exception_with_fail_closed_default_still_fails(self) -> None:
        # Default fail_policy is fail_closed; even a hook with
        # fail_open_exception declared (but fail_policy=fail_closed)
        # routes to hook_exception.
        registry = _seed_registry(
            hook_class=_RaiseHook,
            fail_policy="fail_closed",
            fail_open_exception="RecoverableHookError",
        )
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        result = await dispatcher.dispatch(
            phase="dlp_pre",
            payload=b"data",
            context_template=_ctx_template(),
        )
        assert result.outcome == "failed"
        assert result.failure_mode == "hook_exception"


# ---------------------------------------------------------------------------
# Fail-open carve-out — declared exception class only
# ---------------------------------------------------------------------------


class TestDispatcherFailOpenCarveOut:
    @pytest.mark.asyncio
    async def test_matching_declared_exception_treated_as_pass(self) -> None:
        # fail_policy=fail_open + fail_open_exception="RecoverableHookError"
        # AND _RaiseHook raises RecoverableHookError → treated as pass,
        # chain continues.
        registry = _seed_registry(
            hook_class=_RaiseHook,
            fail_policy="fail_open",
            fail_open_exception="RecoverableHookError",
        )
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        result = await dispatcher.dispatch(
            phase="dlp_pre",
            payload=b"data",
            context_template=_ctx_template(),
        )
        assert result.outcome == "passed"
        assert result.failure_mode is None
        assert result.final_payload == b"data"

    @pytest.mark.asyncio
    async def test_non_matching_exception_still_fails_closed(self) -> None:
        # fail_policy=fail_open BUT _RaiseGenericHook raises RuntimeError,
        # not the declared RecoverableHookError. Fail-closed is the
        # only safe outcome for unanticipated exceptions.
        registry = _seed_registry(
            hook_class=_RaiseGenericHook,
            fail_policy="fail_open",
            fail_open_exception="RecoverableHookError",
        )
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        result = await dispatcher.dispatch(
            phase="dlp_pre",
            payload=b"data",
            context_template=_ctx_template(),
        )
        assert result.outcome == "failed"
        assert result.failure_mode == "hook_exception"

    @pytest.mark.asyncio
    async def test_fail_open_does_not_apply_to_timeout(self) -> None:
        # Even with fail_policy=fail_open + fail_open_exception="TimeoutError",
        # a timeout is fail-closed because the exception happens
        # OUTSIDE the hook's catch boundary (asyncio.wait_for raises
        # at the dispatcher level, not from inside _invoke). The
        # dispatcher pins ``hook_timeout`` as fail-closed regardless.
        registry = _seed_registry(
            hook_class=_SlowHook,
            timeout_seconds=0.05,
            fail_policy="fail_open",
            fail_open_exception="TimeoutError",
        )
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        result = await dispatcher.dispatch(
            phase="dlp_pre",
            payload=b"data",
            context_template=_ctx_template(),
        )
        assert result.outcome == "failed"
        assert result.failure_mode == "hook_timeout"

    @pytest.mark.asyncio
    async def test_fail_open_does_not_apply_to_malformed_result(self) -> None:
        # HookContractError subclasses are SDK contract violations,
        # never recoverable. fail-open never applies.
        registry = _seed_registry(
            hook_class=_MalformedResultHook,
            fail_policy="fail_open",
            fail_open_exception="HookResultShapeError",
        )
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        result = await dispatcher.dispatch(
            phase="dlp_pre",
            payload=b"data",
            context_template=_ctx_template(),
        )
        assert result.outcome == "failed"
        assert result.failure_mode == "hook_malformed_result"


# ---------------------------------------------------------------------------
# Loader / constructor HookContractError NEVER fail-opens (T7 R1 review fix)
#
# Threat model: a malicious declaration sets ``fail_policy="fail_open"`` AND
# ``fail_open_exception="HookContractError"`` (or a subclass name like
# ``HookResultShapeError``) and ships a callable_loader / __init__ that
# raises that exact class. Without the explicit ``except HookContractError``
# in the loader/constructor block, the generic ``except Exception`` would
# route through ``_route_exception``'s MRO walk and fail-open the SDK
# contract violation — directly contradicting the T7 invariant that SDK
# contract errors are never recoverable.
# ---------------------------------------------------------------------------


def _loader_raises_contract_error() -> type:
    """Loader that raises ``HookResultShapeError`` (subclass of
    ``HookContractError``). Stand-in for any contract violation a
    malicious or buggy pack might raise during entry-point resolution."""
    from cognic_agentos.sdk.hook import HookResultShapeError

    raise HookResultShapeError("simulated loader contract violation")


def _loader_raises_recoverable() -> type:
    """Loader that raises a non-contract exception. Used to verify the
    symmetric path — the loader / constructor's generic exception
    handler STILL fail-opens for legitimate recoverable errors when
    declared, ensuring the contract-error fix doesn't accidentally
    fail-close all loader-path exceptions."""
    raise RecoverableHookError("simulated recoverable loader failure")


class _ConstructorContractErrorHook(Hook):
    """Constructor raises ``HookResultShapeError`` (subclass of
    ``HookContractError``). The declaration's
    ``fail_open_exception="HookContractError"`` would, without the
    fix, match via the MRO walk in ``_route_exception`` and smuggle
    the contract violation past the malformed-result gate."""

    hook_id: ClassVar[str] = "ctor_contract_error_hook"
    phase: ClassVar[HookPhase] = "dlp_pre"

    def __init__(self) -> None:
        # Importing inside __init__ rather than at class-definition
        # time so the import error (if any) doesn't surface at
        # collection.
        from cognic_agentos.sdk.hook import HookResultShapeError

        raise HookResultShapeError("simulated constructor contract violation")

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        return HookResult(decision="pass", redacted_payload=None, policy_reason=None)


class _ConstructorRecoverableErrorHook(Hook):
    """Constructor raises a non-contract exception — the symmetric
    legitimate fail-open path. With ``fail_policy="fail_open"`` and a
    matching ``fail_open_exception``, this MUST fail-open (proves the
    contract-error fix doesn't over-block)."""

    hook_id: ClassVar[str] = "ctor_recoverable_hook"
    phase: ClassVar[HookPhase] = "dlp_pre"

    def __init__(self) -> None:
        raise RecoverableHookError("simulated recoverable constructor failure")

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        return HookResult(decision="pass", redacted_payload=None, policy_reason=None)


class TestDispatcherLoaderConstructorContractError:
    """T7 R1 review fix — pin that ``HookContractError`` from the
    loader / constructor path is ALWAYS routed to
    ``hook_malformed_result`` fail-closed, even when the declaration
    nominates a fail-open carve-out matching the contract-error
    class name (or a parent class name via MRO)."""

    @pytest.mark.asyncio
    async def test_loader_HookContractError_never_fail_opens_exact_match(
        self,
    ) -> None:
        # Loader raises HookResultShapeError; declaration nominates
        # the EXACT class name as fail_open_exception. Without the
        # fix, the MRO walk would match and fail-open. WITH the fix,
        # the explicit ``except HookContractError`` catches it FIRST
        # and routes to hook_malformed_result fail-closed.
        registry = HookRegistry(max_timeout_seconds=30.0)
        registry.register_pack(
            VerifiedHookPack(
                distribution_name="cognic-hook-loader-contract-error",
                distribution_version="0.1.0",
                signature_digest="sha256:" + "a" * 64,
                declarations=(
                    HookDeclaration(
                        hook_id="loader_contract_error_hook",
                        phase="dlp_pre",
                        ordering_class="input_redaction",
                        timeout_seconds=1.0,
                        fail_policy="fail_open",
                        fail_open_exception="HookResultShapeError",
                        callable_loader=_loader_raises_contract_error,
                    ),
                ),
            )
        )
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        result = await dispatcher.dispatch(
            phase="dlp_pre",
            payload=b"data",
            context_template=_ctx_template(),
        )
        assert result.outcome == "failed"
        assert result.failure_mode == "hook_malformed_result"

    @pytest.mark.asyncio
    async def test_loader_HookContractError_never_fail_opens_parent_match(
        self,
    ) -> None:
        # Same threat model with the declared name pointing at the
        # PARENT class (HookContractError). The MRO walk in
        # _route_exception would match HookContractError in
        # type(HookResultShapeError(...)).__mro__ and fail-open. The
        # fix prevents this entirely by short-circuiting BEFORE
        # _route_exception sees the exception.
        registry = HookRegistry(max_timeout_seconds=30.0)
        registry.register_pack(
            VerifiedHookPack(
                distribution_name="cognic-hook-loader-parent-match",
                distribution_version="0.1.0",
                signature_digest="sha256:" + "b" * 64,
                declarations=(
                    HookDeclaration(
                        hook_id="loader_parent_match_hook",
                        phase="dlp_pre",
                        ordering_class="input_redaction",
                        timeout_seconds=1.0,
                        fail_policy="fail_open",
                        fail_open_exception="HookContractError",  # parent
                        callable_loader=_loader_raises_contract_error,
                    ),
                ),
            )
        )
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        result = await dispatcher.dispatch(
            phase="dlp_pre",
            payload=b"data",
            context_template=_ctx_template(),
        )
        assert result.outcome == "failed"
        assert result.failure_mode == "hook_malformed_result"

    @pytest.mark.asyncio
    async def test_constructor_HookContractError_never_fail_opens(self) -> None:
        # Constructor raises HookResultShapeError; declaration
        # nominates HookContractError (the parent class). Same fix
        # applies — the loader/constructor try block catches
        # HookContractError BEFORE the generic Exception handler.
        registry = _seed_registry(
            hook_class=_ConstructorContractErrorHook,
            fail_policy="fail_open",
            fail_open_exception="HookContractError",
        )
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        result = await dispatcher.dispatch(
            phase="dlp_pre",
            payload=b"data",
            context_template=_ctx_template(),
        )
        assert result.outcome == "failed"
        assert result.failure_mode == "hook_malformed_result"

    @pytest.mark.asyncio
    async def test_loader_recoverable_exception_still_fail_opens_when_matched(
        self,
    ) -> None:
        # Symmetric sanity check — the loader/constructor path's
        # generic-exception fail-open path is NOT broken by the
        # contract-error fix. A genuine recoverable exception
        # (RecoverableHookError, NOT a HookContractError subclass)
        # with a matching fail_open_exception MUST fail-open as
        # designed.
        registry = HookRegistry(max_timeout_seconds=30.0)
        registry.register_pack(
            VerifiedHookPack(
                distribution_name="cognic-hook-loader-recoverable",
                distribution_version="0.1.0",
                signature_digest="sha256:" + "c" * 64,
                declarations=(
                    HookDeclaration(
                        hook_id="loader_recoverable_hook",
                        phase="dlp_pre",
                        ordering_class="input_redaction",
                        timeout_seconds=1.0,
                        fail_policy="fail_open",
                        fail_open_exception="RecoverableHookError",
                        callable_loader=_loader_raises_recoverable,
                    ),
                ),
            )
        )
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        result = await dispatcher.dispatch(
            phase="dlp_pre",
            payload=b"data",
            context_template=_ctx_template(),
        )
        assert result.outcome == "passed"
        assert result.failure_mode is None

    @pytest.mark.asyncio
    async def test_constructor_recoverable_exception_fail_opens_when_matched(
        self,
    ) -> None:
        # Same as the loader case but with a constructor-raised
        # recoverable exception. Confirms the constructor-side
        # generic-exception path also fail-opens correctly.
        registry = _seed_registry(
            hook_class=_ConstructorRecoverableErrorHook,
            fail_policy="fail_open",
            fail_open_exception="RecoverableHookError",
        )
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        result = await dispatcher.dispatch(
            phase="dlp_pre",
            payload=b"data",
            context_template=_ctx_template(),
        )
        assert result.outcome == "passed"
        assert result.failure_mode is None

    @pytest.mark.asyncio
    async def test_loader_recoverable_exception_default_fail_closed(self) -> None:
        # Default fail_policy=fail_closed: a recoverable exception in
        # the loader path still fail-closes (sanity check; pre-fix
        # behavior preserved).
        registry = HookRegistry(max_timeout_seconds=30.0)
        registry.register_pack(
            VerifiedHookPack(
                distribution_name="cognic-hook-loader-default",
                distribution_version="0.1.0",
                signature_digest="sha256:" + "d" * 64,
                declarations=(
                    HookDeclaration(
                        hook_id="loader_default_hook",
                        phase="dlp_pre",
                        ordering_class="input_redaction",
                        timeout_seconds=1.0,
                        fail_policy="fail_closed",
                        fail_open_exception=None,
                        callable_loader=_loader_raises_recoverable,
                    ),
                ),
            )
        )
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        result = await dispatcher.dispatch(
            phase="dlp_pre",
            payload=b"data",
            context_template=_ctx_template(),
        )
        assert result.outcome == "failed"
        assert result.failure_mode == "hook_exception"


# ---------------------------------------------------------------------------
# Malformed result → hook_malformed_result
# ---------------------------------------------------------------------------


class TestDispatcherMalformedResult:
    @pytest.mark.asyncio
    async def test_malformed_result_routes_to_hook_malformed_result(self) -> None:
        registry = _seed_registry(hook_class=_MalformedResultHook)
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        result = await dispatcher.dispatch(
            phase="dlp_pre",
            payload=b"data",
            context_template=_ctx_template(),
        )
        assert result.outcome == "failed"
        assert result.failure_mode == "hook_malformed_result"
        assert result.failed_hook_id == "malformed_result_hook"


# ---------------------------------------------------------------------------
# Timeout → hook_timeout
# ---------------------------------------------------------------------------


class TestDispatcherTimeout:
    @pytest.mark.asyncio
    async def test_timeout_routes_to_hook_timeout(self) -> None:
        registry = _seed_registry(
            hook_class=_SlowHook,
            timeout_seconds=0.05,  # 50ms; SlowHook sleeps 10s
        )
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        result = await dispatcher.dispatch(
            phase="dlp_pre",
            payload=b"data",
            context_template=_ctx_template(),
        )
        assert result.outcome == "failed"
        assert result.failure_mode == "hook_timeout"
        assert result.failed_hook_id == "slow_hook"

    @pytest.mark.asyncio
    async def test_timeout_uses_min_of_declaration_and_runtime_ceiling(self) -> None:
        # Declaration timeout = 5.0s; runtime ceiling = 0.05s. The
        # dispatcher MUST use the lower (0.05s) — defense-in-depth
        # against a permissive admission ceiling.
        registry = _seed_registry(
            hook_class=_SlowHook,
            timeout_seconds=5.0,
            max_timeout_seconds=10.0,  # admission ceiling
        )
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=0.05,  # tighter runtime ceiling
        )
        result = await dispatcher.dispatch(
            phase="dlp_pre",
            payload=b"data",
            context_template=_ctx_template(),
        )
        # SlowHook sleeps 10s; runtime ceiling is 50ms → timeout fires
        # (not the declaration's 5s).
        assert result.outcome == "failed"
        assert result.failure_mode == "hook_timeout"


# ---------------------------------------------------------------------------
# Payload-unscannable budget — pre-loop fail-closed
# ---------------------------------------------------------------------------


class TestDispatcherPayloadUnscannable:
    @pytest.mark.asyncio
    async def test_oversized_payload_refuses_before_any_hook_runs(self) -> None:
        _TrackingHook.invocations = []
        registry = _seed_registry(hook_class=_TrackingHook)
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=100,  # tight budget
            max_timeout_seconds_runtime=30.0,
        )
        result = await dispatcher.dispatch(
            phase="dlp_pre",
            payload=b"x" * 1000,  # 10x the budget
            context_template=_ctx_template(),
        )
        assert result.outcome == "failed"
        assert result.failure_mode == "hook_payload_unscannable"
        # NO hook was invoked.
        assert _TrackingHook.invocations == []

    @pytest.mark.asyncio
    async def test_payload_at_budget_boundary_is_allowed(self) -> None:
        # Exactly at budget is allowed; only strictly above refuses.
        registry = _seed_registry(hook_class=_PassHook)
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10,
            max_timeout_seconds_runtime=30.0,
        )
        result = await dispatcher.dispatch(
            phase="dlp_pre",
            payload=b"0123456789",  # exactly 10 bytes
            context_template=_ctx_template(),
        )
        assert result.outcome == "passed"


# ---------------------------------------------------------------------------
# policy_input_digest = sha256 of ORIGINAL payload (never transformed)
# ---------------------------------------------------------------------------


class TestDispatcherPolicyInputDigest:
    @pytest.mark.asyncio
    async def test_digest_is_original_payload_not_transformed(self) -> None:
        registry = _seed_registry(hook_class=_RedactHook)
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        result = await dispatcher.dispatch(
            phase="dlp_pre",
            payload=b"original_with_pii",
            context_template=_ctx_template(),
        )
        # Redact transformed payload → b"REDACTED"; digest is of ORIGINAL.
        assert result.final_payload == b"REDACTED"
        assert result.policy_input_digest == hashlib.sha256(b"original_with_pii").hexdigest()

    @pytest.mark.asyncio
    async def test_digest_present_on_every_outcome(self) -> None:
        # passed
        registry_pass = _seed_registry(hook_class=_PassHook)
        d_pass = HookDispatcher(
            registry=registry_pass,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        result_pass = await d_pass.dispatch(
            phase="dlp_pre", payload=b"x", context_template=_ctx_template()
        )
        assert result_pass.policy_input_digest

        # refused
        registry_ref = _seed_registry(hook_class=_RefuseHook)
        d_ref = HookDispatcher(
            registry=registry_ref,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        result_ref = await d_ref.dispatch(
            phase="dlp_pre", payload=b"x", context_template=_ctx_template()
        )
        assert result_ref.policy_input_digest

        # failed (exception)
        registry_fail = _seed_registry(hook_class=_RaiseGenericHook)
        d_fail = HookDispatcher(
            registry=registry_fail,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        result_fail = await d_fail.dispatch(
            phase="dlp_pre", payload=b"x", context_template=_ctx_template()
        )
        assert result_fail.policy_input_digest

        # failed (payload_unscannable) — digest still computed since
        # the size check is the first thing the dispatcher does AFTER
        # taking the digest.
        registry_uns = HookRegistry(max_timeout_seconds=30.0)
        d_uns = HookDispatcher(
            registry=registry_uns,
            max_payload_bytes=1,
            max_timeout_seconds_runtime=30.0,
        )
        result_uns = await d_uns.dispatch(
            phase="dlp_pre", payload=b"too_big", context_template=_ctx_template()
        )
        assert result_uns.policy_input_digest


# ---------------------------------------------------------------------------
# Snapshot semantics — registry mutation mid-dispatch does NOT affect
# the current dispatch's iteration target
# ---------------------------------------------------------------------------


class _SelfRegisteringHook(Hook):
    """Calls registry.register_pack from inside _invoke. Used to
    exercise the snapshot-semantics invariant: the new pack registered
    mid-dispatch MUST NOT be added to the current dispatch's iteration."""

    hook_id: ClassVar[str] = "self_registering_hook"
    phase: ClassVar[HookPhase] = "dlp_pre"

    # Class-level reference to the registry the hook should mutate.
    # Set up by the test before dispatch.
    target_registry: ClassVar[HookRegistry | None] = None

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        target = type(self).target_registry
        if target is not None:
            new_pack = VerifiedHookPack(
                distribution_name="cognic-hook-injected",
                distribution_version="0.1.0",
                signature_digest="sha256:" + "f" * 64,
                declarations=(
                    HookDeclaration(
                        hook_id=_TrackingHook.hook_id,
                        phase="dlp_pre",
                        ordering_class="input_normalization",  # rank 40
                        timeout_seconds=1.0,
                        fail_policy="fail_closed",
                        fail_open_exception=None,
                        callable_loader=lambda: _TrackingHook,
                    ),
                ),
            )
            target.register_pack(new_pack)
        return HookResult(decision="pass", redacted_payload=None, policy_reason=None)


class TestDispatcherSnapshotSemantics:
    @pytest.mark.asyncio
    async def test_mid_dispatch_registration_not_seen_by_current_dispatch(self) -> None:
        _TrackingHook.invocations = []
        registry = _seed_registry(hook_class=_SelfRegisteringHook)
        _SelfRegisteringHook.target_registry = registry
        try:
            dispatcher = HookDispatcher(
                registry=registry,
                max_payload_bytes=10_000,
                max_timeout_seconds_runtime=30.0,
            )
            result = await dispatcher.dispatch(
                phase="dlp_pre",
                payload=b"data",
                context_template=_ctx_template(),
            )
            # The dispatch saw ONLY the original _SelfRegisteringHook
            # (the snapshot taken at dispatch entry); the injected
            # _TrackingHook was registered mid-dispatch but is NOT in
            # the snapshot's iteration target.
            assert result.outcome == "passed"
            assert _TrackingHook.invocations == []
            # A SECOND dispatch DOES see the injected hook (new
            # snapshot at new dispatch entry).
            result2 = await dispatcher.dispatch(
                phase="dlp_pre",
                payload=b"data2",
                context_template=_ctx_template(),
            )
            # The self-registering hook tries to register again →
            # idempotent same-digest re-register is a no-op (returns
            # existing entries). The second dispatch sees BOTH hooks.
            assert result2.outcome == "passed"
            assert len(_TrackingHook.invocations) == 1
        finally:
            _SelfRegisteringHook.target_registry = None


# ---------------------------------------------------------------------------
# HookContext per-hook construction — hook_id varies, others carry through
# ---------------------------------------------------------------------------


class TestDispatcherContextPerHook:
    @pytest.mark.asyncio
    async def test_context_hook_id_filled_per_hook(self) -> None:
        _TrackingHook.invocations = []
        registry = _seed_registry(hook_class=_TrackingHook)
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        template = _ctx_template(
            pack_id="calling-pack",
            tenant_id="acme",
            request_id="req-42",
        )
        await dispatcher.dispatch(
            phase="dlp_pre",
            payload=b"data",
            context_template=template,
        )
        observed_ctx, _ = _TrackingHook.invocations[0]
        # hook_id was filled in by the dispatcher.
        assert observed_ctx.hook_id == "tracking_hook"
        # Other fields carried through from the template.
        assert observed_ctx.pack_id == "calling-pack"
        assert observed_ctx.tenant_id == "acme"
        assert observed_ctx.request_id == "req-42"

    @pytest.mark.asyncio
    async def test_template_hook_id_must_be_empty_sentinel(self) -> None:
        # The template is the caller's invocation-context; hook_id is
        # the dispatcher's responsibility. A non-empty hook_id on the
        # template signals confusion at the call site → refuse fail-fast.
        registry = _seed_registry(hook_class=_PassHook)
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        template = HookContext(
            hook_id="caller_set_this_wrong",  # sentinel violation
            phase="dlp_pre",
            pack_id="x",
            tenant_id="y",
            request_id="z",
            trace_id=None,
            parent_trace_id=None,
            manifest_data_classes=(),
            manifest_purpose="advisory",
        )
        with pytest.raises(ValueError, match=r"hook_id"):
            await dispatcher.dispatch(
                phase="dlp_pre",
                payload=b"data",
                context_template=template,
            )

    @pytest.mark.asyncio
    async def test_template_phase_must_match_dispatch_phase(self) -> None:
        # The template carries `phase` for hook visibility; the
        # dispatcher refuses if it disagrees with the dispatch call's
        # `phase` argument (otherwise hooks see contradictory metadata).
        registry = _seed_registry(hook_class=_PassHook)
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        template = _ctx_template(phase="dlp_post")  # mismatch
        with pytest.raises(ValueError, match=r"phase"):
            await dispatcher.dispatch(
                phase="dlp_pre",  # different
                payload=b"data",
                context_template=template,
            )


# ---------------------------------------------------------------------------
# HookDispatchResult shape — frozen + slotted; closed-enum fields
# ---------------------------------------------------------------------------


class TestDispatchResultShape:
    @pytest.mark.asyncio
    async def test_dispatch_result_is_frozen_and_slotted(self) -> None:
        registry = _seed_registry(hook_class=_PassHook)
        dispatcher = HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        result = await dispatcher.dispatch(
            phase="dlp_pre", payload=b"x", context_template=_ctx_template()
        )
        # Pin the wire-shape type for the dispatcher's return (consumes
        # the `HookDispatchResult` import meaningfully — the dispatcher
        # MUST return this exact frozen + slotted dataclass).
        assert isinstance(result, HookDispatchResult)
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.outcome = "stolen"  # type: ignore[misc,assignment]
        # Slot-table miss → AttributeError or TypeError (Python-version-
        # dependent surface; both signal immutability).
        with pytest.raises((AttributeError, TypeError)):
            result.injected = "bad"  # type: ignore[attr-defined]

    def test_failure_mode_closed_enum_has_5_values(self) -> None:
        from typing import get_args

        members = set(get_args(HookFailureMode))
        assert members == {
            "hook_timeout",
            "hook_exception",
            "hook_malformed_result",
            "hook_policy_refused",
            "hook_payload_unscannable",
        }

    def test_dispatch_outcome_closed_enum_has_3_values(self) -> None:
        from typing import get_args

        members = set(get_args(HookDispatchOutcome))
        assert members == {"passed", "refused", "failed"}


# ---------------------------------------------------------------------------
# All five HookFailureMode values reachable via dispatch
# ---------------------------------------------------------------------------


class TestEveryFailureModeReachable:
    """Pin that EVERY closed-enum value is actually triggerable via
    dispatch — adding a new value to the literal forces this test to
    be updated, which forces the doctrine review."""

    @pytest.mark.asyncio
    async def test_all_five_failure_modes_reachable(self) -> None:
        observed: set[HookFailureMode] = set()

        # hook_timeout
        registry_t = _seed_registry(hook_class=_SlowHook, timeout_seconds=0.05)
        d_t = HookDispatcher(
            registry=registry_t,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        r_t = await d_t.dispatch(phase="dlp_pre", payload=b"x", context_template=_ctx_template())
        if r_t.failure_mode is not None:
            observed.add(r_t.failure_mode)

        # hook_exception
        registry_e = _seed_registry(hook_class=_RaiseGenericHook)
        d_e = HookDispatcher(
            registry=registry_e,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        r_e = await d_e.dispatch(phase="dlp_pre", payload=b"x", context_template=_ctx_template())
        if r_e.failure_mode is not None:
            observed.add(r_e.failure_mode)

        # hook_malformed_result
        registry_m = _seed_registry(hook_class=_MalformedResultHook)
        d_m = HookDispatcher(
            registry=registry_m,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        r_m = await d_m.dispatch(phase="dlp_pre", payload=b"x", context_template=_ctx_template())
        if r_m.failure_mode is not None:
            observed.add(r_m.failure_mode)

        # hook_policy_refused
        registry_r = _seed_registry(hook_class=_RefuseHook)
        d_r = HookDispatcher(
            registry=registry_r,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
        )
        r_r = await d_r.dispatch(phase="dlp_pre", payload=b"x", context_template=_ctx_template())
        if r_r.failure_mode is not None:
            observed.add(r_r.failure_mode)

        # hook_payload_unscannable
        registry_u = HookRegistry(max_timeout_seconds=30.0)
        d_u = HookDispatcher(
            registry=registry_u,
            max_payload_bytes=1,
            max_timeout_seconds_runtime=30.0,
        )
        r_u = await d_u.dispatch(
            phase="dlp_pre",
            payload=b"too_big",
            context_template=_ctx_template(),
        )
        if r_u.failure_mode is not None:
            observed.add(r_u.failure_mode)

        assert observed == {
            "hook_timeout",
            "hook_exception",
            "hook_malformed_result",
            "hook_policy_refused",
            "hook_payload_unscannable",
        }


# ---------------------------------------------------------------------------
# Imported-name pin — tests confirm public surface is what we assert
# ---------------------------------------------------------------------------


def test_public_surface_is_what_we_imported() -> None:
    """Pin that the dispatcher's public surface is the four names this
    test imports — adding/removing a name forces this regression to
    update, which forces doctrine review."""
    from cognic_agentos.packs.hooks import dispatcher as d_mod

    expected = {
        "HookDispatcher",
        "HookDispatchOutcome",
        "HookDispatchResult",
        "HookFailureMode",
    }
    assert expected.issubset(set(d_mod.__all__))


def test_decision_decorator_pin() -> None:
    """HookDecision is re-exported via SDK; pin that the dispatcher
    routes on the same closed-enum values (pass / redact / mask / refuse)."""
    from typing import get_args

    members = set(get_args(HookDecision))
    assert members == {"pass", "redact", "mask", "refuse"}
