"""Sprint-7A2 T8 — :mod:`cognic_agentos.packs.hooks.dlp_integration` regression suite.

T8 wires the runtime DLP scan adapter ``DLPGuard`` per ADR-017 line 97
("pack manifest names which hooks must run; AgentOS resolves them via
the plugin registry"). The adapter is the second runtime execution path
for hooks (after the dispatcher itself, T7) and gates governed input
flowing into pack code (``scan_pre``) + governed output flowing back to
the caller (``scan_post``).

Critical-controls watchpoints (per Sprint-7A2 plan-of-record T8 +
strict-review-applies-to-runtime-execution-path doctrine):

* Per-pack selector semantics — only hooks named in ``declared_hook_ids``
  run for this pack; other registered hooks for the same phase do not.
* Fail-closed default — unresolved hook_ids, dispatcher failure, and
  dispatcher refusal all route to ``outcome="refused"`` with closed-enum
  ``DLPRefusalReason``.
* Payload-contents-never-logged invariant — DLPGuard inherits the
  dispatcher's digest-only audit; payload bytes never reach the audit
  emitter (mechanically pinned by
  ``tests/architecture/test_hook_payload_never_logged.py`` extending
  to cover ``dlp_integration.py``).
* Closed-enum ``DLPRefusalReason`` has exactly 3 values (pinned via
  ``typing.get_args``).
* Audit emitter is token-free — the dict the emitter receives carries
  IDs + closed-enum policy metadata + digest; no payload bytes, no
  raw exception messages with payload material.
* ``DLPGuardOutcome`` is frozen + slotted so the calling-pack invocation
  surface cannot mutate the result.
* Dispatcher-canonical order respected (NOT manifest declaration order)
  — pinned via the dispatcher's own regression suite + smoke-tested here.

Critical-controls T12 promotion: ``packs/hooks/dlp_integration.py`` joins
the gate alongside ``packs/hooks/registry.py`` + ``packs/hooks/dispatcher.py``
+ ``cli/validators/hooks.py``. The 95/90 floor lives at T12; this suite
is the regression spine.
"""

from __future__ import annotations

import dataclasses
import hashlib
from collections.abc import Callable
from typing import ClassVar

import pytest

from cognic_agentos.cli._governance_vocab import HookPhase
from cognic_agentos.packs.hooks.dispatcher import HookDispatcher
from cognic_agentos.packs.hooks.dlp_integration import (
    AuditEmitter,
    DLPGuard,
    DLPGuardOutcome,
    DLPRefusalReason,
)
from cognic_agentos.packs.hooks.registry import (
    HookDeclaration,
    HookRegistry,
    VerifiedHookPack,
)
from cognic_agentos.sdk.hook import Hook, HookContext, HookResult

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _ctx_template(
    *,
    phase: HookPhase = "dlp_pre",
    pack_id: str = "calling-pack",
    tenant_id: str = "tenant-1",
    request_id: str = "req-1",
) -> HookContext:
    """Sentinel-hook_id HookContext template."""
    return HookContext(
        hook_id="",
        phase=phase,
        pack_id=pack_id,
        tenant_id=tenant_id,
        request_id=request_id,
        trace_id="trace-1",
        parent_trace_id=None,
        manifest_data_classes=("pii",),
        manifest_purpose="advisory",
    )


class _RedactPiiHook(Hook):
    """Pre-hook: redacts PII from input payload."""

    hook_id: ClassVar[str] = "redact_pii"
    phase: ClassVar[HookPhase] = "dlp_pre"

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        return HookResult(
            decision="redact", redacted_payload=b"REDACTED:" + payload, policy_reason=None
        )


class _MaskAccountHook(Hook):
    """Post-hook: masks account numbers from output payload."""

    hook_id: ClassVar[str] = "mask_accounts"
    phase: ClassVar[HookPhase] = "dlp_post"

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        return HookResult(
            decision="mask", redacted_payload=b"MASKED:" + payload, policy_reason=None
        )


class _RefuseDataClassHook(Hook):
    """Pre-hook: refuses based on data-class policy."""

    hook_id: ClassVar[str] = "refuse_data_class"
    phase: ClassVar[HookPhase] = "dlp_pre"

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        return HookResult(
            decision="refuse",
            redacted_payload=None,
            policy_reason="customer_pii_egress_blocked",
        )


class _RaiseHook(Hook):
    """Pre-hook: raises generic exception → routes to hook_exception."""

    hook_id: ClassVar[str] = "raise_hook"
    phase: ClassVar[HookPhase] = "dlp_pre"

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        raise RuntimeError("simulated runtime failure")


class _LateRefuseHook(Hook):
    """Pre-hook in input_normalization class (rank 40 — runs LATEST in
    dlp_pre). Refuses based on policy. Used to compose a
    redact-then-refuse chain for the T8 R1 P2-1 regression."""

    hook_id: ClassVar[str] = "late_refuse"
    phase: ClassVar[HookPhase] = "dlp_pre"

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        return HookResult(
            decision="refuse",
            redacted_payload=None,
            policy_reason="late_policy_blocked",
        )


def _make_loader(cls: type[Hook]) -> Callable[[], type[Hook]]:
    """Helper that closes over a hook class with a typed lambda —
    avoids mypy ``Cannot infer type of lambda`` on default-arg
    closure-capture patterns inside generator expressions."""
    return lambda: cls


def _seed_registry_with(
    hooks: list[tuple[type[Hook], HookPhase, str]],
    *,
    distribution_name: str = "cognic-hook-test",
    distribution_version: str = "0.1.0",
    signature_digest: str = "sha256:" + "c" * 64,
    timeout_seconds: float = 1.0,
    max_timeout_seconds: float = 30.0,
) -> HookRegistry:
    """Seed a registry with one verified pack carrying multiple hooks.
    ``hooks`` is a list of (hook_class, phase, ordering_class)."""
    registry = HookRegistry(max_timeout_seconds=max_timeout_seconds)
    decls = tuple(
        HookDeclaration(
            hook_id=cls.hook_id,
            phase=phase,
            ordering_class=oc,  # type: ignore[arg-type]
            timeout_seconds=timeout_seconds,
            fail_policy="fail_closed",
            fail_open_exception=None,
            callable_loader=_make_loader(cls),
        )
        for cls, phase, oc in hooks
    )
    pack = VerifiedHookPack(
        distribution_name=distribution_name,
        distribution_version=distribution_version,
        signature_digest=signature_digest,
        declarations=decls,
    )
    registry.register_pack(pack)
    return registry


def _build_guard(
    registry: HookRegistry,
    *,
    audit_emitter: AuditEmitter | None = None,
    max_payload_bytes: int = 10_000,
    max_timeout_seconds_runtime: float = 30.0,
) -> DLPGuard:
    dispatcher = HookDispatcher(
        registry=registry,
        max_payload_bytes=max_payload_bytes,
        max_timeout_seconds_runtime=max_timeout_seconds_runtime,
        audit_emitter=None,  # DLPGuard injects its own emitter at T8
    )
    return DLPGuard(
        dispatcher=dispatcher,
        audit_emitter=audit_emitter,
    )


# ---------------------------------------------------------------------------
# DLPGuardOutcome — shape + immutability
# ---------------------------------------------------------------------------


class TestDLPGuardOutcomeShape:
    """``DLPGuardOutcome`` is the wire-shape contract between DLPGuard
    and the calling-pack invocation surface; pin field set + immutability."""

    def test_outcome_is_frozen_and_slotted(self) -> None:
        outcome = DLPGuardOutcome(
            outcome="passed",
            final_payload=b"data",
            refusal_reason=None,
            underlying_failure_mode=None,
            underlying_policy_reason=None,
            failed_hook_id=None,
            failed_pack_distribution_name=None,
            policy_input_digest="abc",
        )
        with pytest.raises((AttributeError, TypeError)):
            outcome.outcome = "refused"  # type: ignore[misc]
        # Slotted: cannot add arbitrary attributes.
        with pytest.raises((AttributeError, TypeError)):
            outcome.injected = "bad"  # type: ignore[attr-defined]


class TestDLPRefusalReasonClosedEnum:
    """``DLPRefusalReason`` is a closed-enum 3-value Literal — pin
    membership via ``typing.get_args``. Adding a value forces this
    test to update, which forces doctrine review per Doctrine Lock E."""

    def test_refusal_reason_has_three_values(self) -> None:
        from typing import get_args

        members = set(get_args(DLPRefusalReason))
        assert members == {
            "dlp_hook_id_unresolved",
            "dlp_dispatcher_failed",
            "dlp_dispatcher_refused",
        }


# ---------------------------------------------------------------------------
# scan_pre — happy paths
# ---------------------------------------------------------------------------


class TestDLPGuardScanPrePassed:
    @pytest.mark.asyncio
    async def test_no_declared_hooks_returns_passed_unchanged(self) -> None:
        registry = _seed_registry_with([(_RedactPiiHook, "dlp_pre", "input_redaction")])
        guard = _build_guard(registry)
        outcome = await guard.scan_pre(
            payload=b"hello",
            declared_hook_ids=[],
            context_template=_ctx_template(),
        )
        assert outcome.outcome == "passed"
        assert outcome.final_payload == b"hello"
        assert outcome.refusal_reason is None
        # Digest computed against the original payload.
        assert outcome.policy_input_digest == hashlib.sha256(b"hello").hexdigest()

    @pytest.mark.asyncio
    async def test_declared_hook_runs_and_transforms_payload(self) -> None:
        registry = _seed_registry_with([(_RedactPiiHook, "dlp_pre", "input_redaction")])
        guard = _build_guard(registry)
        outcome = await guard.scan_pre(
            payload=b"raw_pii",
            declared_hook_ids=["redact_pii"],
            context_template=_ctx_template(),
        )
        assert outcome.outcome == "passed"
        assert outcome.final_payload == b"REDACTED:raw_pii"
        assert outcome.refusal_reason is None

    @pytest.mark.asyncio
    async def test_payload_digest_is_sha256_of_original(self) -> None:
        registry = _seed_registry_with([(_RedactPiiHook, "dlp_pre", "input_redaction")])
        guard = _build_guard(registry)
        outcome = await guard.scan_pre(
            payload=b"input_bytes",
            declared_hook_ids=["redact_pii"],
            context_template=_ctx_template(),
        )
        # Even with redaction, the digest is the ORIGINAL payload's
        # — pinned by the dispatcher's HookDispatchResult contract.
        assert outcome.policy_input_digest == hashlib.sha256(b"input_bytes").hexdigest()


# ---------------------------------------------------------------------------
# scan_pre — refusal paths
# ---------------------------------------------------------------------------


class TestDLPGuardScanPreUnresolved:
    """Unresolved declared hook_id → refused with
    reason=dlp_hook_id_unresolved."""

    @pytest.mark.asyncio
    async def test_unknown_hook_id_refuses_fail_closed(self) -> None:
        registry = _seed_registry_with([(_RedactPiiHook, "dlp_pre", "input_redaction")])
        guard = _build_guard(registry)
        outcome = await guard.scan_pre(
            payload=b"data",
            declared_hook_ids=["this_hook_does_not_exist"],
            context_template=_ctx_template(),
        )
        assert outcome.outcome == "refused"
        assert outcome.refusal_reason == "dlp_hook_id_unresolved"
        # final_payload returns ORIGINAL on refusal paths.
        assert outcome.final_payload == b"data"
        # Digest still computed against the original.
        assert outcome.policy_input_digest == hashlib.sha256(b"data").hexdigest()

    @pytest.mark.asyncio
    async def test_one_unknown_among_known_refuses(self) -> None:
        registry = _seed_registry_with([(_RedactPiiHook, "dlp_pre", "input_redaction")])
        guard = _build_guard(registry)
        outcome = await guard.scan_pre(
            payload=b"data",
            declared_hook_ids=["redact_pii", "ghost"],  # second unknown
            context_template=_ctx_template(),
        )
        assert outcome.outcome == "refused"
        assert outcome.refusal_reason == "dlp_hook_id_unresolved"
        # No partial dispatch — payload unchanged.
        assert outcome.final_payload == b"data"

    @pytest.mark.asyncio
    async def test_phase_mismatch_unresolved(self) -> None:
        """A hook registered under dlp_post is unresolved when looked
        up in dlp_pre — the lookup is keyed on (phase, hook_id)."""
        registry = _seed_registry_with([(_MaskAccountHook, "dlp_post", "output_masking")])
        guard = _build_guard(registry)
        outcome = await guard.scan_pre(
            payload=b"data",
            declared_hook_ids=["mask_accounts"],  # exists, but in dlp_post
            context_template=_ctx_template(),
        )
        assert outcome.outcome == "refused"
        assert outcome.refusal_reason == "dlp_hook_id_unresolved"


class TestDLPGuardScanPreDispatcherFailure:
    """Dispatcher returned outcome=failed (timeout / exception /
    malformed / payload_unscannable) → refused with
    reason=dlp_dispatcher_failed and underlying_failure_mode populated."""

    @pytest.mark.asyncio
    async def test_hook_exception_routes_to_dispatcher_failed(self) -> None:
        registry = _seed_registry_with([(_RaiseHook, "dlp_pre", "input_redaction")])
        guard = _build_guard(registry)
        outcome = await guard.scan_pre(
            payload=b"data",
            declared_hook_ids=["raise_hook"],
            context_template=_ctx_template(),
        )
        assert outcome.outcome == "refused"
        assert outcome.refusal_reason == "dlp_dispatcher_failed"
        assert outcome.underlying_failure_mode == "hook_exception"
        assert outcome.failed_hook_id == "raise_hook"

    @pytest.mark.asyncio
    async def test_payload_unscannable_routes_to_dispatcher_failed(self) -> None:
        registry = _seed_registry_with([(_RedactPiiHook, "dlp_pre", "input_redaction")])
        guard = _build_guard(registry, max_payload_bytes=4)
        outcome = await guard.scan_pre(
            payload=b"too_long_payload",
            declared_hook_ids=["redact_pii"],
            context_template=_ctx_template(),
        )
        assert outcome.outcome == "refused"
        assert outcome.refusal_reason == "dlp_dispatcher_failed"
        assert outcome.underlying_failure_mode == "hook_payload_unscannable"


class TestDLPGuardScanPreDispatcherRefused:
    """Dispatcher returned outcome=refused (legitimate hook_policy_refused)
    → refused with reason=dlp_dispatcher_refused +
    underlying_policy_reason propagated."""

    @pytest.mark.asyncio
    async def test_hook_refusal_translates_with_policy_reason(self) -> None:
        registry = _seed_registry_with([(_RefuseDataClassHook, "dlp_pre", "input_authorization")])
        guard = _build_guard(registry)
        outcome = await guard.scan_pre(
            payload=b"data",
            declared_hook_ids=["refuse_data_class"],
            context_template=_ctx_template(),
        )
        assert outcome.outcome == "refused"
        assert outcome.refusal_reason == "dlp_dispatcher_refused"
        assert outcome.underlying_failure_mode == "hook_policy_refused"
        assert outcome.underlying_policy_reason == "customer_pii_egress_blocked"
        assert outcome.failed_hook_id == "refuse_data_class"


# ---------------------------------------------------------------------------
# scan_post — mirrors scan_pre with phase=dlp_post
# ---------------------------------------------------------------------------


class TestDLPGuardScanPost:
    @pytest.mark.asyncio
    async def test_no_declared_hooks_returns_passed(self) -> None:
        registry = _seed_registry_with([(_MaskAccountHook, "dlp_post", "output_masking")])
        guard = _build_guard(registry)
        outcome = await guard.scan_post(
            payload=b"output",
            declared_hook_ids=[],
            context_template=_ctx_template(phase="dlp_post"),
        )
        assert outcome.outcome == "passed"
        assert outcome.final_payload == b"output"

    @pytest.mark.asyncio
    async def test_declared_hook_transforms_output(self) -> None:
        registry = _seed_registry_with([(_MaskAccountHook, "dlp_post", "output_masking")])
        guard = _build_guard(registry)
        outcome = await guard.scan_post(
            payload=b"output_with_account",
            declared_hook_ids=["mask_accounts"],
            context_template=_ctx_template(phase="dlp_post"),
        )
        assert outcome.outcome == "passed"
        assert outcome.final_payload == b"MASKED:output_with_account"

    @pytest.mark.asyncio
    async def test_unresolved_in_post_phase_refuses(self) -> None:
        registry = _seed_registry_with([(_MaskAccountHook, "dlp_post", "output_masking")])
        guard = _build_guard(registry)
        outcome = await guard.scan_post(
            payload=b"output",
            declared_hook_ids=["unknown_post"],
            context_template=_ctx_template(phase="dlp_post"),
        )
        assert outcome.outcome == "refused"
        assert outcome.refusal_reason == "dlp_hook_id_unresolved"


# ---------------------------------------------------------------------------
# Audit emission
# ---------------------------------------------------------------------------


class TestDLPGuardAuditEmission:
    """Audit emitter receives token-free dicts on refusal paths.
    Payload bytes never reach the emitter — the digest is the only
    payload-derived field (mechanically pinned by
    test_hook_payload_never_logged.py)."""

    @pytest.mark.asyncio
    async def test_emitter_called_on_unresolved_id(self) -> None:
        emissions: list[dict[str, object]] = []

        async def _emit(row: dict[str, object]) -> None:
            emissions.append(row)

        registry = _seed_registry_with([(_RedactPiiHook, "dlp_pre", "input_redaction")])
        guard = _build_guard(registry, audit_emitter=_emit)
        await guard.scan_pre(
            payload=b"data",
            declared_hook_ids=["unknown"],
            context_template=_ctx_template(),
        )
        assert len(emissions) >= 1
        # Token-free: the only payload-derived value MUST be the digest.
        for row in emissions:
            assert b"data" not in str(row).encode()
            # No raw payload bytes in any field
            assert "data" not in str({k: v for k, v in row.items() if k != "policy_input_digest"})

    @pytest.mark.asyncio
    async def test_emitter_called_on_dispatcher_refused(self) -> None:
        emissions: list[dict[str, object]] = []

        async def _emit(row: dict[str, object]) -> None:
            emissions.append(row)

        registry = _seed_registry_with([(_RefuseDataClassHook, "dlp_pre", "input_authorization")])
        guard = _build_guard(registry, audit_emitter=_emit)
        outcome = await guard.scan_pre(
            payload=b"data",
            declared_hook_ids=["refuse_data_class"],
            context_template=_ctx_template(),
        )
        assert outcome.refusal_reason == "dlp_dispatcher_refused"
        assert len(emissions) >= 1

    @pytest.mark.asyncio
    async def test_emitter_NOT_called_on_passed(self) -> None:
        """When DLPGuard returns outcome=passed, it does NOT emit a
        DLPGuard-level audit row — the dispatcher's per-hook emitter
        already covers the per-hook audit. DLPGuard emits ONLY on
        refusal paths to keep the audit chain ordered (one DLP-level
        row per refused invocation; per-hook rows from the dispatcher)."""
        emissions: list[dict[str, object]] = []

        async def _emit(row: dict[str, object]) -> None:
            emissions.append(row)

        registry = _seed_registry_with([(_RedactPiiHook, "dlp_pre", "input_redaction")])
        guard = _build_guard(registry, audit_emitter=_emit)
        outcome = await guard.scan_pre(
            payload=b"data",
            declared_hook_ids=["redact_pii"],
            context_template=_ctx_template(),
        )
        assert outcome.outcome == "passed"
        # No DLPGuard-level emissions on the happy path.
        assert emissions == []

    @pytest.mark.asyncio
    async def test_no_emitter_does_not_raise(self) -> None:
        """audit_emitter=None — DLPGuard must not raise on refusal."""
        registry = _seed_registry_with([(_RedactPiiHook, "dlp_pre", "input_redaction")])
        guard = _build_guard(registry, audit_emitter=None)
        outcome = await guard.scan_pre(
            payload=b"data",
            declared_hook_ids=["unknown"],
            context_template=_ctx_template(),
        )
        assert outcome.outcome == "refused"


# ---------------------------------------------------------------------------
# Caller-input validation
# ---------------------------------------------------------------------------


class TestDLPGuardInputValidation:
    """Caller-input validation (template hook_id sentinel + phase
    agreement) raises :class:`ValueError` fail-fast — DLPGuard mirrors
    the dispatcher's caller-input contract."""

    @pytest.mark.asyncio
    async def test_phase_mismatch_raises_value_error(self) -> None:
        registry = _seed_registry_with([(_RedactPiiHook, "dlp_pre", "input_redaction")])
        guard = _build_guard(registry)
        with pytest.raises(ValueError, match="phase"):
            await guard.scan_pre(
                payload=b"data",
                declared_hook_ids=[],
                context_template=_ctx_template(phase="dlp_post"),
            )

    @pytest.mark.asyncio
    async def test_hook_id_sentinel_violation_raises_value_error(self) -> None:
        registry = _seed_registry_with([(_RedactPiiHook, "dlp_pre", "input_redaction")])
        guard = _build_guard(registry)
        bad_template = dataclasses.replace(_ctx_template(), hook_id="forbidden")
        with pytest.raises(ValueError, match="hook_id"):
            await guard.scan_pre(
                payload=b"data",
                declared_hook_ids=[],
                context_template=bad_template,
            )


# ---------------------------------------------------------------------------
# Public surface pin
# ---------------------------------------------------------------------------


def test_public_surface_is_what_we_imported() -> None:
    """Pin DLPGuard public surface — adding/removing a name forces
    this regression to update, which forces doctrine review."""
    from cognic_agentos.packs.hooks import dlp_integration as m

    expected = {"DLPGuard", "DLPGuardOutcome", "DLPRefusalReason"}
    assert expected.issubset(set(m.__all__))


def test_dlp_integration_re_exported_from_packs_hooks() -> None:
    """Pin that DLPGuard is re-exported from the packs.hooks package."""
    from cognic_agentos.packs.hooks import (
        DLPGuard as ReDLPGuard,
    )
    from cognic_agentos.packs.hooks import (
        DLPGuardOutcome as ReDLPGuardOutcome,
    )
    from cognic_agentos.packs.hooks import (
        DLPRefusalReason as ReDLPRefusalReason,
    )

    assert ReDLPGuard is DLPGuard
    assert ReDLPGuardOutcome is DLPGuardOutcome
    # Literal aliases compare by identity of the underlying type.
    assert ReDLPRefusalReason is DLPRefusalReason


# ---------------------------------------------------------------------------
# T8 R1 review fixes — three regression classes pinning the contract
# clarifications surfaced by reviewer at halt-before-commit:
#
#   * P2-1: refusal path returns ORIGINAL payload, NOT the dispatcher's
#     last-seen (possibly partially-transformed) payload.
#   * P2-2: oversized payload + unknown hook_id returns
#     dlp_dispatcher_failed / hook_payload_unscannable, NOT
#     dlp_hook_id_unresolved (preserves dispatcher's budget-check-
#     before-lookup precedence).
#   * Bonus: duplicate hook_id in declared_hook_ids dedupes silently
#     at the dispatcher level (T10 validator refuses at build time;
#     this is runtime defense-in-depth).
# ---------------------------------------------------------------------------


class TestDLPGuardRefusalReturnsOriginalPayload:
    """T8 R1 P2-1 fix — refusal paths return the ORIGINAL payload,
    NOT the dispatcher's ``final_payload`` (which may be a partially-
    transformed last-seen payload from an earlier redact/mask hook
    that completed before a later hook refused).

    Without this fix, a calling pack invocation that assumes refused
    outcomes carry the original input would receive partially-
    transformed bytes — leaking the redact-hook's transformation to
    a path that should see no DLP processing at all.
    """

    @pytest.mark.asyncio
    async def test_redact_then_refuse_returns_original_payload(self) -> None:
        """Two-hook chain: input_redaction (rank 30) redacts, then
        input_normalization (rank 40) refuses. DLPGuardOutcome.outcome
        must be 'refused' AND final_payload must be the ORIGINAL
        payload (NOT the post-redaction transformed payload)."""
        registry = _seed_registry_with(
            [
                (_RedactPiiHook, "dlp_pre", "input_redaction"),  # rank 30 — runs first
                (_LateRefuseHook, "dlp_pre", "input_normalization"),  # rank 40 — refuses after
            ],
        )
        guard = _build_guard(registry)
        outcome = await guard.scan_pre(
            payload=b"original_pii_data",
            declared_hook_ids=["redact_pii", "late_refuse"],
            context_template=_ctx_template(),
        )
        # Refused.
        assert outcome.outcome == "refused"
        assert outcome.refusal_reason == "dlp_dispatcher_refused"
        assert outcome.underlying_failure_mode == "hook_policy_refused"
        assert outcome.underlying_policy_reason == "late_policy_blocked"
        assert outcome.failed_hook_id == "late_refuse"
        # **CRITICAL**: final_payload is the ORIGINAL, NOT b"REDACTED:original_pii_data".
        assert outcome.final_payload == b"original_pii_data"
        assert b"REDACTED" not in outcome.final_payload

    @pytest.mark.asyncio
    async def test_redact_then_dispatcher_fail_returns_original(self) -> None:
        """Two-hook chain: redact (rank 30) succeeds, then a hook
        that raises (rank 40) fails. DLPGuardOutcome.final_payload
        must be the ORIGINAL despite the redact transformation."""

        # Build a "raise after redact" via a custom rank-40 hook.
        class _LateRaiseHook(Hook):
            hook_id: ClassVar[str] = "late_raise"
            phase: ClassVar[HookPhase] = "dlp_pre"

            async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
                raise RuntimeError("simulated late failure")

        registry = _seed_registry_with(
            [
                (_RedactPiiHook, "dlp_pre", "input_redaction"),
                (_LateRaiseHook, "dlp_pre", "input_normalization"),
            ],
        )
        guard = _build_guard(registry)
        outcome = await guard.scan_pre(
            payload=b"original_pii_data",
            declared_hook_ids=["redact_pii", "late_raise"],
            context_template=_ctx_template(),
        )
        assert outcome.outcome == "refused"
        assert outcome.refusal_reason == "dlp_dispatcher_failed"
        assert outcome.underlying_failure_mode == "hook_exception"
        # ORIGINAL payload — not REDACTED:original_pii_data.
        assert outcome.final_payload == b"original_pii_data"
        assert b"REDACTED" not in outcome.final_payload

    @pytest.mark.asyncio
    async def test_unresolved_id_path_returns_original_payload(self) -> None:
        """The unresolved-id path (caught HookDispatchSelectionError)
        also returns the ORIGINAL payload (no transformation could
        have happened since dispatch did not start)."""
        registry = _seed_registry_with([(_RedactPiiHook, "dlp_pre", "input_redaction")])
        guard = _build_guard(registry)
        outcome = await guard.scan_pre(
            payload=b"untouched",
            declared_hook_ids=["unknown_hook"],
            context_template=_ctx_template(),
        )
        assert outcome.outcome == "refused"
        assert outcome.refusal_reason == "dlp_hook_id_unresolved"
        assert outcome.final_payload == b"untouched"


class TestDLPGuardBudgetPrecedence:
    """T8 R1 P2-2 fix — DLPGuard delegates ALL precedence decisions
    to the dispatcher's ``dispatch_for_pack`` so the dispatcher's
    budget-check-before-lookup ordering is preserved.

    Without this fix, an oversized payload + unknown hook_id would
    return ``dlp_hook_id_unresolved`` (because DLPGuard's pre-
    validation pass ran lookup BEFORE budget) — the wrong refusal
    reason for a payload that should have been rejected by the
    budget guard, AND wasted digest computation on bytes that
    should never have been hashed.
    """

    @pytest.mark.asyncio
    async def test_oversized_with_unknown_hook_id_returns_payload_unscannable(
        self,
    ) -> None:
        registry = _seed_registry_with([(_RedactPiiHook, "dlp_pre", "input_redaction")])
        guard = _build_guard(registry, max_payload_bytes=4)
        outcome = await guard.scan_pre(
            payload=b"too_long_payload",
            declared_hook_ids=["unknown_hook_id"],  # would be unresolved at lookup
            context_template=_ctx_template(),
        )
        # Budget check fires BEFORE lookup — refusal reason is
        # dlp_dispatcher_failed (not dlp_hook_id_unresolved).
        assert outcome.outcome == "refused"
        assert outcome.refusal_reason == "dlp_dispatcher_failed"
        assert outcome.underlying_failure_mode == "hook_payload_unscannable"

    @pytest.mark.asyncio
    async def test_oversized_with_known_hook_id_still_returns_unscannable(
        self,
    ) -> None:
        """Sanity: oversized + known hook_id also routes through
        dlp_dispatcher_failed (since the hook never runs) — pinned
        for completeness."""
        registry = _seed_registry_with([(_RedactPiiHook, "dlp_pre", "input_redaction")])
        guard = _build_guard(registry, max_payload_bytes=4)
        outcome = await guard.scan_pre(
            payload=b"too_long_payload",
            declared_hook_ids=["redact_pii"],
            context_template=_ctx_template(),
        )
        assert outcome.outcome == "refused"
        assert outcome.refusal_reason == "dlp_dispatcher_failed"
        assert outcome.underlying_failure_mode == "hook_payload_unscannable"


class TestDispatchForPackDuplicateDedupe:
    """T8 R1 bonus — declared_hook_ids may contain duplicates;
    dispatcher silently dedupes the iteration target so a hook runs
    AT MOST ONCE per dispatch.

    T10's manifest validator refuses duplicate hook_ids in
    ``[data_governance].dlp_pre_hooks`` / ``dlp_post_hooks`` at
    build time; this regression pins the runtime defense-in-depth
    behavior for malformed manifests that somehow slipped past the
    build gate.
    """

    @pytest.mark.asyncio
    async def test_duplicate_hook_ids_run_hook_once(self) -> None:
        # Use a tracking hook so we can count invocations.
        invocation_count = 0

        class _CountingRedactHook(Hook):
            hook_id: ClassVar[str] = "counting_redact"
            phase: ClassVar[HookPhase] = "dlp_pre"

            async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
                nonlocal invocation_count
                invocation_count += 1
                return HookResult(
                    decision="redact",
                    redacted_payload=b"X:" + payload,
                    policy_reason=None,
                )

        registry = _seed_registry_with(
            [(_CountingRedactHook, "dlp_pre", "input_redaction")],
        )
        guard = _build_guard(registry)
        outcome = await guard.scan_pre(
            payload=b"data",
            declared_hook_ids=["counting_redact", "counting_redact", "counting_redact"],
            context_template=_ctx_template(),
        )
        # Hook ran exactly ONCE — silent dedupe.
        assert invocation_count == 1
        # Successful pass with single transformation applied.
        assert outcome.outcome == "passed"
        assert outcome.final_payload == b"X:data"


class TestHookDispatchSelectionErrorCarriesHookId:
    """T8 R1 P2-2 follow-up — ``HookDispatchSelectionError.hook_id``
    + ``.phase`` attributes let DLPGuard populate audit rows with
    the offending id without re-parsing the exception message."""

    @pytest.mark.asyncio
    async def test_dlp_unresolved_audit_carries_failed_hook_id(self) -> None:
        emissions: list[dict[str, object]] = []

        async def _emit(row: dict[str, object]) -> None:
            emissions.append(row)

        registry = _seed_registry_with([(_RedactPiiHook, "dlp_pre", "input_redaction")])
        guard = _build_guard(registry, audit_emitter=_emit)
        outcome = await guard.scan_pre(
            payload=b"data",
            declared_hook_ids=["the_unknown_one"],
            context_template=_ctx_template(),
        )
        assert outcome.refusal_reason == "dlp_hook_id_unresolved"
        # The unresolved hook_id flows through to outcome + audit.
        assert outcome.failed_hook_id == "the_unknown_one"
        assert any(row.get("failed_hook_id") == "the_unknown_one" for row in emissions)
