"""Sprint 8A T3 — pure Stage-1 shape validation + closed-enum vocab pins.

NO I/O. Stage-2 admission (catalog + cosign + SBOM + Rego) lives in
T5 (sandbox/admission.py); these tests cover ONLY the pure validation
surface per the Sprint 8A spec §6.1.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import typing

import pytest

from cognic_agentos.sandbox import (
    CheckpointId,
    PackAdmissionContext,
    SandboxLifecycleEvent,
    SandboxLifecycleRefused,
    SandboxPolicy,
    SandboxPolicyViolationReason,
    SandboxRefusalReason,
    validate_policy_shape,
)


class TestClosedEnumPartitionInvariants:
    """Pin the wire-protocol-public closed-enum values + counts."""

    def test_sandbox_refusal_reason_has_exactly_36_values(self) -> None:
        # Sprint 8.5 T1 extended 15 → 21 (6 new wake-time arms per spec §3.3).
        # Sprint 10 T7 extended 21 → 22 (1 kernel-boundary cross-tenant guard
        # per Sprint-10 spec §4.1 — `sandbox_credential_request_tenant_mismatch`).
        # Sprint 10 T9 extended 22 → 26 (4 new values lifted into the Literal:
        # 3 `sandbox_credential_mint_failed_*` values + 1
        # `sandbox_credential_ttl_exceeds_tenant_max`). The 3 mint-failure
        # values gain Stage-2 raise sites at T10's backend `create()`
        # post-admission per Sprint-10 spec §7.1; the TTL-cap value is
        # Literal-only — the cap continues to surface as
        # `sandbox_policy_rego_denied` because `OPAEngine.Decision` has no
        # per-rule-name channel (Rego-reason surfacing deferred to a future
        # task per Sprint-10 spec §7.3 amendment).
        # Sprint 10.1 extended 26 → 27 (1 post-mint granted-vs-requested
        # TTL refusal — `sandbox_credential_lease_ttl_grant_exceeds_request`
        # — for the new `VaultLeaseGrantExceedsRequest` exception at
        # `core/vault.lease_credential` per ADR-004 §25 amendment).
        # Sprint 10.6 T16 extended 27 → 36 (9 new credential-projection
        # refusal values per spec §5.1; Literal-only at T16 — the Stage-2
        # raise sites live at the T18 `sandbox/projection.py` planner +
        # the T21 lifecycle integration that lands later in the sprint).
        values = typing.get_args(SandboxRefusalReason)
        assert len(values) == 36, (
            f"SandboxRefusalReason must have 36 values per spec §4.1 + "
            f"8.5 §3.3 + 10 §4.1 + 10 §6.1 + 10.1 ADR-004 §25 amendment + "
            f"10.6 §5.1 (9 credential-projection values); "
            f"found {len(values)}: {values}"
        )

    def test_sandbox_policy_violation_reason_has_exactly_6_values(self) -> None:
        # T10c R1 P1.2 amended this from 5 → 6 with the addition of
        # ``egress_audit_unreadable`` (fail-closed for unreadable
        # proxy_log). Pinned at 6 to catch any future drift.
        values = typing.get_args(SandboxPolicyViolationReason)
        assert len(values) == 6, (
            f"SandboxPolicyViolationReason must have 6 values per spec §4.2 + "
            f"T10c R1 P1.2; found {len(values)}: {values}"
        )

    def test_sandbox_lifecycle_event_has_exactly_15_values(self) -> None:
        # Sprint 8.5 T1 extended 8 → 12 (4 new events per spec §3.3).
        # Sprint 10 T9 extended 12 → 15 (3 new lease lifecycle events per
        # Sprint-10 spec §6.2: sandbox.lifecycle.lease_minted /
        # .lease_revoked / .lease_revoke_failed).
        values = typing.get_args(SandboxLifecycleEvent)
        assert len(values) == 15, (
            f"SandboxLifecycleEvent must have 15 values per spec §4.3 + 8.5 §3.3 + 10 §6.2; "
            f"found {len(values)}: {values}"
        )

    def test_sandbox_refusal_reason_includes_high_risk_pre_13_5(self) -> None:
        assert "sandbox_high_risk_tier_refused_pre_13_5" in typing.get_args(SandboxRefusalReason)

    def test_sandbox_policy_violation_reason_does_not_include_cpu_cap_exceeded(self) -> None:
        # Round-3 P2 fix: --cpus throttling under cap is NOT a violation
        violations = typing.get_args(SandboxPolicyViolationReason)
        assert "cpu_cap_exceeded" not in violations
        assert "cpu_time_budget_exceeded" in violations

    def test_sandbox_lifecycle_event_does_not_include_warm_pool_replenished(self) -> None:
        # User-locked taxonomy: replenishment is the cause; the event
        # is still `precreated` per spec §4.3.
        events = typing.get_args(SandboxLifecycleEvent)
        assert "sandbox.warm_pool.replenished" not in events
        assert "sandbox.warm_pool.precreated" in events

    def test_sandbox_refusal_reason_canonical_values_present(self) -> None:
        """Exact-match guard on the 36-value Literal: the canonical set
        documented in spec §4.1 (8A 15 vocab) + spec §3.3 (8.5 6 new
        wake-time arms) + Sprint-10 spec §4.1 (T7 1 new kernel-boundary
        cross-tenant guard) + Sprint-10 spec §6.1 (T9 4 new values: 3
        mint-failure + 1 TTL-cap) + Sprint-10.1 ADR-004 §25 amendment
        (1 new post-mint granted-vs-requested TTL refusal
        `sandbox_credential_lease_ttl_grant_exceeds_request` mapped
        from the new `VaultLeaseGrantExceedsRequest` exception at
        `core/vault.lease_credential`) + Sprint-10.6 spec §5.1 (T16 9
        new credential-projection values; Literal-only at T16 — T18
        `sandbox/projection.py` planner + T21 lifecycle integration
        own the Stage-2 raise sites later in the sprint). The 3
        Sprint-10 mint-failure values gain Stage-2 raise sites at
        T10's backend `create()` post-admission per Sprint-10 spec
        §7.1; the TTL-cap value `sandbox_credential_ttl_exceeds_tenant_max`
        is Literal-only — the cap continues to surface as
        `sandbox_policy_rego_denied` (Rego-reason surfacing through
        `OPAEngine.Decision` deferred to a future task per Sprint-10
        spec §7.3 amendment). The Sprint-10.1 TTL-grant refusal IS
        wired (5th arm in the shared mapping helper + 5-value backend
        except-tuples in the same commit per Finding B of the
        2026-05-24 plan-review round 1)."""
        values = set(typing.get_args(SandboxRefusalReason))
        expected = {
            # Sprint 8A — 15 values
            "sandbox_credential_adapter_not_configured",
            "sandbox_runtime_deps_unsupported_in_production",
            "sandbox_high_risk_tier_refused_pre_13_5",
            "sandbox_image_digest_not_in_canonical_catalog",
            "sandbox_image_cosign_verification_failed",
            "sandbox_image_sbom_check_failed",
            "sandbox_image_digest_format_invalid",
            "sandbox_policy_exceeds_tenant_max_cpu",
            "sandbox_policy_exceeds_tenant_max_memory",
            "sandbox_policy_exceeds_tenant_max_walltime",
            "sandbox_policy_egress_host_invalid",
            "sandbox_policy_egress_protocol_not_http",
            "sandbox_policy_rego_denied",
            "sandbox_backend_unavailable",
            "sandbox_warm_pool_drained",
            # Sprint 8.5 T1 — 6 new wake-time arms (spec §3.3)
            "sandbox_wake_checkpoint_not_found",
            "sandbox_wake_checkpoint_corrupt",
            "sandbox_wake_checkpoint_retention_expired",
            "sandbox_wake_session_tombstoned",
            "sandbox_wake_tenant_mismatch",
            "sandbox_wake_policy_revalidation_failed",
            # Sprint 10 T7 — kernel-boundary cross-tenant request guard
            # (Sprint-10 spec §4.1; raised by admit_policy when
            # VaultLeaseRequest.tenant_id != actor.tenant_id).
            "sandbox_credential_request_tenant_mismatch",
            # Sprint 10 T9 — 3 mint-failure values (Stage-2 raise sites
            # at T10's backend create() per Sprint-10 spec §7.1):
            "sandbox_credential_mint_failed_vault_unavailable",
            "sandbox_credential_mint_failed_secret_path_unknown",
            "sandbox_credential_mint_failed_auth_denied",
            # Sprint 10 T9 — 1 TTL-cap value (Literal-only; no T9/T10
            # Stage-2 raise site — cap continues to surface as
            # sandbox_policy_rego_denied per Sprint-10 spec §7.3
            # amendment).
            "sandbox_credential_ttl_exceeds_tenant_max",
            # Sprint 10.1 — 1 post-mint granted-vs-requested TTL refusal
            # per ADR-004 §25 amendment. Mapped from the new
            # VaultLeaseGrantExceedsRequest exception (5th value in the
            # core/vault closed taxonomy) at the sandbox boundary via
            # _shared_credentials._mint_exception_to_refusal_reason.
            # Wired at the backend create() Stage-2 except-tuple in the
            # SAME commit as this Literal extension per Finding B of
            # the 2026-05-24 plan-review round 1.
            "sandbox_credential_lease_ttl_grant_exceeds_request",
            # Sprint 10.6 T16 — 9 credential-projection refusals per
            # spec §5.1. Wire-public closed-enum surface; Literal-only
            # at T16 — Stage-2 raise sites land at T18
            # ``sandbox/projection.py`` planner (field-set / value-
            # shape checks) + T21 lifecycle integration (substrate
            # preflight + workload-GID resolution). Trigger envelopes
            # registered at T16 are honest no-op registration stubs
            # pointing at T18/T21 behavior owners per the
            # registration-coverage doctrine at
            # ``tests/conformance/sandbox/test_refusal_taxonomy.py``.
            "sandbox_credential_projection_field_set_mismatch",
            "sandbox_credential_staging_path_not_tmpfs",
            "sandbox_credential_projection_workload_gid_unknown",
            "sandbox_credential_projection_image_gid_manifest_mismatch",
            "sandbox_credential_projection_image_user_directive_non_numeric",
            "sandbox_credential_projection_root_workload_refused",
            "sandbox_credential_projection_field_value_non_string",
            "sandbox_credential_projection_field_value_empty_string",
            "sandbox_credential_projection_field_value_size_exceeded",
        }
        assert values == expected, f"drift: {values ^ expected}"

    def test_sandbox_lifecycle_event_canonical_values_present(self) -> None:
        """Spot-check the 15-value Literal contains the canonical set
        documented in spec §4.3 (8A 8 events) + spec §3.3 (8.5 4 new) +
        Sprint-10 spec §6.2 (T9 3 new lease lifecycle events).

        Sprint 8.5 T1 introduces this assertion (mirrors the
        SandboxRefusalReason canonical-values pin); locks the lifecycle
        event vocabulary against name drift independently from the
        count guard.
        """
        values = set(typing.get_args(SandboxLifecycleEvent))
        expected = {
            # Sprint 8A — 8 events
            "sandbox.lifecycle.created",
            "sandbox.lifecycle.exec_completed",
            "sandbox.lifecycle.destroyed",
            "sandbox.lifecycle.refused",
            "sandbox.policy.violated",
            "sandbox.warm_pool.precreated",
            "sandbox.warm_pool.checked_out",
            "sandbox.warm_pool.drained",
            # Sprint 8.5 T1 — 4 new (spec §3.3); tombstoning is a STORAGE
            # artifact, NOT a lifecycle event (destroy() reuses 8A's
            # sandbox.lifecycle.destroyed with 2 new conditional payload
            # keys per spec §5.1).
            "sandbox.lifecycle.checkpointed",
            "sandbox.lifecycle.suspended",
            "sandbox.lifecycle.woken",
            "sandbox.lifecycle.checkpoint_purged",
            # Sprint 10 T9 — 3 new lease lifecycle events per Sprint-10
            # spec §6.2 (emitted from SandboxBackend.create() +
            # .destroy() at T10).
            "sandbox.lifecycle.lease_minted",
            "sandbox.lifecycle.lease_revoked",
            "sandbox.lifecycle.lease_revoke_failed",
        }
        assert values == expected, f"drift: {values ^ expected}"

    def test_sandbox_policy_violation_reason_canonical_values_present(self) -> None:
        values = set(typing.get_args(SandboxPolicyViolationReason))
        expected = {
            "cpu_time_budget_exceeded",
            "memory_cap_exceeded",
            "walltime_cap_exceeded",
            "egress_host_not_allow_listed",
            "egress_protocol_not_http",
            # T10c R1 P1.2 — fail-closed for unreadable proxy_log
            "egress_audit_unreadable",
        }
        assert values == expected, f"drift: {values ^ expected}"


class TestSprint106CredentialProjectionRefusalReasons:
    """Sprint 10.6 T16 — wire-public Literal extension drift detector.

    Pins the 9 credential-projection refusal values added to
    ``SandboxRefusalReason`` at T16 per spec §5.1. The dedicated
    drift detector here is independent of the umbrella exact-match
    test at
    ``TestClosedEnumPartitionInvariants.test_sandbox_refusal_reason_canonical_values_present``
    so a future drift in the 9 T16-specific values produces a crisp
    diagnostic separate from the broader 36-value count drift.

    All 9 values are Literal-only at T16 — Stage-2 raise sites land
    at the T18 ``sandbox/projection.py`` planner (field-set + value-
    shape checks) + the T21 lifecycle integration (substrate
    preflight + workload-GID resolution). The conformance trigger
    envelopes registered in ``tests/conformance/sandbox/refusal_dispatch.py``
    at T16 are honest no-op registration stubs per the registration-
    coverage doctrine; behavior coverage lives in the T18 planner
    unit suite + T21 cross-backend conformance suite.
    """

    def test_count_is_thirty_six(self) -> None:
        # Crisp count guard — separate from the membership assertion
        # so drift in size shows a clean diagnostic. Mirrors the
        # ``test_refusal_reason_count_locked_at_*`` pattern from the
        # conformance suite.
        assert len(typing.get_args(SandboxRefusalReason)) == 36

    def test_all_nine_credential_projection_values_present(self) -> None:
        values = set(typing.get_args(SandboxRefusalReason))
        expected_new = {
            "sandbox_credential_projection_field_set_mismatch",
            "sandbox_credential_staging_path_not_tmpfs",
            "sandbox_credential_projection_workload_gid_unknown",
            "sandbox_credential_projection_image_gid_manifest_mismatch",
            "sandbox_credential_projection_image_user_directive_non_numeric",
            "sandbox_credential_projection_root_workload_refused",
            "sandbox_credential_projection_field_value_non_string",
            "sandbox_credential_projection_field_value_empty_string",
            "sandbox_credential_projection_field_value_size_exceeded",
        }
        missing = expected_new - values
        assert not missing, (
            f"Sprint 10.6 T16 credential-projection refusal values "
            f"missing from SandboxRefusalReason Literal: {sorted(missing)}. "
            f"Add to protocol.py per spec §5.1; the runtime Stage-2 raise "
            f"sites land at T18 + T21."
        )


class TestSandboxPublicSurfaceExports:
    """Pin the wire-public surface re-exported from
    ``cognic_agentos.sandbox.__init__``. Sprint 8.5 T1 adds
    ``CheckpointId`` to the public surface; this regression pins it +
    locks the canonical import path callers (CheckpointStore at T3 +
    backend wake() impls at T6/T7) depend on.
    """

    def test_checkpoint_id_is_importable_from_package_root(self) -> None:
        """``from cognic_agentos.sandbox import CheckpointId`` MUST succeed.

        CheckpointId is the return type of the wire-public
        ``SandboxSession.checkpoint()`` Protocol method per spec §3.4;
        the public sandbox package re-export is the canonical import
        path (NOT ``cognic_agentos.sandbox.protocol.CheckpointId``
        directly — internal module). Without this re-export,
        consumer-side imports break + the public API diverges from the
        rest of the Protocol-facing types (already re-exported here).
        """
        # Module-level import already exercised the path at file load;
        # this test additionally pins __all__ membership.
        from cognic_agentos import sandbox as sandbox_pkg

        assert "CheckpointId" in sandbox_pkg.__all__, (
            "CheckpointId MUST be listed in cognic_agentos.sandbox.__all__ "
            "(Sprint 8.5 T1 public-surface re-export)"
        )
        assert hasattr(sandbox_pkg, "CheckpointId"), (
            "CheckpointId MUST be importable from cognic_agentos.sandbox"
        )
        # Verify the canonical-vs-public types are the same object —
        # protects against a future refactor that creates a divergent
        # re-export pointing at a different NewType.
        from cognic_agentos.sandbox.protocol import CheckpointId as _Canonical

        assert CheckpointId is _Canonical


class TestRiskTierDriftDetectorTestOnly:
    """Pin the sandbox-local RiskTier Literal against
    cli/_governance_vocab.RiskTier at test time WITHOUT a runtime
    cross-module import.

    Per feedback_drift_detector_test_only_no_runtime_import +
    AGENTS.md "Plugin discipline" (runtime sandbox code must not import
    build-time CLI vocab). Each module declares its own local Literal;
    this test imports from BOTH and asserts equality so drift fails CI.
    """

    def test_sandbox_local_risk_tier_matches_cli_governance_vocab(self) -> None:
        from cognic_agentos.cli._governance_vocab import RiskTier as CLIRiskTier
        from cognic_agentos.sandbox.policy import RiskTier as SandboxRiskTier

        cli_values = frozenset(typing.get_args(CLIRiskTier))
        sandbox_values = frozenset(typing.get_args(SandboxRiskTier))
        assert sandbox_values == cli_values, (
            f"sandbox/policy.py:RiskTier must mirror "
            f"cli/_governance_vocab.py:RiskTier verbatim. "
            f"sandbox-only: {sandbox_values - cli_values}; "
            f"cli-only: {cli_values - sandbox_values}"
        )

    def test_sandbox_module_does_not_runtime_import_cli_vocab(self) -> None:
        """AST-walk sandbox/policy.py source; assert no
        `from cognic_agentos.cli` import statement. Runtime sandbox
        must not depend on build-time CLI vocab."""
        from cognic_agentos.sandbox import policy

        source = inspect.getsource(policy)
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert not node.module.startswith("cognic_agentos.cli"), (
                    f"sandbox/policy.py must not import from cognic_agentos.cli "
                    f"(found `from {node.module} import ...`); per AGENTS.md "
                    "Plugin discipline + feedback_drift_detector_test_only_"
                    "no_runtime_import"
                )


class TestStage1ShapeValidationArms:
    """Per spec §6.1 step 1+2 — each Stage-1 refusal arm must fire on
    a minimal-deviating policy. Reaches the in-scope T3 refusal arms
    only (Stage-2 arms covered at T5)."""

    @staticmethod
    def _valid_policy_base(**overrides: object) -> SandboxPolicy:
        """Minimum valid SandboxPolicy that passes Stage-1 with the
        given field overrides."""
        defaults: dict[str, object] = {
            "cpu_cores": 0.5,
            "cpu_time_budget_s": None,
            "memory_mb": 256,
            "walltime_s": 30.0,
            "runtime_image": "cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
            "egress_allow_list": ("api.example.com",),
            "vault_path": None,
        }
        defaults.update(overrides)
        return SandboxPolicy(**defaults)  # type: ignore[arg-type]

    def test_minimum_valid_policy_passes(self) -> None:
        validate_policy_shape(self._valid_policy_base())

    def test_cpu_cores_zero_refuses_exceeds_tenant_max_cpu(self) -> None:
        with pytest.raises(SandboxLifecycleRefused) as exc:
            validate_policy_shape(self._valid_policy_base(cpu_cores=0))
        assert exc.value.reason == "sandbox_policy_exceeds_tenant_max_cpu"

    def test_cpu_cores_negative_refuses_exceeds_tenant_max_cpu(self) -> None:
        with pytest.raises(SandboxLifecycleRefused) as exc:
            validate_policy_shape(self._valid_policy_base(cpu_cores=-0.5))
        assert exc.value.reason == "sandbox_policy_exceeds_tenant_max_cpu"

    def test_memory_mb_zero_refuses_exceeds_tenant_max_memory(self) -> None:
        with pytest.raises(SandboxLifecycleRefused) as exc:
            validate_policy_shape(self._valid_policy_base(memory_mb=0))
        assert exc.value.reason == "sandbox_policy_exceeds_tenant_max_memory"

    def test_walltime_zero_refuses_exceeds_tenant_max_walltime(self) -> None:
        with pytest.raises(SandboxLifecycleRefused) as exc:
            validate_policy_shape(self._valid_policy_base(walltime_s=0))
        assert exc.value.reason == "sandbox_policy_exceeds_tenant_max_walltime"

    def test_cpu_time_budget_zero_refuses(self) -> None:
        with pytest.raises(SandboxLifecycleRefused) as exc:
            validate_policy_shape(self._valid_policy_base(cpu_time_budget_s=0))
        assert exc.value.reason == "sandbox_policy_exceeds_tenant_max_cpu"

    def test_cpu_time_budget_none_passes(self) -> None:
        validate_policy_shape(self._valid_policy_base(cpu_time_budget_s=None))

    def test_image_ref_without_at_sha256_refuses(self) -> None:
        with pytest.raises(SandboxLifecycleRefused) as exc:
            validate_policy_shape(
                self._valid_policy_base(runtime_image="cognic/sandbox-runtime-python:v1")
            )
        assert exc.value.reason == "sandbox_image_digest_format_invalid"

    def test_image_ref_with_malformed_digest_refuses(self) -> None:
        with pytest.raises(SandboxLifecycleRefused) as exc:
            validate_policy_shape(
                self._valid_policy_base(
                    runtime_image="cognic/sandbox-runtime-python:v1@sha256:not-a-real-digest"
                )
            )
        assert exc.value.reason == "sandbox_image_digest_format_invalid"

    def test_image_ref_with_uppercase_hex_digest_refuses(self) -> None:
        """Spec §6.1 step 1: digest must be `^sha256:[0-9a-f]{64}$` —
        lowercase hex only per OCI convention."""
        with pytest.raises(SandboxLifecycleRefused) as exc:
            validate_policy_shape(
                self._valid_policy_base(
                    runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "A" * 64
                )
            )
        assert exc.value.reason == "sandbox_image_digest_format_invalid"

    def test_image_ref_with_leading_hyphen_component_refuses(self) -> None:
        """Round-9 R9 P1 reviewer fix: each `/`-delimited repo
        component MUST start with `[a-z0-9]`; ``cognic/-bad`` has the
        second component starting with `-`."""
        with pytest.raises(SandboxLifecycleRefused) as exc:
            validate_policy_shape(
                self._valid_policy_base(runtime_image="cognic/-bad:v1@sha256:" + "a" * 64)
            )
        assert exc.value.reason == "sandbox_image_digest_format_invalid"

    def test_image_ref_with_empty_repo_component_refuses(self) -> None:
        """Round-9 R9 P1 reviewer fix: consecutive `/` produces an
        empty component which is not a valid OCI ref."""
        with pytest.raises(SandboxLifecycleRefused) as exc:
            validate_policy_shape(
                self._valid_policy_base(runtime_image="cognic//bad:v1@sha256:" + "a" * 64)
            )
        assert exc.value.reason == "sandbox_image_digest_format_invalid"

    def test_image_ref_with_trailing_slash_refuses(self) -> None:
        """Round-9 R9 P1 reviewer fix: trailing `/` on the repository
        path produces an empty trailing component."""
        with pytest.raises(SandboxLifecycleRefused) as exc:
            validate_policy_shape(
                self._valid_policy_base(runtime_image="cognic/bad/:v1@sha256:" + "a" * 64)
            )
        assert exc.value.reason == "sandbox_image_digest_format_invalid"

    def test_image_ref_with_leading_hyphen_first_component_refuses(self) -> None:
        """Defence-in-depth — even the FIRST component must not
        start with a hyphen (or any separator)."""
        with pytest.raises(SandboxLifecycleRefused) as exc:
            validate_policy_shape(
                self._valid_policy_base(runtime_image="-cognic/sandbox:v1@sha256:" + "a" * 64)
            )
        assert exc.value.reason == "sandbox_image_digest_format_invalid"

    def test_image_ref_with_trailing_separator_in_component_refuses(self) -> None:
        """Components cannot end with a separator per OCI; ``sandbox-``
        is a malformed component."""
        with pytest.raises(SandboxLifecycleRefused) as exc:
            validate_policy_shape(
                self._valid_policy_base(runtime_image="cognic/sandbox-:v1@sha256:" + "a" * 64)
            )
        assert exc.value.reason == "sandbox_image_digest_format_invalid"

    def test_image_ref_with_double_dash_separator_passes(self) -> None:
        """Round-9 R9 P2 reviewer fix: OCI grammar allows ``-+`` (one
        or more dashes) between alphanumeric runs. ``sandbox--runtime``
        is a valid OCI component."""
        validate_policy_shape(
            self._valid_policy_base(runtime_image="cognic/sandbox--runtime:v1@sha256:" + "a" * 64)
        )

    def test_image_ref_with_triple_dash_separator_passes(self) -> None:
        """OCI grammar's ``-+`` separator allows any positive number of
        consecutive dashes between alphanumeric runs."""
        validate_policy_shape(
            self._valid_policy_base(runtime_image="cognic/sandbox---runtime:v1@sha256:" + "a" * 64)
        )

    def test_image_ref_with_double_underscore_separator_passes(self) -> None:
        """Round-9 R9 P2 reviewer fix: OCI grammar allows ``__``
        (exactly two underscores) as a separator. Bank per-pack images
        commonly use this form (e.g. ``bank__internal_pack``)."""
        validate_policy_shape(
            self._valid_policy_base(runtime_image="cognic/sandbox__runtime:v1@sha256:" + "a" * 64)
        )

    def test_image_ref_with_single_underscore_separator_passes(self) -> None:
        validate_policy_shape(
            self._valid_policy_base(runtime_image="cognic/sandbox_runtime:v1@sha256:" + "a" * 64)
        )

    def test_image_ref_with_dot_separator_passes(self) -> None:
        validate_policy_shape(
            self._valid_policy_base(runtime_image="cognic/sandbox.runtime:v1@sha256:" + "a" * 64)
        )

    def test_image_ref_with_triple_underscore_separator_refuses(self) -> None:
        """OCI grammar: only ``__`` (exactly two) allowed for
        underscore-separator; three+ consecutive underscores are not
        valid. Reviewer's negative-case companion to the double-
        underscore positive test."""
        with pytest.raises(SandboxLifecycleRefused) as exc:
            validate_policy_shape(
                self._valid_policy_base(
                    runtime_image="cognic/sandbox___runtime:v1@sha256:" + "a" * 64
                )
            )
        assert exc.value.reason == "sandbox_image_digest_format_invalid"

    def test_image_ref_with_double_dot_separator_refuses(self) -> None:
        """OCI grammar: only single ``.`` allowed; two consecutive dots
        are not a valid separator. Reviewer's negative-case companion
        to the single-dot positive test."""
        with pytest.raises(SandboxLifecycleRefused) as exc:
            validate_policy_shape(
                self._valid_policy_base(
                    runtime_image="cognic/sandbox..runtime:v1@sha256:" + "a" * 64
                )
            )
        assert exc.value.reason == "sandbox_image_digest_format_invalid"

    def test_image_ref_with_mixed_underscore_dot_separator_refuses(self) -> None:
        """OCI grammar: separator must match exactly one alternative
        (``[._]`` / ``__`` / ``-+``); mixed ``_.`` between alphanumeric
        runs doesn't satisfy any single alternative."""
        with pytest.raises(SandboxLifecycleRefused) as exc:
            validate_policy_shape(
                self._valid_policy_base(
                    runtime_image="cognic/sandbox_.runtime:v1@sha256:" + "a" * 64
                )
            )
        assert exc.value.reason == "sandbox_image_digest_format_invalid"

    def test_ftp_scheme_in_egress_refuses_protocol_not_http(self) -> None:
        with pytest.raises(SandboxLifecycleRefused) as exc:
            validate_policy_shape(
                self._valid_policy_base(egress_allow_list=("ftp://files.example.com",))
            )
        assert exc.value.reason == "sandbox_policy_egress_protocol_not_http"

    def test_leading_hyphen_in_egress_refuses_host_invalid(self) -> None:
        with pytest.raises(SandboxLifecycleRefused) as exc:
            validate_policy_shape(self._valid_policy_base(egress_allow_list=("-bad.example.com",)))
        assert exc.value.reason == "sandbox_policy_egress_host_invalid"

    def test_empty_egress_host_refuses_host_invalid(self) -> None:
        with pytest.raises(SandboxLifecycleRefused) as exc:
            validate_policy_shape(self._valid_policy_base(egress_allow_list=("",)))
        assert exc.value.reason == "sandbox_policy_egress_host_invalid"

    def test_double_dot_egress_host_refuses_host_invalid(self) -> None:
        with pytest.raises(SandboxLifecycleRefused) as exc:
            validate_policy_shape(self._valid_policy_base(egress_allow_list=("a..b.com",)))
        assert exc.value.reason == "sandbox_policy_egress_host_invalid"

    def test_http_scheme_with_valid_host_passes(self) -> None:
        validate_policy_shape(
            self._valid_policy_base(egress_allow_list=("http://api.example.com",))
        )

    def test_https_scheme_with_valid_host_passes(self) -> None:
        validate_policy_shape(
            self._valid_policy_base(egress_allow_list=("https://api.example.com",))
        )

    def test_localhost_passes_as_egress_host(self) -> None:
        validate_policy_shape(self._valid_policy_base(egress_allow_list=("localhost",)))

    def test_empty_egress_allow_list_passes(self) -> None:
        """A sandbox with no outbound network is a legal policy."""
        validate_policy_shape(self._valid_policy_base(egress_allow_list=()))

    def test_full_oci_ref_with_registry_and_port_passes(self) -> None:
        """OCI parser must accept refs from registries with dots + ports."""
        validate_policy_shape(
            self._valid_policy_base(
                runtime_image="registry.example.com:5000/cognic/sandbox-runtime:v1@sha256:"
                + "a" * 64,
            )
        )


class TestPackAdmissionContextShape:
    def test_pack_admission_context_has_6_constructor_fields(self) -> None:
        """Round-3 third-follow-on amendment: PackAdmissionContext has
        6 fields (pack_id + pack_version + pack_artifact_digest +
        risk_tier + declares_dynamic_install + profile)."""
        fields = {f.name for f in dataclasses.fields(PackAdmissionContext)}
        expected = {
            "pack_id",
            "pack_version",
            "pack_artifact_digest",
            "risk_tier",
            "declares_dynamic_install",
            "profile",
        }
        assert fields == expected, f"PackAdmissionContext drift: {fields ^ expected}"

    def test_pack_admission_context_is_frozen(self) -> None:
        """Behavior-level pin: attempting to mutate a constructed
        instance raises ``dataclasses.FrozenInstanceError``. This
        proves frozen-ness without relying on ``__dataclass_params__``
        (which mypy does not recognise as a documented attribute)."""
        ctx = PackAdmissionContext(
            pack_id="p",
            pack_version="v1",
            pack_artifact_digest="sha256:" + "1" * 64,
            risk_tier="internal_write",
            declares_dynamic_install=False,
            profile="production",
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            ctx.pack_id = "mutated"  # type: ignore[misc]

    def test_pack_admission_context_constructs_with_canonical_fields(self) -> None:
        ctx = PackAdmissionContext(
            pack_id="cognic.test_pack",
            pack_version="v1.0.0",
            pack_artifact_digest="sha256:" + "1" * 64,
            risk_tier="internal_write",
            declares_dynamic_install=False,
            profile="production",
        )
        assert ctx.pack_id == "cognic.test_pack"
        assert ctx.risk_tier == "internal_write"
