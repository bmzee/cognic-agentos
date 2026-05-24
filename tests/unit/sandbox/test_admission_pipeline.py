"""Sprint 8A T5 — Stage-2 async admission pipeline.

Critical-controls module per AGENTS.md + spec §17. PURE TDD: every
Stage-2 step gets a dedicated failure-arm test; ordering invariants
+ Stage-1-short-circuit invariants get dedicated pin tests.

Plan-vs-reality fixups vs the T2 plan-of-record (verified at session
compose time per ``feedback_verify_code_citations_at_doc_write``):

* The plan imported ``KernelDefaultCredentialAdapter`` from a not-yet-
  existing ``sandbox/credentials`` module (T8 owns it per the File
  Structure table). Per user direction the Protocol + sentinel class
  live in ``sandbox/admission`` for T5; T8 either re-exports or moves
  the canonical home when it lands.
* The plan called ``rego_engine.evaluate("data.cognic.sandbox.admit",
  input={...})`` with positional + ``decision.allowed`` / ``deny_reason``
  fields. Three drift fixups:
  (a) The real ``OPAEngine.evaluate`` signature at
      ``core/policy/engine.py:269`` is kw-only ``evaluate(*,
      decision_point: str, input: dict)`` returning ``Decision(allow:
      bool, rule_matched: str | None, reasoning: str,
      decision_data: dict[str, Any] | None)`` at ``core/policy/engine.py:133``.
  (b) The wire-protocol-public decision-point is
      ``data.cognic.sandbox.admit.allow`` (spec §6.1 step 9 + §816 + §920),
      pointing at the ``allow`` boolean expression INSIDE the package —
      NOT the bare ``data.cognic.sandbox.admit`` package. OPA evaluate
      raises ``RegoEvaluationError`` on non-boolean expression values
      per ``core/policy/engine.py:296-298``; querying the bare package
      would return the package dict once T11's real bundle lands.
  (c) Decision shape uses ``.allow`` (not ``.allowed``) + ``.reasoning``
      (not ``.deny_reason``) per ``core/policy/engine.py:133``.
  Tests + admit_policy use the real shape on all three.
* The plan mocked ``MagicMock(per_tenant_max_cpu=4.0, ...)``. The
  Settings extension lands the 3 fields under the ``sandbox_`` prefix
  per the in-repo ``ui_event_stream_*`` / ``adapters_*`` sectioning
  convention. Tests + admit_policy use ``sandbox_per_tenant_max_*``.

CC watchpoints pinned by tests in this file:

* ``_HIGH_RISK_TIERS_PRE_13_5`` is exactly the 6 ADR-014 high-risk
  RiskTier values (drift detector against ``cli/_governance_vocab``;
  test-only cross-module import per
  ``feedback_drift_detector_test_only_no_runtime_import``).
* ``KernelDefaultCredentialAdapter`` is fail-loud on every method call
  (the production-grade-rule sentinel; admit_policy's isinstance check
  is the ONLY safe consumption path).
* admit_policy is the single admission seam (Stage-1 always runs
  before any Stage-2 await; backends MUST NOT call
  ``validate_policy_shape`` directly).
* Step ordering is fixed: credential → dynamic-install → high-risk
  → tenant-max → catalog → cosign → SBOM → Rego (per spec §6.1).
"""

from __future__ import annotations

import typing
from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.core.policy.engine import Decision
from cognic_agentos.sandbox import (
    PackAdmissionContext,
    SandboxLifecycleRefused,
    SandboxPolicy,
)
from cognic_agentos.sandbox.admission import (
    _HIGH_RISK_TIERS_PRE_13_5,
    CatalogProtocol,
    CredentialAdapter,
    KernelDefaultCredentialAdapter,
    admit_policy,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


_VALID_DIGEST = "sha256:" + "a" * 64
_VALID_PACK_DIGEST = "sha256:" + "b" * 64
_VALID_IMAGE_REF = "cognic/sandbox-runtime-python:v1@" + _VALID_DIGEST


def _valid_policy(**overrides: object) -> SandboxPolicy:
    """Build a Stage-1-clean SandboxPolicy with optional overrides."""

    base: dict[str, object] = {
        "cpu_cores": 1.0,
        "cpu_time_budget_s": None,
        "memory_mb": 256,
        "walltime_s": 30.0,
        "runtime_image": _VALID_IMAGE_REF,
        "egress_allow_list": ("api.example.com",),
        "vault_path": None,
    }
    base.update(overrides)
    return SandboxPolicy(**base)  # type: ignore[arg-type]


def _valid_pack_context(**overrides: object) -> PackAdmissionContext:
    """Build a Stage-2-clean PackAdmissionContext with optional overrides."""

    base: dict[str, object] = {
        "pack_id": "cognic.test_pack",
        "pack_version": "v1.0.0",
        "pack_artifact_digest": _VALID_PACK_DIGEST,
        "risk_tier": "internal_write",
        "declares_dynamic_install": False,
        "profile": "production",
    }
    base.update(overrides)
    return PackAdmissionContext(**base)  # type: ignore[arg-type]


def _passing_settings() -> MagicMock:
    """A Settings mock whose tenant caps comfortably exceed every
    fixture policy. Sandbox-prefixed per the in-repo Settings convention.

    Sprint 10 T8 — ``sandbox_kernel_default_max_credential_ttl_s`` is
    set to a stable concrete value (900s — the kernel default per spec
    §5.2). A bare MagicMock would synthesise a fresh MagicMock per
    attribute access, breaking the T7 byte-shape-equivalence regression
    at ``test_no_kwarg_and_explicit_empty_kwarg_are_byte_shape_equivalent``
    (each call's input dict would carry a different MagicMock id for
    the ``kernel_default.max_credential_ttl_s`` slot)."""

    return MagicMock(
        sandbox_per_tenant_max_cpu=4.0,
        sandbox_per_tenant_max_memory=1024,
        sandbox_per_tenant_max_walltime=300.0,
        sandbox_kernel_default_max_credential_ttl_s=900,
    )


def _passing_catalog() -> MagicMock:
    """Round-6 R6 P1 #1 doctrine: ``is_canonical`` /
    ``is_tenant_allow_listed`` are sync bool returns (NOT awaitables);
    only ``verify_*_or_refuse`` are async. Using ``MagicMock()`` keeps
    the sync methods sync; only the async methods get
    ``AsyncMock(...)`` reassignment."""

    catalog = MagicMock()
    catalog.is_canonical.return_value = True
    catalog.is_tenant_allow_listed.return_value = True
    catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
    catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
    return catalog


def _passing_rego() -> MagicMock:
    """Real ``OPAEngine.evaluate`` returns ``Decision(allow=bool, ...)``
    not a ``MagicMock(allowed=bool)`` per ``core/policy/engine.py:133``
    + ``:269``. Tests use the real Decision dataclass shape."""

    rego = MagicMock()
    rego.evaluate = AsyncMock(
        return_value=Decision(
            allow=True,
            rule_matched="data.cognic.sandbox.admit.allow",
            reasoning="ok",
            decision_data=None,
        )
    )
    return rego


# ---------------------------------------------------------------------------
# Step-arm refusal tests (spec §6.1 steps 3 through 9)
# ---------------------------------------------------------------------------


class TestAdmissionRefusalArms:
    async def test_credential_adapter_default_stub_refuses_when_vault_path_set(
        self,
    ) -> None:
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _valid_policy(vault_path="secret/test"),
                tenant_id="t-1",
                actor=MagicMock(),
                pack_context=_valid_pack_context(),
                catalog=_passing_catalog(),
                credential_adapter=KernelDefaultCredentialAdapter(),
                rego_engine=_passing_rego(),
                settings=_passing_settings(),
            )
        assert exc.value.reason == "sandbox_credential_adapter_not_configured"

    async def test_dynamic_install_refused_in_production(self) -> None:
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _valid_policy(),
                tenant_id="t-1",
                actor=MagicMock(),
                pack_context=_valid_pack_context(
                    declares_dynamic_install=True, profile="production"
                ),
                catalog=_passing_catalog(),
                credential_adapter=AsyncMock(spec=CredentialAdapter),
                rego_engine=_passing_rego(),
                settings=_passing_settings(),
            )
        assert exc.value.reason == "sandbox_runtime_deps_unsupported_in_production"

    async def test_dynamic_install_permitted_in_dev_profile(self) -> None:
        """Dev profile bypasses the dynamic-install refusal so pack
        authors can iterate without re-baking the runtime image. The
        downstream steps still gate admission."""

        await admit_policy(
            _valid_policy(),
            tenant_id="t-1",
            actor=MagicMock(),
            pack_context=_valid_pack_context(declares_dynamic_install=True, profile="development"),
            catalog=_passing_catalog(),
            credential_adapter=AsyncMock(spec=CredentialAdapter),
            rego_engine=_passing_rego(),
            settings=_passing_settings(),
        )
        # No exception → dev profile bypassed the dynamic-install gate

    @pytest.mark.parametrize(
        "tier",
        [
            "customer_data_read",
            "customer_data_write",
            "payment_action",
            "regulator_communication",
            "cross_tenant",
            "high_risk_custom",
        ],
    )
    async def test_high_risk_tier_refused_pre_13_5(self, tier: str) -> None:
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _valid_policy(),
                tenant_id="t-1",
                actor=MagicMock(),
                pack_context=_valid_pack_context(risk_tier=tier),
                catalog=_passing_catalog(),
                credential_adapter=AsyncMock(spec=CredentialAdapter),
                rego_engine=_passing_rego(),
                settings=_passing_settings(),
            )
        assert exc.value.reason == "sandbox_high_risk_tier_refused_pre_13_5"

    async def test_tenant_max_cpu_exceeded(self) -> None:
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _valid_policy(cpu_cores=16.0),
                tenant_id="t-1",
                actor=MagicMock(),
                pack_context=_valid_pack_context(),
                catalog=_passing_catalog(),
                credential_adapter=AsyncMock(spec=CredentialAdapter),
                rego_engine=_passing_rego(),
                settings=_passing_settings(),
            )
        assert exc.value.reason == "sandbox_policy_exceeds_tenant_max_cpu"

    async def test_tenant_max_memory_exceeded(self) -> None:
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _valid_policy(memory_mb=8192),
                tenant_id="t-1",
                actor=MagicMock(),
                pack_context=_valid_pack_context(),
                catalog=_passing_catalog(),
                credential_adapter=AsyncMock(spec=CredentialAdapter),
                rego_engine=_passing_rego(),
                settings=_passing_settings(),
            )
        assert exc.value.reason == "sandbox_policy_exceeds_tenant_max_memory"

    async def test_tenant_max_walltime_exceeded(self) -> None:
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _valid_policy(walltime_s=3600.0),
                tenant_id="t-1",
                actor=MagicMock(),
                pack_context=_valid_pack_context(),
                catalog=_passing_catalog(),
                credential_adapter=AsyncMock(spec=CredentialAdapter),
                rego_engine=_passing_rego(),
                settings=_passing_settings(),
            )
        assert exc.value.reason == "sandbox_policy_exceeds_tenant_max_walltime"

    async def test_image_not_in_canonical_catalog_or_tenant_allow_list(
        self,
    ) -> None:
        catalog = MagicMock()
        catalog.is_canonical.return_value = False
        catalog.is_tenant_allow_listed.return_value = False

        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _valid_policy(),
                tenant_id="t-1",
                actor=MagicMock(),
                pack_context=_valid_pack_context(),
                catalog=catalog,
                credential_adapter=AsyncMock(spec=CredentialAdapter),
                rego_engine=_passing_rego(),
                settings=_passing_settings(),
            )
        assert exc.value.reason == "sandbox_image_digest_not_in_canonical_catalog"

    async def test_cosign_verification_fail(self) -> None:
        catalog = _passing_catalog()
        catalog.verify_cosign_or_refuse = AsyncMock(
            side_effect=SandboxLifecycleRefused(
                "sandbox_image_cosign_verification_failed",
                detail="signature mismatch",
            )
        )
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _valid_policy(),
                tenant_id="t-1",
                actor=MagicMock(),
                pack_context=_valid_pack_context(),
                catalog=catalog,
                credential_adapter=AsyncMock(spec=CredentialAdapter),
                rego_engine=_passing_rego(),
                settings=_passing_settings(),
            )
        assert exc.value.reason == "sandbox_image_cosign_verification_failed"

    async def test_sbom_check_fail(self) -> None:
        catalog = _passing_catalog()
        catalog.verify_sbom_policy_or_refuse = AsyncMock(
            side_effect=SandboxLifecycleRefused(
                "sandbox_image_sbom_check_failed",
                detail="GPL-3.0 detected",
            )
        )
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _valid_policy(),
                tenant_id="t-1",
                actor=MagicMock(),
                pack_context=_valid_pack_context(),
                catalog=catalog,
                credential_adapter=AsyncMock(spec=CredentialAdapter),
                rego_engine=_passing_rego(),
                settings=_passing_settings(),
            )
        assert exc.value.reason == "sandbox_image_sbom_check_failed"

    async def test_rego_denied(self) -> None:
        rego = MagicMock()
        rego.evaluate = AsyncMock(
            return_value=Decision(
                allow=False,
                rule_matched="data.cognic.sandbox.admit.allow",
                reasoning="bank-overlay-policy-tightened",
                decision_data=None,
            )
        )
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _valid_policy(),
                tenant_id="t-1",
                actor=MagicMock(),
                pack_context=_valid_pack_context(),
                catalog=_passing_catalog(),
                credential_adapter=AsyncMock(spec=CredentialAdapter),
                rego_engine=rego,
                settings=_passing_settings(),
            )
        assert exc.value.reason == "sandbox_policy_rego_denied"
        # Reasoning surfaces in the refusal detail so examiners can
        # trace WHY the Rego bundle denied.
        assert "bank-overlay-policy-tightened" in exc.value.detail


# ---------------------------------------------------------------------------
# Happy-path pin
# ---------------------------------------------------------------------------


class TestAdmissionHappyPath:
    async def test_all_passing_admits_without_raise(self) -> None:
        await admit_policy(
            _valid_policy(),
            tenant_id="t-1",
            actor=MagicMock(),
            pack_context=_valid_pack_context(),
            catalog=_passing_catalog(),
            credential_adapter=AsyncMock(spec=CredentialAdapter),
            rego_engine=_passing_rego(),
            settings=_passing_settings(),
        )
        # No exception raised → all 9 admission steps passed.

    async def test_admit_policy_falls_through_on_green_path(self) -> None:
        """admit_policy is fail-loud-only: the ``-> None`` return is
        enforced by the type system (so an explicit ``is None`` check
        would be a void-assignment mypy error); this runtime pin
        proves the awaited call falls through normally on the
        green-path (does NOT raise + does NOT yield mid-flight)."""

        # Plain await — runtime falls through iff all 9 admission steps
        # passed. Equivalent to "returns None" in mypy's worldview.
        await admit_policy(
            _valid_policy(),
            tenant_id="t-1",
            actor=MagicMock(),
            pack_context=_valid_pack_context(),
            catalog=_passing_catalog(),
            credential_adapter=AsyncMock(spec=CredentialAdapter),
            rego_engine=_passing_rego(),
            settings=_passing_settings(),
        )

    async def test_admit_policy_passes_canonical_rego_decision_point(
        self,
    ) -> None:
        """The Rego decision-point string is the wire-protocol-public
        bundle name; T9 owns the bundle at
        ``policies/_default/sandbox.rego``. Pinned here so future
        bundle renames produce an admission-test failure rather than a
        silent runtime mis-routing."""

        rego = _passing_rego()
        await admit_policy(
            _valid_policy(),
            tenant_id="t-1",
            actor=MagicMock(),
            pack_context=_valid_pack_context(),
            catalog=_passing_catalog(),
            credential_adapter=AsyncMock(spec=CredentialAdapter),
            rego_engine=rego,
            settings=_passing_settings(),
        )
        rego.evaluate.assert_awaited_once()
        call_kwargs = rego.evaluate.call_args.kwargs
        # Wire-contract: points at the ``.allow`` boolean expression
        # INSIDE the package, NOT the bare package. OPA evaluate raises
        # RegoEvaluationError on non-boolean results; querying the bare
        # package returns the package dict once T11's bundle lands.
        # Spec §6.1 step 9 + §816 are the wire-protocol-public source.
        assert call_kwargs["decision_point"] == "data.cognic.sandbox.admit.allow"

    async def test_admit_policy_threads_runtime_image_bools_into_rego_input(
        self,
    ) -> None:
        """T11 pre-commit fix — the Rego bundle's rule 4
        (``_runtime_image_authorised``) requires
        ``runtime_image_in_canonical_set`` AND
        ``runtime_image_in_tenant_allow_list`` precomputed bools in
        the input dict. Without these, every otherwise-safe admission
        that already passed catalog + cosign + SBOM reaches the
        bundle with both fields undefined and is denied with
        ``sandbox_policy_rego_denied`` — a silent dead end. This
        regression pins both keys are sent + carry the catalog's
        precomputed bool values."""

        rego = _passing_rego()
        catalog = _passing_catalog()
        # _passing_catalog defaults BOTH bools to True; the bundle's
        # rule 4 ``_runtime_image_authorised`` matches when either is
        # true. Pin both to verify the wiring threads the catalog's
        # bools end-to-end (not a hardcoded literal somewhere in
        # admission.py).
        catalog.is_canonical.return_value = True
        catalog.is_tenant_allow_listed.return_value = False
        await admit_policy(
            _valid_policy(),
            tenant_id="t-1",
            actor=MagicMock(),
            pack_context=_valid_pack_context(),
            catalog=catalog,
            credential_adapter=AsyncMock(spec=CredentialAdapter),
            rego_engine=rego,
            settings=_passing_settings(),
        )
        rego.evaluate.assert_awaited_once()
        rego_input = rego.evaluate.call_args.kwargs["input"]
        # Both keys MUST be present + carry the bool values the
        # catalog returned (not hardcoded literals).
        assert rego_input["runtime_image_in_canonical_set"] is True
        assert rego_input["runtime_image_in_tenant_allow_list"] is False

    async def test_admit_policy_threads_tenant_allow_list_bool_when_only_path_is_overlay(
        self,
    ) -> None:
        """Companion to the above — the tenant-allow-list escape hatch
        is what makes rule 4 actually decidable for non-canonical
        bank-overlay images. Pin that when the canonical set is false
        but the tenant allow-list is true, the bundle still receives
        both bools (not the canonical short-circuit dropping the
        second key, etc.)."""

        rego = _passing_rego()
        catalog = _passing_catalog()
        catalog.is_canonical.return_value = False
        catalog.is_tenant_allow_listed.return_value = True
        await admit_policy(
            _valid_policy(),
            tenant_id="t-1",
            actor=MagicMock(),
            pack_context=_valid_pack_context(),
            catalog=catalog,
            credential_adapter=AsyncMock(spec=CredentialAdapter),
            rego_engine=rego,
            settings=_passing_settings(),
        )
        rego_input = rego.evaluate.call_args.kwargs["input"]
        assert rego_input["runtime_image_in_canonical_set"] is False
        assert rego_input["runtime_image_in_tenant_allow_list"] is True


class TestSprint10T7RequiresCredentialsBackwardCompat:
    """Sprint 10 T7 — `admit_policy` gains a keyword-only
    ``requires_credentials: Sequence[VaultLeaseRequest] = ()`` kwarg.
    Every Sprint-8A call site in this test module passes NO kwarg —
    the default empty value MUST be a complete byte-shape no-op for
    backward-compat. The substantive T7 tests live in
    ``tests/unit/sandbox/test_admit_credentials.py``; this class pins
    the no-kwarg ≡ explicit-empty-kwarg equivalence so a future
    refactor that changes the default away from ``()`` is caught HERE
    rather than only at the dedicated T7 file."""

    async def test_no_kwarg_and_explicit_empty_kwarg_are_byte_shape_equivalent(
        self,
    ) -> None:
        """Call admit_policy twice with the same fixtures — once
        omitting ``requires_credentials`` entirely, once passing
        ``requires_credentials=()`` explicitly — and assert the Rego
        input dicts are byte-shape identical."""

        rego_implicit = _passing_rego()
        await admit_policy(
            _valid_policy(),
            tenant_id="t-1",
            actor=MagicMock(),
            pack_context=_valid_pack_context(),
            catalog=_passing_catalog(),
            credential_adapter=AsyncMock(spec=CredentialAdapter),
            rego_engine=rego_implicit,
            settings=_passing_settings(),
            # No `requires_credentials` kwarg.
        )

        rego_explicit = _passing_rego()
        await admit_policy(
            _valid_policy(),
            tenant_id="t-1",
            actor=MagicMock(),
            pack_context=_valid_pack_context(),
            catalog=_passing_catalog(),
            credential_adapter=AsyncMock(spec=CredentialAdapter),
            rego_engine=rego_explicit,
            settings=_passing_settings(),
            requires_credentials=(),
        )

        implicit_input = rego_implicit.evaluate.call_args.kwargs["input"]
        explicit_input = rego_explicit.evaluate.call_args.kwargs["input"]
        assert implicit_input == explicit_input
        # Both paths MUST produce the empty-list shape (NOT a missing
        # key — bundle reads ``count(input.requires_credentials)``
        # unconditionally).
        assert implicit_input["requires_credentials"] == []
        assert explicit_input["requires_credentials"] == []


# ---------------------------------------------------------------------------
# Step-ordering invariants (spec §6.1)
# ---------------------------------------------------------------------------


class TestAdmissionPipelineOrderingInvariants:
    """Each pair of refusals tests an explicit step-ordering claim. A
    future refactor that reorders steps will trip exactly one of these
    pin tests with a different ``.reason`` value."""

    async def test_credential_check_runs_before_high_risk_tier_check(
        self,
    ) -> None:
        """Step 3 (credential) BEFORE step 4 (high-risk). A high-risk-
        tier pack with vault_path + default credential adapter MUST
        refuse with credential_adapter_not_configured (step 3 fires
        first), NOT high_risk_tier_refused_pre_13_5 (step 4)."""

        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _valid_policy(vault_path="secret/p"),
                tenant_id="t-1",
                actor=MagicMock(),
                pack_context=_valid_pack_context(risk_tier="payment_action"),
                catalog=_passing_catalog(),
                credential_adapter=KernelDefaultCredentialAdapter(),
                rego_engine=_passing_rego(),
                settings=_passing_settings(),
            )
        assert exc.value.reason == "sandbox_credential_adapter_not_configured"

    async def test_credential_check_runs_before_dynamic_install_refusal(
        self,
    ) -> None:
        """Step 3 (credential) BEFORE step 3a (dynamic-install). A pack
        with BOTH vault_path + default credential adapter AND
        declares_dynamic_install=True / profile='production' MUST
        refuse with credential_adapter_not_configured (step 3 fires
        first), NOT runtime_deps_unsupported_in_production (step 3a).
        Pins the credential→dynamic-install adjacency that T5 R1 P2
        surfaced as gap in the original ordering coverage."""

        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _valid_policy(vault_path="secret/p"),
                tenant_id="t-1",
                actor=MagicMock(),
                pack_context=_valid_pack_context(
                    declares_dynamic_install=True, profile="production"
                ),
                catalog=_passing_catalog(),
                credential_adapter=KernelDefaultCredentialAdapter(),
                rego_engine=_passing_rego(),
                settings=_passing_settings(),
            )
        assert exc.value.reason == "sandbox_credential_adapter_not_configured"

    async def test_dynamic_install_refusal_runs_before_high_risk_tier_check(
        self,
    ) -> None:
        """Step 3a (dynamic-install) BEFORE step 4 (high-risk). A
        high-risk pack with declares_dynamic_install=True in production
        MUST refuse with runtime_deps_unsupported_in_production, NOT
        high_risk_tier."""

        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _valid_policy(),
                tenant_id="t-1",
                actor=MagicMock(),
                pack_context=_valid_pack_context(
                    declares_dynamic_install=True,
                    profile="production",
                    risk_tier="payment_action",
                ),
                catalog=_passing_catalog(),
                credential_adapter=AsyncMock(spec=CredentialAdapter),
                rego_engine=_passing_rego(),
                settings=_passing_settings(),
            )
        assert exc.value.reason == "sandbox_runtime_deps_unsupported_in_production"

    async def test_high_risk_tier_refusal_runs_before_tenant_max_check(
        self,
    ) -> None:
        """Step 4 (high-risk) BEFORE step 5 (tenant-max). A high-risk
        pack with cpu_cores > tenant max MUST refuse with high_risk
        (step 4), NOT exceeds_tenant_max_cpu (step 5)."""

        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _valid_policy(cpu_cores=16.0),
                tenant_id="t-1",
                actor=MagicMock(),
                pack_context=_valid_pack_context(risk_tier="payment_action"),
                catalog=_passing_catalog(),
                credential_adapter=AsyncMock(spec=CredentialAdapter),
                rego_engine=_passing_rego(),
                settings=_passing_settings(),
            )
        assert exc.value.reason == "sandbox_high_risk_tier_refused_pre_13_5"

    async def test_tenant_max_runs_before_catalog_check(self) -> None:
        """Step 5 (tenant-max) BEFORE step 6 (catalog). A policy that
        violates tenant-max AND has a non-canonical image MUST refuse
        with exceeds_tenant_max (step 5), NOT not_in_canonical_catalog
        (step 6)."""

        catalog = MagicMock()
        catalog.is_canonical.return_value = False
        catalog.is_tenant_allow_listed.return_value = False
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _valid_policy(cpu_cores=16.0),
                tenant_id="t-1",
                actor=MagicMock(),
                pack_context=_valid_pack_context(),
                catalog=catalog,
                credential_adapter=AsyncMock(spec=CredentialAdapter),
                rego_engine=_passing_rego(),
                settings=_passing_settings(),
            )
        assert exc.value.reason == "sandbox_policy_exceeds_tenant_max_cpu"

    async def test_catalog_runs_before_cosign_verification(self) -> None:
        """Step 6 (catalog) BEFORE step 7 (cosign). A policy with a
        non-canonical image MUST refuse with not_in_canonical_catalog
        (step 6), and cosign verification MUST NOT have been called."""

        catalog = MagicMock()
        catalog.is_canonical.return_value = False
        catalog.is_tenant_allow_listed.return_value = False
        catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
        catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
        with pytest.raises(SandboxLifecycleRefused):
            await admit_policy(
                _valid_policy(),
                tenant_id="t-1",
                actor=MagicMock(),
                pack_context=_valid_pack_context(),
                catalog=catalog,
                credential_adapter=AsyncMock(spec=CredentialAdapter),
                rego_engine=_passing_rego(),
                settings=_passing_settings(),
            )
        catalog.verify_cosign_or_refuse.assert_not_called()
        catalog.verify_sbom_policy_or_refuse.assert_not_called()

    async def test_cosign_runs_before_sbom_check(self) -> None:
        """Step 7 (cosign) BEFORE step 8 (SBOM). A cosign failure MUST
        short-circuit before the SBOM checker is called."""

        catalog = _passing_catalog()
        catalog.verify_cosign_or_refuse = AsyncMock(
            side_effect=SandboxLifecycleRefused(
                "sandbox_image_cosign_verification_failed", detail="bad"
            )
        )
        with pytest.raises(SandboxLifecycleRefused):
            await admit_policy(
                _valid_policy(),
                tenant_id="t-1",
                actor=MagicMock(),
                pack_context=_valid_pack_context(),
                catalog=catalog,
                credential_adapter=AsyncMock(spec=CredentialAdapter),
                rego_engine=_passing_rego(),
                settings=_passing_settings(),
            )
        catalog.verify_sbom_policy_or_refuse.assert_not_called()

    async def test_sbom_runs_before_rego(self) -> None:
        """Step 8 (SBOM) BEFORE step 9 (Rego). An SBOM failure MUST
        short-circuit before the Rego engine is called."""

        catalog = _passing_catalog()
        catalog.verify_sbom_policy_or_refuse = AsyncMock(
            side_effect=SandboxLifecycleRefused("sandbox_image_sbom_check_failed", detail="bad")
        )
        rego = _passing_rego()
        with pytest.raises(SandboxLifecycleRefused):
            await admit_policy(
                _valid_policy(),
                tenant_id="t-1",
                actor=MagicMock(),
                pack_context=_valid_pack_context(),
                catalog=catalog,
                credential_adapter=AsyncMock(spec=CredentialAdapter),
                rego_engine=rego,
                settings=_passing_settings(),
            )
        rego.evaluate.assert_not_called()


# ---------------------------------------------------------------------------
# Stage-1-before-Stage-2 invariants (single-seam contract)
# ---------------------------------------------------------------------------


class TestStage1RunsBeforeStage2:
    """Round-4 R4 P1 #4 pin: admit_policy is the single admission seam;
    calls ``validate_policy_shape()`` (Stage 1) BEFORE any async I/O.
    Without this, backends could drift by calling Stage-1 separately
    (or forgetting to). Each test below verifies a Stage-1 arm fires
    BEFORE any Stage-2 dep is touched."""

    async def test_malformed_image_digest_refuses_before_catalog_call(
        self,
    ) -> None:
        """Stage-1 rejects digest-format-invalid (no @sha256: suffix)
        WITHOUT calling catalog.is_canonical() or any other async dep."""

        catalog = _passing_catalog()
        rego = _passing_rego()
        cred = AsyncMock(spec=CredentialAdapter)

        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _valid_policy(runtime_image="cognic/sandbox-runtime-python:v1"),  # no @sha256:
                tenant_id="t-1",
                actor=MagicMock(),
                pack_context=_valid_pack_context(),
                catalog=catalog,
                credential_adapter=cred,
                rego_engine=rego,
                settings=_passing_settings(),
            )
        assert exc.value.reason == "sandbox_image_digest_format_invalid"
        # Stage-1 short-circuited — zero Stage-2 deps were called.
        catalog.is_canonical.assert_not_called()
        catalog.verify_cosign_or_refuse.assert_not_called()
        catalog.verify_sbom_policy_or_refuse.assert_not_called()
        rego.evaluate.assert_not_called()

    async def test_malformed_egress_host_refuses_before_catalog_call(
        self,
    ) -> None:
        """Stage-1 rejects egress_host_invalid (leading-hyphen RFC 1123
        violation) WITHOUT any async I/O."""

        catalog = _passing_catalog()
        rego = _passing_rego()
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _valid_policy(egress_allow_list=("-bad.example.com",)),
                tenant_id="t-1",
                actor=MagicMock(),
                pack_context=_valid_pack_context(),
                catalog=catalog,
                credential_adapter=AsyncMock(spec=CredentialAdapter),
                rego_engine=rego,
                settings=_passing_settings(),
            )
        assert exc.value.reason == "sandbox_policy_egress_host_invalid"
        catalog.is_canonical.assert_not_called()
        rego.evaluate.assert_not_called()

    async def test_non_http_egress_scheme_refuses_at_stage_1(self) -> None:
        """Stage-1 rejects non-HTTP schemes (Wave-1 allows http/https
        only) WITHOUT any async I/O."""

        catalog = _passing_catalog()
        rego = _passing_rego()

        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _valid_policy(egress_allow_list=("ftp://files.example.com",)),
                tenant_id="t-1",
                actor=MagicMock(),
                pack_context=_valid_pack_context(),
                catalog=catalog,
                credential_adapter=AsyncMock(spec=CredentialAdapter),
                rego_engine=rego,
                settings=_passing_settings(),
            )
        assert exc.value.reason == "sandbox_policy_egress_protocol_not_http"
        catalog.is_canonical.assert_not_called()
        rego.evaluate.assert_not_called()


# ---------------------------------------------------------------------------
# CC pin: closed-enum high-risk-tier drift detector against ADR-014
# ---------------------------------------------------------------------------


class TestHighRiskTierDriftDetectorTestOnly:
    """Drift detector — ``_HIGH_RISK_TIERS_PRE_13_5`` MUST equal exactly
    the 6 ADR-014 canonical RiskTier values that are NOT in
    ``{read_only, internal_write}``. Drift breaks the transitional
    fail-closed admission gate.

    Per ``feedback_drift_detector_test_only_no_runtime_import``: the
    cross-module import lives ONLY in this test; the production
    admission module declares ``_HIGH_RISK_TIERS_PRE_13_5`` directly.
    The two-set equality assertion below pins lockstep."""

    def test_high_risk_tier_set_matches_adr_014_canonical_minus_low_risk(
        self,
    ) -> None:
        from cognic_agentos.cli._governance_vocab import RiskTier

        canonical_8 = frozenset(typing.get_args(RiskTier))
        # The 2 low-risk tiers (no admission halt) are read_only +
        # internal_write per ADR-014 §29-30; the remaining 6 are
        # high-risk and must trip the pre-13.5 transitional refusal.
        low_risk = frozenset({"read_only", "internal_write"})
        expected_high_risk = canonical_8 - low_risk

        assert expected_high_risk == _HIGH_RISK_TIERS_PRE_13_5
        assert len(_HIGH_RISK_TIERS_PRE_13_5) == 6

    def test_high_risk_tier_set_is_frozenset_not_set(self) -> None:
        """frozenset prevents accidental mutation at import time."""

        assert isinstance(_HIGH_RISK_TIERS_PRE_13_5, frozenset)


# ---------------------------------------------------------------------------
# CC pin: KernelDefaultCredentialAdapter is fail-loud
# ---------------------------------------------------------------------------


class TestKernelDefaultCredentialAdapterIsFailLoud:
    """The sentinel is the production-grade ``NotImplementedError``
    pointing-at-ADR scaffold per CLAUDE.md. admit_policy's isinstance
    check is the ONLY safe consumption path; every other method call
    on this class MUST raise."""

    async def test_fetch_secret_raises_not_implemented_pointing_at_sprint_10(
        self,
    ) -> None:
        sentinel = KernelDefaultCredentialAdapter()
        with pytest.raises(NotImplementedError, match="Sprint 10"):
            await sentinel.fetch_secret("secret/anywhere")

    def test_isinstance_check_distinguishes_stub_from_real_adapter(self) -> None:
        """admit_policy step 3 uses isinstance to detect the sentinel.
        A real CredentialAdapter (e.g. an AsyncMock matching the
        Protocol shape) MUST NOT match the isinstance check."""

        real = AsyncMock(spec=CredentialAdapter)
        sentinel = KernelDefaultCredentialAdapter()
        assert isinstance(sentinel, KernelDefaultCredentialAdapter)
        assert not isinstance(real, KernelDefaultCredentialAdapter)


# ---------------------------------------------------------------------------
# CC pin: Protocol shapes (T6 + T8 land concrete impls against these)
# ---------------------------------------------------------------------------


class TestProtocolShapes:
    """T6 + T8 implement concrete classes against the Protocols
    declared in ``sandbox/admission``. These pins catch a future
    Protocol-method drift that would silently break the concrete
    impls (a renamed method would only fail at first-call time
    otherwise)."""

    def test_catalog_protocol_declares_four_methods(self) -> None:
        # ``runtime_checkable`` Protocols expose their declared methods
        # via __annotations__-style introspection. We grep by
        # hasattr on a fresh structurally-conforming AsyncMock.
        expected_methods = {
            "is_canonical",
            "is_tenant_allow_listed",
            "verify_cosign_or_refuse",
            "verify_sbom_policy_or_refuse",
        }
        for name in expected_methods:
            assert hasattr(CatalogProtocol, name), (
                f"CatalogProtocol missing required method {name!r}; "
                f"T6 concrete impl will silently break on first call"
            )

    def test_credential_adapter_protocol_declares_fetch_secret(self) -> None:
        assert hasattr(CredentialAdapter, "fetch_secret")

    def test_runtime_checkable_admits_structural_match(self) -> None:
        """The Protocols are ``runtime_checkable`` per spec §5 so a
        bank overlay can register an alternative concrete impl without
        explicit subclassing."""

        real = AsyncMock(spec=CredentialAdapter)
        assert isinstance(real, CredentialAdapter)


# ---------------------------------------------------------------------------
# CC pin: Settings extension lands the 3 sandbox_per_tenant_max_* fields
# ---------------------------------------------------------------------------


class TestSettingsSandboxPerTenantMaxFields:
    """T5 extension to ``core/config.py:Settings``: 3 sandbox_-prefixed
    per-tenant-cap fields. Pinned here so a future Settings refactor
    that drops or renames these fields fails this test BEFORE
    admit_policy AttributeErrors in production."""

    def test_settings_has_sandbox_per_tenant_max_cpu_default(self) -> None:
        from cognic_agentos.core.config import Settings

        s = Settings()
        assert hasattr(s, "sandbox_per_tenant_max_cpu")
        assert isinstance(s.sandbox_per_tenant_max_cpu, float)
        assert s.sandbox_per_tenant_max_cpu > 0

    def test_settings_has_sandbox_per_tenant_max_memory_default(self) -> None:
        from cognic_agentos.core.config import Settings

        s = Settings()
        assert hasattr(s, "sandbox_per_tenant_max_memory")
        assert isinstance(s.sandbox_per_tenant_max_memory, int)
        assert s.sandbox_per_tenant_max_memory > 0

    def test_settings_has_sandbox_per_tenant_max_walltime_default(self) -> None:
        from cognic_agentos.core.config import Settings

        s = Settings()
        assert hasattr(s, "sandbox_per_tenant_max_walltime")
        assert isinstance(s.sandbox_per_tenant_max_walltime, float)
        assert s.sandbox_per_tenant_max_walltime > 0
