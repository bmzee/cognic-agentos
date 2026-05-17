"""Sprint 8A T8 — credentials.py re-export shim.

Pins that:

* `sandbox.credentials` re-exports the SAME OBJECTS as `sandbox.admission`
  for `CredentialAdapter` + `KernelDefaultCredentialAdapter` (re-export
  equivalence; NOT structural duplication — duplicates would drift).
* `sandbox.__init__` exposes both import paths and they resolve to the
  same objects.
* `KernelDefaultCredentialAdapter` satisfies the @runtime_checkable
  `CredentialAdapter` Protocol.
* `fetch_secret` raises `NotImplementedError` with the actual T5-committed
  stub message (cites Sprint 10 + ADR-009 + ``VaultCredentialAdapter`` +
  "fail-loud sentinel"; ADR-009 is the canonical pluggable-adapter ADR,
  ADR-004's credential-scope is the architectural intent).
* Defence-in-depth: when ``policy.vault_path is None``, admit_policy
  NEVER calls ``fetch_secret`` on the wired adapter, regardless of
  which adapter is wired (the admission step-3 check is gated on
  ``vault_path is not None``).

The richer ``CredentialLease + mint_lease/revoke_lease`` lease API
belongs to Sprint 10's concrete ``VaultCredentialAdapter`` design and
is intentionally NOT part of the Wave-1 ``CredentialAdapter`` Protocol;
``test_credential_adapter_declares_fetch_secret_only`` pins this.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.sandbox import (
    CredentialAdapter,
    KernelDefaultCredentialAdapter,
)


class TestReExportEquivalence:
    """The shim MUST re-export the SAME object (not a duplicate
    declaration). Object identity catches drift-by-duplicate before
    runtime."""

    def test_credential_adapter_is_same_object_via_both_paths(self) -> None:
        from cognic_agentos.sandbox.admission import (
            CredentialAdapter as AdmissionCA,
        )
        from cognic_agentos.sandbox.credentials import (
            CredentialAdapter as CredentialsCA,
        )

        assert AdmissionCA is CredentialsCA, (
            "credentials.py must re-export the SAME CredentialAdapter "
            "Protocol from sandbox.admission, not redeclare it. "
            "Object-identity check catches a duplicate declaration "
            "that would otherwise pass `isinstance` checks but drift "
            "in signature."
        )

    def test_kernel_default_is_same_object_via_both_paths(self) -> None:
        from cognic_agentos.sandbox.admission import (
            KernelDefaultCredentialAdapter as AdmissionKDCA,
        )
        from cognic_agentos.sandbox.credentials import (
            KernelDefaultCredentialAdapter as CredentialsKDCA,
        )

        assert AdmissionKDCA is CredentialsKDCA

    def test_sandbox_package_exposes_same_object_as_credentials_module(
        self,
    ) -> None:
        """`from cognic_agentos.sandbox import X` and `from
        cognic_agentos.sandbox.credentials import X` MUST resolve to
        the same object so consumers can use either path."""
        from cognic_agentos.sandbox import CredentialAdapter as PkgCA
        from cognic_agentos.sandbox import (
            KernelDefaultCredentialAdapter as PkgKDCA,
        )
        from cognic_agentos.sandbox.credentials import (
            CredentialAdapter as CredentialsCA,
        )
        from cognic_agentos.sandbox.credentials import (
            KernelDefaultCredentialAdapter as CredentialsKDCA,
        )

        assert PkgCA is CredentialsCA
        assert PkgKDCA is CredentialsKDCA


class TestProtocolShape:
    def test_kernel_default_satisfies_credential_adapter_protocol(self) -> None:
        """The stub MUST satisfy the @runtime_checkable Protocol so
        admission's isinstance check works AND the type system accepts
        the stub wherever a real CredentialAdapter is expected."""
        adapter = KernelDefaultCredentialAdapter()
        assert isinstance(adapter, CredentialAdapter)

    def test_credential_adapter_declares_fetch_secret_only(self) -> None:
        """T5 landed the single-method ``fetch_secret`` API. The
        richer ``mint_lease/revoke_lease`` lease API belongs to
        Sprint 10's concrete ``VaultCredentialAdapter`` design —
        adding it to the Wave-1 Protocol would be scope creep. This
        pin catches an accidental re-introduction of the lease API
        onto the Protocol."""
        # Walk public attributes the Protocol declares. The Protocol
        # is structural so we check the canonical method exists and
        # the Sprint-10 lease methods do NOT.
        public_names = {name for name in dir(CredentialAdapter) if not name.startswith("_")}
        assert "fetch_secret" in public_names, (
            "CredentialAdapter Protocol must declare fetch_secret per "
            "the T5-committed single-method API"
        )
        # Negative pins for the Sprint-10 lease API that T8's
        # pre-patch plan body incorrectly tried to add.
        assert "mint_lease" not in public_names, (
            "mint_lease belongs to Sprint 10's VaultCredentialAdapter "
            "design, NOT the Wave-1 Protocol. See Post-T8 implementation "
            "notes in the plan-of-record."
        )
        assert "revoke_lease" not in public_names, (
            "revoke_lease belongs to Sprint 10's VaultCredentialAdapter "
            "design, NOT the Wave-1 Protocol. See Post-T8 implementation "
            "notes in the plan-of-record."
        )


class TestStubFailsLoudWithSprintTenPointer:
    @pytest.mark.asyncio
    async def test_fetch_secret_raises_not_implemented_with_sprint_10_pointer(
        self,
    ) -> None:
        adapter = KernelDefaultCredentialAdapter()
        with pytest.raises(NotImplementedError) as exc:
            await adapter.fetch_secret("secret/test")
        # Per AGENTS.md production-grade rule: stub error message MUST
        # cite the sprint that replaces it AND the ADR that owns the
        # contract. The T5-committed message cites Sprint 10 + ADR-009
        # (ADR-009 is the pluggable-adapter home where the real Vault
        # implementation lives; ADR-004 is the sandbox-primitive ADR
        # that lifts the architectural intent into a sandbox-level
        # concept).
        msg = str(exc.value)
        assert "Sprint 10" in msg
        assert "ADR-009" in msg
        assert "VaultCredentialAdapter" in msg
        assert "fail-loud sentinel" in msg

    @pytest.mark.asyncio
    async def test_fetch_secret_echoes_called_path_in_error(self) -> None:
        """The T5-committed stub message includes the requested path
        (repr'd) so debugging logs can identify which secret was being
        fetched when the sentinel fired. This pins that contract."""
        adapter = KernelDefaultCredentialAdapter()
        with pytest.raises(NotImplementedError) as exc:
            await adapter.fetch_secret("secret/prod/db-password")
        msg = str(exc.value)
        assert "'secret/prod/db-password'" in msg


class TestSandboxesWithoutCredentialsUnaffected:
    """Sandboxes whose policy has vault_path=None never call the
    credential adapter; the fail-loud stub is invisible to them. This
    is the load-bearing invariant from spec §2.2 ("Sandboxes that do
    not request credentials are unaffected"). The actual sandbox-
    without-creds happy path lands in T10a's lifecycle test; this
    is the unit-level pin that fetch_secret is NEVER called when
    policy.vault_path is None."""

    @pytest.mark.asyncio
    async def test_admit_policy_does_not_call_fetch_secret_when_vault_path_none(
        self,
    ) -> None:
        from cognic_agentos.sandbox import (
            PackAdmissionContext,
            SandboxPolicy,
        )
        from cognic_agentos.sandbox.admission import admit_policy

        # Wrap the stub so we can assert fetch_secret was never called.
        # The AsyncMock(side_effect=...) preserves the underlying
        # NotImplementedError if it WERE accidentally called — so a
        # leaky test path fails-loud rather than silently passing.
        stub = KernelDefaultCredentialAdapter()
        original_fetch_secret = stub.fetch_secret
        stub.fetch_secret = AsyncMock(  # type: ignore[method-assign]
            side_effect=original_fetch_secret
        )

        # MagicMock for catalog so sync membership probes return real
        # bools; verify_* async methods get explicit AsyncMock.
        catalog = MagicMock()
        catalog.is_canonical.return_value = True
        catalog.is_tenant_allow_listed.return_value = False
        catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
        catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)

        # Rego decision shape: real `Decision.allow` (not `.allowed`)
        # per core/policy/engine.py:133. Use MagicMock for the
        # decision object so attribute access returns a real bool.
        rego = MagicMock()
        rego_decision = MagicMock()
        rego_decision.allow = True
        rego_decision.reasoning = ""
        rego.evaluate = AsyncMock(return_value=rego_decision)

        # Settings: the sandbox_per_tenant_max_* prefixed names per
        # Post-T5 implementation note #2.
        settings = MagicMock(
            sandbox_per_tenant_max_cpu=4.0,
            sandbox_per_tenant_max_memory=1024,
            sandbox_per_tenant_max_walltime=300.0,
        )

        policy = SandboxPolicy(
            cpu_cores=0.5,
            cpu_time_budget_s=None,
            memory_mb=256,
            walltime_s=30.0,
            runtime_image=("cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64),
            egress_allow_list=(),
            vault_path=None,  # ← KEY: no creds requested
        )
        ctx = PackAdmissionContext(
            pack_id="p",
            pack_version="v1",
            pack_artifact_digest="sha256:" + "1" * 64,
            risk_tier="internal_write",
            declares_dynamic_install=False,
            profile="production",
        )

        await admit_policy(
            policy,
            tenant_id="t-1",
            actor=MagicMock(),
            pack_context=ctx,
            catalog=catalog,
            credential_adapter=stub,
            rego_engine=rego,
            settings=settings,
        )

        stub.fetch_secret.assert_not_called()
