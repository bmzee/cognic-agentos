"""Sprint 10 T7 — ``admit_policy()`` requires_credentials threading.

Critical-controls module under test per AGENTS.md: ``sandbox/admission.py``
+ ``sandbox/protocol.py`` (Literal extension). T7 ships:

* New keyword-only ``requires_credentials: Sequence[VaultLeaseRequest] = ()``
  kwarg on ``admit_policy`` — default empty tuple keeps every Sprint-8A
  call site byte-shape backward-compatible.
* Cross-tenant guard at the kernel boundary: any request whose
  ``tenant_id`` does not match the admitting ``actor.tenant_id`` raises
  ``SandboxLifecycleRefused`` with the NEW closed-enum reason
  ``sandbox_credential_request_tenant_mismatch`` (the Literal extension
  lands in this same commit per the bisection-invariant doctrine —
  every commit on the branch must lint clean on its own).
* Sentinel-adapter refusal under non-empty ``requires_credentials`` —
  reuses the EXISTING Sprint-8A reason
  ``sandbox_credential_adapter_not_configured`` (NOT a new value)
  per the T7 scope lock; the new wave of ``sandbox_credential_*``
  reasons (3 mint-failure + 1 TTL cap) lands in T9 at the create/mint
  boundary that actually raises them.
* Rego input threading: the ``input`` dict gains a top-level
  ``requires_credentials`` key whose value is a list of per-request
  ``{secret_path, ttl_s, scope_label}`` dicts — actor/tenant identity
  stays at the existing top-level ``tenant_id`` key (the Rego bundle
  composes the cross-tenant decidability from there).

T7 SCOPE LOCK (Round-0 review, plan §"Scope locks"): T7 MUST NOT touch
``core.vault.lease_credential`` / ``core.vault.revoke_credential`` and
MUST NOT collapse any of the 4-value T4 taxonomy
(``VaultUnavailable`` / ``VaultPathNotFound`` / ``VaultAuthDenied`` /
``VaultProtocolError``) into ``SandboxLifecycleRefused``. The
mint-exception collapse to ``sandbox_credential_mint_failed_*`` is
**T10**'s job (the backend ``create()`` + ``destroy()`` seam where
``mint_lease`` is actually called); T7 is admission-time only and
never reaches the mint pathway.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.core.policy.engine import Decision
from cognic_agentos.core.vault import VaultLeaseActorRef, VaultLeaseRequest
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox import (
    PackAdmissionContext,
    SandboxLifecycleRefused,
    SandboxPolicy,
)
from cognic_agentos.sandbox.admission import (
    CredentialAdapter,
    KernelDefaultCredentialAdapter,
    admit_policy,
)

# ---------------------------------------------------------------------------
# Shared fixtures — mirror the test_admission_pipeline.py factory pattern
# ---------------------------------------------------------------------------


_VALID_DIGEST = "sha256:" + "a" * 64
_VALID_PACK_DIGEST = "sha256:" + "b" * 64
_VALID_IMAGE_REF = "cognic/sandbox-runtime-python:v1@" + _VALID_DIGEST


def _valid_policy(**overrides: object) -> SandboxPolicy:
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
    return MagicMock(
        sandbox_per_tenant_max_cpu=4.0,
        sandbox_per_tenant_max_memory=1024,
        sandbox_per_tenant_max_walltime=300.0,
    )


def _passing_catalog() -> MagicMock:
    catalog = MagicMock()
    catalog.is_canonical.return_value = True
    catalog.is_tenant_allow_listed.return_value = True
    catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
    catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
    return catalog


def _passing_rego() -> MagicMock:
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


def _actor(tenant_id: str = "t-1", subject: str = "alice@bank") -> Actor:
    """Production-grade Actor (Pydantic-validated). Tests that need to
    pin cross-tenant behaviour MUST use real Actor instances — a
    MagicMock would silently accept any ``.tenant_id`` attribute and
    defeat the kernel-boundary guard under test."""

    return Actor(
        subject=subject,
        tenant_id=tenant_id,
        scopes=frozenset(),
        actor_type="human",
    )


def _request(
    *,
    tenant_id: str = "t-1",
    secret_path: str = "database/creds/x",
    ttl_s: int = 900,
    scope_label: str = "s",
    actor_subject: str = "alice@bank",
) -> VaultLeaseRequest:
    return VaultLeaseRequest(
        secret_path=secret_path,
        ttl_s=ttl_s,
        tenant_id=tenant_id,
        actor_ref=VaultLeaseActorRef(actor_subject=actor_subject, actor_type="human"),
        scope_label=scope_label,
    )


# ---------------------------------------------------------------------------
# T7 — backward-compat: default empty kwarg is byte-shape no-op
# ---------------------------------------------------------------------------


class TestAdmitPolicyRequiresCredentialsBackwardCompat:
    async def test_default_requires_credentials_kwarg_is_byte_shape_no_op(self) -> None:
        """Sprint-8A call sites do NOT pass ``requires_credentials``. The
        default ``()`` MUST be a complete byte-shape no-op:

        * No additional refusal arm fires.
        * The Rego input gains an EMPTY ``requires_credentials`` key
          (consistent shape so the bundle can `count(input.requires_credentials)`
          unconditionally without a key-presence guard)."""

        rego = _passing_rego()
        await admit_policy(
            _valid_policy(),
            tenant_id="t-1",
            actor=_actor(tenant_id="t-1"),
            pack_context=_valid_pack_context(),
            catalog=_passing_catalog(),
            credential_adapter=AsyncMock(spec=CredentialAdapter),
            rego_engine=rego,
            settings=_passing_settings(),
        )
        # No exception → backward-compat OK.
        rego.evaluate.assert_awaited_once()
        rego_input = rego.evaluate.call_args.kwargs["input"]
        # The key MUST be present + empty so the Rego bundle has a
        # single uniform shape on both the credentials-requested and
        # no-credentials paths.
        assert "requires_credentials" in rego_input
        assert rego_input["requires_credentials"] == []


# ---------------------------------------------------------------------------
# T7 — sentinel-adapter refusal under non-empty requires_credentials
# ---------------------------------------------------------------------------


class TestAdmitPolicyRequiresCredentialsSentinelRefusal:
    async def test_sentinel_adapter_refuses_with_existing_8a_reason(self) -> None:
        """When ``requires_credentials`` is non-empty AND the wired
        adapter is the fail-loud Sprint-8A
        ``KernelDefaultCredentialAdapter`` sentinel, admit_policy
        refuses with the EXISTING
        ``sandbox_credential_adapter_not_configured`` reason — NOT a
        new closed-enum value.

        T7 scope lock: the 3 ``sandbox_credential_mint_failed_*`` reasons
        land in T9 (Literal) + T10 (Stage-2 raise at backend
        ``create()`` post-admission per spec §7.1). The 4th Sprint-10
        value ``sandbox_credential_ttl_exceeds_tenant_max`` lands in T9
        (Literal only; no Stage-2 raise — the cap continues to surface
        as ``sandbox_policy_rego_denied`` per spec §7.3 amendment, since
        ``OPAEngine.Decision`` has no per-rule-name channel; Rego-reason
        surfacing is deferred to a future task). T7 admission threading
        reuses the existing sentinel-refusal vocabulary."""

        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _valid_policy(),
                tenant_id="t-1",
                actor=_actor(tenant_id="t-1"),
                pack_context=_valid_pack_context(),
                catalog=_passing_catalog(),
                credential_adapter=KernelDefaultCredentialAdapter(),
                rego_engine=_passing_rego(),
                settings=_passing_settings(),
                requires_credentials=[_request(tenant_id="t-1")],
            )
        assert exc.value.reason == "sandbox_credential_adapter_not_configured"

    async def test_sentinel_adapter_with_empty_requires_credentials_does_not_refuse(
        self,
    ) -> None:
        """Negative pin: the sentinel-refusal arm fires ONLY when
        ``requires_credentials`` is non-empty. An empty kwarg + sentinel
        wired + ``policy.vault_path=None`` MUST NOT refuse — this is the
        live Sprint-8A backward-compat path."""

        await admit_policy(
            _valid_policy(),  # vault_path=None
            tenant_id="t-1",
            actor=_actor(tenant_id="t-1"),
            pack_context=_valid_pack_context(),
            catalog=_passing_catalog(),
            credential_adapter=KernelDefaultCredentialAdapter(),
            rego_engine=_passing_rego(),
            settings=_passing_settings(),
            # Default `requires_credentials=()`.
        )


# ---------------------------------------------------------------------------
# T7 — Rego input dict gains top-level requires_credentials key
# ---------------------------------------------------------------------------


class TestAdmitPolicyThreadsRequiresCredentialsIntoRegoInput:
    async def test_rego_input_carries_per_request_shape(self) -> None:
        """The Rego input dict gains a top-level ``requires_credentials``
        list whose entries carry the per-request 3-tuple
        ``{secret_path, ttl_s, scope_label}`` — NOT including actor /
        tenant (those live at the existing top-level ``tenant_id`` key
        + the per-request ``tenant_id`` field, which the kernel-boundary
        check enforces matches actor.tenant_id BEFORE the Rego call)."""

        rego = _passing_rego()
        request = _request(
            tenant_id="t-1",
            secret_path="database/creds/x",
            ttl_s=900,
            scope_label="role-read",
        )
        await admit_policy(
            _valid_policy(),
            tenant_id="t-1",
            actor=_actor(tenant_id="t-1"),
            pack_context=_valid_pack_context(),
            catalog=_passing_catalog(),
            credential_adapter=AsyncMock(spec=CredentialAdapter),
            rego_engine=rego,
            settings=_passing_settings(),
            requires_credentials=[request],
        )
        rego.evaluate.assert_awaited_once()
        rego_input = rego.evaluate.call_args.kwargs["input"]
        assert "requires_credentials" in rego_input
        assert rego_input["requires_credentials"] == [
            {
                "secret_path": "database/creds/x",
                "ttl_s": 900,
                "scope_label": "role-read",
            }
        ]

    async def test_rego_input_carries_multiple_requests_in_order(self) -> None:
        """Order-preserving projection — packs declaring multiple lease
        requests see them in declaration order in the Rego input."""

        rego = _passing_rego()
        requests = [
            _request(secret_path="database/creds/reader", scope_label="reader"),
            _request(secret_path="aws/creds/role-x", scope_label="aws-role-x"),
        ]
        await admit_policy(
            _valid_policy(),
            tenant_id="t-1",
            actor=_actor(tenant_id="t-1"),
            pack_context=_valid_pack_context(),
            catalog=_passing_catalog(),
            credential_adapter=AsyncMock(spec=CredentialAdapter),
            rego_engine=rego,
            settings=_passing_settings(),
            requires_credentials=requests,
        )
        rego_input = rego.evaluate.call_args.kwargs["input"]
        assert [entry["secret_path"] for entry in rego_input["requires_credentials"]] == [
            "database/creds/reader",
            "aws/creds/role-x",
        ]

    async def test_rego_input_requires_credentials_does_not_leak_actor_or_tenant(
        self,
    ) -> None:
        """Anti-leak pin — the per-request projection MUST NOT include
        ``actor_subject`` / ``actor_type`` / ``tenant_id`` fields. The
        kernel-boundary cross-tenant guard runs BEFORE the Rego call;
        the Rego bundle never needs to re-decide tenant identity per
        request. Pinning the projection shape forbids future drift
        toward "let the bundle do it" since that drift is the exact
        bug class the kernel-boundary check defends against."""

        rego = _passing_rego()
        request = _request(tenant_id="t-1", actor_subject="alice@bank")
        await admit_policy(
            _valid_policy(),
            tenant_id="t-1",
            actor=_actor(tenant_id="t-1"),
            pack_context=_valid_pack_context(),
            catalog=_passing_catalog(),
            credential_adapter=AsyncMock(spec=CredentialAdapter),
            rego_engine=rego,
            settings=_passing_settings(),
            requires_credentials=[request],
        )
        rego_input = rego.evaluate.call_args.kwargs["input"]
        entry = rego_input["requires_credentials"][0]
        # Per-request projection MUST be EXACTLY the 3-key allow-list.
        assert set(entry.keys()) == {"secret_path", "ttl_s", "scope_label"}


# ---------------------------------------------------------------------------
# T7 — kernel-boundary cross-tenant request guard
# ---------------------------------------------------------------------------


class TestAdmitPolicyRefusesCrossTenantRequest:
    async def test_cross_tenant_request_refused_with_new_closed_enum_reason(
        self,
    ) -> None:
        """When ``VaultLeaseRequest.tenant_id != actor.tenant_id``,
        admit_policy refuses with the NEW closed-enum reason
        ``sandbox_credential_request_tenant_mismatch``. The Literal
        extension lands in this same commit per the bisection-invariant
        doctrine: every commit on the branch must lint clean on its
        own (mypy treats ``SandboxLifecycleRefused.reason`` as
        ``SandboxRefusalReason`` Literal — raising a not-yet-declared
        value would fail mypy).

        Architectural-arrow rationale: ``VaultLeaseRequest`` itself
        cannot enforce this check at construction time because the
        request is constructed in ``core/vault`` which has NO knowledge
        of the requesting actor — the architectural arrow runs
        ``sandbox → core``, never the other direction. The cross-tenant
        check is a KERNEL-boundary concern owned by admit_policy."""

        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _valid_policy(),
                tenant_id="tenant-acme",
                actor=_actor(tenant_id="tenant-acme"),
                pack_context=_valid_pack_context(),
                catalog=_passing_catalog(),
                credential_adapter=AsyncMock(spec=CredentialAdapter),
                rego_engine=_passing_rego(),
                settings=_passing_settings(),
                requires_credentials=[_request(tenant_id="tenant-OTHER")],
            )
        assert exc.value.reason == "sandbox_credential_request_tenant_mismatch"
        # Refusal detail surfaces both tenant_ids so examiners can
        # correlate the offending request without re-reading the chain
        # payload (load-bearing for incident response).
        assert "tenant-acme" in exc.value.detail
        assert "tenant-OTHER" in exc.value.detail

    async def test_cross_tenant_check_short_circuits_before_rego(self) -> None:
        """Ordering pin: the cross-tenant check runs BEFORE the Rego
        evaluation — examiners reading the chain row should see the
        kernel-boundary refusal, NOT a Rego deny that happens to fire
        for a coincidentally-related reason."""

        rego = _passing_rego()
        with pytest.raises(SandboxLifecycleRefused):
            await admit_policy(
                _valid_policy(),
                tenant_id="tenant-acme",
                actor=_actor(tenant_id="tenant-acme"),
                pack_context=_valid_pack_context(),
                catalog=_passing_catalog(),
                credential_adapter=AsyncMock(spec=CredentialAdapter),
                rego_engine=rego,
                settings=_passing_settings(),
                requires_credentials=[_request(tenant_id="tenant-OTHER")],
            )
        # Rego MUST NOT have been called — the kernel-boundary guard
        # short-circuited.
        rego.evaluate.assert_not_awaited()

    async def test_first_cross_tenant_request_in_mixed_list_triggers_refusal(
        self,
    ) -> None:
        """Many-request projection — when one of N requests has a
        mismatching tenant, admit_policy refuses on the FIRST bad
        request rather than projecting an inconsistent batch into the
        Rego input. Pin the refusal carries the offending tenant_id in
        the detail (NOT a generic "one or more requests mismatched")."""

        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _valid_policy(),
                tenant_id="tenant-acme",
                actor=_actor(tenant_id="tenant-acme"),
                pack_context=_valid_pack_context(),
                catalog=_passing_catalog(),
                credential_adapter=AsyncMock(spec=CredentialAdapter),
                rego_engine=_passing_rego(),
                settings=_passing_settings(),
                requires_credentials=[
                    _request(tenant_id="tenant-acme"),
                    _request(tenant_id="tenant-OTHER"),
                ],
            )
        assert exc.value.reason == "sandbox_credential_request_tenant_mismatch"
        assert "tenant-OTHER" in exc.value.detail

    async def test_same_tenant_request_does_not_refuse(self) -> None:
        """Positive baseline: matching tenant_id + real adapter wired +
        non-empty requires_credentials passes the kernel-boundary +
        sentinel checks AND the green-path Rego eval."""

        await admit_policy(
            _valid_policy(),
            tenant_id="t-1",
            actor=_actor(tenant_id="t-1"),
            pack_context=_valid_pack_context(),
            catalog=_passing_catalog(),
            credential_adapter=AsyncMock(spec=CredentialAdapter),
            rego_engine=_passing_rego(),
            settings=_passing_settings(),
            requires_credentials=[_request(tenant_id="t-1")],
        )
        # No exception → green path under non-empty requires_credentials.

    async def test_cross_tenant_check_wins_over_sentinel_adapter_check(self) -> None:
        """Round-1 ordering pin (user-found): when BOTH the sentinel
        adapter is wired AND the request is cross-tenant,
        ``sandbox_credential_request_tenant_mismatch`` MUST win over
        ``sandbox_credential_adapter_not_configured``.

        The cross-tenant signal is the more security-critical refusal —
        it identifies a tenant-isolation-violating request shape that
        examiners need to triage regardless of adapter wiring. Masking
        it behind the sentinel-not-configured reason would hide a
        cross-tenant attempt under a generic ops-config message, and
        re-wiring a real adapter later would silently unmask the
        violation rather than reporting it at the original refusal.

        Pins the spec/plan ordering (plan §1166-1180): cross-tenant
        guard runs FIRST inside the ``if requires_credentials:`` block;
        sentinel-adapter check fires SECOND only after every request
        has passed the cross-tenant gate."""

        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _valid_policy(),
                tenant_id="tenant-acme",
                actor=_actor(tenant_id="tenant-acme"),
                pack_context=_valid_pack_context(),
                catalog=_passing_catalog(),
                credential_adapter=KernelDefaultCredentialAdapter(),
                rego_engine=_passing_rego(),
                settings=_passing_settings(),
                requires_credentials=[_request(tenant_id="tenant-OTHER")],
            )
        assert exc.value.reason == "sandbox_credential_request_tenant_mismatch"
        assert "tenant-acme" in exc.value.detail
        assert "tenant-OTHER" in exc.value.detail
