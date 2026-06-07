"""ADR-023 Task 7 — per-tenant sandbox cap overlay wiring into admit_policy.

Option A (locked): admit_policy gains an OPTIONAL resolver. When wired, the
three sandbox caps are resolved ONCE and feed BOTH the Step-5 Python tenant-max
check AND the Step-9 Rego ``tenant_max`` input. When absent (the Wave-2
seam-only default — no production Runtime->sandbox overlay path yet), the base
``settings.sandbox_per_tenant_max_*`` caps are used (byte-equivalent to
pre-ADR-023 behaviour). A corrupt / loosening stored overlay fails CLOSED.
"""

from __future__ import annotations

import typing
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.core.config_overlay.resolver import (
    TenantConfigOverlayInvalid,
    TenantConfigResolver,
)
from cognic_agentos.core.policy.engine import Decision
from cognic_agentos.sandbox import (
    PackAdmissionContext,
    SandboxLifecycleRefused,
    SandboxPolicy,
)
from cognic_agentos.sandbox.admission import CredentialAdapter, admit_policy
from cognic_agentos.sandbox.protocol import SandboxRefusalReason


def _policy(**ov: Any) -> SandboxPolicy:
    base: dict[str, Any] = {
        "cpu_cores": 1.0,
        "cpu_time_budget_s": None,
        "memory_mb": 256,
        "walltime_s": 30.0,
        "runtime_image": "cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
        "egress_allow_list": ("api.example.com",),
        "vault_path": None,
    }
    base.update(ov)
    return SandboxPolicy(**base)


def _pack_ctx() -> PackAdmissionContext:
    return PackAdmissionContext(
        pack_id="cognic.t",
        pack_version="v1.0.0",
        pack_artifact_digest="sha256:" + "b" * 64,
        risk_tier="internal_write",
        declares_dynamic_install=False,
        profile="production",
    )


def _settings() -> MagicMock:
    # Base caps — used ONLY when no resolver is wired (the Option-A fallback).
    return MagicMock(
        sandbox_per_tenant_max_cpu=4.0,
        sandbox_per_tenant_max_memory=1024,
        sandbox_per_tenant_max_walltime=300.0,
        sandbox_kernel_default_max_credential_ttl_s=900,
    )


def _catalog() -> MagicMock:
    c = MagicMock()
    c.is_canonical.return_value = True
    c.is_tenant_allow_listed.return_value = True
    c.verify_cosign_or_refuse = AsyncMock(return_value=None)
    c.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
    return c


def _rego() -> MagicMock:
    r = MagicMock()
    r.evaluate = AsyncMock(
        return_value=Decision(
            allow=True,
            rule_matched="data.cognic.sandbox.admit.allow",
            reasoning="ok",
            decision_data=None,
        )
    )
    return r


class _FakeResolver(TenantConfigResolver):
    """Typed test double — subclasses TenantConfigResolver so it satisfies the
    ``TenantConfigResolver | None`` param under strict mypy, overriding the two
    read methods admit_policy may call (deliberately NOT calling
    super().__init__ — it needs no store/audit/base)."""

    def __init__(
        self, caps: dict[str, int | float] | None = None, *, invalid: bool = False
    ) -> None:
        self._caps: dict[str, int | float] = caps or {}
        self._invalid = invalid
        # Records every effective_many(...) call so a test can pin the §5
        # single-snapshot contract (ONE batch read for all three caps).
        self.calls: list[tuple[tuple[str, ...], str]] = []

    async def effective_many(
        self, field_keys: tuple[str, ...], tenant_id: str
    ) -> dict[str, int | float]:
        self.calls.append((field_keys, tenant_id))
        if self._invalid:
            raise TenantConfigOverlayInvalid(
                "sandbox_per_tenant_max_cpu", "tenant_overlay_loosens_ceiling"
            )
        return {k: self._caps[k] for k in field_keys}

    async def effective(self, field_key: str, tenant_id: str) -> int | float:
        # admit_policy MUST use the batch effective_many primitive (one
        # snapshot for all three caps). Per-field effective() reads would
        # reopen the concurrent-mutation interleaving window §5 closes —
        # fail loud so any such regression is caught by the suite.
        raise AssertionError(
            "admit_policy must resolve caps via effective_many (single "
            "snapshot), not per-field effective()"
        )


_TIGHT: dict[str, int | float] = {
    "sandbox_per_tenant_max_cpu": 1.0,
    "sandbox_per_tenant_max_memory": 1024,
    "sandbox_per_tenant_max_walltime": 300.0,
}
_BASE: dict[str, int | float] = {
    "sandbox_per_tenant_max_cpu": 4.0,
    "sandbox_per_tenant_max_memory": 1024,
    "sandbox_per_tenant_max_walltime": 300.0,
}


async def _admit(
    policy: SandboxPolicy,
    resolver: TenantConfigResolver | None,
    rego: MagicMock | None = None,
) -> MagicMock:
    rego = rego or _rego()
    await admit_policy(
        policy,
        tenant_id="t-1",
        actor=MagicMock(),
        pack_context=_pack_ctx(),
        catalog=_catalog(),
        credential_adapter=AsyncMock(spec=CredentialAdapter),
        rego_engine=rego,
        settings=_settings(),
        resolver=resolver,
    )
    return rego


def test_refusal_enum_has_overlay_invalid_value() -> None:
    assert "sandbox_tenant_config_overlay_invalid" in typing.get_args(SandboxRefusalReason)


async def test_tightened_overlay_drives_python_refusal() -> None:
    with pytest.raises(SandboxLifecycleRefused) as e:  # policy 2.0 > tightened 1.0
        await _admit(_policy(cpu_cores=2.0), _FakeResolver(_TIGHT))
    assert e.value.reason == "sandbox_policy_exceeds_tenant_max_cpu"
    assert "1.0" in e.value.detail  # tightened cap, NOT base 4.0


async def test_tightened_overlay_reaches_rego_tenant_max() -> None:
    rego = await _admit(_policy(cpu_cores=0.5), _FakeResolver(_TIGHT))  # under tightened cap
    tenant_max = rego.evaluate.call_args.kwargs["input"]["tenant_max"]
    assert tenant_max == {"cpu_cores": 1.0, "memory_mb": 1024, "walltime_s": 300.0}


async def test_no_overlay_uses_base_caps() -> None:
    rego = await _admit(_policy(cpu_cores=3.0), _FakeResolver(_BASE))  # 3.0 < base 4.0 -> admits
    assert rego.evaluate.call_args.kwargs["input"]["tenant_max"]["cpu_cores"] == 4.0


async def test_corrupt_overlay_fails_closed() -> None:
    with pytest.raises(SandboxLifecycleRefused) as e:
        await _admit(_policy(), _FakeResolver(invalid=True))
    assert e.value.reason == "sandbox_tenant_config_overlay_invalid"


async def test_resolver_called_once_for_all_three_caps() -> None:
    # §5 single-snapshot contract — the three caps MUST be resolved in ONE
    # effective_many(...) batch (NOT three effective() reads), else a future
    # refactor reopens the concurrent-mutation interleaving window. The fake's
    # effective() raises AssertionError, so any per-field fallback also fails.
    resolver = _FakeResolver(_TIGHT)
    await _admit(_policy(cpu_cores=0.5), resolver)
    assert resolver.calls == [
        (
            (
                "sandbox_per_tenant_max_cpu",
                "sandbox_per_tenant_max_memory",
                "sandbox_per_tenant_max_walltime",
            ),
            "t-1",
        )
    ]


# Option A — the None-resolver fallback preserves base-cap behaviour
# (byte-equivalent to pre-ADR-023; every existing call-site passes no resolver).
async def test_no_resolver_uses_settings_base_caps() -> None:
    rego = await _admit(_policy(cpu_cores=3.0), None)  # settings cpu 4.0 -> admits
    assert rego.evaluate.call_args.kwargs["input"]["tenant_max"]["cpu_cores"] == 4.0


async def test_no_resolver_settings_cap_still_refuses() -> None:
    with pytest.raises(SandboxLifecycleRefused) as e:  # 5.0 > settings 4.0
        await _admit(_policy(cpu_cores=5.0), None)
    assert e.value.reason == "sandbox_policy_exceeds_tenant_max_cpu"
    assert "4.0" in e.value.detail  # base settings cap
