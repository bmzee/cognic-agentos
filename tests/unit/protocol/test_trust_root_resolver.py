"""Sprint 7B.3 T9 Slice A — TrustRootResolver protocol module tests.

Per the plan-of-record §490 + R1 P2 #3: the T9 approve handler resolves
the per-tenant trust root (ADR-012 §134 — typically Vault-backed) via a
``TrustRootResolver`` protocol threaded through the app-factory stack.
The kernel ships a fail-loud :class:`KernelDefaultTrustRootResolver`
scaffold per the AGENTS.md production-grade rule — a silent in-process
fallback that pretends to work is forbidden; the scaffold raises
``NotImplementedError`` pointing at the ADR so bank overlays MUST inject
a real resolver.

The T9 approve handler treats BOTH ``trust_root_resolver is None`` AND a
``NotImplementedError`` raised from ``resolve_trust_root`` as the
"per-tenant trust root not configured" signal → SignatureGateInput
outcome ``red`` / red_reason ``signature_trust_root_not_configured``.
"""

from __future__ import annotations

import inspect
import typing
from pathlib import Path

import pytest

from cognic_agentos.protocol.trust_root_resolver import (
    KernelDefaultTrustRootResolver,
    TrustRootResolver,
)


class TestSprint7B3T9SliceATrustRootResolverProtocol:
    """The protocol surface — runtime-checkable + async + keyword-only."""

    def test_kernel_default_satisfies_the_protocol(self) -> None:
        assert isinstance(KernelDefaultTrustRootResolver(), TrustRootResolver)

    def test_resolve_trust_root_is_a_coroutine_function(self) -> None:
        assert inspect.iscoroutinefunction(KernelDefaultTrustRootResolver.resolve_trust_root)

    def test_resolve_trust_root_takes_keyword_only_tenant_id(self) -> None:
        sig = inspect.signature(KernelDefaultTrustRootResolver.resolve_trust_root)
        # ``self`` + keyword-only ``tenant_id``.
        assert list(sig.parameters) == ["self", "tenant_id"]
        assert sig.parameters["tenant_id"].kind is inspect.Parameter.KEYWORD_ONLY


class TestSprint7B3T9SliceAKernelDefaultFailsLoud:
    """The kernel-default scaffold fails loud — never a synthetic path."""

    @pytest.mark.asyncio
    async def test_resolve_trust_root_raises_not_implemented_error(self) -> None:
        resolver = KernelDefaultTrustRootResolver()
        with pytest.raises(NotImplementedError):
            await resolver.resolve_trust_root(tenant_id="tenant-a")

    @pytest.mark.asyncio
    async def test_not_implemented_error_message_points_at_adr_012(self) -> None:
        resolver = KernelDefaultTrustRootResolver()
        with pytest.raises(NotImplementedError) as exc_info:
            await resolver.resolve_trust_root(tenant_id="tenant-a")
        message = str(exc_info.value)
        assert "ADR-012" in message
        assert "create_app" in message

    def test_return_annotation_is_path(self) -> None:
        # ``from __future__ import annotations`` stringifies annotations;
        # resolve them so the contract assertion checks the real type.
        hints = typing.get_type_hints(KernelDefaultTrustRootResolver.resolve_trust_root)
        assert hints["return"] is Path
