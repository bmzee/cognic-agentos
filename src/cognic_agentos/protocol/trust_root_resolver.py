"""Sprint 7B.3 T9 — per-tenant trust-root resolver protocol (R1 P2 #3).

Layer classification: **protocol layer**.

The T9 approve endpoint's Gate 1 (cosign signature verification per
ADR-016) needs the per-tenant trust root to hand to
:meth:`cognic_agentos.protocol.trust_gate.TrustGate.verify_pack_signature`.
Per ADR-012 §134 the trust root is per-tenant — typically loaded from
Vault (``secret/cognic/<tenant>/trust-root`` via a ``SecretAdapter``).

This module declares the :class:`TrustRootResolver` Protocol that the
app-factory stack threads through to the approve handler closure
(``create_app`` → ``build_packs_router`` → ``build_review_routes`` →
handler), and a fail-loud kernel-default scaffold.

**Production-grade rule (AGENTS.md).** The kernel ships
:class:`KernelDefaultTrustRootResolver` — a scaffold whose
:meth:`~KernelDefaultTrustRootResolver.resolve_trust_root` raises
``NotImplementedError`` pointing at the ADR. A silent in-process
fallback that returns a synthetic path would pretend to work; the
scaffold fails loud instead. Bank overlays MUST inject a real
resolver via ``create_app(trust_root_resolver=...)``.

**Approve-handler contract.** The T9 handler treats BOTH
``trust_root_resolver is None`` AND a ``NotImplementedError`` raised
from ``resolve_trust_root`` as the "per-tenant trust root not
configured" signal — Gate 1 ``SignatureGateInput`` resolves to
``outcome="red"`` / ``red_reason="signature_trust_root_not_configured"``
(distinct from the verifier-not-configured red-reason per R5 P2 #4 —
the verifier and the trust-root resolver are two separate
dependencies).

**NOT-CC for Sprint 7B.3.** This module is wire-protocol-public
(bank overlays plug in the real resolver against this Protocol) but
the kernel-shipped surface is a Protocol declaration + a fail-loud
scaffold with no decision logic — there is nothing to get wrong in a
way that bypasses a control. It is promoted to critical controls
when a real resolver lands (the Vault-backed implementation makes
allow/deny decisions about which trust root a tenant gets).
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

__all__ = ["KernelDefaultTrustRootResolver", "TrustRootResolver"]


@runtime_checkable
class TrustRootResolver(Protocol):
    """Resolve the per-tenant cosign trust root (ADR-012 §134).

    Bank overlays implement this against their secret store (Vault per
    ADR-009 / ADR-012 §134). The kernel ships only
    :class:`KernelDefaultTrustRootResolver` — a fail-loud scaffold.

    ``runtime_checkable`` so ``create_app`` + the wiring tests can
    ``isinstance``-assert a supplied resolver satisfies the contract.
    """

    async def resolve_trust_root(self, *, tenant_id: str) -> Path:
        """Return the absolute :class:`~pathlib.Path` to ``tenant_id``'s
        cosign trust root.

        :raises NotImplementedError: by the kernel-default scaffold —
            the approve handler maps this to
            ``signature_trust_root_not_configured``.
        """
        ...


class KernelDefaultTrustRootResolver:
    """Fail-loud kernel-default :class:`TrustRootResolver` scaffold.

    Per the AGENTS.md production-grade rule, the kernel does NOT ship a
    synthetic / in-memory trust root — that would let an unconfigured
    deployment silently "verify" signatures against a fake root. The
    scaffold raises ``NotImplementedError`` pointing at the ADR so the
    misconfiguration is loud, and the T9 approve handler routes it to a
    red Gate 1 rather than crashing the request.
    """

    async def resolve_trust_root(self, *, tenant_id: str) -> Path:
        """Always raises — the kernel default is never a real resolver."""
        raise NotImplementedError(
            "TrustRootResolver is not configured. Per ADR-012 §134 the "
            "per-tenant cosign trust root is loaded from the secret store "
            "(Vault: secret/cognic/<tenant>/trust-root via a SecretAdapter, "
            "per ADR-009). Bank overlays MUST inject a real resolver via "
            "create_app(trust_root_resolver=<overlay-resolver>); the kernel "
            "default fails loud rather than returning a synthetic path that "
            f"would pretend to work (requested tenant_id={tenant_id!r})."
        )
