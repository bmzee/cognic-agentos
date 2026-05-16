"""Sprint-7B.4 T7 — ElicitationAdapter Protocol + KernelDefault fail-loud scaffold.

Per ADR-020 §69-77 + the AGENTS.md production-grade rule, the
kernel-shipped default adapter raises :class:`NotImplementedError`
pointing at the ADR rather than returning a synthetic result. Bank
overlays plug in real adapter implementations against this Protocol;
the gate at :file:`portal/api/ui/elicitation_gate.py` (T8) calls
``adapter.get_context(...)`` for the tenant-scoped 5-step refusal
check, and the action handler at :file:`portal/api/ui/action_routes.py`
(T11) calls ``adapter.handle_submission(...)`` after the gate passes.

Mirrors the Sprint 7B.3 T9 :class:`KernelDefaultTrustRootResolver`
precedent for the Protocol + fail-loud-scaffold pattern.

**Architectural arrow** — this module is FastAPI-free, portal-free,
core-free. The wire types here are upstream of every consumer; reverse
imports would create a circular dependency time bomb when portal
handlers + bank-overlay adapters both depend on it. Pinned by an AST
scan in :file:`tests/unit/protocol/test_elicitation_adapter.py::TestModuleImportsClean`.
"""

from __future__ import annotations

import dataclasses
import uuid
from datetime import datetime
from typing import Any, Literal, Protocol, runtime_checkable

__all__ = [
    "ElicitationAdapter",
    "ElicitationBackendError",
    "ElicitationContext",
    "ElicitationMode",
    "ElicitationResult",
    "KernelDefaultElicitationAdapter",
]


#: 2-value closed-enum literal of elicitation delivery modes.
#:
#: - ``"url"`` — adapter returns a delivery URL; UI redirects the user
#:   to the bank-overlay's elicitation surface (e.g. an OIDC redirect
#:   page, an external form host); the user completes there and
#:   resolution lands via a server-to-server callback that the
#:   bank-overlay's adapter wires.
#: - ``"form"`` — adapter accepts the form payload inline via the
#:   POST /api/v1/ui/actions endpoint; no redirect.
#:
#: Wire-protocol-public: drift breaks every adapter implementing the
#: Protocol below + the T8 elicitation_gate's mode-applicability check.
ElicitationMode = Literal["url", "form"]


@dataclasses.dataclass(frozen=True)
class ElicitationContext:
    """Tenant-scoped context for an in-flight elicitation, resolved by
    the adapter at gate step 2 (Section 5b of the design spec).

    Returned by :meth:`ElicitationAdapter.get_context` on success; the
    gate uses this to enforce the 5-step refusal contract (tenant
    ownership, mode applicability, data-class allow-list, expiry, then
    backend dispatch). Frozen so the gate cannot mutate the
    adapter-returned record between resolution + dispatch (defence-in-
    depth against confused-deputy bugs).
    """

    elicitation_id: str
    tenant_id: str
    originating_pack_id: str
    originating_decision_record_id: uuid.UUID
    elicitation_modes: tuple[ElicitationMode, ...]
    data_classes: tuple[str, ...]
    expires_at: datetime | None


@dataclasses.dataclass(frozen=True)
class ElicitationResult:
    """Returned by :meth:`ElicitationAdapter.handle_submission` on the
    green path.

    ``backend_correlation_id`` is the bank-overlay adapter's internal
    handle (the value the adapter would use to look up the submission
    later via a backend admin surface); ``None`` for adapters that
    don't expose such a handle. Frozen so the action handler can
    persist it to the chain row's ``originating_decision_record_id``
    payload without aliasing risk.
    """

    delivered_at: datetime
    backend_correlation_id: str | None


class ElicitationBackendError(RuntimeError):
    """Raised by :meth:`ElicitationAdapter.handle_submission` when the
    backend rejected the payload AFTER the gate passed.

    Maps to the ``elicitation_backend_failed`` ActionRejectionReason at
    the T11 action handler — distinct from the gate's pre-dispatch
    refusal reasons so operators can tell "gate refused" apart from
    "backend rejected" in audit logs without re-running the gate.
    Subclasses :class:`RuntimeError` so it bubbles through the standard
    exception path until the action handler catches it explicitly.
    """


@runtime_checkable
class ElicitationAdapter(Protocol):
    """Narrow elicitation seam — bank overlays plug in a concrete
    adapter against this Protocol; AgentOS ships the fail-loud
    :class:`KernelDefaultElicitationAdapter` scaffold below.

    Two methods drive the two integration points:

      - :meth:`get_context` — called by the T8 elicitation_gate to
        resolve the tenant-scoped context for a submitted
        ``elicitation_id``. Returns ``None`` when the id is unknown to
        the adapter (gate maps to ``elicitation_context_not_found``).
      - :meth:`handle_submission` — called by the T11 action handler
        after the gate passes. Raises
        :class:`ElicitationBackendError` on backend failure (maps to
        ``elicitation_backend_failed``); returns
        :class:`ElicitationResult` on success.

    ``@runtime_checkable`` so the T11 action handler can validate the
    actor-provided adapter shape via ``isinstance`` at app-bootstrap
    time + refuse to mount with a misconfigured overlay (defence-in-
    depth against duck-typed adapter regressions).
    """

    async def get_context(
        self,
        *,
        elicitation_id: str,
        tenant_id: str,
    ) -> ElicitationContext | None: ...

    async def handle_submission(
        self,
        *,
        ctx: ElicitationContext,
        mode: ElicitationMode,
        payload: dict[str, Any],
    ) -> ElicitationResult: ...


class KernelDefaultElicitationAdapter:
    """Production-grade fail-loud scaffold per ADR-020 §69 + the
    AGENTS.md production-grade rule.

    Both methods raise :class:`NotImplementedError` pointing at the ADR
    rather than returning a synthetic result. This is the "stubs that
    raise NotImplementedError pointing at an ADR are explicit
    scaffolding, not mocks" pattern — they fail loudly when called,
    document the contract, and protect against silent in-process
    fallback.

    Mirrors the Sprint 7B.3 T9 ``KernelDefaultTrustRootResolver``
    precedent. Bank overlays inject a real :class:`ElicitationAdapter`
    via ``create_app(elicitation_adapter=...)`` (T12 extension); the
    kernel default is the failing-closed fallback that surfaces
    misconfiguration loudly.
    """

    async def get_context(
        self,
        *,
        elicitation_id: str,
        tenant_id: str,
    ) -> ElicitationContext | None:
        raise NotImplementedError(
            "ADR-020 §69 elicitation adapter is not wired; the kernel "
            "default fails closed. Bank overlays plug in a concrete "
            "ElicitationAdapter against the protocol/elicitation_adapter "
            "Protocol via create_app(elicitation_adapter=...) at T12."
        )

    async def handle_submission(
        self,
        *,
        ctx: ElicitationContext,
        mode: ElicitationMode,
        payload: dict[str, Any],
    ) -> ElicitationResult:
        raise NotImplementedError(
            "ADR-020 §69 elicitation adapter is not wired; the kernel "
            "default fails closed. Bank overlays plug in a concrete "
            "ElicitationAdapter against the protocol/elicitation_adapter "
            "Protocol via create_app(elicitation_adapter=...) at T12."
        )
