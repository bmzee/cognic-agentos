"""``build_runtime(settings, adapters) -> Runtime`` — the canonical composition root.

Builds a minimal spine (engine -> AuditStore/DecisionHistoryStore), the LLMGateway,
and -- only when a cache adapter is present (cache_driver != "none") -- the
governed-memory API factory (T6). Runs async inside the FastAPI lifespan after
``adapters.open_all()`` (the engine + any vault:// resolution are async).
"""

from __future__ import annotations

import dataclasses
from datetime import timedelta
from typing import TYPE_CHECKING

import httpx as _httpx

from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.core.sla import SLAPolicy
from cognic_agentos.db.adapters.secret_resolution import resolve_secret_field
from cognic_agentos.llm.concurrency import ProfileRateLimiter
from cognic_agentos.llm.gateway import LLMGateway
from cognic_agentos.llm.ledger import GatewayCallLedger
from cognic_agentos.llm.preflight import PreflightResolver

if TYPE_CHECKING:
    from cognic_agentos.core.config import Settings
    from cognic_agentos.core.memory.api import MemoryApiFactory
    from cognic_agentos.db.adapters.factory import Adapters

    # T6 lands ``harness/memory_policy.py``; this TYPE_CHECKING-only forward ref
    # lets the ``memory_policy`` field be typed now. Until T6 the module is
    # absent, so mypy reports it import-untyped — suppress that single line.
    from cognic_agentos.harness.memory_policy import (  # type: ignore[import-untyped]
        MemoryPolicyRouter,
    )

#: SLA policy audit-label (an audit label, not a budget; no name Setting per the locked decision).
_SLA_POLICY_NAME = "llm-gateway"


@dataclasses.dataclass(frozen=True, slots=True)
class Runtime:
    """Constructed kernel runtime. Public members are the two Bucket-2 seams; the
    spine is exposed for future reuse but nothing new consumes it this workstream."""

    llm_gateway: LLMGateway
    memory_api_factory: MemoryApiFactory | None
    audit_store: AuditStore
    decision_history_store: DecisionHistoryStore
    memory_policy: MemoryPolicyRouter | None
    _http_client: _httpx.AsyncClient

    async def aclose(self) -> None:
        """Close runtime-owned resources (the gateway's HTTP client). The adapter
        pool's lifecycle (relational engine, cache client) is owned by
        ``Adapters.close_all`` -- NOT here. LLMGateway has no close method."""
        await self._http_client.aclose()


async def build_runtime(settings: Settings, adapters: Adapters) -> Runtime:
    engine = adapters.relational.engine
    audit_store = AuditStore(engine)
    decision_history_store = DecisionHistoryStore(engine)

    # --- Gateway ----------------------------------------------------------
    ledger = GatewayCallLedger(engine)
    rate_limiter = ProfileRateLimiter(
        per_profile=settings.llm_concurrency_per_profile,
        mode=settings.llm_concurrency_mode,
    )
    preflight = PreflightResolver.from_yaml(settings.litellm_config_path)
    sla_policy = SLAPolicy(
        name=_SLA_POLICY_NAME,
        total_budget=timedelta(seconds=settings.llm_sla_total_budget_s),
        warning_threshold=timedelta(seconds=settings.llm_sla_warning_threshold_s),
    )
    litellm_key = settings.litellm_master_key
    if litellm_key is not None and litellm_key.startswith("vault://"):
        litellm_key = await resolve_secret_field(
            litellm_key, secret_adapter=adapters.secret, field_name="litellm_master_key"
        )
    # Create the HTTP client AFTER the fallible vault-resolve above: the resolve can
    # fail loud, and this client is the one resource that would leak — so it must be
    # created last among the fallible steps. Runtime.aclose closes it on the success path.
    http_client = _httpx.AsyncClient(timeout=settings.llm_timeout_s)
    gateway = LLMGateway(
        settings=settings,
        ledger=ledger,
        audit_store=audit_store,
        rate_limiter=rate_limiter,
        preflight=preflight,
        sla_policy=sla_policy,
        http_client=http_client,
        litellm_master_key=litellm_key,
    )

    # --- Memory factory (T6 fills this branch) ----------------------------
    memory_api_factory: MemoryApiFactory | None = None
    memory_policy: MemoryPolicyRouter | None = None
    # if adapters.cache is not None: ... (T6)

    return Runtime(
        llm_gateway=gateway,
        memory_api_factory=memory_api_factory,
        audit_store=audit_store,
        decision_history_store=decision_history_store,
        memory_policy=memory_policy,
        _http_client=http_client,
    )
