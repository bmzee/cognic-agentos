"""``build_runtime(settings, adapters) -> Runtime`` — the canonical composition root.

Builds a minimal spine (engine -> AuditStore/DecisionHistoryStore), the LLMGateway,
and -- only when a cache adapter is present (cache_driver != "none") -- the
governed-memory API factory (T6). Runs async inside the FastAPI lifespan after
``adapters.open_all()`` (the engine + any vault:// resolution are async).
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import httpx as _httpx

from cognic_agentos.core.approval.engine import ApprovalEngine
from cognic_agentos.core.approval.policy import ApprovalPolicy
from cognic_agentos.core.approval.storage import ApprovalRequestStore
from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.config_overlay.resolver import TenantConfigResolver
from cognic_agentos.core.config_overlay.storage import TenantConfigOverlayStore
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.core.policy.engine import OPAEngine
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
    from cognic_agentos.harness.memory_policy import MemoryPolicyRouter

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
    # ADR-023 (Wave-2) — built unconditionally; memory IS production-wired
    # (config_overlay_resolver is threaded into the MemoryAPI factory above),
    # while the portal config-overlay router consumes the same store + resolver.
    config_overlay_store: TenantConfigOverlayStore
    config_overlay_resolver: TenantConfigResolver
    # ADR-014 (Sprint 13.5b1) — built unconditionally (mirrors the config-overlay
    # posture; approval needs only the relational engine). The portal approval
    # router consumes both; 13.5b2's MCP-host seam reuses the SAME engine instance.
    approval_store: ApprovalRequestStore
    approval_engine: ApprovalEngine
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

    # --- ADR-023 (Wave-2) per-tenant config-overlay store + resolver ---
    # Built unconditionally (the overlay surface is independent of memory/cache)
    # and BEFORE the leak-prone http_client: both are pure constructors (no I/O),
    # so they add nothing to the "all fallible construction before http_client"
    # invariant. The resolver is threaded into the MemoryAPI factory below
    # (memory IS production-wired) AND exposed on Runtime for the portal
    # config-overlay router mount. There is NO Runtime-owned sandbox backend, so
    # the resolver is deliberately NOT threaded into any sandbox create path
    # (sandbox stays seam-only — admit_policy accepts a resolver but no
    # Runtime-owned caller passes one).
    overlay_store = TenantConfigOverlayStore(engine)
    overlay_resolver = TenantConfigResolver(
        store=overlay_store,
        base=settings,
        audit=audit_store,
        throttle_s=settings.config_overlay_invalid_at_read_throttle_s,
    )

    # --- ADR-014 (Sprint 13.5b1) approval store + policy + engine ---
    # Built unconditionally (mirrors the config-overlay posture — approval needs
    # only the relational engine) and BEFORE the leak-prone http_client: the
    # OPAEngine.create call is fallible (bundle read + policy.bundle_loaded
    # decision-history emit), so it belongs in the "all fallible construction
    # before http_client" zone. The SINGLE engine instance is shared: the portal
    # approval router (create_app kwargs) + 13.5b2's MCP-host seam both reuse it.
    approval_store = ApprovalRequestStore(decision_history_store)
    approval_opa = await OPAEngine.create(
        bundle_path=settings.tools_policy_bundle,
        audit_store=audit_store,
        decision_history_store=decision_history_store,
        opa_path=settings.opa_path,
        eval_timeout_s=settings.opa_eval_timeout_s,
    )
    approval_engine = ApprovalEngine(
        policy=ApprovalPolicy(opa_engine=approval_opa),
        store=approval_store,
        settings=settings,
        clock=lambda: datetime.now(UTC),
    )

    # --- Gateway sub-deps (the gateway + http_client are built LAST — see below) ---
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
    # --- Memory factory (built BEFORE the gateway + http_client so ALL fallible
    # construction — the vault-resolve above + the memory branch's OPAEngine.create /
    # ensure_collection below — runs before the leak-prone http_client is allocated) ---
    memory_api_factory: MemoryApiFactory | None = None
    memory_policy: MemoryPolicyRouter | None = None
    if adapters.cache is not None:
        # Function-local imports: only loaded when memory is actually wired, so
        # the gateway-only path (cache_driver="none") stays import-light.
        #
        # Composition-root exemption: this block runtime-imports
        # ``core.memory.storage`` (PostgresMemoryAdapter / RedisMemoryAdapter) —
        # the ONE allowed exception to the test_memory_layer_c_no_direct_storage
        # fence. As the DI composition root, build_runtime NAMES the concrete
        # adapters and injects them into MemoryAPI (which enforces MemoryGate on
        # every op); it MUST NOT call put/get/list_* on them directly. The fence
        # path-pins this exemption to harness/runtime.py.
        from cognic_agentos.core.dlp.scanner import ChecksumRegexGazetteerScanner
        from cognic_agentos.core.emergency.kill_switches import RedisMemoryWriteFreezeKillSwitch
        from cognic_agentos.core.memory._context import MemoryCallerContext
        from cognic_agentos.core.memory._routing import RoutingMemoryAdapter
        from cognic_agentos.core.memory.api import MemoryAPI
        from cognic_agentos.core.memory.consent import ConsentValidator
        from cognic_agentos.core.memory.storage import PostgresMemoryAdapter, RedisMemoryAdapter
        from cognic_agentos.core.memory.vector import MemoryVectorIndex
        from cognic_agentos.harness.memory_policy import MemoryPolicyRouter as _Router

        # NOTE: OPAEngine is imported at module top since Sprint 13.5b1 (the
        # approval trio above constructs one unconditionally) — the memory
        # branch reuses that import.

        memory_engine = await OPAEngine.create(
            bundle_path=settings.memory_policy_bundle,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            opa_path=settings.opa_path,
            eval_timeout_s=settings.opa_eval_timeout_s,
        )
        purpose_matrix_engine = await OPAEngine.create(
            bundle_path=settings.memory_purpose_matrix_policy_bundle,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            opa_path=settings.opa_path,
            eval_timeout_s=settings.opa_eval_timeout_s,
        )
        memory_policy = _Router(
            memory_engine=memory_engine, purpose_matrix_engine=purpose_matrix_engine
        )

        cache_client = adapters.cache.client
        routing_adapter = RoutingMemoryAdapter(
            redis_adapter=RedisMemoryAdapter(
                redis_client=cache_client, scratch_ttl_s=settings.memory_scratch_ttl_s
            ),
            pg_adapter=PostgresMemoryAdapter(engine=engine, dh_store=decision_history_store),
            scratch_ttl_s=settings.memory_scratch_ttl_s,
        )
        dlp = ChecksumRegexGazetteerScanner()
        consent = ConsentValidator(audit=decision_history_store)
        kill_switch = RedisMemoryWriteFreezeKillSwitch(
            redis_client=cache_client, cache_ttl_s=settings.memory_kill_switch_cache_ttl_s
        )

        # vector_index — opt-in episodic recall (default OFF). Gated on
        # memory_vector_recall_enabled so /memory startup is NOT coupled to the
        # vector backend (qdrant) reachability by default; the portal endpoints
        # don't use vector recall. When enabled, ensure_collection() runs once.
        vector_index = None
        if settings.memory_vector_recall_enabled:
            vector_index = MemoryVectorIndex(
                embedder=adapters.embedding,
                client=adapters.vector,
                collection=settings.memory_vector_collection,
            )
            await vector_index.ensure_collection()
        object_store = adapters.object_store

        def _factory(ctx: MemoryCallerContext) -> MemoryAPI:
            return MemoryAPI(
                context=ctx,
                adapter=routing_adapter,
                dlp=dlp,
                consent=consent,
                policy=memory_policy,  # type: ignore[arg-type]  # router conforms structurally (mirrors _build_api)
                kill_switch=kill_switch,
                audit=decision_history_store,
                settings=settings,
                object_store=object_store,
                vector_index=vector_index,
                resolver=overlay_resolver,  # ADR-023 — memory production-wired
            )

        memory_api_factory = _factory

    # --- Gateway + HTTP client (allocated LAST) ---------------------------
    # The http_client is created AFTER every fallible construction step above (preflight
    # YAML read, SLAPolicy validation, vault-resolve, and the memory branch's
    # OPAEngine.create / ensure_collection). It is the one resource that would LEAK if a
    # later step raised before Runtime exists (Runtime.aclose is the only path that closes
    # it). Nothing fallible runs after this point — LLMGateway() + Runtime() are pure
    # field assignments.
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
        observability=adapters.observability,
    )

    return Runtime(
        llm_gateway=gateway,
        memory_api_factory=memory_api_factory,
        audit_store=audit_store,
        decision_history_store=decision_history_store,
        memory_policy=memory_policy,
        config_overlay_store=overlay_store,
        config_overlay_resolver=overlay_resolver,
        approval_store=approval_store,
        approval_engine=approval_engine,
        _http_client=http_client,
    )
