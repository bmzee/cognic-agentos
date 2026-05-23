"""Sprint 9.5b C2 — gateway threads ``llm_model_id_map[alias]`` into
``GatewayCallRow.model_id`` at every ledger write site.

CRITICAL CONTROL. The gateway is the cloud-policy enforcer + the
authoritative feed into ``/api/v1/system/effective-routing`` (per
ADR-007). The C2 change wires the Sprint 9.5b Model Registry's
``model_id`` onto every per-call ledger row so the provider-honesty
surface can reach a stable model identity (joinable against the
``models`` table) for every ledger row written from C2 forward.

**User-locked review bar (PR #35 R2 plan-patch D7 message verbatim):**

1. Both gateway ledger-write sites use
   ``self._settings.llm_model_id_map.get(litellm_alias)``.
2. Empty/unmapped map preserves today's behavior:
   ``GatewayCallRow.model_id is None``.
3. Mapped alias writes the exact registered ``model_id``.
4. ``llm/ledger.py`` docstring stops saying "always None" / "backfills".
5. The transitional C1 "gateway does not mention ``llm_model_id_map``"
   test is deleted in the same commit and replaced with the positive
   C2 pins below (this file).

Each bar item maps to ≥1 test below per the
``[[feedback_strict_review_off_gate]]`` discipline. Bars #1 + #4 are
static AST-style source-grep pins (cheap, fast — catch a stale
revert immediately). Bars #2 + #3 are runtime behavior pins exercising
BOTH the strict ledger-write site (``_strict_ledger_write_or_raise``,
happy-path) AND the best-effort ledger-write site
(``_best_effort_ledger_write``, pre-dispatch denial path) — the two
sites the source-grep proves carry the lookup expression.
"""

from __future__ import annotations

import re
from pathlib import Path

import httpx
import pytest
import respx

import cognic_agentos
from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.config import Settings
from cognic_agentos.core.sla import SLAPolicy
from cognic_agentos.llm.concurrency import ProfileRateLimiter
from cognic_agentos.llm.gateway import LLMGateway
from cognic_agentos.llm.ledger import GatewayCallLedger
from cognic_agentos.llm.policy import CloudPolicyViolationError
from cognic_agentos.llm.preflight import PreflightResolver

# ----------------------------------------------------------------------
# Shared source-read helpers
# ----------------------------------------------------------------------


def _gateway_source() -> str:
    root = Path(cognic_agentos.__file__).resolve().parent
    return (root / "llm" / "gateway.py").read_text(encoding="utf-8")


def _ledger_source() -> str:
    root = Path(cognic_agentos.__file__).resolve().parent
    return (root / "llm" / "ledger.py").read_text(encoding="utf-8")


# ----------------------------------------------------------------------
# Shared respx + gateway-construction helpers
# ----------------------------------------------------------------------


def _ok_litellm_response(upstream_model: str) -> httpx.Response:
    """Minimal LiteLLM /chat/completions success shape — mirrors
    ``test_gateway_completion.py`` helper of the same name. Kept
    inline (not imported) so this test file stays self-contained."""
    return httpx.Response(
        200,
        json={
            "id": "test-1",
            "model": upstream_model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "hello"},
                    "finish_reason": "stop",
                }
            ],
        },
    )


def _build_gateway(
    *,
    settings: Settings,
    ledger: GatewayCallLedger,
    audit_store: AuditStore,
    rate_limiter: ProfileRateLimiter,
    preflight: PreflightResolver,
    sla_policy: SLAPolicy,
) -> LLMGateway:
    """Thin gateway constructor — mirrors ``test_gateway_completion.py``
    helper of the same name. Kept inline so this file stays
    self-contained; the real wiring is identical."""
    return LLMGateway(
        settings=settings,
        ledger=ledger,
        audit_store=audit_store,
        rate_limiter=rate_limiter,
        preflight=preflight,
        sla_policy=sla_policy,
        input_pipeline=None,
        output_pipeline=None,
    )


def _settings_with_map(
    *,
    llm_model_id_map: dict[str, str],
    allow_external_llm: bool = False,
    policy_mode: str = "self_hosted",
    allowed_providers: list[str] | None = None,
    base_url: str = "http://litellm.test:4000",
) -> Settings:
    """Build a Settings carrying ``litellm_base_url`` + the requested
    cloud-policy posture + the C2-specific ``llm_model_id_map``. The
    map is the ONLY axis the C2 tests vary across; everything else is
    default-gateway shape."""
    return Settings(
        allow_external_llm=allow_external_llm,
        policy_mode=policy_mode,  # type: ignore[arg-type]
        allowed_providers=allowed_providers or [],
        litellm_base_url=base_url,
        litellm_master_key="sk-test-key",
        llm_model_id_map=llm_model_id_map,
    )


# ──────────────────────────────────────────────────────────────────────
# Bar #1 — source-grep: both sites use the lookup expression
# ──────────────────────────────────────────────────────────────────────


def test_no_remaining_model_id_none_at_construction_site() -> None:
    """Bar #1 — the two ``GatewayCallRow`` construction sites must
    thread the map lookup, not hardcode ``None``. A regression
    would silently swallow Sprint 9.5b's per-call model identity."""
    src = _gateway_source()
    assert "model_id=None" not in src, (
        "stale `model_id=None` survives at a GatewayCallRow construction site"
    )


def test_construction_sites_use_settings_llm_model_id_map_get() -> None:
    """Bar #1 — exactly TWO sites carry the canonical lookup
    expression. The count gate is what proves "both sites" — a
    refactor that adds a third write site would surface here too
    (operator-discipline: every GatewayCallRow construction site
    must thread the map; this test is the count-of-record)."""
    src = _gateway_source()
    occurrences = re.findall(
        r"model_id=self\._settings\.llm_model_id_map\.get\(litellm_alias\)",
        src,
    )
    assert len(occurrences) == 2, f"expected exactly 2 lookup sites, found {len(occurrences)}"


# ──────────────────────────────────────────────────────────────────────
# Bar #4 — D4 plan-patch: ledger.py docstring carries the C2 contract
# ──────────────────────────────────────────────────────────────────────


def test_ledger_docstring_carries_c2_contract() -> None:
    """Bar #4 — ``llm/ledger.py`` module docstring now states the
    Sprint 9.5b C2 write-contract update (D4 plan-patch). The
    presence assertion pins the truthful contract — operators
    reading the module top-doc see what the gateway actually does."""
    src = _ledger_source()
    assert "Sprint 9.5b C2 (ADR-013)" in src, (
        "ledger.py module docstring must reference the Sprint 9.5b "
        "C2 contract update per the D4 plan-patch"
    )


def test_ledger_docstring_drops_stale_always_none_claim() -> None:
    """Bar #4 — the stale "always None on write" phrase is REMOVED
    from ``llm/ledger.py``. Negative source-grep catches a revert
    of the D4 update (or a fresh module that copies the same stale
    phrase by mistake).

    The pre-D4 source uses RST double-backticks around ``None`` (the
    ledger.py module convention is to mark code references with the
    Sphinx ``...`` syntax). Pre-D4 actual: ``always ``None`` on write``.
    Test asserts BOTH the with-backticks AND without-backticks
    formatting are absent — defends against a revert in either form.
    """
    src = _ledger_source()
    assert "always ``None`` on write" not in src, (
        "ledger.py docstring still carries the stale 'always ``None`` "
        "on write' claim (RST-formatted) — the D4 plan-patch update "
        "was reverted or incompletely applied"
    )
    assert "always None on write" not in src, (
        "ledger.py docstring still carries the stale 'always None on "
        "write' claim (plain-formatted) — defence-in-depth catch in "
        "case a future cleanup strips the backticks but keeps the "
        "claim"
    )


# ──────────────────────────────────────────────────────────────────────
# Bars #2 + #3 — runtime behavior at BOTH write sites
# ──────────────────────────────────────────────────────────────────────


class TestStrictLedgerWriteSiteModelId:
    """Bars #2 + #3 — happy-path ``_strict_ledger_write_or_raise`` site
    (called on every successful post-dispatch ledger write)."""

    @respx.mock
    async def test_model_id_is_none_when_map_empty(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        """Bar #2 — empty ``llm_model_id_map`` preserves today's
        behavior: the ledger row's ``model_id`` is ``None``. This is
        the backward-compat baseline — the default ``{}`` map MUST
        NOT change the wire contract for any pre-C2 caller."""
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_ok_litellm_response("ollama/qwen3:8b")
        )
        settings = _settings_with_map(llm_model_id_map={})
        assert settings.llm_model_id_map == {}, "test precondition"

        gateway = _build_gateway(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
        )
        await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-c2-bar2-strict",
            tenant_id="tenant-a",
        )

        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].outcome == "ok"
        assert rows[0].provenance == "resolved"
        # Bar #2 assertion: empty map → model_id is None.
        assert rows[0].model_id is None

    @respx.mock
    async def test_model_id_is_none_when_alias_absent_from_non_empty_map(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        """Bar #2 — the OTHER unmapped scenario: map is non-empty but
        the resolved alias is absent. ``.get(litellm_alias)`` returns
        ``None`` (the dict default) and the ledger row honestly
        reflects "this alias is not registered" rather than inventing
        a value."""
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_ok_litellm_response("ollama/qwen3:8b")
        )
        settings = _settings_with_map(
            # Map carries a DIFFERENT alias — the resolved tier1 alias
            # ("cognic-tier1-dev") is absent.
            llm_model_id_map={"some-other-alias": "some-other-model-id"},
        )

        gateway = _build_gateway(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
        )
        await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-c2-bar2-strict-unmapped",
            tenant_id="tenant-a",
        )

        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        # Bar #2 assertion: unmapped alias → model_id is None.
        assert rows[0].model_id is None

    @respx.mock
    async def test_model_id_matches_registered_value_when_mapped(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        """Bar #3 — when the resolved alias IS in the map, the ledger
        row carries the EXACT registered ``model_id`` (no
        normalisation, no transformation, no fallback)."""
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_ok_litellm_response("ollama/qwen3:8b")
        )
        settings = _settings_with_map(
            llm_model_id_map={
                "cognic-tier1-dev": "cognic-tier1-acme-v1",
            }
        )

        gateway = _build_gateway(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
        )
        await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-c2-bar3-strict",
            tenant_id="tenant-a",
        )

        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].outcome == "ok"
        assert rows[0].provenance == "resolved"
        # Bar #3 assertion: mapped alias → model_id == registered value.
        assert rows[0].model_id == "cognic-tier1-acme-v1"


class TestBestEffortLedgerWriteSiteModelId:
    """Bars #2 + #3 — pre-dispatch ``_best_effort_ledger_write`` site
    (called on policy-denial / guardrail-trip / concurrency-exhaustion
    paths where no upstream call ever happens). The C2 lookup MUST
    apply at this site too — the source-grep proves the expression
    is there; this test proves the expression's runtime value lands
    on the row that gets persisted."""

    async def test_model_id_is_none_on_policy_denial_path_when_map_empty(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        cloud_openai_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        """Bar #2 (best-effort site) — empty map on the denial path
        preserves today's behavior: the persisted ``no_dispatch`` row's
        ``model_id`` is ``None`` (user-found PR #35 R2 C2 coverage
        pin). Matches the strict-site Bar #2 baseline at the
        best-effort write site so the symmetric "empty/unmapped → None"
        invariant is pinned at BOTH ledger-write helpers, not only at
        the happy path."""
        settings = _settings_with_map(
            allow_external_llm=False,
            policy_mode="self_hosted",
            allowed_providers=[],
            llm_model_id_map={},
        )
        assert settings.llm_model_id_map == {}, "test precondition"

        gateway = _build_gateway(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=cloud_openai_resolver,
            sla_policy=default_sla_policy,
        )
        with pytest.raises(CloudPolicyViolationError):
            await gateway.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-c2-bar2-best-effort",
                tenant_id="tenant-a",
            )

        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].outcome == "denied"
        assert rows[0].provenance == "no_dispatch"
        # Bar #2 assertion at the SECOND construction site.
        assert rows[0].model_id is None

    async def test_model_id_matches_registered_value_on_policy_denial_path(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        cloud_openai_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        """Bar #3 (best-effort site) — cloud upstream with
        ``allow_external_llm=False`` denies pre-dispatch; the
        best-effort ledger row writes ``provenance="no_dispatch"`` +
        the mapped ``model_id``. No respx needed — no HTTP call
        happens on the denial path."""
        settings = _settings_with_map(
            allow_external_llm=False,
            policy_mode="self_hosted",
            allowed_providers=[],
            llm_model_id_map={
                "cognic-tier1-dev": "cognic-tier1-acme-v1",
            },
        )

        gateway = _build_gateway(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=cloud_openai_resolver,
            sla_policy=default_sla_policy,
        )
        # The denial path raises CloudPolicyViolationError per the
        # existing gateway contract — pinning the specific exception
        # class (rather than a blind ``Exception``) catches a future
        # refactor that surfaces the denial through a different
        # exception type without updating this assertion.
        with pytest.raises(CloudPolicyViolationError):
            await gateway.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-c2-bar3-best-effort",
                tenant_id="tenant-a",
            )

        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].outcome == "denied"
        assert rows[0].provenance == "no_dispatch"
        # Bar #3 assertion at the SECOND construction site.
        assert rows[0].model_id == "cognic-tier1-acme-v1"
