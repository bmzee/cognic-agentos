"""LLM gateway (Sprint 3) — tier alias resolution + completion flow.

Layer classification: **platform primitive** (critical control per
AGENTS.md — cloud-policy enforcer + provider-honesty ledger feed).

Sprint 3 T2 ships only the tier-name → LiteLLM-alias translator.
The LiteLLM-alias → :class:`ResolvedUpstream` resolver + the
api_base-aware classifier live in :mod:`cognic_agentos.llm.preflight`
(T6) so the classification primitives and the YAML parser stay
co-located. Keeping classification out of this module also avoids
the ``gateway.py → preflight.py → gateway.py`` circular dependency
the Round-1 plan shape carried.

The full ``LLMGateway.completion`` flow lands in T6.

References:
- ``docs/superpowers/plans/2026-04-30-sprint-3-llm-gateway-and-provider-honesty.md``
  Decision-Locking §1 (provider alias semantics: three layers).
- ADR-007 (Provider-Honesty Enforcement).
"""

from __future__ import annotations

import dataclasses as _dataclasses
import datetime as _dt
import json as _json
import logging as _logging
import time as _time
import uuid as _uuid
from typing import TYPE_CHECKING, Literal

import httpx as _httpx

if TYPE_CHECKING:
    from cognic_agentos.db.adapters.protocols import ObservabilityAdapter

from cognic_agentos.core.audit import AuditEvent, AuditStore
from cognic_agentos.core.config import Settings
from cognic_agentos.core.guardrails import (
    GuardrailDirection,
    GuardrailPipeline,
    PipelineResult,
)
from cognic_agentos.core.sla import SLAPolicy, SLAStatus, SLATimer
from cognic_agentos.llm.concurrency import LLMConcurrencyExceeded, ProfileRateLimiter
from cognic_agentos.llm.ledger import GatewayCallLedger, GatewayCallRow
from cognic_agentos.llm.policy import (
    CloudPolicyViolationError,
    GuardrailViolationError,
    enforce_cloud_policy,
)
from cognic_agentos.llm.preflight import (
    PreflightResolver,
    ResolvedUpstream,
    UnknownAliasError,
)

#: Tier vocabulary. Sprint 3 ships two tiers; Sprint 9.5
#: (ADR-013 model registry) may extend.
Tier = Literal["tier1", "tier2"]


#: Closed-enum trace-outcome vocabulary for the observability span
#: (ADR-009 + the gateway-observability workstream). DISTINCT from the
#: ledger's ``outcome`` column vocabulary: the span says ``policy_denied``
#: where the ledger says ``denied``, and the span carries ``invalid_tier``
#: / ``preflight_failure`` / ``strict_ledger_failure`` which have NO ledger
#: equivalent. ``errored_pre_resolution`` is the pre-tier-resolution
#: default — emitted only if no exit path set a value (a bug guard, not a
#: normal outcome). Pinned by
#: ``test_gateway_observability.py::TestTraceOutcomeVocabularyClosed``.
GatewayTraceOutcome = Literal[
    "errored_pre_resolution",
    "invalid_tier",
    "preflight_failure",
    "guardrail_input",
    "policy_denied",
    "concurrency_exhausted",
    "upstream_error",
    "guardrail_output",
    "strict_ledger_failure",
    "ok",
    "drift",
]


class UnknownTierError(ValueError):
    """Raised when :func:`resolve_tier_alias` sees a tier outside
    the :data:`Tier` literal."""


def resolve_tier_alias(tier: str, settings: Settings) -> str:
    """Resolve a tier name to the configured LiteLLM alias.

    Reads ``settings.tier1_alias`` / ``settings.tier2_alias``. Sprint 3
    ships only two tiers; an unknown tier raises
    :class:`UnknownTierError`. The error message lists the known set
    so an operator misconfigured caller does not need to grep the
    source.

    Per Decision-Locking §1: this layer ships only the tier→alias
    translation. The alias→upstream resolution + api_base-aware
    classification happen at the gateway boundary (T6) via
    :class:`cognic_agentos.llm.preflight.PreflightResolver`.

    Args:
        tier: Caller-facing tier name (``"tier1"`` or ``"tier2"``).
        settings: Process settings carrying ``tier1_alias`` and
            ``tier2_alias``.

    Returns:
        The LiteLLM alias (e.g. ``"cognic-tier1-dev"``).

    Raises:
        UnknownTierError: ``tier`` is not in :data:`Tier`. Subclass of
            :class:`ValueError` so generic settings/validation handlers
            still trip on it.
    """
    if tier == "tier1":
        return settings.tier1_alias
    if tier == "tier2":
        return settings.tier2_alias
    raise UnknownTierError(f"unknown tier {tier!r}; expected one of: tier1, tier2")


# ===========================================================================
# T6 phase B — LLMGateway core + helpers.
#
# References:
# - Plan Decision-Locking §1 (provider alias semantics)
# - Plan Decision-Locking §2 (cloud-policy fail-closed)
# - Plan Decision-Locking §3 (guardrail input/output placement +
#   per-route guardrail scope)
# - Plan Decision-Locking §5 (audit + decision-history emission)
# - ADR-007 (Provider-Honesty Enforcement)
# ===========================================================================

_LOG = _logging.getLogger("cognic_agentos.llm.gateway")


def _guardrails_enabled_for(resolved: ResolvedUpstream, scope: str) -> bool:
    """Per-route guardrail-execution decision (Plan Decision-Locking §3
    + T1-followup four-mode contract).

    Pure function; no audit emission. Composes with the inject-None
    axis at the gateway: the call site computes
    ``run = pipeline is not None and _guardrails_enabled_for(...)``.
    """

    if scope == "all":
        return True
    if scope == "external_only":
        return resolved.external
    if scope == "self_hosted_only":
        return not resolved.external
    if scope == "off":
        return False
    raise AssertionError(  # Literal type guarantees coverage at the boundary
        f"unreachable scope {scope!r}; settings validator should have rejected"
    )


class LedgerWriteFailed(RuntimeError):
    """Raised when a strict-regime ledger write fails.

    Per Round-1 reviewer-P1#1: ADR-007 makes the ledger authoritative
    for ``/system/effective-routing``. The success contract is "no
    successful return without a persisted ledger row". When LiteLLM
    dispatched the request and the ledger write fails, the caller MUST
    see a failure rather than a successful response with no
    provenance.
    """


class _MalformedResponseContent(RuntimeError):
    """Internal sentinel for the post-dispatch outer-catch block.

    Round-7 reviewer-P1: response shape failures (KeyError /
    IndexError / TypeError extracting
    ``body['choices'][0]['message']['content']``, or a non-string
    content) raise this so the outer ``except Exception`` block
    strict-ledgers + propagates with full context. Not part of the
    public exception API.
    """


@_dataclasses.dataclass(frozen=True, slots=True)
class GatewayResponse:
    """What the caller gets back on a successful gateway dispatch.

    Round-6 reviewer-P1 fields: the response carries both
    ``upstream_model`` (the actual model_string LiteLLM dispatched
    against) and ``api_base`` (the actual endpoint, recovered via
    ``PreflightResolver.reverse_lookup``). Together they let portal
    UIs surface the truth of what was hit, matching the
    ``/effective-routing`` contract.
    """

    content: str
    upstream_model: str
    api_base: str | None
    external: bool
    request_id: str
    tier: str
    latency_ms: int


@_dataclasses.dataclass(slots=True)
class _CompletionTrace:
    """Mutable per-call trace state for the observability span.

    Initialized BEFORE tier resolution so the ``completion`` wrapper's
    ``finally`` emit always has a well-defined ``outcome`` — even on the
    pre-resolution failure paths where the ledger ``outcome`` var does not
    yet exist. The span reads THIS object, never the ledger ``outcome``
    var; the two vocabularies are distinct (see :data:`GatewayTraceOutcome`).
    """

    request_id: str
    tenant_id: str | None
    tier: str
    flow_start: float
    agent_workforce_id: str | None
    outcome: GatewayTraceOutcome = "errored_pre_resolution"
    litellm_alias: str | None = None
    preflight: ResolvedUpstream | None = None
    actual: ResolvedUpstream | None = None
    usage: dict[str, object] | None = None


class LLMGateway:
    """Single LLM-call chokepoint for ADR-007 provider-honesty.

    Per Plan Decision-Locking §3 the completion flow runs in three
    phases:

    - **Pre-dispatch** (best-effort ledger regime): tier→alias
      resolve, INPUT guardrails, pre-call cloud-policy on preflight,
      concurrency-slot acquire. Failures here ledger best-effort and
      raise; the hash-chained ``audit_event`` already records the
      violation, so a ledger gap costs ``/effective-routing`` count
      fidelity but not chain-of-custody.
    - **Dispatch**: SLA timer + ``httpx.post`` to LiteLLM. Connection-
      class httpx errors (``ConnectError`` / ``ConnectTimeout`` /
      ``PoolTimeout`` / ``LocalProtocolError``) are pre-dispatch best-
      effort; every other ``httpx.RequestError`` subclass is
      possibly-dispatched and uses the strict regime per Round-5
      reviewer-P1.
    - **Post-dispatch** (strict ledger regime): build actual
      ResolvedUpstream (sync helpers — Round-8 reviewer-P1 — so an
      AuditStore failure on the unresolved/ambiguous emit doesn't
      lose the correct provenance), SLA classify, drift telemetry,
      post-response policy recheck, OUTPUT guardrails, strict ledger
      write, return ``GatewayResponse``. Wrapped in an outer
      try/except (Round-7 reviewer-P1) so AuditStore failures or
      malformed-content failures still strict-ledger before
      propagating.

    Constructor takes the substrate (settings, ledger, audit_store,
    rate_limiter, preflight, sla_policy) plus optional input + output
    guardrail pipelines. ``http_client`` is injectable for testing
    via ``respx``. ``litellm_master_key`` is the pre-resolved seam for
    the deferred harness wiring (Wave-1 T3): a future harness resolves
    a ``vault://`` URI and passes the result here; the key is read once
    at construction, and a ``vault://`` URI with no resolved value fails
    loud so ``Bearer vault://...`` can never reach the wire.
    """

    def __init__(
        self,
        *,
        settings: Settings,
        ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        preflight: PreflightResolver,
        sla_policy: SLAPolicy,
        input_pipeline: GuardrailPipeline | None = None,
        output_pipeline: GuardrailPipeline | None = None,
        http_client: _httpx.AsyncClient | None = None,
        litellm_master_key: str | None = None,
        observability: ObservabilityAdapter | None = None,
    ) -> None:
        self._settings = settings
        self._ledger = ledger
        self._audit = audit_store
        self._rate_limiter = rate_limiter
        self._preflight = preflight
        self._sla_policy = sla_policy
        self._input_pipeline = input_pipeline
        self._output_pipeline = output_pipeline
        self._http = http_client or _httpx.AsyncClient(timeout=settings.llm_timeout_s)
        # Wave-1 T3: resolve the LiteLLM master key ONCE at construction. A
        # future harness resolves a vault:// URI via
        # ``db.adapters.secret_resolution.resolve_secret_field`` and passes the
        # result as ``litellm_master_key=``. If no pre-resolved value is passed
        # AND ``settings.litellm_master_key`` is a vault:// URI, fail loud — the
        # gateway must NEVER put "Bearer vault://..." on the wire.
        if litellm_master_key is None and (
            settings.litellm_master_key is not None
            and settings.litellm_master_key.startswith("vault://")
        ):
            raise RuntimeError(
                "litellm_master_key_unresolved_vault_uri: settings.litellm_master_key "
                "is a vault:// URI but no resolved value was passed; the harness must "
                "resolve it and pass litellm_master_key="
            )
        self._litellm_master_key: str | None = (
            litellm_master_key if litellm_master_key is not None else settings.litellm_master_key
        )
        self._observability: ObservabilityAdapter | None = observability

    async def completion(
        self,
        *,
        tier: str,
        messages: list[dict[str, str]],
        request_id: str,
        tenant_id: str | None = None,
        agent_workforce_id: str | None = None,
    ) -> GatewayResponse:
        """The full Plan Decision-Locking §3 flow, wrapped in a best-effort
        observability span (gateway-observability workstream). The span is
        emitted on EVERY exit via the ``finally`` + the dedicated
        :class:`_CompletionTrace`. A strict-ledger failure overrides the
        per-path outcome to ``strict_ledger_failure`` (the call ultimately
        failed on the provenance write)."""
        trace = _CompletionTrace(
            request_id=request_id,
            tenant_id=tenant_id,
            tier=tier,
            flow_start=_time.monotonic(),
            agent_workforce_id=agent_workforce_id,
        )
        try:
            return await self._run_completion(trace=trace, messages=messages)
        except LedgerWriteFailed:
            trace.outcome = "strict_ledger_failure"
            raise
        finally:
            await self._emit_completion_trace_best_effort(trace)

    async def _run_completion(
        self,
        *,
        trace: _CompletionTrace,
        messages: list[dict[str, str]],
    ) -> GatewayResponse:
        """The Plan Decision-Locking §3 flow body. Reads the stable per-call
        values from ``trace`` and sets ``trace.outcome`` / ``.preflight`` /
        ``.actual`` / ``.usage`` at each exit so the wrapper's ``finally``
        emits a well-defined span. The ledger ``outcome`` var below is
        UNCHANGED — its vocabulary is the ledger's, not the span's."""
        tier = trace.tier
        request_id = trace.request_id
        tenant_id = trace.tenant_id
        flow_start = trace.flow_start

        try:
            litellm_alias = resolve_tier_alias(tier, self._settings)
        except UnknownTierError:
            trace.outcome = "invalid_tier"
            raise
        trace.litellm_alias = litellm_alias
        try:
            preflight_resolved = self._preflight.resolve(litellm_alias)
        except (UnknownAliasError, ValueError):
            trace.outcome = "preflight_failure"
            raise
        trace.preflight = preflight_resolved

        actual_resolved: ResolvedUpstream | None = None  # set after LiteLLM responds
        outcome: str = "ok"
        scope: str = self._settings.llm_guardrail_scope

        # --- 1. INPUT guardrails (pre-dispatch — best-effort regime) -----------
        # T1 follow-up: per-route scope + inject-None compose. Input
        # direction classifies on ``preflight_resolved.external``
        # (decision lands BEFORE LiteLLM dispatches; preflight is the
        # only signal we have). Local-narrow binding for mypy.
        input_pipeline = self._input_pipeline
        run_input_guardrails = input_pipeline is not None and _guardrails_enabled_for(
            preflight_resolved, scope
        )
        if run_input_guardrails:
            joined = "\n".join(m.get("content", "") for m in messages)
            ip_result: PipelineResult = await input_pipeline.check(  # type: ignore[union-attr]
                joined,
                direction=GuardrailDirection.INPUT,
                request_id=request_id,
                tenant_id=tenant_id,
            )
            input_trips = [r for r in ip_result.results if not r.passed]
            if input_trips:
                outcome = "guardrail_input"
                trace.outcome = "guardrail_input"
                trip_summary = ",".join(r.guardrail_name for r in input_trips)
                err = GuardrailViolationError("input", trip_summary)
                await self._best_effort_ledger_write(
                    request_id=request_id,
                    tenant_id=tenant_id,
                    tier=tier,
                    litellm_alias=litellm_alias,
                    preflight=preflight_resolved,
                    flow_start=flow_start,
                    outcome=outcome,
                )
                raise err

        # --- 2. Pre-call cloud-policy on preflight ResolvedUpstream -----------
        decision = enforce_cloud_policy(
            resolved=preflight_resolved,
            settings=self._settings,
            post_response=False,
        )
        if not decision.allowed:
            outcome = "denied"
            trace.outcome = "policy_denied"
            await self._audit.append(
                AuditEvent(
                    event_type="gateway.cloud_policy_denied",
                    request_id=request_id,
                    payload=decision.audit_payload,
                    tenant_id=tenant_id,
                    iso_controls=("ISO42001.A.9.2",),
                )
            )
            await self._best_effort_ledger_write(
                request_id=request_id,
                tenant_id=tenant_id,
                tier=tier,
                litellm_alias=litellm_alias,
                preflight=preflight_resolved,
                flow_start=flow_start,
                outcome=outcome,
            )
            raise CloudPolicyViolationError.from_decision(decision)

        # --- 3-9. Concurrency slot + dispatch + post-dispatch -----------------
        # Round-3 reviewer-P2: natural ``async with`` shape. When
        # ``__aenter__`` raises (LLMConcurrencyExceeded in fail_fast),
        # ``__aexit__`` is NOT called per the language spec, so the
        # exception propagates to the outer ``except`` for ledger-
        # write + re-raise. Body exceptions trigger the limiter's
        # ``__aexit__(type(exc), exc, tb)`` correctly, preserving
        # exception context.
        try:
            async with self._rate_limiter.acquire(profile=tier):
                # --- 4. SLA timer + dispatch (Round-5 reviewer-P1: split
                # connect-class vs possibly-dispatched httpx errors) -----
                sla_start = _dt.datetime.now(_dt.UTC)
                deadline = SLATimer.compute_deadline(start=sla_start, policy=self._sla_policy)

                try:
                    resp = await self._http.post(
                        f"{self._settings.litellm_base_url}/chat/completions",
                        json={"model": litellm_alias, "messages": messages},
                        headers={"Authorization": (f"Bearer {self._litellm_master_key}")},
                    )
                except (
                    _httpx.ConnectError,
                    _httpx.ConnectTimeout,
                    _httpx.PoolTimeout,
                    _httpx.LocalProtocolError,
                ):
                    # Definitively pre-dispatch — connection never
                    # established or local request malformed before
                    # going on the wire.
                    outcome = "upstream_error"
                    trace.outcome = "upstream_error"
                    await self._best_effort_ledger_write(
                        request_id=request_id,
                        tenant_id=tenant_id,
                        tier=tier,
                        litellm_alias=litellm_alias,
                        preflight=preflight_resolved,
                        flow_start=flow_start,
                        outcome=outcome,
                    )
                    raise
                except _httpx.RequestError as exc:
                    # ReadTimeout / ReadError / WriteError / WriteTimeout
                    # / RemoteProtocolError — request was sent (possibly
                    # in full); LiteLLM may already have contacted
                    # upstream. Strict regime with preflight identity.
                    outcome = "upstream_error"
                    trace.outcome = "upstream_error"
                    await self._strict_ledger_write_or_raise(
                        request_id=request_id,
                        tenant_id=tenant_id,
                        tier=tier,
                        litellm_alias=litellm_alias,
                        resolved=preflight_resolved,
                        flow_start=flow_start,
                        outcome=outcome,
                        original_exc=exc,
                    )
                    raise

                # We have a response — DISPATCHED. Strict regime engages.
                # Round-7 reviewer-P1: the entire post-dispatch block
                # is wrapped so AuditStore failures + content shape
                # failures still strict-ledger before propagating.
                try:
                    try:
                        resp.raise_for_status()
                        body = resp.json()
                    except (_httpx.HTTPStatusError, _json.JSONDecodeError) as exc:
                        # Round-9 reviewer-P2: narrow the JSON-parse
                        # catch to ``json.JSONDecodeError`` (subclass
                        # of ``ValueError``) so the outer pass-through
                        # list can include it WITHOUT swallowing every
                        # downstream ValueError. The exception class
                        # is also added to the outer ``except`` tuple
                        # so this branch's strict ledger row is the
                        # ONLY row written for the call (ADR-007 one-
                        # call/one-ledger-row contract for
                        # /effective-routing counts).
                        outcome = "upstream_error"
                        trace.outcome = "upstream_error"
                        await self._strict_ledger_write_or_raise(
                            request_id=request_id,
                            tenant_id=tenant_id,
                            tier=tier,
                            litellm_alias=litellm_alias,
                            resolved=preflight_resolved,
                            flow_start=flow_start,
                            outcome=outcome,
                            original_exc=exc,
                        )
                        raise

                    # Round-6 reviewer-P1: missing/empty/non-string
                    # ``model`` field is a provenance gap.
                    raw_actual = body.get("model")
                    pending_audit: AuditEvent | None
                    if not isinstance(raw_actual, str) or not raw_actual.strip():
                        actual_resolved, pending_audit = self._build_unresolved_actual(
                            cause="missing_model_field",
                            preflight_resolved=preflight_resolved,
                            request_id=request_id,
                            tenant_id=tenant_id,
                        )
                    else:
                        actual_resolved, pending_audit = self._build_actual_resolved(
                            actual_model_string=raw_actual,
                            preflight_resolved=preflight_resolved,
                            request_id=request_id,
                            tenant_id=tenant_id,
                        )
                    # Round-8 reviewer-P1: actual_resolved is bound
                    # BEFORE the audit emit. If append raises, the
                    # outer catch-all has the correct provenance state.
                    trace.actual = actual_resolved
                    if pending_audit is not None:
                        await self._audit.append(pending_audit)

                    # --- 5. SLA classify (post-dispatch — strict regime) ---
                    now = _dt.datetime.now(_dt.UTC)
                    if SLATimer.classify(now=now, deadline=deadline) is SLAStatus.BREACHED:
                        elapsed_ms = int((now - sla_start).total_seconds() * 1000)
                        budget_ms = int(self._sla_policy.total_budget.total_seconds() * 1000)
                        await self._audit.append(
                            AuditEvent(
                                event_type="sla.breach",
                                request_id=request_id,
                                payload={
                                    "alias": litellm_alias,
                                    "preflight_model": preflight_resolved.model_string,
                                    "actual_model": actual_resolved.model_string,
                                    "elapsed_ms": elapsed_ms,
                                    "budget_ms": budget_ms,
                                },
                                tenant_id=tenant_id,
                                iso_controls=("ISO42001.A.9.2",),
                            )
                        )

                    # --- 6. Provider-honesty drift event -------------------
                    # Round-2 reviewer-P1#1: drift event emitted on
                    # ANY model_string mismatch (catches external→
                    # external provider drift).
                    drift = actual_resolved.model_string != preflight_resolved.model_string
                    if drift:
                        await self._audit.append(
                            AuditEvent(
                                event_type="gateway.upstream_drift_detected",
                                request_id=request_id,
                                payload={
                                    "alias": litellm_alias,
                                    "preflight_model": preflight_resolved.model_string,
                                    "preflight_api_base": preflight_resolved.api_base,
                                    "preflight_external": preflight_resolved.external,
                                    "actual_model": actual_resolved.model_string,
                                    "actual_api_base": actual_resolved.api_base,
                                    "actual_external": actual_resolved.external,
                                },
                                tenant_id=tenant_id,
                                iso_controls=("ISO42001.A.9.2",),
                            )
                        )

                    # --- 7. POST-RESPONSE policy recheck -------------------
                    # Round-2 reviewer-P1#1 + Round-4 P1: re-run the
                    # enforcer on actual_resolved. provenance != "resolved"
                    # is a fail-closed gate the enforcer handles
                    # internally (Round-4+5+6 P1).
                    actual_decision = enforce_cloud_policy(
                        resolved=actual_resolved,
                        settings=self._settings,
                        post_response=True,
                    )
                    if not actual_decision.allowed:
                        outcome = "denied"
                        trace.outcome = "policy_denied"
                        await self._audit.append(
                            AuditEvent(
                                event_type="gateway.cloud_policy_denied",
                                request_id=request_id,
                                payload=actual_decision.audit_payload,
                                tenant_id=tenant_id,
                                iso_controls=("ISO42001.A.9.2",),
                            )
                        )
                        policy_err = CloudPolicyViolationError.from_decision(actual_decision)
                        await self._strict_ledger_write_or_raise(
                            request_id=request_id,
                            tenant_id=tenant_id,
                            tier=tier,
                            litellm_alias=litellm_alias,
                            resolved=actual_resolved,
                            flow_start=flow_start,
                            outcome=outcome,
                            original_exc=policy_err,
                        )
                        raise policy_err

                    # --- 7a. Extract content (Round-7 reviewer-P1) ---------
                    try:
                        content = body["choices"][0]["message"]["content"]
                    except (KeyError, IndexError, TypeError) as exc:
                        raise _MalformedResponseContent(str(exc)) from exc
                    if not isinstance(content, str):
                        raise _MalformedResponseContent(
                            f"choices[0].message.content is not str: got {type(content).__name__}"
                        )

                    # --- 8. OUTPUT guardrails (post-dispatch — strict) -----
                    # T1 follow-up: per-route scope + inject-None compose.
                    # Output direction classifies on
                    # ``actual_resolved.external``.
                    output_pipeline = self._output_pipeline
                    run_output_guardrails = output_pipeline is not None and _guardrails_enabled_for(
                        actual_resolved, scope
                    )
                    if run_output_guardrails:
                        op_result: PipelineResult = await output_pipeline.check(  # type: ignore[union-attr]
                            content,
                            direction=GuardrailDirection.OUTPUT,
                            request_id=request_id,
                            tenant_id=tenant_id,
                        )
                        output_trips = [r for r in op_result.results if not r.passed]
                        if output_trips:
                            outcome = "guardrail_output"
                            trace.outcome = "guardrail_output"
                            trip_summary = ",".join(r.guardrail_name for r in output_trips)
                            err_g = GuardrailViolationError("output", trip_summary)
                            await self._strict_ledger_write_or_raise(
                                request_id=request_id,
                                tenant_id=tenant_id,
                                tier=tier,
                                litellm_alias=litellm_alias,
                                resolved=actual_resolved,
                                flow_start=flow_start,
                                outcome=outcome,
                                original_exc=err_g,
                            )
                            raise err_g

                    # --- 9. Strict ledger write THEN return ---------------
                    outcome = "drift" if drift else "ok"
                    # Span provenance: capture usage counts + the per-path
                    # outcome BEFORE the strict ledger write so a subsequent
                    # LedgerWriteFailed (→ wrapper override) still carries the
                    # usage it had. ``body`` is in scope from ``resp.json()``.
                    trace.usage = body.get("usage") if isinstance(body.get("usage"), dict) else None
                    trace.outcome = "drift" if drift else "ok"
                    latency_ms = int((_time.monotonic() - flow_start) * 1000)
                    await self._strict_ledger_write_or_raise(
                        request_id=request_id,
                        tenant_id=tenant_id,
                        tier=tier,
                        litellm_alias=litellm_alias,
                        resolved=actual_resolved,
                        flow_start=flow_start,
                        outcome=outcome,
                        original_exc=None,
                    )
                    return GatewayResponse(
                        content=content,
                        upstream_model=actual_resolved.model_string,
                        api_base=actual_resolved.api_base,
                        external=actual_resolved.external,
                        request_id=request_id,
                        tier=tier,
                        latency_ms=latency_ms,
                    )
                except (
                    CloudPolicyViolationError,
                    GuardrailViolationError,
                    LedgerWriteFailed,
                    _httpx.HTTPStatusError,
                    _json.JSONDecodeError,
                ):
                    # Already strict-ledgered inline (or
                    # LedgerWriteFailed from a strict-ledger failure /
                    # HTTP-status raise / JSON-decode raise inside the
                    # inner try). Re-raise. Round-9 reviewer-P2: the
                    # explicit ``json.JSONDecodeError`` arm closes the
                    # double-ledger gap that otherwise wrote two
                    # outcome="upstream_error" rows for one call.
                    raise
                except Exception as exc:
                    trace.outcome = "upstream_error"
                    # Round-7 reviewer-P1: AuditStore failures +
                    # malformed-content path land here. Strict-ledger
                    # with actual_resolved if bound, else preflight.
                    best_resolved = actual_resolved or preflight_resolved
                    await self._strict_ledger_write_or_raise(
                        request_id=request_id,
                        tenant_id=tenant_id,
                        tier=tier,
                        litellm_alias=litellm_alias,
                        resolved=best_resolved,
                        flow_start=flow_start,
                        outcome="upstream_error",
                        original_exc=exc,
                    )
                    raise
        except LLMConcurrencyExceeded:
            # Round-2 reviewer-P2 + Round-3 P2: ledger best-effort
            # then propagate. The ``async with`` __aenter__ raised;
            # __aexit__ was not called.
            outcome = "concurrency_exhausted"
            trace.outcome = "concurrency_exhausted"
            await self._best_effort_ledger_write(
                request_id=request_id,
                tenant_id=tenant_id,
                tier=tier,
                litellm_alias=litellm_alias,
                preflight=preflight_resolved,
                flow_start=flow_start,
                outcome=outcome,
            )
            raise

    def _build_actual_resolved(
        self,
        *,
        actual_model_string: str,
        preflight_resolved: ResolvedUpstream,
        request_id: str,
        tenant_id: str | None,
    ) -> tuple[ResolvedUpstream, AuditEvent | None]:
        """Round-3+4+5+6+8 fail-closed disambiguation.

        Round-8 reviewer-P1: synchronous; returns
        ``(ResolvedUpstream, AuditEvent | None)``. The caller assigns
        the resolved object BEFORE awaiting the audit emission, so a
        failure inside ``AuditStore.append`` on the unresolved or
        ambiguous paths cannot leave ``actual_resolved`` unbound — the
        outer post-dispatch catch-all then strict-ledgers with the
        correct provenance state, not the preflight identity.

        Four cases:
          * 0 matches → delegate to ``_build_unresolved_actual`` with
            cause="model_not_in_yaml".
          * 1 match → return ``(match, None)``.
          * N matches uniform classification → return
            ``(matches[0], None)``; treatment identical regardless
            of which alias matched.
          * N matches MIXED classification → fail-closed
            ``provenance="ambiguous"`` + ``api_base=None`` + emit
            ``gateway.upstream_classification_ambiguous``.
        """
        matches = self._preflight.reverse_lookup(actual_model_string)
        if not matches:
            return self._build_unresolved_actual(
                cause="model_not_in_yaml",
                preflight_resolved=preflight_resolved,
                request_id=request_id,
                tenant_id=tenant_id,
                actual_model_string=actual_model_string,
            )
        externals = {m.external for m in matches}
        if len(externals) == 1:
            return matches[0], None  # unambiguous
        # Mixed-classification collision — fail-closed.
        constructed = ResolvedUpstream(
            alias=preflight_resolved.alias,
            model_string=actual_model_string,
            api_base=None,
            external=True,
            provenance="ambiguous",
        )
        event = AuditEvent(
            event_type="gateway.upstream_classification_ambiguous",
            request_id=request_id,
            payload={
                "actual_model_string": actual_model_string,
                "matching_aliases": [m.alias for m in matches],
                "matching_classifications": [
                    {
                        "alias": m.alias,
                        "api_base": m.api_base,
                        "external": m.external,
                    }
                    for m in matches
                ],
            },
            tenant_id=tenant_id,
            iso_controls=("ISO42001.A.9.2",),
        )
        return constructed, event

    def _build_unresolved_actual(
        self,
        *,
        cause: str,  # "model_not_in_yaml" | "missing_model_field"
        preflight_resolved: ResolvedUpstream,
        request_id: str,
        tenant_id: str | None,
        actual_model_string: str | None = None,
    ) -> tuple[ResolvedUpstream, AuditEvent]:
        """Round-5+6+8 reviewer-P1 — provenance-gap fail-close.

        Synchronous so the T6 caller assigns the resolved object
        BEFORE awaiting the audit emission. If the subsequent
        ``self._audit.append(event)`` raises, ``actual_resolved`` is
        already bound to the correct ``provenance="unresolved"``
        object — outer catch-all ledgers with the right provenance,
        not the preflight identity (false historical claim).
        """
        constructed = ResolvedUpstream(
            alias=preflight_resolved.alias,
            model_string=actual_model_string or "<missing>",
            api_base=None,
            external=True,
            provenance="unresolved",
        )
        event = AuditEvent(
            event_type="gateway.upstream_unresolved",
            request_id=request_id,
            payload={
                "cause": cause,
                "actual_model_string": actual_model_string,
                "preflight_alias": preflight_resolved.alias,
                "preflight_model_string": preflight_resolved.model_string,
                "known_aliases": list(self._preflight.known_aliases),
            },
            tenant_id=tenant_id,
            iso_controls=("ISO42001.A.9.2",),
        )
        return constructed, event

    async def _strict_ledger_write_or_raise(
        self,
        *,
        request_id: str,
        tenant_id: str | None,
        tier: str,
        litellm_alias: str,
        resolved: ResolvedUpstream,
        flow_start: float,
        outcome: str,
        original_exc: Exception | None,
    ) -> None:
        """Strict-regime ledger write per Round-1 reviewer-P1#1 +
        Round-6 reviewer-P1.

        Persists the full provenance state (api_base + provenance) so
        ``/system/effective-routing`` can authoritatively classify
        historical rows without re-resolving the current YAML.
        """
        try:
            await self._ledger.write_row(
                GatewayCallRow(
                    id=_uuid.uuid4(),
                    ts=_dt.datetime.now(_dt.UTC),
                    request_id=request_id,
                    tenant_id=tenant_id,
                    tier=tier,  # type: ignore[arg-type]
                    litellm_alias=litellm_alias,
                    upstream_model=resolved.model_string,
                    upstream_api_base=resolved.api_base,
                    external=resolved.external,
                    provenance=resolved.provenance,
                    latency_ms=int((_time.monotonic() - flow_start) * 1000),
                    outcome=outcome,
                    model_id=self._settings.llm_model_id_map.get(litellm_alias),
                )
            )
        except Exception as ledger_exc:
            _LOG.exception(
                "strict ledger write failed; raising LedgerWriteFailed (ADR-007 success contract)"
            )
            raise LedgerWriteFailed(
                f"ledger write failed for request_id={request_id} "
                f"upstream={resolved.model_string}: {ledger_exc}"
            ) from (original_exc or ledger_exc)

    async def _best_effort_ledger_write(
        self,
        *,
        request_id: str,
        tenant_id: str | None,
        tier: str,
        litellm_alias: str,
        preflight: ResolvedUpstream,
        flow_start: float,
        outcome: str,
    ) -> None:
        """Best-effort ledger write for pre-dispatch failure paths.

        Round-6+7 reviewer-P1: persists the *intended* preflight
        identity (alias / model_string / api_base / external) with
        ``provenance="no_dispatch"`` so the operator sees what was
        about to be dispatched. ``/system/effective-routing`` filters
        drift detection to ``provenance != "no_dispatch"`` —
        ``no_dispatch`` rows are operator-side telemetry of pre-
        dispatch denials/trips, not evidence of actual upstream
        contact.
        """
        try:
            await self._ledger.write_row(
                GatewayCallRow(
                    id=_uuid.uuid4(),
                    ts=_dt.datetime.now(_dt.UTC),
                    request_id=request_id,
                    tenant_id=tenant_id,
                    tier=tier,  # type: ignore[arg-type]
                    litellm_alias=litellm_alias,
                    upstream_model=preflight.model_string,
                    upstream_api_base=preflight.api_base,
                    external=preflight.external,
                    provenance="no_dispatch",
                    latency_ms=int((_time.monotonic() - flow_start) * 1000),
                    outcome=outcome,
                    model_id=self._settings.llm_model_id_map.get(litellm_alias),
                )
            )
        except Exception:
            _LOG.exception("best-effort ledger write failed; pre-dispatch path — not chaining")

    async def _emit_completion_trace_best_effort(self, trace: _CompletionTrace) -> None:
        """Best-effort, value-free observability span — one per completion,
        on EVERY exit path. Mirrors ``_best_effort_ledger_write``'s fail-open
        discipline: any failure (adapter raise, serialization error) is
        caught + logged + swallowed so a trace failure NEVER fails the LLM
        call. Observability is not a governance gate — the hash-chained
        ``audit_event`` + the ledger remain the records of truth.

        Value-free by construction: only metadata + token COUNTS enter the
        attribute set — never message / prompt / response content. A reviewer
        can confirm value-freeness by reading the keys below.
        """
        observability = self._observability
        if observability is None:
            return
        try:
            latency_ms = int((_time.monotonic() - trace.flow_start) * 1000)
            attributes: dict[str, object] = {
                "llm.gateway.outcome": trace.outcome,
                "llm.gateway.request_id": trace.request_id,
                "llm.gateway.tier": trace.tier,
                "llm.gateway.latency_ms": latency_ms,
            }
            if trace.tenant_id is not None:
                attributes["llm.gateway.tenant_id"] = trace.tenant_id
            if trace.litellm_alias is not None:
                attributes["llm.gateway.litellm_alias"] = trace.litellm_alias
            if trace.preflight is not None:
                attributes["gen_ai.request.model"] = trace.preflight.model_string
                attributes["llm.gateway.external"] = trace.preflight.external
            if trace.actual is not None:
                attributes["gen_ai.response.model"] = trace.actual.model_string
                attributes["llm.gateway.provenance"] = trace.actual.provenance
            if trace.usage is not None:
                input_tokens = trace.usage.get("prompt_tokens")
                output_tokens = trace.usage.get("completion_tokens")
                if isinstance(input_tokens, int):
                    attributes["gen_ai.usage.input_tokens"] = input_tokens
                if isinstance(output_tokens, int):
                    attributes["gen_ai.usage.output_tokens"] = output_tokens
            if trace.agent_workforce_id is not None:
                attributes["llm.gateway.agent_workforce_id"] = trace.agent_workforce_id
            await observability.emit_trace("llm.gateway.completion", attributes)
        except Exception:
            _LOG.exception("llm.gateway.trace_emit_failed")


__all__ = (
    "GatewayResponse",
    "GatewayTraceOutcome",
    "LLMGateway",
    "LedgerWriteFailed",
    "Tier",
    "UnknownTierError",
    "_guardrails_enabled_for",
    "resolve_tier_alias",
)
