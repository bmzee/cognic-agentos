# Gateway Observability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Emit one best-effort, value-free `llm.gateway.completion` OTel span per `LLMGateway.completion` call (every exit path) via the existing generic `ObservabilityAdapter.emit_trace`, thread the adapter through `build_runtime`, and add an env-gated live eval-judge proof.

**Architecture:** A dedicated `_CompletionTrace` state object is initialized BEFORE tier resolution and carries a pinned closed-enum `trace_outcome` (distinct from the ledger's `outcome` var). `completion(...)` becomes a thin wrapper — `trace` init + `try/except LedgerWriteFailed/finally` — delegating the existing 370-line body to a renamed `_run_completion(...)`; the `finally` runs a best-effort `_emit_completion_trace_best_effort(trace)` that NEVER fails the LLM call. The span is metadata-only (no prompt/response content). `harness/runtime.py` threads `observability=adapters.observability` (off-gate). The live proof injects a hermetic recording adapter into a real `build_runtime` and exercises the real eval-judge route.

**Tech Stack:** Python 3.12, `uv run` for everything, `pytest` + `respx` (hermetic LiteLLM HTTP), `httpx.ASGITransport` (live proof). The edited critical-control module is `src/cognic_agentos/llm/gateway.py` (CC floor 0.95 line / 0.90 branch, `tools/check_critical_coverage.py:743`) — use `core-controls-engineer` + `/critical-module-mode`.

---

## Source-of-truth references

- Spec: `docs/superpowers/specs/2026-06-06-gateway-observability-design.md` (locked decisions; the §41 dedicated-trace-state [P1] contract; the value-free attribute table; the §68 live-proof contract).
- ADR-007 (provider honesty — the `drift` signal), ADR-009 (`ObservabilityAdapter`), ADR-010 (the eval-judge consumer).
- The seam: `ObservabilityAdapter.emit_trace(self, name: str, attributes: dict[str, Any]) -> None` at `src/cognic_agentos/db/adapters/protocols.py:331` (`@runtime_checkable` Protocol; implemented by LangfuseOtel + Dynatrace).

## The complete exit map (drives Task 2)

`completion()` has these exits. The ambient `outcome` var (set at `gateway.py:273` AFTER tier resolution) uses the LEDGER vocabulary; `trace_outcome` is a DISTINCT vocabulary the span reads:

| # | Exit site (current line) | ambient `outcome` | pinned `trace_outcome` |
|---|---|---|---|
| 1 | `resolve_tier_alias` raises (`:270`, before `:273`) | *(unset)* | `invalid_tier` |
| 2 | `preflight.resolve` raises (`:271`, before `:273`) | *(unset)* | `preflight_failure` |
| 3 | input-guardrail trip → `raise err` (`:307`) | `guardrail_input` | `guardrail_input` |
| 4 | pre-dispatch policy deny → raise (`:335`) | `denied` | `policy_denied` |
| 5 | connect-class httpx → `raise` (`:377`) | `upstream_error` | `upstream_error` |
| 6 | possibly-dispatched httpx → `raise` (`:394`) | `upstream_error` | `upstream_error` |
| 7 | HTTP-status / JSON-decode → `raise` (`:426`) | `upstream_error` | `upstream_error` |
| 8 | post-dispatch policy deny → raise (`:529`) | `denied` | `policy_denied` |
| 9 | output-guardrail trip → raise (`:571`) | `guardrail_output` | `guardrail_output` |
| 10 | success `return` (`:586`) | `ok`/`drift` | `ok` / `drift` |
| 11 | outer `except Exception` → `raise` (`:625`) | *(arg only)* | `upstream_error` |
| 12 | concurrency exhausted → `raise` (`:640`) | `concurrency_exhausted` | `concurrency_exhausted` |
| 13 | **any** `LedgerWriteFailed` propagates from a strict write | *(per-path, already set)* | `strict_ledger_failure` (**override** in the wrapper) |
| — | sentinel (no exit set a value — bug guard) | — | `errored_pre_resolution` |

**Why #13 is an override in the wrapper, not inline:** the success path sets `outcome = "ok"/"drift"` at `:574` BEFORE the strict ledger write at `:576`. If that write raises `LedgerWriteFailed`, the per-path `trace.outcome` is already `"ok"/"drift"` (or `"guardrail_output"`/`"upstream_error"`/`"policy_denied"` on the other strict-write paths). The wrapper's `except LedgerWriteFailed: trace.outcome = "strict_ledger_failure"` overrides it — the call ultimately failed on the provenance write, and that is what the span must report. `LedgerWriteFailed` is raised ONLY by `_strict_ledger_write_or_raise` (`:792`), so this catch is precise.

**Why #1/#2 use localized, type-specific `except`:** `resolve_tier_alias` raises ONLY `UnknownTierError` (`gateway.py:95`); `preflight.resolve` raises `UnknownAliasError` (`preflight.py:311`) OR a plain `ValueError` (unset `${VAR}`). Each is wrapped in a localized try/except around the SINGLE offending statement, catching the exact types (`except UnknownTierError` / `except (UnknownAliasError, ValueError)`) and re-raising. Type-specific + single-statement scope (NOT a broad outer `except Exception`) means an UNEXPECTED resolver bug is NOT mislabeled as `invalid_tier`/`preflight_failure` — it falls through to the `errored_pre_resolution` sentinel (an honest "unknown" in telemetry) and still propagates to the caller unchanged. A broad outer `except ValueError`/`except KeyError` is rejected for the opposite reason: it would also catch deep-body failures and mislabel them.

---

### Task 1: gateway.py scaffolding — enum + trace state + constructor seam + emit helper (NO completion wiring yet)

This task is purely additive: the closed enum, the `_CompletionTrace` dataclass, the `observability` constructor param, and the best-effort emit helper. `completion()` is UNCHANGED in this task. The helper is unit-tested in isolation (so its branches are covered at this commit and the CC floor holds before Task 2 wires it).

**Files:**
- Modify: `src/cognic_agentos/llm/gateway.py` (imports `:22-52`; new module-level enum + dataclass after `:56`; `__init__` `:218-258`; new helper after `_best_effort_ledger_write` `:839`; `__all__` `:841-849`)
- Test (create): `tests/unit/llm/test_gateway_observability.py`

- [ ] **Step 1: Write the failing tests for the enum + constructor + helper**

Create `tests/unit/llm/test_gateway_observability.py`. Reuse the gateway conftest fixtures (`settings_for_gateway`, `gateway_ledger`, `audit_store`, `rate_limiter`, `dev_resolver`, `default_sla_policy`) exactly as `tests/unit/llm/test_gateway_completion.py` does.

```python
"""Gateway-observability workstream — value-free OTel span (ADR-009).

Critical-controls posture (gateway.py is on the CC coverage gate):
- Task 1 unit-tests the emit helper in ISOLATION (every attribute branch +
  the None-observability early return + the fail-open path), so the helper
  is fully covered at this commit before Task 2 wires it into completion().
"""

from __future__ import annotations

import logging
import typing

import pytest

from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.config import Settings
from cognic_agentos.core.sla import SLAPolicy
from cognic_agentos.db.adapters.protocols import AdapterHealth
from cognic_agentos.llm.concurrency import ProfileRateLimiter
from cognic_agentos.llm.gateway import (
    GatewayTraceOutcome,
    LLMGateway,
    _CompletionTrace,
)
from cognic_agentos.llm.ledger import GatewayCallLedger
from cognic_agentos.llm.preflight import PreflightResolver, ResolvedUpstream


class _RecordingObservability:
    """Hermetic in-process ObservabilityAdapter test double — structurally
    conforms to the @runtime_checkable Protocol; only emit_trace is exercised."""

    def __init__(self, *, raise_on_emit: bool = False) -> None:
        self.captured: list[tuple[str, dict[str, object]]] = []
        self._raise = raise_on_emit

    async def emit_trace(self, name: str, attributes: dict[str, object]) -> None:
        if self._raise:
            raise RuntimeError("boom: emit_trace failed")
        self.captured.append((name, attributes))

    async def emit_metric(self, name: str, value: float, attributes: dict[str, object]) -> None: ...
    async def flush(self) -> None: ...
    async def health_check(self) -> AdapterHealth:
        # MUST return AdapterHealth (not object) — the double is assigned to an
        # ``ObservabilityAdapter``-typed slot, so mypy checks Protocol conformance
        # and a wider return type (object) fails. Never called in unit tests.
        return AdapterHealth(status="ok", driver="recording", latency_ms=0.0)


def _build_gateway(
    *,
    settings: Settings,
    ledger: GatewayCallLedger,
    audit_store: AuditStore,
    rate_limiter: ProfileRateLimiter,
    preflight: PreflightResolver,
    sla_policy: SLAPolicy,
    observability: _RecordingObservability | None = None,
) -> LLMGateway:
    return LLMGateway(
        settings=settings,
        ledger=ledger,
        audit_store=audit_store,
        rate_limiter=rate_limiter,
        preflight=preflight,
        sla_policy=sla_policy,
        observability=observability,
    )


def _trace(**overrides: object) -> _CompletionTrace:
    base: dict[str, object] = {
        "request_id": "req-1",
        "tenant_id": "tenant-a",
        "tier": "tier1",
        "flow_start": 0.0,
        "agent_workforce_id": None,
    }
    base.update(overrides)
    return _CompletionTrace(**base)  # type: ignore[arg-type]


def _preflight_upstream() -> ResolvedUpstream:
    return ResolvedUpstream(
        alias="cognic-tier1-dev",
        model_string="ollama/qwen3:8b",
        api_base="http://ollama:11434",
        external=False,
        provenance="resolved",
    )


class TestTraceOutcomeVocabularyClosed:
    def test_trace_outcome_has_exactly_eleven_values(self) -> None:
        assert len(typing.get_args(GatewayTraceOutcome)) == 11

    def test_trace_outcome_value_set_is_pinned(self) -> None:
        assert set(typing.get_args(GatewayTraceOutcome)) == {
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
        }


class TestConstructorSeam:
    def test_observability_defaults_to_none(
        self, settings_for_gateway, gateway_ledger, audit_store, rate_limiter,
        dev_resolver, default_sla_policy,
    ) -> None:
        gw = _build_gateway(
            settings=settings_for_gateway, ledger=gateway_ledger, audit_store=audit_store,
            rate_limiter=rate_limiter, preflight=dev_resolver, sla_policy=default_sla_policy,
        )
        assert gw._observability is None

    def test_observability_is_held_when_injected(
        self, settings_for_gateway, gateway_ledger, audit_store, rate_limiter,
        dev_resolver, default_sla_policy,
    ) -> None:
        rec = _RecordingObservability()
        gw = _build_gateway(
            settings=settings_for_gateway, ledger=gateway_ledger, audit_store=audit_store,
            rate_limiter=rate_limiter, preflight=dev_resolver, sla_policy=default_sla_policy,
            observability=rec,
        )
        assert gw._observability is rec


class TestEmitHelperValueFree:
    async def test_full_trace_emits_one_value_free_span(
        self, settings_for_gateway, gateway_ledger, audit_store, rate_limiter,
        dev_resolver, default_sla_policy,
    ) -> None:
        rec = _RecordingObservability()
        gw = _build_gateway(
            settings=settings_for_gateway, ledger=gateway_ledger, audit_store=audit_store,
            rate_limiter=rate_limiter, preflight=dev_resolver, sla_policy=default_sla_policy,
            observability=rec,
        )
        pf = _preflight_upstream()
        tr = _trace(
            outcome="ok", litellm_alias="cognic-tier1-dev", preflight=pf, actual=pf,
            usage={"prompt_tokens": 12, "completion_tokens": 7},
            agent_workforce_id="wf-9",
        )
        await gw._emit_completion_trace_best_effort(tr)

        assert len(rec.captured) == 1
        name, attrs = rec.captured[0]
        assert name == "llm.gateway.completion"
        assert attrs["llm.gateway.outcome"] == "ok"
        assert attrs["llm.gateway.request_id"] == "req-1"
        assert attrs["llm.gateway.tenant_id"] == "tenant-a"
        assert attrs["llm.gateway.tier"] == "tier1"
        assert attrs["llm.gateway.litellm_alias"] == "cognic-tier1-dev"
        assert attrs["gen_ai.request.model"] == "ollama/qwen3:8b"
        assert attrs["gen_ai.response.model"] == "ollama/qwen3:8b"
        assert attrs["llm.gateway.external"] is False
        assert attrs["llm.gateway.provenance"] == "resolved"
        assert attrs["gen_ai.usage.input_tokens"] == 12
        assert attrs["gen_ai.usage.output_tokens"] == 7
        assert attrs["llm.gateway.agent_workforce_id"] == "wf-9"
        assert "llm.gateway.latency_ms" in attrs
        # VALUE-FREE: no message / prompt / response content anywhere.
        blob = repr(attrs).lower()
        assert "content" not in blob and "message" not in blob and "hello" not in blob

    async def test_minimal_trace_omits_optional_attributes(
        self, settings_for_gateway, gateway_ledger, audit_store, rate_limiter,
        dev_resolver, default_sla_policy,
    ) -> None:
        rec = _RecordingObservability()
        gw = _build_gateway(
            settings=settings_for_gateway, ledger=gateway_ledger, audit_store=audit_store,
            rate_limiter=rate_limiter, preflight=dev_resolver, sla_policy=default_sla_policy,
            observability=rec,
        )
        # Pre-resolution failure shape: no alias, no preflight, no actual, no usage,
        # no workforce id, tenant None.
        tr = _trace(outcome="invalid_tier", tenant_id=None)
        await gw._emit_completion_trace_best_effort(tr)

        _, attrs = rec.captured[0]
        assert attrs["llm.gateway.outcome"] == "invalid_tier"
        for absent in (
            "llm.gateway.tenant_id", "llm.gateway.litellm_alias", "gen_ai.request.model",
            "llm.gateway.external", "gen_ai.response.model", "llm.gateway.provenance",
            "gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens",
            "llm.gateway.agent_workforce_id",
        ):
            assert absent not in attrs

    async def test_usage_without_int_tokens_omits_token_attrs(
        self, settings_for_gateway, gateway_ledger, audit_store, rate_limiter,
        dev_resolver, default_sla_policy,
    ) -> None:
        rec = _RecordingObservability()
        gw = _build_gateway(
            settings=settings_for_gateway, ledger=gateway_ledger, audit_store=audit_store,
            rate_limiter=rate_limiter, preflight=dev_resolver, sla_policy=default_sla_policy,
            observability=rec,
        )
        tr = _trace(outcome="ok", usage={"note": "no counts here"})
        await gw._emit_completion_trace_best_effort(tr)
        _, attrs = rec.captured[0]
        assert "gen_ai.usage.input_tokens" not in attrs
        assert "gen_ai.usage.output_tokens" not in attrs

    async def test_none_observability_is_a_noop(
        self, settings_for_gateway, gateway_ledger, audit_store, rate_limiter,
        dev_resolver, default_sla_policy,
    ) -> None:
        gw = _build_gateway(
            settings=settings_for_gateway, ledger=gateway_ledger, audit_store=audit_store,
            rate_limiter=rate_limiter, preflight=dev_resolver, sla_policy=default_sla_policy,
            observability=None,
        )
        # Must not raise.
        await gw._emit_completion_trace_best_effort(_trace(outcome="ok"))

    async def test_emit_failure_is_swallowed_and_logged(
        self, settings_for_gateway, gateway_ledger, audit_store, rate_limiter,
        dev_resolver, default_sla_policy, caplog,
    ) -> None:
        rec = _RecordingObservability(raise_on_emit=True)
        gw = _build_gateway(
            settings=settings_for_gateway, ledger=gateway_ledger, audit_store=audit_store,
            rate_limiter=rate_limiter, preflight=dev_resolver, sla_policy=default_sla_policy,
            observability=rec,
        )
        with caplog.at_level(logging.ERROR, logger="cognic_agentos.llm.gateway"):
            await gw._emit_completion_trace_best_effort(_trace(outcome="ok"))  # must NOT raise
        assert any("llm.gateway.trace_emit_failed" in r.message for r in caplog.records)
```

- [ ] **Step 2: Run the tests — verify they fail (symbols not defined)**

Run: `uv run pytest tests/unit/llm/test_gateway_observability.py -x -q`
Expected: FAIL — `ImportError: cannot import name 'GatewayTraceOutcome'` (and `_CompletionTrace`).

- [ ] **Step 3: Add the TYPE_CHECKING import + the closed enum + the trace dataclass**

In `src/cognic_agentos/llm/gateway.py`, change the typing import (`:30`) and add the Protocol import under `TYPE_CHECKING` (gateway.py already has `from __future__ import annotations` at `:22`, so the annotation is a string — NO runtime import, NO layering cycle):

```python
from typing import TYPE_CHECKING, Literal
```

Add immediately after the `import httpx as _httpx` block (after `:32`):

```python
if TYPE_CHECKING:
    from cognic_agentos.db.adapters.protocols import ObservabilityAdapter
```

Add after the `Tier` literal (after `:56`):

```python
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
```

Add the dataclass after `GatewayResponse` (after `:178`):

```python
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
```

- [ ] **Step 4: Add the constructor seam**

In `__init__`, add the param after `litellm_master_key` (`:230`):

```python
        litellm_master_key: str | None = None,
        observability: ObservabilityAdapter | None = None,
    ) -> None:
```

And store it (after the `self._litellm_master_key` assignment ends at `:258`):

```python
        self._observability: ObservabilityAdapter | None = observability
```

- [ ] **Step 5: Add the emit helper**

Add after `_best_effort_ledger_write` (after `:838`, before `__all__`):

```python
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
```

- [ ] **Step 6: Add `GatewayTraceOutcome` to `__all__`**

In `__all__` (`:841-849`), add `"GatewayTraceOutcome",` (keep alphabetical-ish; `_CompletionTrace` stays private — NOT in `__all__`):

```python
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
```

- [ ] **Step 7: Run the tests — verify they pass**

Run: `uv run pytest tests/unit/llm/test_gateway_observability.py -q`
Expected: PASS (all of Task 1's tests).

- [ ] **Step 8: Run the gate ladder for the touched scope**

```bash
uv run mypy src tests
uv run ruff check .
uv run ruff format --check .
uv run pytest tests/unit/llm/ -q
```
Expected: clean. (If ruff flags `BLE001` on the helper's `except Exception`, note the existing `_best_effort_ledger_write` at `:837` uses the same bare `except Exception` with no `noqa` — the project config permits it; match that style.)

- [ ] **Step 9: HALT for review + commit token**

Produce the halt summary (files modified, gate-ladder results, the CC-floor note that Task 1 is additive and the helper is covered in isolation). Do NOT commit without the explicit token. On token: run the full suite, stage EXACTLY `src/cognic_agentos/llm/gateway.py` + `tests/unit/llm/test_gateway_observability.py` by explicit path, commit.

```bash
uv run pytest -q   # full suite at the CC-module commit
git add src/cognic_agentos/llm/gateway.py tests/unit/llm/test_gateway_observability.py
git commit -m "feat(gateway-observability): trace-outcome enum + _CompletionTrace + observability seam + emit helper"
```

---

### Task 2: Wire the span into `completion()` — thin wrapper + `_run_completion` + per-exit `trace.outcome`

Refactor `completion()` into a thin trace-wrapper delegating to `_run_completion` (the existing body, renamed), set `trace.outcome` / `.preflight` / `.actual` / `.usage` at each exit, and add the `LedgerWriteFailed` override. The ledger `outcome` var is UNCHANGED. This is the behavioral heart; the full per-path span matrix lives here.

**Files:**
- Modify: `src/cognic_agentos/llm/gateway.py` (`completion` `:260-640` → wrapper + `_run_completion`)
- Test (extend): `tests/unit/llm/test_gateway_observability.py`

- [ ] **Step 1: Write the failing per-path span matrix**

Append to `tests/unit/llm/test_gateway_observability.py`. These mirror the respx + fixture patterns in `tests/unit/llm/test_gateway_completion.py`, `test_gateway_drift.py`, `test_gateway_httpx_dispatch_errors.py`, `test_gateway_guardrails.py`, `test_gateway_concurrency_ledger.py`, and `test_gateway_post_dispatch_strict_discipline.py`. Use the `_RecordingObservability` from Task 1; build the gateway with `observability=rec`; after each call assert exactly one captured span and its `llm.gateway.outcome`.

```python
import httpx
import respx

from cognic_agentos.llm.policy import CloudPolicyViolationError, GuardrailViolationError


def _ok_litellm_response(model: str = "ollama/qwen3:8b", *, usage: dict | None = None) -> httpx.Response:
    body: dict = {
        "id": "resp-test",
        "object": "chat.completion",
        "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "hello"},
                     "finish_reason": "stop"}],
    }
    if usage is not None:
        body["usage"] = usage
    return httpx.Response(200, json=body)


def _only_span(rec: _RecordingObservability) -> dict[str, object]:
    assert len(rec.captured) == 1, f"expected exactly one span, got {len(rec.captured)}"
    name, attrs = rec.captured[0]
    assert name == "llm.gateway.completion"
    return attrs


class TestCompletionSpanPerPath:
    @respx.mock
    async def test_success_emits_ok_span_with_usage(
        self, settings_for_gateway, gateway_ledger, audit_store, rate_limiter,
        dev_resolver, default_sla_policy,
    ) -> None:
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_ok_litellm_response("ollama/qwen3:8b",
                                              usage={"prompt_tokens": 5, "completion_tokens": 9})
        )
        rec = _RecordingObservability()
        gw = _build_gateway(
            settings=settings_for_gateway, ledger=gateway_ledger, audit_store=audit_store,
            rate_limiter=rate_limiter, preflight=dev_resolver, sla_policy=default_sla_policy,
            observability=rec,
        )
        await gw.completion(tier="tier1", messages=[{"role": "user", "content": "hi"}],
                            request_id="req-ok", tenant_id="tenant-a")
        attrs = _only_span(rec)
        assert attrs["llm.gateway.outcome"] == "ok"
        assert attrs["gen_ai.request.model"] == "ollama/qwen3:8b"
        assert attrs["gen_ai.response.model"] == "ollama/qwen3:8b"
        assert attrs["gen_ai.usage.input_tokens"] == 5
        assert attrs["gen_ai.usage.output_tokens"] == 9
        assert attrs["llm.gateway.provenance"] == "resolved"
```

Add one test per remaining `trace_outcome`, each asserting `_only_span(rec)["llm.gateway.outcome"]`:

- `test_drift_emits_drift_span` — mock the LiteLLM response with a DIFFERENT `model` than preflight (mirror `test_gateway_drift.py`); assert `"drift"`. Assert `gen_ai.response.model` != `gen_ai.request.model`.
- `test_invalid_tier_emits_invalid_tier_span` — call `completion(tier="tier99", ...)`; `pytest.raises(...)` (UnknownTierError); assert `"invalid_tier"` and that `gen_ai.request.model` is absent (no preflight).
- `test_preflight_failure_emits_preflight_failure_span` — use a resolver whose alias is unresolvable / unset-env-var (mirror however `test_gateway_*` triggers a preflight raise; e.g. a `PreflightResolver` built from YAML referencing an unset `${VAR}` so `resolve()` raises `ValueError`); `pytest.raises`; assert `"preflight_failure"`.
- `test_input_guardrail_trip_emits_guardrail_input_span` — inject an `input_pipeline` that trips (mirror `test_gateway_guardrails.py`); `pytest.raises(GuardrailViolationError)`; assert `"guardrail_input"`; assert `gen_ai.response.model` absent (no dispatch).
- `test_pre_dispatch_policy_deny_emits_policy_denied_span` — cloud resolver + default deny settings (mirror `test_gateway_completion.py::TestPreDispatchDenialPath`); `pytest.raises(CloudPolicyViolationError)`; assert `"policy_denied"`.
- `test_post_dispatch_policy_deny_emits_policy_denied_span` — allow pre-dispatch, but make the ACTUAL model trip the post-response recheck (mirror `test_gateway_policy.py`'s post-dispatch deny); assert `"policy_denied"`; assert `gen_ai.response.model` present (dispatched).
- `test_concurrency_exhausted_emits_concurrency_span` — `ProfileRateLimiter` in fail_fast at capacity (mirror `test_gateway_concurrency_ledger.py`); `pytest.raises`; assert `"concurrency_exhausted"`.
- `test_connect_error_emits_upstream_error_span` — `respx....mock(side_effect=httpx.ConnectError("x"))`; `pytest.raises(httpx.ConnectError)`; assert `"upstream_error"`.
- `test_possibly_dispatched_error_emits_upstream_error_span` — `side_effect=httpx.ReadTimeout("x")` (mirror `test_gateway_httpx_dispatch_errors.py`); `pytest.raises`; assert `"upstream_error"`.
- `test_http_status_error_emits_upstream_error_span` — mock a 500 response; `pytest.raises(httpx.HTTPStatusError)`; assert `"upstream_error"`.
- `test_output_guardrail_trip_emits_guardrail_output_span` — inject an `output_pipeline` that trips on the response (mirror `test_gateway_guardrails.py`); `pytest.raises(GuardrailViolationError)`; assert `"guardrail_output"`.
- `test_strict_ledger_failure_overrides_to_strict_ledger_failure_span` — happy-path response, but make the ledger write raise on the SUCCESS path. Mirror however `test_gateway_ledger*.py` injects a failing ledger (e.g. a ledger double whose `write_row` raises). `pytest.raises(LedgerWriteFailed)`; assert `"strict_ledger_failure"` (NOT `"ok"`). This is the override pin — load-bearing.

Plus the end-to-end agent-id + fail-open tests:

```python
class TestCompletionSpanEndToEnd:
    @respx.mock
    async def test_agent_workforce_id_threads_to_span(
        self, settings_for_gateway, gateway_ledger, audit_store, rate_limiter,
        dev_resolver, default_sla_policy,
    ) -> None:
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_ok_litellm_response())
        rec = _RecordingObservability()
        gw = _build_gateway(
            settings=settings_for_gateway, ledger=gateway_ledger, audit_store=audit_store,
            rate_limiter=rate_limiter, preflight=dev_resolver, sla_policy=default_sla_policy,
            observability=rec,
        )
        await gw.completion(tier="tier1", messages=[{"role": "user", "content": "hi"}],
                            request_id="req-wf", agent_workforce_id="wf-42")
        assert _only_span(rec)["llm.gateway.agent_workforce_id"] == "wf-42"

    @respx.mock
    async def test_omitted_agent_workforce_id_absent_from_span(
        self, settings_for_gateway, gateway_ledger, audit_store, rate_limiter,
        dev_resolver, default_sla_policy,
    ) -> None:
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_ok_litellm_response())
        rec = _RecordingObservability()
        gw = _build_gateway(
            settings=settings_for_gateway, ledger=gateway_ledger, audit_store=audit_store,
            rate_limiter=rate_limiter, preflight=dev_resolver, sla_policy=default_sla_policy,
            observability=rec,
        )
        await gw.completion(tier="tier1", messages=[{"role": "user", "content": "hi"}],
                            request_id="req-no-wf")
        assert "llm.gateway.agent_workforce_id" not in _only_span(rec)

    @respx.mock
    async def test_emit_failure_does_not_fail_the_call(
        self, settings_for_gateway, gateway_ledger, audit_store, rate_limiter,
        dev_resolver, default_sla_policy,
    ) -> None:
        """Fail-open through completion(): the span adapter raises, but the
        LLM call still returns its GatewayResponse."""
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_ok_litellm_response())
        rec = _RecordingObservability(raise_on_emit=True)
        gw = _build_gateway(
            settings=settings_for_gateway, ledger=gateway_ledger, audit_store=audit_store,
            rate_limiter=rate_limiter, preflight=dev_resolver, sla_policy=default_sla_policy,
            observability=rec,
        )
        resp = await gw.completion(tier="tier1", messages=[{"role": "user", "content": "hi"}],
                                   request_id="req-failopen")
        assert resp.content == "hello"  # call succeeded despite the trace failure
```

- [ ] **Step 2: Run the matrix — verify it fails (no span emitted yet)**

Run: `uv run pytest tests/unit/llm/test_gateway_observability.py::TestCompletionSpanPerPath -x -q`
Expected: FAIL — `len(rec.captured) == 0` (completion does not emit yet).

- [ ] **Step 3: Refactor `completion` into the wrapper + `_run_completion`**

In `src/cognic_agentos/llm/gateway.py`:

(0) Add `UnknownAliasError` to the existing preflight import (`:49-52`) — `_run_completion` narrows the preflight catch to it (`UnknownAliasError` is exported from preflight, `__all__` at `preflight.py:358-362`):

```python
from cognic_agentos.llm.preflight import (
    PreflightResolver,
    ResolvedUpstream,
    UnknownAliasError,
)
```

(a) Add the NEW thin wrapper as `completion` (replacing the current `:260-267` signature + opening). The body that currently runs (`:269-640`) MOVES into `_run_completion` (see (b)); do NOT re-indent it — it relocates at the same method-body level.

```python
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
```

(b) Rename the existing method body to `_run_completion` and replace its old preamble (`:269-274`) with the trace-aware preamble (the localized pre-resolution catches + the alias rebinds). The OLD `flow_start = _time.monotonic()` at `:269` is REMOVED (the wrapper owns `flow_start` now, on `trace`):

```python
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
        # ... the EXISTING body continues UNCHANGED from the current line 276
        #     ("--- 1. INPUT guardrails ...") through the end, EXCEPT for the
        #     small inline trace.* insertions listed in Step 4 below.
```

- [ ] **Step 4: Add the inline `trace.*` assignments at each exit (precise anchors)**

In `_run_completion`'s relocated body, make these EXACT insertions. Each is one line added immediately AFTER its anchor (the anchor lines are the existing ledger-`outcome` assignments / bind points):

| Anchor (existing line, unchanged) | Insert immediately after |
|---|---|
| `outcome = "guardrail_input"` (was `:295`) | `trace.outcome = "guardrail_input"` |
| `outcome = "denied"` (pre-dispatch, was `:316`) | `trace.outcome = "policy_denied"` |
| `outcome = "upstream_error"` (connect-class, was `:367`) | `trace.outcome = "upstream_error"` |
| `outcome = "upstream_error"` (possibly-dispatched, was `:383`) | `trace.outcome = "upstream_error"` |
| `outcome = "upstream_error"` (HTTP-status/JSON, was `:415`) | `trace.outcome = "upstream_error"` |
| the `if pending_audit is not None:` line (was `:449`) | *(insert the line BEFORE it)* `trace.actual = actual_resolved` |
| `outcome = "denied"` (post-dispatch, was `:508`) | `trace.outcome = "policy_denied"` |
| `outcome = "guardrail_output"` (was `:558`) | `trace.outcome = "guardrail_output"` |
| `outcome = "drift" if drift else "ok"` (success, was `:574`) | `trace.usage = body.get("usage") if isinstance(body.get("usage"), dict) else None` then `trace.outcome = "drift" if drift else "ok"` |
| `outcome="upstream_error",` arg in the outer `except Exception` block — add a statement at the TOP of that block (was `:611`, first line after `except Exception as exc:`) | `trace.outcome = "upstream_error"` |
| `outcome = "concurrency_exhausted"` (was `:630`) | `trace.outcome = "concurrency_exhausted"` |

Notes:
- `trace.actual = actual_resolved` goes BEFORE the `await self._audit.append(pending_audit)` so even an AuditStore failure (→ outer `except Exception` → `upstream_error`) still carries the actual provenance on the span.
- On the success path, set `trace.usage` from `body` (in scope) BEFORE the strict ledger write so a subsequent `LedgerWriteFailed` (→ wrapper override) still emits the usage it had.
- Do NOT touch the ledger `outcome` var anywhere — it feeds `_strict_ledger_write_or_raise` / `_best_effort_ledger_write` and the ledger row vocabulary is a separate contract.

- [ ] **Step 5: Run the full matrix — verify it passes**

Run: `uv run pytest tests/unit/llm/test_gateway_observability.py -q`
Expected: PASS (all per-path + end-to-end span tests).

- [ ] **Step 6: Run the existing gateway suite — verify NO regression**

Run: `uv run pytest tests/unit/llm/ -q`
Expected: PASS — the refactor preserves all existing completion behavior (the ledger `outcome`, audit events, exceptions, and `GatewayResponse` are unchanged). The existing `test_gateway_completion.py` etc. construct the gateway WITHOUT `observability` (defaults `None`) → the emit helper is a no-op → no behavior change.

- [ ] **Step 7: Verify the CC coverage floor on FRESH data**

```bash
uv run pytest --cov=cognic_agentos --cov-branch --cov-report=json -q
uv run python tools/check_critical_coverage.py
```
Expected: the FULL suite green + the gate green. **The coverage run MUST be full-package (`--cov=cognic_agentos`), NOT gateway-only** — `check_critical_coverage.py` validates ALL 113 critical files and FAILS any critical file MISSING from `coverage.json` (tool `:2105`), so a gateway-only `coverage.json` would red the other 112 files. Confirm `src/cognic_agentos/llm/gateway.py` ≥ 0.95 line / 0.90 branch in the gate output. (Per `feedback_verify_promotion_meets_floor_at_promotion_time` — this is an on-gate CC module; verify the floor against fresh full-package coverage in this task, not just the existing ≈99% claim.) If any new gateway line/branch is uncovered, add the focused negative-path test in THIS commit. **This `--cov=cognic_agentos` run IS the full-suite execution for the Step 8 commit.**

- [ ] **Step 8: Full gate ladder + HALT for review + commit token**

```bash
uv run mypy src tests
uv run ruff check .
uv run ruff format --check .
```
HALT: produce the halt summary mapping each `trace_outcome` to its pinning test + the `strict_ledger_failure` override pin + the fail-open pin + the CC-floor-on-fresh-data result. Do NOT commit without the token. On token: Step 7's `--cov=cognic_agentos` run already executed the FULL suite green — re-run `uv run pytest -q` ONLY if the mypy/ruff pass above required a code change; then:

```bash
git add src/cognic_agentos/llm/gateway.py tests/unit/llm/test_gateway_observability.py
git commit -m "feat(gateway-observability): emit value-free span on every completion exit via finally + dedicated trace-state"
```

---

### Task 3: Thread `observability` through `build_runtime` (harness — OFF-gate)

`harness/runtime.py` is the composition root — OFF the CC gate (Doctrine F; verified absent from `_CRITICAL_FILES`). One-line kwarg + a white-box test mirroring the existing `_litellm_master_key` assertion.

**Files:**
- Modify: `src/cognic_agentos/harness/runtime.py:174-183` (the `LLMGateway(...)` construction)
- Test (extend): `tests/unit/harness/test_runtime.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/harness/test_runtime.py` (reuse the `_litellm_yaml` helper + `memory_registry`/`memory_settings` fixtures already in that file):

```python
async def test_build_runtime_threads_observability_into_gateway(
    memory_registry, memory_settings, tmp_path
):
    """build_runtime threads adapters.observability into the gateway (the
    gateway-observability seam). White-box on the private attr — mirrors the
    _litellm_master_key assertion: proves the wiring, not just 'no raise'."""
    s = memory_settings.model_copy(
        update={"litellm_config_path": _litellm_yaml(tmp_path), "cache_driver": "none"}
    )
    adapters = build_adapters(s, registry=memory_registry)
    await adapters.open_all()
    try:
        runtime = await build_runtime(s, adapters)
        assert runtime.llm_gateway._observability is adapters.observability
        await runtime.aclose()
    finally:
        await adapters.close_all()
```

- [ ] **Step 2: Run it — verify it fails**

Run: `uv run pytest tests/unit/harness/test_runtime.py::test_build_runtime_threads_observability_into_gateway -x -q`
Expected: FAIL — `runtime.llm_gateway._observability is None` (the gateway ctor defaults `observability=None`; build_runtime does not pass it yet).

- [ ] **Step 3: Add the kwarg**

In `src/cognic_agentos/harness/runtime.py`, in the `LLMGateway(...)` construction (`:174-183`), add the kwarg (after `litellm_master_key=litellm_key,` at `:182`):

```python
        http_client=http_client,
        litellm_master_key=litellm_key,
        observability=adapters.observability,
    )
```

- [ ] **Step 4: Run it — verify it passes**

Run: `uv run pytest tests/unit/harness/test_runtime.py -q`
Expected: PASS (the new test + the existing runtime tests).

- [ ] **Step 5: Gate ladder + HALT + commit token**

```bash
uv run mypy src tests
uv run ruff check .
uv run ruff format --check .
```
HALT. On token — this touches the composition root (a shared surface), so run the FULL suite at commit:

```bash
uv run pytest -q
git add src/cognic_agentos/harness/runtime.py tests/unit/harness/test_runtime.py
git commit -m "feat(gateway-observability): thread adapters.observability into the gateway in build_runtime"
```

---

### Task 4: Env-gated live eval-judge proof

A real-LLM judge call through the real gateway + a hermetic recording `ObservabilityAdapter` wired into a real `build_runtime`, asserting BOTH (a) an `llm.gateway.completion` span emitted through the seam AND (b) the `eval.judge_verdict` chain row. Env-gated; **fails loud** (assert, NOT skip) when opted-in but misconfigured. Default CI never hits a real upstream.

**Files:**
- Test (create): `tests/integration/llm/test_gateway_observability_live.py`
- Reference (read, do not modify): `tests/unit/portal/api/evaluation/test_routes.py:57-124` (the `_StubBinder` / `_actor` / `_build_app` shape to MIRROR + the chain-row assertion), `tests/unit/harness/test_runtime.py:76-115` (the chain-head seeding pattern on `adapters.relational.engine`), `src/cognic_agentos/harness/runtime.py` (`build_runtime`).

- [ ] **Step 1: Write the env-gated live proof**

`Adapters` is `@dataclass(slots=True)` (NOT frozen) — so `adapters.observability` is reassignable. Inject the recording adapter by reassigning it AFTER `build_adapters` and BEFORE `build_runtime`, then inject the constructed gateway into `create_app(llm_gateway=...)` and publish the runtime on `app.state.runtime` so the eval route's runtime-first DH-store resolution finds the store.

```python
"""Live eval-judge proof — real LLM + real gateway + recording observability.

Env-gated on COGNIC_RUN_GATEWAY_OBSERVABILITY_INTEGRATION=1. Per the
integration-test discipline (mirrors the Sprint-10.1 Z2 fail-loud contract):
opted-in but misconfigured (no reachable LiteLLM proxy / model) FAILS LOUD
(AssertionError), NOT skip. NOT opted in -> skip (casual local `uv run pytest`).

What this proves: the real-LLM call + the gateway emitting the
`llm.gateway.completion` span THROUGH the adapter seam + the
`eval.judge_verdict` chain row — end-to-end. It does NOT prove real Langfuse
INGESTION (the recording adapter is in-process); that stays a deferred
operational check.

Env contract (all required when opted in; each asserted fail-loud):
- COGNIC_LITELLM_BASE_URL — a reachable LiteLLM proxy base URL (the gateway
  POSTs ``{base}/chat/completions`` at gateway.py:354).
- COGNIC_LITELLM_MODEL — the model string the proxy serves for the tier1
  alias (written into the litellm YAML below; also drives preflight
  classification — see the policy note in the test).
Optional:
- COGNIC_LITELLM_MASTER_KEY — bearer key for the proxy (None if unsecured).
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy import select

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import (  # noqa: F401  (registers table in _metadata)
    _decision_history,
)
from cognic_agentos.db.adapters.protocols import AdapterHealth
from cognic_agentos.portal.rbac.actor import Actor

_OPTED_IN = os.environ.get("COGNIC_RUN_GATEWAY_OBSERVABILITY_INTEGRATION") == "1"

pytestmark = pytest.mark.skipif(
    not _OPTED_IN,
    reason="set COGNIC_RUN_GATEWAY_OBSERVABILITY_INTEGRATION=1 (+ COGNIC_LITELLM_BASE_URL "
    "+ COGNIC_LITELLM_MODEL pointing at a reachable LiteLLM proxy) to run the live proof",
)


class _RecordingObservability:
    def __init__(self) -> None:
        self.captured: list[tuple[str, dict[str, object]]] = []

    async def emit_trace(self, name: str, attributes: dict[str, object]) -> None:
        self.captured.append((name, attributes))

    async def emit_metric(self, name: str, value: float, attributes: dict[str, object]) -> None: ...
    async def flush(self) -> None: ...
    async def health_check(self) -> AdapterHealth:
        return AdapterHealth(status="ok", driver="recording", latency_ms=0.0)


class _StubBinder:
    """Mirror tests/unit/portal/api/evaluation/test_routes.py::_StubBinder."""

    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: object) -> Actor:
        return self._actor


def _actor() -> Actor:
    return Actor(
        subject="svc",
        tenant_id="t1",
        scopes=frozenset({"eval.judge.run"}),
        actor_type="service",  # type: ignore[arg-type]
    )


async def test_live_eval_judge_emits_gateway_span_and_chain_row(
    memory_settings, memory_registry, tmp_path
) -> None:
    from fastapi import FastAPI

    from cognic_agentos.db.adapters.factory import build_adapters
    from cognic_agentos.harness import build_runtime
    from cognic_agentos.portal.api.evaluation.routes import build_eval_routes

    # --- fail-loud config preconditions (opted in => prove it or fail) ----
    base_url = os.environ.get("COGNIC_LITELLM_BASE_URL")
    model = os.environ.get("COGNIC_LITELLM_MODEL")
    assert base_url, "opted in but COGNIC_LITELLM_BASE_URL unset — fail loud (NOT skip)"
    assert model, "opted in but COGNIC_LITELLM_MODEL unset — fail loud (NOT skip)"

    # Minimal litellm YAML mapping the tier1 alias -> the proxy's model.
    cfg = tmp_path / "litellm.yaml"
    cfg.write_text(
        "model_list:\n"
        "  - model_name: cognic-tier1-dev\n"
        "    litellm_params:\n"
        f"      model: {model}\n"
    )
    # Reuse the proven in-memory DB config (memory_settings: db_driver='memory' etc.),
    # point the LLM at the real proxy. cache_driver='none' keeps the memory branch out
    # (gateway-only path). NOTE: if the proxy model classifies as EXTERNAL (preflight
    # via gateway.py:211 _is_external), the live operator must also set the matching
    # policy env (e.g. allow_external_llm + allowed_providers) so the pre-call cloud-
    # policy gate passes — otherwise the span outcome is "policy_denied", not "ok".
    settings = memory_settings.model_copy(
        update={
            "litellm_config_path": cfg,
            "litellm_base_url": base_url,
            "tier1_alias": "cognic-tier1-dev",
            "litellm_master_key": os.environ.get("COGNIC_LITELLM_MASTER_KEY"),
            "cache_driver": "none",
        }
    )

    adapters = build_adapters(settings, registry=memory_registry)
    recording = _RecordingObservability()
    adapters.observability = recording  # Adapters is @dataclass(slots=True), NOT frozen
    await adapters.open_all()
    try:
        # Seed the chain tables + heads on the pool engine — build_runtime constructs
        # DecisionHistoryStore but does NOT migrate/seed; open_all() only connects.
        # Mirrors test_runtime.py::test_build_runtime_wires_memory_when_cache_present.
        eng = adapters.relational.engine
        async with eng.begin() as conn:
            await conn.run_sync(_metadata.create_all)
            for chain_id in ("audit_event", "decision_history"):
                await conn.execute(
                    _chain_heads.insert().values(
                        chain_id=chain_id,
                        latest_sequence=0,
                        latest_hash=ZERO_HASH,
                        updated_at=datetime.now(UTC),
                    )
                )

        runtime = await build_runtime(settings, adapters)
        assert runtime.llm_gateway._observability is recording  # the seam under test

        # Mirror test_routes.py::_build_app, but with the REAL gateway + runtime.
        app = FastAPI()
        app.state.actor_binder = _StubBinder(_actor())
        app.state.ui_event_broker = None
        app.state.llm_gateway = runtime.llm_gateway
        app.state.decision_history_store = None  # resolved runtime-first from app.state.runtime
        app.state.runtime = runtime
        app.include_router(build_eval_routes(eval_judge_tier="tier1"), prefix="/api/v1/eval")

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            resp = await client.post(
                "/api/v1/eval/judge",
                json={
                    "candidate_output": "2 + 2 = 4",
                    "criteria": [{"name": "correct", "description": "is the arithmetic correct"}],
                },
            )
        assert resp.status_code == 200, resp.text

        # (a) the gateway emitted the span THROUGH the adapter seam.
        spans = [a for n, a in recording.captured if n == "llm.gateway.completion"]
        assert len(spans) == 1
        assert spans[0]["llm.gateway.outcome"] in {"ok", "drift"}
        assert "content" not in repr(spans[0]).lower()  # value-free even live

        # (b) the eval.judge_verdict chain row was written. The persisted column is
        # `event_type` (DecisionRecord.decision_type maps to it — decision_history.py:195
        # + the docstring at :220-222), NOT `decision_type`.
        async with eng.connect() as conn:
            rows = list(
                (
                    await conn.execute(
                        select(_decision_history).where(
                            _decision_history.c.event_type == "eval.judge_verdict"
                        )
                    )
                ).fetchall()
            )
        assert len(rows) == 1
        await runtime.aclose()
    finally:
        await adapters.close_all()
```

The only deployment-specific inputs are `COGNIC_LITELLM_BASE_URL` + `COGNIC_LITELLM_MODEL` (+ the optional master key + the policy env the inline NOTE calls out) — each asserted fail-loud. Everything else (chain-head seeding, the mirrored `_build_app` shape, the `ASGITransport` POST, both assertions, the `event_type` query) is concrete. The `_StubBinder` / `_actor` / app-state shape are copied verbatim from `tests/unit/portal/api/evaluation/test_routes.py:57-124`.

- [ ] **Step 2: Verify it skips cleanly when NOT opted in**

Run: `uv run pytest tests/integration/llm/test_gateway_observability_live.py -q`
Expected: SKIPPED (1 skipped) — `COGNIC_RUN_GATEWAY_OBSERVABILITY_INTEGRATION` unset.

- [ ] **Step 3: Verify the fail-loud branch when opted-in but misconfigured**

Run: `env -u COGNIC_LITELLM_BASE_URL -u COGNIC_LITELLM_MODEL COGNIC_RUN_GATEWAY_OBSERVABILITY_INTEGRATION=1 uv run pytest tests/integration/llm/test_gateway_observability_live.py -q`
Expected: FAILED (AssertionError on the `COGNIC_LITELLM_BASE_URL` precondition) — NOT skipped. The `env -u` explicitly UNSETS the two LLM vars so the missing-env (fail-loud) branch fires regardless of whether the developer's shell already exports them — without it, a shell that already has `COGNIC_LITELLM_BASE_URL` set would spuriously pass (or attempt a real call). This proves the opted-in-but-misconfigured path fails loud.

- [ ] **Step 4: Gate ladder + HALT + commit token**

```bash
uv run mypy src tests
uv run ruff check .
uv run ruff format --check .
```
HALT (note: the live test is env-gated → the default suite skips it; the fail-loud branch is verified in Step 3). On token:

```bash
git add tests/integration/llm/test_gateway_observability_live.py
git commit -m "test(gateway-observability): env-gated live eval-judge proof (recording adapter + real LLM)"
```

---

### Task 5: CC-gate verification + closeout

**Files:**
- Verify (no edit): `tools/check_critical_coverage.py` (gateway floor), `tests/unit/tools/test_check_critical_coverage.py` (`_EXPECTED_ENTRY_COUNT`)
- Create: `docs/closeouts/2026-06-06-gateway-observability.md`

- [ ] **Step 1: Confirm NO `_CRITICAL_FILES` count change**

This workstream edits the ALREADY-gated `gateway.py` and the OFF-gate `harness/runtime.py` — it adds NO new gated module. Confirm:

```bash
uv run pytest tests/unit/tools/test_check_critical_coverage.py -q
```
Expected: PASS with `_EXPECTED_ENTRY_COUNT` UNCHANGED (113). If this fails, STOP — the count must not change.

- [ ] **Step 2: Full-suite + CC-gate green on fresh coverage**

```bash
uv run pytest --cov=cognic_agentos --cov-branch --cov-report=json -q
uv run python tools/check_critical_coverage.py
```
Expected: full suite green; `check_critical_coverage.py` green incl. `src/cognic_agentos/llm/gateway.py` ≥ 0.95/0.90.

- [ ] **Step 3: Write the closeout**

Create `docs/closeouts/2026-06-06-gateway-observability.md` mirroring `docs/closeouts/2026-06-06-eval-judge-slice.md`. Carry the honest-scope markers from the spec §85-89 VERBATIM in spirit:
- Option A — metadata-only span; no content; first-class Langfuse generation records deferred.
- The gateway→adapter emit is **live-proven against a real LLM** (Task 4) — retiring the eval-judge "no live real-LLM judge call" marker. **Real Langfuse INGESTION** stays a separate, deferred operational check.
- Best-effort: a trace failure never fails an LLM call (bounded in-process overhead, not zero-delay).
- CC: `llm/gateway.py` (on-gate) held its 0.95/0.90 floor on fresh data; `harness/runtime.py` off-gate; `_CRITICAL_FILES` count unchanged at 113.

Cite each claim at `file:line` per `feedback_verify_code_citations_at_doc_write` (Read/grep-back every symbol named).

- [ ] **Step 4: HALT + commit token**

HALT. On token:

```bash
git add docs/closeouts/2026-06-06-gateway-observability.md
git commit -m "docs(gateway-observability): closeout — value-free span on every gateway exit, live-proven seam"
```

Then proceed to `superpowers:finishing-a-development-branch` (push + PR with split tokens).

---

## Self-review

**1. Spec coverage:**
- Spec §17 constructor seam → Task 1 Step 4. §18 `agent_workforce_id` param → Task 2 Step 3 (wrapper signature). §19 one span every exit → Task 2 (the per-path matrix + the `finally`). §20 `build_runtime` thread → Task 3. §21 live proof → Task 4.
- §41 dedicated trace-state (NOT ambient `outcome`) → Task 1 (`_CompletionTrace`, sentinel default) + Task 2 (per-exit `trace.outcome`); the exit map table + the `strict_ledger_failure` override capture the [P1] contract. §41 `drift` distinct from `ok` → exit #10 + `test_drift_emits_drift_span`.
- §43 `finally`-style emit → Task 2 wrapper. §45 fail-open (awaited, never fails) → Task 1 helper (`except Exception` swallow + log) + Task 2 `test_emit_failure_does_not_fail_the_call`. §47-66 value-free attribute table → Task 1 helper (exact keys) + `test_full_trace_emits_one_value_free_span` (value-free assertion). §64 `agent_workforce_id` only-when-present → Task 2 present/absent tests.
- §70-72 live proof (recording adapter + real LLM; seam not ingestion; fail-loud) → Task 4. §74-76 CC discipline (gateway only gated edit; harness off-gate; no count change) → Task 2 Step 7 + Task 5. §78-83 testing → Tasks 1-4. §85-89 honest-scope markers → Task 5 closeout.

**2. Placeholder scan:** Task 4 is now fully specified — chain-head seeding, the mirrored `_build_app` shape, the `ASGITransport` POST, both assertions, and the `event_type` chain query are concrete code; the only deployment-specific inputs (`COGNIC_LITELLM_BASE_URL` / `COGNIC_LITELLM_MODEL` / the optional master key / the policy env the inline NOTE calls out) are env-driven with fail-loud asserts — correct for an env-gated integration test (the deployment endpoint cannot be hardcoded). The Task 2 body relocation is specified as a precise anchor table (Step 4) rather than a 370-line reproduction — every insertion has an exact anchor. No TBD/TODO/"handle edge cases"/placeholder-comment-as-code anywhere.

**3. Type consistency:** `GatewayTraceOutcome` (11 values) is defined in Task 1 and consumed in Task 2 + the drift-pin test — same name throughout. `_CompletionTrace` fields (`request_id`/`tenant_id`/`tier`/`flow_start`/`agent_workforce_id`/`outcome`/`litellm_alias`/`preflight`/`actual`/`usage`) match between the dataclass (Task 1 Step 3), the helper (Task 1 Step 5), the wrapper (Task 2 Step 3), and the inline insertions (Task 2 Step 4). `_emit_completion_trace_best_effort` / `_run_completion` names are consistent across tasks. `observability` kwarg name matches between the gateway ctor (Task 1) and `build_runtime` (Task 3). The recording double's `emit_trace(name, attributes)` matches the Protocol at `protocols.py:331`.
