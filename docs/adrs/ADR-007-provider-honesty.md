# ADR-007 — Provider-Honesty Enforcement

## Status
**APPROVED for implementation** on 2026-04-26.

## Context

Cognic AgentOS markets a "Self-Hosted-First" posture and the UI displays a `PROFILE: self-hosted` chip prominently. During cognic monorepo local-smoke testing on 2026-04-25, Langfuse traces revealed the system was in fact routing to `openai/gpt-5.4` despite the chip's claim — the discrepancy went undetected because the chip is a static label decoupled from runtime reality.

The cloud-policy enforcer in `llm/gateway.py` works correctly at the Python layer (it would have refused if invoked with the right alias), but the chip is rendered by the portal UI from `cfg.selfHostedOnly` runtime config — a value with no audited connection to which model the gateway actually called.

This is a governance integrity issue, not a UI bug. A bank operator looking at the UI must be able to trust what the UI says about deployment posture.

## Decision

The portal API exposes `GET /api/v1/system/effective-routing` returning the live routing reality:

```json
{
  "tier1": {"alias": "cognic-tier1-cloud-openai", "upstream": "openai/gpt-5.4", "external": true},
  "tier2": {...},
  "embedding": {"provider": "ollama", "model": "qwen3-embedding:8b"},
  "policy": {"allow_external_llm": true, "mode": "cloud_openai", "allowed_providers": ["cloud_openai"]},
  "recent_calls_24h": {"openai/gpt-5.4": 142, "ollama/qwen3-embedding:8b": 312},
  "last_check": "2026-04-26T05:00:00Z"
}
```

The data source has **two layers** so the endpoint stays honest even when Langfuse is unreachable:

1. **Primary: local gateway call ledger.** `cognic_agentos.llm.gateway.completion()` writes a ledger entry to a Postgres table (`gateway_call_ledger`) on every LLM invocation: timestamp, resolved alias, upstream model identifier (parsed from LiteLLM response `model` field), `external` boolean, latency, outcome, request_id, model_id (per ADR-013). This is the **authoritative source** for `/effective-routing` because it's local, transactional, and never lossy.
2. **Secondary: Langfuse generations.** When reachable, Langfuse adds tracing context (full prompt/response, judge verdicts, cost). Used to enrich the response, not as the primary signal.
3. **Settings:** `get_settings()` provides `policy` (`allow_external_llm`, `mode`, `allowed_providers`).

If Langfuse is down: endpoint serves from the ledger + settings only; `langfuse_available: false` flag set in response so operators see the degraded mode. **The honesty claim never depends on Langfuse availability** — drift detection works as long as the local Postgres adapter is reachable (which is also a `/readyz` critical dependency).

The portal UI's `PROFILE` chip is reclassified by reading from this endpoint:
- `policy.allow_external_llm == false` AND no `external: true` upstream in last 24h → `PROFILE: self-hosted` (green)
- `policy.allow_external_llm == false` BUT `external: true` upstream in last 24h → `PROFILE: self-hosted (DRIFT)` (red, alert)
- `policy.allow_external_llm == true` AND `mode == "self_hosted"` → `PROFILE: self-hosted` (green; cloud is allowed but not used)
- `policy.allow_external_llm == true` AND `mode != "self_hosted"` → `PROFILE: cloud (override)` (yellow, intentional)

A new Tech Console tab "Provider audit" surfaces the full last-24h breakdown so an operator can see exactly which models have been hit.

### Cognic Strategy v5.0 alignment

The Master Strategy v5.0 mandates **"Self-Hosted-First posture"** as one of the six design principles. This ADR enforces that mandate at the runtime layer — claims about posture must be auditable statements, not static labels.

## Consequences

### Positive
- **Posture claims are auditable** — the `PROFILE` chip reflects measured reality
- **Drift detection** — banks see immediately if cloud was inadvertently enabled
- **Examiner story** — auditor can fetch `effective-routing` for any 24h window
- **Bank operator trust** — the chip matches the truth

### Negative
- **Ledger storage growth** — every LLM call writes a row; tenant policy specifies retention (default 90 days, then archive to ObjectStoreAdapter per ADR-009). Periodic compaction job in Sprint 9.5 timeframe.
- **Cache TTL** — endpoint reads recent calls from the ledger; short cache (≤60s) for repeated probes to avoid table-scan pressure.

### Neutral
- This applies regardless of whether banks adopt agent packs from Cognic or write their own — the OS measures actual model invocations through the gateway

## Implementation
- Phase 2: `GET /api/v1/system/effective-routing` endpoint hitting Langfuse + settings
- Phase 2: portal UI chip reads from the endpoint, applies classification rules
- Phase 2: Tech Console "Provider audit" tab
- Phase 3: alert on drift (PROFILE flips from `self-hosted` to `self-hosted (DRIFT)`) — emits a SIEM event

## References
- Cognic Master Strategy v5.0 — Self-Hosted-First principle
- Investigation log 2026-04-25 (cognic monorepo local-smoke) — discovered the gap
- ADR-006 (ISO 42001) — drift event maps to control A.9.2 (operational logging)
