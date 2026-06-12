# Cognic AgentOS Sprint Working Summary

Source: `docs/BUILD_PLAN.md` · Status source: [`docs/AS_BUILT_CAPABILITY_MAP.md`](AS_BUILT_CAPABILITY_MAP.md)

This is the compact RESPONSIBILITY index — what each sprint owns, not what is done. For execution status, read the per-sprint status/reconciliation blocks in `docs/BUILD_PLAN.md` and the as-built capability map. Phases 1-4 deliver the bank-deployable AgentOS platform; Phase 5 (Studio) stays deferred pending bank demand.

## Phase 1 - Foundation

- **Sprint 1A - Bootstrap:** repo/package setup, minimal FastAPI app, Docker image, CI discipline, and basic architecture checks.
- **Sprint 1B - Observability:** structured logging, request IDs, OpenTelemetry, Prometheus metrics, OpenAPI export, and `/readyz`.
- **Sprint 1C - Adapter protocols:** protocol layer plus Postgres, Qdrant, Vault, Ollama, and Langfuse-OTel reference adapters.
- **Sprint 1D - Enterprise adapters:** Oracle, Dynatrace, and OpenAI-compatible embedding support for enterprise deployments.
- **Sprint 2 - Governance chain foundation:** tamper-evident audit, decision history, hash-chain verification, schema vocabulary, and baseline migrations.
- **Sprint 2.5 - Operational governance:** SLA timers, escalation lifecycle, guardrail pipeline, live DB integration tests, and critical-controls coverage gates.
- **Sprint 3 - LLM gateway and provider-honesty:** one governed LLM chokepoint, cloud-policy enforcement, provenance-aware ledgering, and `/effective-routing`.

## Phase 2 - Protocol And Packs

- **Sprint 4 - Plugin registry and trust gate:** pack discovery, cosign and supply-chain attestation checks, per-tenant allow-listing, and policy-engine seed.
- **Sprint 5 - MCP host:** production MCP transport hardening, OAuth/PRM authorization, STDIO restrictions, capability validation, and audit linkage.
- **Sprint 6 - A2A endpoint:** A2A 1.0 inbound/outbound support, signed Agent Cards, streaming, tasks, artifacts, cancellation, and UI event stubs.
- **Sprint 7A - SDK and CLI:** pack scaffolding, validation, test harness commands, signing support, and conformance checks for pack authors.
- **Sprint 7B - Bank pack lifecycle:** portal APIs for pack review/approval/install/revoke, RBAC scopes, evidence panels, and UI event-stream endpoints.

## Phase 3 - Isolation, Compliance, And Model Lifecycle

- **Sprint 8 - Sandbox primitive:** isolated execution backend for tools touching untrusted code or external systems.
- **Sprint 8.5 - Resumable sessions:** checkpoint, suspend, and wake support for durable sandbox sessions.
- **Sprint 9 - ISO 42001 evidence:** control registry, tagged governance events, and examiner-ready evidence-pack export.
- **Sprint 9.5 - Model registry:** model records, lifecycle state, portal API, RBAC, provider-honesty integration, and decision linkage.
- **Sprint 10 - Vault credential leasing:** short-TTL credentials scoped to sandbox operations and revoked at sandbox teardown.

## Phase 4 - Bank-Deployable AgentOS

- **Sprint 11 - Sub-agent primitive:** orchestrator-worker delegation with isolated context, privilege de-escalation, recursion caps, and budgets.
- **Sprint 11.5 - Memory governance:** governed memory API for remember, recall, forget, redact, export, and subject listing, with consent and data-class enforcement.
- **Sprint 12 - Evaluation harness:** bulk testing against bank corpora, simulated scenarios, persistent eval results, and CLI workflows.
- **Sprint 13 - LLM judge and adversarial testing:** explainable judge verdicts, live-case replay, adversarial corpus generation, and promotion gates.
- **Sprint 13.5 - Runtime approval + policy conversion:** approval engine, portal approval API, MCP/sandbox/scheduler/memory approval seams, and Rego CONVERT work; emergency controls carved to Sprint 13.6.
- **Sprint 13.6 - Emergency controls:** full ADR-018 kill-switch class set, quotas, fail-closed propagation, scheduler/gateway integration, portal/RBAC surfaces.
- **Sprint 14 - Deployment kit:** per-tenant Helm and docker-compose deployment assets, bank overlay template, and operator runbook.
- **Sprint 15 - End-to-end production-readiness validation:** extract real packs, install them on AgentOS, run real queries, and prove the full governed audit chain. *(Re-sequenced into the capability map's forward items 4-8; the validation is production-readiness, not a POC.)*

## Phase 5 - AgentOS Studio (Deferred)

- **Sprint 16 - Studio API and storage:** persisted Studio-authored pack definitions, CRUD endpoints, and compiler foundation.
- **Sprint 17 - Studio trust model:** ADR-021, instance-key signing, Studio author allow-lists, and audit fields for Studio-authored packs.
- **Sprint 18 - Studio UI shell:** separate Studio UI and tool-authoring workflow.
- **Sprint 19 - Skill composition:** visual builder for composing deterministic skill flows.
- **Sprint 20 - Agent authoring:** prompt, allowed tools, sub-agent permissions, and ISO 42001 declarations for authored agents.
- **Sprint 21 - Promotion workflow:** Studio-authored pack promotion from dev to stage to prod using 4-eyes RBAC approval.

## Status (2026-06-12 reconciliation)

Sprints 1A through 13.5c3 are MERGED (incl. the inserted sub-sprints: 2.5, 7A2, 8.5, 9.5, 10.1, 10.5, 10.6, 11.5a-c, 12, 13a-c, and the 13.5 approval arc a/b1/b2/c1-c3). Remaining before the forward sequence takes over: 13.5c4 + 13.6. The reconciled forward sequence (composition-root wiring, managed runtime, workflow orchestration, ADK, deployment substrate Z1, runbooks/checklist) lives in [`docs/AS_BUILT_CAPABILITY_MAP.md`](AS_BUILT_CAPABILITY_MAP.md) — do not maintain sprint counts here.
