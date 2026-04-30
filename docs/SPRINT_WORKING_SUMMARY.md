# Cognic AgentOS Sprint Working Summary

Source: `docs/BUILD_PLAN.md`

This is the compact view of what each sprint is responsible for. Phases 1-4 deliver the bank-deployable AgentOS platform. Phase 5, AgentOS Studio, is deferred until after Phase 4 stabilizes and bank demand is confirmed.

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
- **Sprint 13.5 - Approval, policy, and emergency controls:** runtime tool approval, expanded Rego policy engine, kill switches, quotas, and fail-closed controls.
- **Sprint 14 - Deployment kit:** per-tenant Helm and docker-compose deployment assets, bank overlay template, and operator runbook.
- **Sprint 15 - End-to-end POC:** extract real packs, install them on AgentOS, run real queries, and prove the full governed audit chain.

## Phase 5 - AgentOS Studio (Deferred)

- **Sprint 16 - Studio API and storage:** persisted Studio-authored pack definitions, CRUD endpoints, and compiler foundation.
- **Sprint 17 - Studio trust model:** ADR-021, instance-key signing, Studio author allow-lists, and audit fields for Studio-authored packs.
- **Sprint 18 - Studio UI shell:** separate Studio UI and tool-authoring workflow.
- **Sprint 19 - Skill composition:** visual builder for composing deterministic skill flows.
- **Sprint 20 - Agent authoring:** prompt, allowed tools, sub-agent permissions, and ISO 42001 declarations for authored agents.
- **Sprint 21 - Promotion workflow:** Studio-authored pack promotion from dev to stage to prod using 4-eyes RBAC approval.

## Completion Count

- **Core AgentOS completion:** 18 remaining sprints from Sprint 3 through Sprint 15.
- **Including deferred Studio:** 24 remaining sprints from Sprint 3 through Sprint 21.
