# Sprint 6 — A2A Endpoint (Pinned to A2A 1.0 Spec) + UI Event-Stream Stub Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cognic AgentOS speaks A2A 1.0 inbound + outbound, **pinned to the released A2A 1.0 wire-spec with conformance fixtures** (per ADR-003 + `docs/A2A-CONFORMANCE.md`) — not a Cognic-bespoke shape. Wave 1 implements the mandatory feature set (Agent Cards, Tasks, Streaming, Artifacts, Capability negotiation, Cancellation, Error taxonomy, per-tenant token authz). Wave 2 features (push notifications, multi-modal, long-running task resumption, mTLS) are explicitly refused with closed-enum reasons. Sprint 6 also seeds the **UI event-stream contract** per ADR-020 — a typed event taxonomy + emit-hook layer that mirrors every audit event in-process, with the SSE endpoint deferred to Sprint 7B.

**Architecture:** Ten new protocol modules under `src/cognic_agentos/protocol/a2a_*` plus one for `ui_events.py`. Inbound A2A traffic enters via a new `POST /api/v1/a2a` portal endpoint, routed by a single owner (`A2AEndpoint`) that holds the task-lifecycle state machine and emits chain-linked decision_history records. Outbound dispatch fetches the target's signed Agent Card from the spec well-known path, verifies the JWS against the Sprint-4 trust root, and dispatches to the URL inside the verified card's `supportedInterfaces[].url` — never to a caller-supplied URL. The A2A wire format is generated from upstream protobuf source (Sprint-6 T2 lock); a CI drift gate fails the build if the spec moves beyond the pinned version. The UI event-stream layer (T12) ships only the typed Pydantic schema + emit hooks at the harness boundary; SSE transport lands at Sprint 7B per ADR-020's phased schedule. Decision Lock: A2A 1.0 only (no 0.x compatibility, no 2.x speculative); Wave-2 features fail-closed with explicit error codes (no silent-accept).

**Tech Stack:**
- A2A wire format: official **`a2a-sdk == X.Y.Z`** Python SDK pulled into the `adapters` extra group (kernel-image-free; default-adapters image carries it). Schema source: spec-published protobuf compiled to Pydantic via the SDK's generated bindings, with parity check against the spec's JSON-schema bindings.
- HTTP layer: `httpx.AsyncClient` (admission-side authz client + outbound dispatch + Agent Card fetch). No new HTTP library introduced.
- JWS verification: `python-jose[cryptography]` (already pinned in Sprint-4 trust gate work; reused here for Agent Card signature verification).
- Streaming: A2A 1.0 streaming-message envelope (chunked HTTP / spec wire format), distinct from the Sprint-7B portal SSE endpoint.
- UI events: Pydantic v2 typed event models for **all 11 ADR-020 Wave-1 event families** (`agent_run`, `tool_call`, `subagent`, `approval`, `artifact`, `interrupt`, `frontend_action`, `memory`, `decision_audit`, `policy`, `kill_switch`); Sprint 6 wires emit hooks for the 3 families with existing emit sites (`tool_call`, `decision_audit`, `artifact`); no transport in this sprint (SSE endpoint = Sprint 7B per ADR-020 phase table).
- Audit: Sprint-2 `AuditStore` + Sprint-2 `DecisionHistoryStore`. Every A2A inbound + outbound emits chained events via the same hash-chain primitives the MCP host (Sprint 5) uses.
- Trust root: Sprint-4 `TrustGate` per-tenant cosign root extended to verify Agent Card detached JWS files via the same authority. No second trust root introduced.
- Object store: Sprint-4 `LocalObjectStoreAdapter` for artifact references (tasks return large outputs by reference, not value).
- Config: Sprint-1B `Settings` extended with A2A-specific fields (token-cache TTL, schema-drift CI gate env-var, conformance-fixtures path).

**Decision Lock — A2A 1.0 only + UI events SSE deferred to Sprint 7B:**

This plan locks the following decisions at plan time. Future implementers MUST consult AGENTS.md per-edit halt-before-commit before deviating from any of these:

1. **A2A spec version: 1.0 only.** No 0.x compatibility shim; no 2.x speculative implementation. The version-negotiation matrix (T8) refuses every non-1.0 version with `VersionNotSupportedError` and a `Supported-A2A-Versions: 1.0` response header. When upstream A2A releases 1.1+, the version bump is a deliberate reviewed change tied to the schema-drift CI gate (T6) — NOT a silent extension.
2. **Wave-2 features refused with closed-enum reasons.** Push-notification subscribe, multi-modal payloads, long-running task resumption, mTLS auth — all four are spec-valid features but Wave-1 explicitly refuses them. Refusal is closed-enum (`a2a_wave2_feature_refused` with a sub-tag identifying the feature) so a future Wave-2 implementation simply removes the refusal site rather than threading a new code path.
3. **No anonymous A2A.** Every inbound call requires `Authorization: Bearer ...` against a per-tenant pinned token (Vault-rotated). Anonymous calls refused with `a2a_anonymous_refused` (mirrors Sprint-5 `mcp_anonymous_refused`).
4. **Outbound dispatch URLs come from verified Agent Cards.** Architecture-test (T4) + runtime canary (T14) enforce: every outbound `httpx` call's URL parameter must trace to a JWS-verified Agent Card's `supportedInterfaces[].url`. Caller-supplied URLs and model-output URLs never reach `httpx.AsyncClient.post(url=...)`.
5. **UI event SSE endpoint is Sprint-7B work.** ADR-020 explicitly schedules the SSE transport for Sprint 7B (after Sprint-7A's `agentos sign --bundle` SDK + CLI). Sprint 6 ships ONLY the typed Pydantic event SCHEMA — for **all 11 ADR-020 Wave-1 event families** — plus the in-process emit-hook layer that wires the 3 families with existing emit sites (`tool_call`, `decision_audit`, `artifact`). The remaining 8 families have schema-only stubs whose emit hooks land in their owning sprints (`subagent` @ Sprint 8; `frontend_action` @ Sprint 7B alongside SSE; `memory` @ Sprint 11.5; `approval` / `interrupt` / `policy` / `kill_switch` @ Sprint 13.5; `agent_run` when the run primitive lands). The schema is stable from day one.
6. **Sub-agent boundary held to ADR-005 (Sprint 8).** Sprint 6 ships outbound A2A *transport* (the bytes-on-the-wire half — Agent Card fetch + JWS verify + dispatch); ADR-005's `spawn_subagent` *orchestration* (recursion cap, policy negotiation, parent-child trace lineage semantics beyond chain linkage) ships with the sub-agent primitive in Sprint 8. The `protocol/a2a_endpoint.py` outbound surface is a low-level transport call; the harness-side `spawn_subagent` wrapper that consumes it lands later.
7. **AgentCard JWS verification rides Sprint-4 trust root.** No second trust authority introduced. The same per-tenant trust root that signs the wheel signs the Agent Card. Sprint-4's `protocol/trust_gate.py` is extended (additive) with a JWS-verification method; no architecture change.

**Self-Review (placeholder — completed at end of document):** Spec-coverage check, Placeholder scan, Type consistency, Doctrine-drift scan against ADR-003 + ADR-020 + A2A-CONFORMANCE.md.

---

## Document map

This plan runs T1–T16 followed by six dedicated doctrine-decision sections and the Self-Review checklist:

- **File Structure** — files created / modified by Sprint 6 with one-line responsibility-per-file.
- **Tasks T1–T16** — the implementation arc, in dependency order, each with files / steps / commit shape.
- **Doctrine Decision A — A2A SDK + protobuf pin** — `a2a-sdk == X.Y.Z`; kernel-vs-default-adapters split rationale.
- **Doctrine Decision B — Caller-controlled URL threat model** — proposes `docs/A2A-CALLER-URL-THREAT-MODEL.md`; documents four reachable URL surfaces.
- **Doctrine Decision C — Schema-drift CI gate env policy** — `@pytest.mark.a2a_upstream` env-gate; `COGNIC_RUN_A2A_UPSTREAM=1` opt-in; CI sets the var; local dev skips by default.
- **Doctrine Decision D — Sub-agent boundary** — Sprint 6 transport only; ADR-005 `spawn_subagent` orchestration is Sprint 8.
- **Doctrine Decision E — UI events Wave-1 taxonomy stability** — schema for **all 11 ADR-020 Wave-1 families** ships in Sprint 6; emit hooks wire only for the 3 with existing emit sites (`tool_call`, `decision_audit`, `artifact`); other 8 families are model-only stubs whose hooks land in their owning sprints per the ADR-020 phase table.
- **Doctrine Decision F — Critical-controls expansion rationale** — per-module case for the 21 → 27 gate growth.
- **Self-Review** — completion checklist.

---

## File Structure

Sprint 6 creates 11 new protocol modules + 7 new portal endpoints + 1 new threat-model document + 1 new closeout note. It modifies 9 existing files.

### Created (~22 files in `src/`)

**Protocol layer (10 A2A modules + 1 UI events module):**
- `src/cognic_agentos/protocol/a2a_endpoint.py` — single owner of the inbound A2A receiver + task lifecycle state machine. **Critical-controls module.** Routes incoming calls by entry-point name via plugin registry; emits `a2a.task_received` + `a2a.task_lifecycle_*` audit + decision_history rows; refuses anonymous calls; refuses unknown targets with `a2a_unknown_target` (501 with ADR-002 reference per BUILD_PLAN exit criterion).
- `src/cognic_agentos/protocol/a2a_authz.py` — per-tenant pinned-token authorization client. **Critical-controls module.** Validates `Authorization: Bearer <token>` against per-tenant Vault path; emits `a2a.token_rejected` audit row on refusal; closed-enum `A2AAuthzReason` (8 values: token-missing, token-malformed, tenant-mismatch, token-revoked, vault-read-failed, audience-mismatch, scope-insufficient, anonymous-refused).
- `src/cognic_agentos/protocol/a2a_agent_cards.py` — Agent Card publisher (per-pack `/.well-known/agent-card.json` route) AND verifier (inbound at registration + outbound at dispatch). **Critical-controls module.** Two-pass validation: upstream A2A 1.0 schema (via `a2a-sdk` SDK) + AgentOS bank-grade profile (mandatory `provider`, `securitySchemes`, `securityRequirements`, `signatures`, ≥1 `supportedInterfaces` entry). JWS verification rides Sprint-4 `TrustGate` per-tenant trust root. Card content hash-chained into `decision_history` at registration.
- `src/cognic_agentos/protocol/a2a_schema.py` — pinned A2A 1.0 wire-format types. **Critical-controls module.** Re-exports `a2a-sdk` SDK Pydantic types under stable AgentOS names so downstream code keeps working when we bump the SDK pin. Includes `_PINNED_PROTOBUF_DIGEST` + `_PINNED_JSON_SCHEMA_DIGEST` constants the drift CI gate (T6) verifies against.
- `src/cognic_agentos/protocol/a2a_version.py` — `A2A-Version` HTTP header parser + responder per ADR-003 §"Version negotiation". Closed-enum `A2AVersionOutcome` — **6 values**: `accepted` (`1.0` matches pinned), `absent_rejected` (no header → rejected with `Supported-A2A-Versions: 1.0`; spec interprets absent as `0.3`), `legacy_rejected` (`0.x` → rejected), `higher_minor_degraded` (`1.<higher minor>` → processed with feature-degradation warning), `unsupported_rejected` (`2.x` or unknown → rejected with `Supported-A2A-Versions`), `malformed_rejected` (malformed header → spec-defined parse error).
- `src/cognic_agentos/protocol/a2a_streaming.py` — A2A 1.0 streaming-message protocol support (chunked HTTP + spec wire envelopes). NOT portal/UI SSE (that's Sprint-7B per ADR-020). Emits `task.progress` / `task.completed` / `task.failed` envelopes per spec; chain-linked into decision_history via `_emit_streaming_evidence` helper mirroring Sprint-5's `_emit_call_evidence`.
- `src/cognic_agentos/protocol/a2a_artifacts.py` — artifact reference generator. Large outputs (PDFs, evidence packs, JSON > 64 KiB) stored via Sprint-4's `LocalObjectStoreAdapter` and returned as `ArtifactRef(uri, sha256, size_bytes, mime_type)`; small payloads remain inline; per-tenant retention configurable via `Settings.a2a_artifact_retention_seconds`.
- `src/cognic_agentos/protocol/a2a_capability_negotiation.py` — `GET /api/v1/a2a/capabilities` endpoint backing module. Reads pack manifests' declared `[tool.cognic.a2a].capabilities_supported`; returns canonical A2A 1.0 capability list (subset of the agent's manifest declaration; never broader).
- `src/cognic_agentos/protocol/a2a_cancellation.py` — task cancellation primitive. `cancel_task(task_id, *, reason)` flips lifecycle to `cancelled`, emits `a2a.task_cancelled` chained event with partial-state payload digest, refuses subsequent calls against the cancelled task ID with `a2a_task_already_cancelled`.
- `src/cognic_agentos/protocol/a2a_errors.py` — full A2A 1.0 error taxonomy as a closed-enum Literal. 14 spec-defined codes (per A2A 1.0 §error-codes): `task_not_found`, `task_already_cancelled`, `version_not_supported`, `agent_card_signature_invalid`, `agent_card_not_found`, `unknown_target`, `capability_not_supported`, `streaming_not_supported`, `artifact_too_large`, `artifact_retention_exceeded`, `wave2_feature_refused`, `anonymous_refused`, `tenant_token_invalid`, `parse_error`. Re-exported through `protocol/__init__.py`.
- `src/cognic_agentos/protocol/ui_events.py` — typed UI event taxonomy (Wave 1) per ADR-020. **Critical-controls module** (per ADR-020 stop rule — public event schema). **All 11 Wave-1 Pydantic event-family models seeded in Sprint 6** (R0 P2 reviewer correction — schema covers full ADR-020 §"Event taxonomy (Wave 1)" regardless of which sprint wires the emit hooks): `agent_run.{started,progress,completed,failed,cancelled,paused,resumed}`, `tool_call.{requested,approved,denied,started,progress,completed,failed}`, `subagent.{spawned,completed,failed,recursion_capped}`, `approval.{pending,granted,granted_second,denied,expired}`, `artifact.{started,chunk,completed}`, `interrupt.{requested_by_agent,requested_by_operator,acknowledged}`, `frontend_action.{submitted,accepted,rejected}`, `memory.{recall_started,recall_completed,forget,redact}`, `decision_audit.event_appended`, `policy.{decision_evaluated,bundle_loaded}`, `kill_switch.{flipped,reverted}`. Emit-hook protocol (`UIEventHook`) wires **3 families in Sprint 6** (the families with existing emit sites): `tool_call.*` (mirrors Sprint-5's `audit.tool_invocation_*`), `decision_audit.event_appended` (mirrors every `DecisionHistoryStore.append`), `artifact.*` (mirrors Sprint-6 T11's artifact lifecycle). The other 8 families have model-only stubs; their emit hooks land in their owning sprints per the ADR-020 phase table. Sprint-6 audit emits are NOT changed — UI events are an ADDITIVE mirror at the same call site. **No SSE endpoint** in Sprint 6 (ADR-020 schedules SSE for Sprint 7B).

**Portal endpoints (in `src/cognic_agentos/portal/api/app.py` + new routers under `portal/api/routes/`):**
- `portal/api/routes/a2a.py` — new router. Mounts `POST /api/v1/a2a` (inbound receiver, calls `A2AEndpoint.handle`); `GET /api/v1/a2a/tasks/{task_id}` (status); `POST /api/v1/a2a/tasks/{task_id}/cancel` (cancellation); `GET /api/v1/a2a/capabilities` (capability negotiation).
- `portal/api/routes/agent_cards.py` — new router. Mounts `GET /api/v1/system/agent-cards` (multi-agent catalog — Cognic-specific, NOT the spec well-known path); `GET /.well-known/agent-card.json` per-pack route serving the pack's signed AgentCard JSON (one origin per agent in Wave 1).

**Test fixtures (~3 files):**
- `tests/fixtures/a2a-conformance/valid/` — curated valid A2A 1.0 messages from the official conformance suite (Tasks, Streaming envelopes, Artifacts references, Cancellation requests). Each fixture is a JSON file named `<spec_section>__<scenario>.json`.
- `tests/fixtures/a2a-conformance/invalid/` — curated invalid messages (malformed envelopes, missing required fields, version-mismatch headers, unsigned-card claims). Each accompanied by an `_expected.json` declaring the exact spec error code that MUST surface.
- `tests/fixtures/cognic_test_agent_pack/` — Sprint-6 agent pack fixture (mirrors Sprint-5's `cognic_test_mcp_pack` shape: import-poisoned, full Sprint-4-shaped attestation set, signed AgentCard JSON + detached JWS, `[tool.cognic.a2a]` manifest block populated). The pack is intentionally inert for the unit lane.

**Threat model document (1 file):**
- `docs/A2A-CALLER-URL-THREAT-MODEL.md` — authoritative reference for why outbound A2A dispatch URLs MUST come from the verified Agent Card's `supportedInterfaces[].url`, never from caller input or model output. Catalogues the four reachable URL surfaces (inbound `target_agent` field, outbound `spawn_subagent`, AgentCard discovery URL, push-notification webhooks). Pack authors + reviewers consult it when evaluating Wave-1 A2A traffic. **Mirrors the structure of `docs/MCP-STDIO-THREAT-MODEL.md`** (Sprint 5 T3); same 4-gate doctrine pattern.

**Closeout note (1 file):**
- `docs/closeouts/2026-05-XX-sprint-6-a2a-endpoint.md` (date filled at commit time) — Sprint-6 closeout mirroring Sprint-5's structure: header (parent SHA, branch state, commit count) → What ships → CI gates table → Doctrine adherence → Test + coverage state → Plan-review findings closed → ADR-003 / ADR-020 validation table → Doctrine amendments → Carryover → Out-of-scope → Next sprint.

**Architecture tests (2 files):**
- `tests/architecture/test_a2a_no_subprocess.py` — static-AST scan banning `subprocess` / `os.exec*` / `os.spawn*` / `os.system` / `os.popen` / `asyncio.create_subprocess_*` / `multiprocessing.Process` / `shell=True` under any module whose path matches `protocol/a2a_*.py`. Mirrors Sprint-5 T4. Three self-tests pin the collector contract.
- `tests/architecture/test_a2a_no_caller_controlled_url.py` — static-AST scan asserting that NO module under `protocol/a2a_*` calls `httpx.AsyncClient.get/post/put/delete(url=<x>)` where `<x>` traces to a function parameter, request-body field, or model-output string. Every outbound dispatch URL MUST come from a literal-or-allowlisted source: a JWS-verified Agent Card's `supportedInterfaces[].url` OR a `Settings.a2a_*_url` field OR a hardcoded well-known suffix. Three self-tests pin the collector + the URL-source-classifier.

**Unit test modules (~16 files):**
- `tests/unit/protocol/test_a2a_authz.py` — token validation contract.
- `tests/unit/protocol/test_a2a_schema.py` — schema-type contract.
- `tests/unit/protocol/test_a2a_schema_drift.py` — env-gated CI drift gate (`@pytest.mark.a2a_upstream`).
- `tests/unit/protocol/test_a2a_agent_cards.py` — two-pass validator + JWS verify.
- `tests/unit/protocol/test_a2a_agent_card_jws_required.py` — registration refused on unsigned / non-allow-listed signer.
- `tests/unit/protocol/test_a2a_agent_card_outbound_verification.py` — outbound dispatch fetches card, verifies JWS, dispatches to `supportedInterfaces[].url`.
- `tests/unit/protocol/test_a2a_agent_card_chain_audit.py` — card content hash-chained at registration.
- `tests/unit/protocol/test_a2a_version.py` — version-header negotiation (6 cases per `A2AVersionOutcome`).
- `tests/unit/protocol/test_a2a_endpoint.py` — inbound receiver + lifecycle.
- `tests/unit/protocol/test_a2a_streaming.py` — task streaming wire format.
- `tests/unit/protocol/test_a2a_artifacts.py` — large output → reference; small payload → inline.
- `tests/unit/protocol/test_a2a_capability_negotiation.py` — `/capabilities` lists exactly the manifest's declarations.
- `tests/unit/protocol/test_a2a_cancellation.py` — in-flight task cancelled; partial-state audit emitted.
- `tests/unit/protocol/test_a2a_error_taxonomy.py` — every spec-defined error path returns the spec's code.
- `tests/unit/protocol/test_a2a_chain_audit.py` — parent + 3 child messages → cross-agent chain proof.
- `tests/unit/protocol/test_a2a_unknown_target.py` — unknown target → 501 with ADR-002 reference.
- `tests/unit/protocol/test_a2a_anonymous_refused.py` — anonymous call → 401 with `a2a_anonymous_refused`.
- `tests/unit/protocol/test_a2a_spec_conformance.py` — runs the conformance fixtures.
- `tests/unit/protocol/test_a2a_no_caller_controlled_url.py` — runtime canary (T14) complementing the architecture test.
- `tests/unit/protocol/test_a2a_wave2_features_refused.py` — push notifications, multi-modal, long-running resumption all refused with `a2a_wave2_feature_refused`.
- `tests/unit/protocol/test_a2a_outbound_version.py` — every outbound call includes `A2A-Version: 1.0`.
- `tests/unit/protocol/test_a2a_fixture_pack_admission.py` — registry admits `cognic_test_agent_pack` through the full Sprint-4 admission pipeline + Sprint-6 AgentCard JWS verification step.
- `tests/unit/protocol/test_ui_events.py` — typed event-family models + emit-hook contract.
- `tests/unit/protocol/test_ui_events_audit_mirror.py` — Sprint-5 audit emits get parallel typed UI events without changing the audit emit shape.

### Modified (~9 files)

- `pyproject.toml` — add `a2a-sdk == X.Y.Z` to `adapters` extra (kernel image stays SDK-free).
- `uv.lock` — refresh after pin lands.
- `src/cognic_agentos/core/config.py` — Sprint-6 settings (T1): `a2a_token_cache_ttl_s`, `a2a_artifact_retention_seconds`, `a2a_pinned_spec_version`, `a2a_schema_drift_check_enabled`, `a2a_card_jws_max_size_bytes`, `a2a_outbound_request_timeout_s`, `a2a_inbound_request_timeout_s`. Mirrors Sprint-5's `mcp_*` setting block shape. **Halt-before-commit** because `core/config.py` ships AGENTS.md-cited critical-controls knobs (token cache, retention windows, fail-closed timeouts).
- `src/cognic_agentos/protocol/__init__.py` — export new modules (`A2AEndpoint`, `A2AAuthzClient`, `A2AAgentCardVerifier`, `A2AVersionNegotiator`, `UIEventEmitter`, etc.); extend the closed-enum re-exports.
- `src/cognic_agentos/portal/api/app.py` — **two-phase amendment** (R0 P2 reviewer correction). T2 ONLY adds the `is_a2a_available()` log branch (kernel-resilient `try/except ImportError` for the `a2a-sdk`); kernel image still boots without it (mirrors Sprint-5 T2 R3 P1 doctrine). T2 does NOT mount any HTTP routes — that follows in: T9 (`POST /api/v1/a2a` receiver + Agent-Card publisher routes), T11 (`/api/v1/a2a/capabilities` + `/cancel` + artifacts retrieval). T12 wires `UIEventEmitter` at the harness boundary (in-process emit hooks; **no SSE endpoint** — Sprint 7B owns that per ADR-020 phase table). The two-phase shape avoids the Sprint-5 T15 R1 P2 #1 overclaim trap (`create_prod_app` MUST NOT promise wiring it doesn't actually do).
- `src/cognic_agentos/protocol/trust_gate.py` — additive: `verify_jws_blob(jws_bytes, *, payload_bytes, tenant_id)` method that reuses the per-tenant cosign trust root for JWS signature verification. **Critical-controls module — halt-before-commit.** No subprocess / no shell. Wraps `python-jose` JWS verification with the same secure-default posture as the cosign caller (timeout, explicit env, no-fallthrough on key resolution).
- `src/cognic_agentos/protocol/plugin_registry.py` — additive: extend the admission pipeline with an Agent Card JWS verification step **AFTER the trust gate's wheel cosign verifies AND after the Sprint-5 deferred-load manifest extractor reads `agent_card_jws_path`** (R0 P2 reviewer correction — pack must be cosign-trusted FIRST so its declared metadata is trustworthy enough to read). The full ordering is: (1) per-tenant allow-list; (2) wheel cosign verification (Sprint-4 trust gate); (3) full Sprint-4 attestation pipeline (SBOM / SLSA / in-toto / vuln / license / Sigstore); (4) Sprint-5 deferred-load manifest extraction via `Distribution.locate_file()`; (5) **NEW Sprint-6 step:** read `agent_card_jws_path` from the cosign-verified manifest, fetch the detached JWS bytes, verify against the per-tenant trust root via `TrustGate.verify_jws_blob`. On failure at step (5), registration refused with `a2a_agent_card_signature_invalid`. Closed-enum `RefusalReason` extension: add the 6 new A2A reasons (count goes 26 → 32). **Critical-controls module — halt-before-commit.**
- `tests/unit/protocol/test_refusal_reason_completeness.py` — drift-detector update: 26 → 32 expected count + the 6 new A2A reason names. Mirrors the Sprint-5 R1/R2/R3 closed-enum doctrine: every new reason gets a literal entry, a frozenset entry, a per-reason test-arm coverage row, and a count-pin.
- `tools/check_critical_coverage.py` — T15 extension. Gate grows 21 → 27 modules at the strict 95/90 floor: `a2a_authz`, `a2a_agent_cards`, `a2a_endpoint`, `a2a_schema`, `a2a_version`, `ui_events`. (R0 P2 fix — `a2a_version.py` added per AGENTS.md §"Wire-protocol contracts" stop-rule; version negotiation IS wire-protocol surface even though the module is small + pure-functional.) Per-module rationale comment block follows the Sprint-5 R1 P3 pattern (transport-owned vs host-owned invariants stay where they live in the codebase).
- `docs/BUILD_PLAN.md` — Sprint-6 status flipped to **CLOSED** at T16 commit time.
- `AGENTS.md` — T16 doctrine update: append a new "Protocol — A2A endpoint (Sprint 6)" section under the critical-controls list listing all **6 Sprint-6 critical-controls modules** (R0 P2 reviewer correction added `a2a_version.py` to the original quintet) with their per-module rationale lines. Mirrors the Sprint-5 amendment shape.
- `tests/architecture/test_mcp_stdio_no_subprocess.py` — sentinel tightened: the `test_at_least_one_mcp_module_exists` lower-bound stays at `>= 5`; a parallel `tests/architecture/test_a2a_no_subprocess.py::test_at_least_one_a2a_module_exists` is added with `>= 9` (the Sprint-6 a2a quintet `endpoint, authz, agent_cards, schema, version, streaming, artifacts, capability_negotiation, cancellation, errors` = 10 modules; the floor is 9 to leave room for one rename without tripping the test).

---

## Task 1: Sprint-6 settings + closed-enum vocabulary scaffolding

**Files:**
- Modify: `src/cognic_agentos/core/config.py` — add 7 Sprint-6 settings.
- Modify: `.env.example` — operator-facing docs for the new settings.
- Modify: `src/cognic_agentos/protocol/__init__.py` — declare the closed-enum vocabularies so subsequent task imports just work.
- Test: `tests/unit/test_config.py` — extend with the 7 new fields + their defaults + validation.

**Halt-before-commit:** Yes (T1 touches `core/config.py` which ships fail-closed timeouts + retention windows; AGENTS.md per-edit rule applies).

- [ ] **Step 1: Write the failing settings tests**

```python
# tests/unit/test_config.py — append the Sprint-6 fixture class
from cognic_agentos.core.config import Settings


class TestSprint6A2ASettings:
    def test_a2a_token_cache_ttl_s_default(self) -> None:
        s = Settings()
        assert s.a2a_token_cache_ttl_s == 300

    def test_a2a_artifact_retention_seconds_default(self) -> None:
        s = Settings()
        assert s.a2a_artifact_retention_seconds == 7 * 24 * 3600

    def test_a2a_pinned_spec_version_default(self) -> None:
        s = Settings()
        assert s.a2a_pinned_spec_version == "1.0"

    def test_a2a_schema_drift_check_enabled_default(self) -> None:
        s = Settings()
        # Drift check OFF by default; CI sets COGNIC_RUN_A2A_UPSTREAM=1 to opt in.
        assert s.a2a_schema_drift_check_enabled is False

    def test_a2a_card_jws_max_size_bytes_default(self) -> None:
        s = Settings()
        # 64 KiB cap matches the AgentCard size budget the trust gate
        # validates against; larger files are an attack vector.
        assert s.a2a_card_jws_max_size_bytes == 64 * 1024

    def test_a2a_outbound_request_timeout_s_default(self) -> None:
        s = Settings()
        assert s.a2a_outbound_request_timeout_s == 30

    def test_a2a_inbound_request_timeout_s_default(self) -> None:
        s = Settings()
        # Inbound timeout is the deadline for `A2AEndpoint.handle()` to
        # produce a response on a non-streaming task.
        assert s.a2a_inbound_request_timeout_s == 60

    def test_a2a_outbound_timeout_must_be_positive(self) -> None:
        with pytest.raises(ValidationError):
            Settings(a2a_outbound_request_timeout_s=0)

    def test_a2a_card_jws_max_size_bytes_must_be_positive(self) -> None:
        with pytest.raises(ValidationError):
            Settings(a2a_card_jws_max_size_bytes=0)
```

- [ ] **Step 2: Run; expect FAIL** (`AttributeError` on every Settings attribute access)

Run: `uv run pytest tests/unit/test_config.py::TestSprint6A2ASettings -v`
Expected: FAIL — no `a2a_*` fields on `Settings`.

- [ ] **Step 3: Implement settings**

```python
# Append to src/cognic_agentos/core/config.py inside the Settings class
# (after the mcp_* block from Sprint 5)

# ---------------------------------------------------------------------------
# Sprint 6 — A2A endpoint + UI event-stream stub (per ADR-003 + ADR-020)
# ---------------------------------------------------------------------------

#: TTL for the per-tenant A2A pinned-token cache. Tokens are read from
#: Vault on cache miss + refreshed before TTL elapses. Default 300s
#: matches Sprint-5 mcp_oauth_token_cache_ttl_s for operational
#: consistency.
a2a_token_cache_ttl_s: int = Field(default=300, gt=0)

#: Retention window for A2A artifact references stored via
#: ObjectStoreAdapter. Default 7 days; tenants override per
#: regulatory class. Matches Sprint-4 sigstore_bundle_retention_seconds
#: lower bound for non-cosign-bundle objects.
a2a_artifact_retention_seconds: int = Field(default=7 * 24 * 3600, gt=0)

#: Pinned A2A spec version. Bumping requires an explicit reviewed
#: change tied to the schema-drift CI gate (T6) — never silent.
a2a_pinned_spec_version: str = Field(default="1.0", pattern=r"^[0-9]+\.[0-9]+$")

#: Whether the schema-drift CI gate runs at startup. False locally
#: (saves network round-trip on every test run); CI sets
#: COGNIC_RUN_A2A_UPSTREAM=1 which the env-var-binding pulls in as
#: True. The drift gate itself is in tests/unit/protocol/
#: test_a2a_schema_drift.py.
a2a_schema_drift_check_enabled: bool = Field(default=False)

#: Maximum size of a detached AgentCard JWS file the trust gate
#: accepts. JWS files >64 KiB are an attack vector (DoS via
#: large-blob signature verification + memory pressure).
a2a_card_jws_max_size_bytes: int = Field(default=64 * 1024, gt=0)

#: Timeout for outbound A2A HTTP calls (Agent Card fetch + task
#: dispatch). 30s matches Sprint-5 mcp_oauth_request_timeout_s.
a2a_outbound_request_timeout_s: int = Field(default=30, gt=0)

#: Deadline for inbound non-streaming A2A `handle()` calls before
#: the endpoint emits `task.failed` with `deadline_exceeded`. 60s
#: budget for typical bank-grade tool-bound tasks.
a2a_inbound_request_timeout_s: int = Field(default=60, gt=0)
```

- [ ] **Step 4: Implement closed-enum vocab declarations**

```python
# Append to src/cognic_agentos/protocol/__init__.py

# Sprint-6 closed-enum vocabularies. Each is pinned by a drift
# detector in tests/unit/protocol/test_refusal_reason_completeness.py
# (extended in T1) and by per-module test_*.py contract tests.

#: A2A authorization failure reasons. 8 values; mirrors the
#: Sprint-5 AuthzReason layout but tailored to A2A's pinned-token
#: posture (no PRM, no RFC 8707 — those are MCP/OAuth concepts).
A2AAuthzReason = Literal[
    "a2a_anonymous_refused",
    "a2a_token_missing",
    "a2a_token_malformed",
    "a2a_tenant_mismatch",
    "a2a_token_revoked",
    "a2a_vault_read_failed",
    "a2a_audience_mismatch",
    "a2a_scope_insufficient",
]

#: A2A version-negotiation outcomes. 6 values per ADR-003 §"Version
#: negotiation".
A2AVersionOutcome = Literal[
    "accepted",
    "absent_rejected",
    "legacy_rejected",
    "higher_minor_degraded",
    "unsupported_rejected",
    "malformed_rejected",
]

#: A2A error taxonomy. 14 spec-defined codes per A2A 1.0
#: §error-codes — these are wire-protocol values, not Cognic-bespoke.
A2AErrorCode = Literal[
    "task_not_found",
    "task_already_cancelled",
    "version_not_supported",
    "agent_card_signature_invalid",
    "agent_card_not_found",
    "unknown_target",
    "capability_not_supported",
    "streaming_not_supported",
    "artifact_too_large",
    "artifact_retention_exceeded",
    "wave2_feature_refused",
    "anonymous_refused",
    "tenant_token_invalid",
    "parse_error",
]

#: AgentCard validation outcomes. Two-pass: upstream A2A 1.0 schema
#: + AgentOS bank-grade profile. 7 values.
AgentCardValidationReason = Literal[
    "agent_card_upstream_schema_invalid",      # spec-conformance gate
    "agent_card_profile_provider_missing",     # AgentOS profile gate
    "agent_card_profile_security_schemes_missing",
    "agent_card_profile_security_requirements_missing",
    "agent_card_profile_signatures_missing",
    "agent_card_profile_supported_interfaces_empty",
    "agent_card_profile_top_level_url_forbidden",  # spec violation
]
```

- [ ] **Step 5: Run; expect PASS**

Run: `uv run pytest tests/unit/test_config.py::TestSprint6A2ASettings -v`
Expected: 9 passed.

- [ ] **Step 6: Update `.env.example`**

```bash
# A2A endpoint (Sprint 6, per ADR-003 + docs/A2A-CONFORMANCE.md)
COGNIC_A2A_TOKEN_CACHE_TTL_S=300
COGNIC_A2A_ARTIFACT_RETENTION_SECONDS=604800
COGNIC_A2A_PINNED_SPEC_VERSION=1.0
COGNIC_A2A_SCHEMA_DRIFT_CHECK_ENABLED=false
COGNIC_A2A_CARD_JWS_MAX_SIZE_BYTES=65536
COGNIC_A2A_OUTBOUND_REQUEST_TIMEOUT_S=30
COGNIC_A2A_INBOUND_REQUEST_TIMEOUT_S=60

# CI opt-in for the upstream-schema drift check
# (test_a2a_schema_drift.py — pulls upstream protobuf + JSON-schema
# bindings; needs network)
# COGNIC_RUN_A2A_UPSTREAM=1
```

- [ ] **Step 7: Commit**

```bash
git add src/cognic_agentos/core/config.py \
        src/cognic_agentos/protocol/__init__.py \
        .env.example \
        tests/unit/test_config.py
git commit -m "feat(sprint-6): add A2A endpoint settings + closed-enum vocab scaffolding (T1)"
```

---

## Task 2: A2A SDK + protobuf pin + kernel/adapters split

**Files:**
- Modify: `pyproject.toml` — add `a2a-sdk == X.Y.Z` to the `adapters` extra group.
- Modify: `uv.lock` — refresh after pin lands.
- Modify: `src/cognic_agentos/portal/api/app.py` — `create_prod_app` (default-adapters factory) wires the A2A SDK; `create_app` (kernel) does NOT. Mirrors Sprint-5 T2 R3 P1 doctrine.
- Modify: `src/cognic_agentos/protocol/__init__.py` — `is_a2a_available()` helper that mirrors `is_mcp_available()` from Sprint 5.
- Test: `tests/unit/protocol/test_optional_dep_loader.py` — extend the existing kernel-vs-adapters dependency-loader fixture with A2A SDK presence/absence arms.

**Halt-before-commit:** Yes (touches `portal/api/app.py` lifespan factory which is on the AGENTS.md critical-controls list as a kernel-startup boundary).

- [ ] **Step 1: Pin the SDK + record the pin decision**

The pin point is **`a2a-sdk == X.Y.Z`** (April 2026 release, Linux-Foundation-governed). The SDK ships:
- Generated Pydantic types from the spec's protobuf source (canonical data model per ADR-003 + A2A-CONFORMANCE.md).
- A `JsonSchemaBindings` namespace exposing the spec-published JSON-schema bindings used as the parity-check side of T6's drift gate.
- A reference HTTP client + server skeletons (we DO NOT use the server skeleton — `protocol/a2a_endpoint.py` is our own implementation; we use the SDK only for wire-format types + version-header utilities).

We considered three alternatives:

| Option | Decision | Reason |
|---|---|---|
| Vendor `.proto` + compile via `betterproto` | Rejected | Vendoring the protobuf source means we own a fork of the spec wire format. Drift between our compiled types and upstream becomes invisible until the JSON-schema parity test (T6) catches it; by then any change has already merged. The official SDK gives us upstream's Pydantic types directly + a parity check against the spec's JSON-schema. |
| Use a third-party `a2a-py` community shim | Rejected | Wave 1 community shims are not Linux-Foundation-governed; they may diverge from spec. The official `a2a-sdk` package matches the spec authors' own tests. |
| **Pin official `a2a-sdk == X.Y.Z`** | **Selected** | Spec authors' own types; LF governance; consumed by 150+ orgs in production per ADR-003. Schema-drift CI gate (T6) catches upstream drift. Sprint-7A `agentos validate` will use the same SDK. |

- [ ] **Step 2: Update `pyproject.toml`**

```toml
# pyproject.toml — extend the adapters extra group (Sprint-5 already
# added mcp == 1.27.0 here; A2A 1.0 SDK joins it)
[project.optional-dependencies]
adapters = [
    # ... Sprint-5 entries unchanged ...
    "mcp == 1.27.0",
    # Sprint 6 — A2A 1.0 SDK + JWS verification dependency
    "a2a-sdk == X.Y.Z",
    # python-jose was already pinned by Sprint 4 trust gate work; no
    # second copy.
]
```

- [ ] **Step 3: Refresh lockfile + commit lock alongside the pin**

Run: `uv lock`
Expected: `uv.lock` updates with the new transitive tree (a2a-sdk pulls in `pydantic >= 2.5`, `httpx >= 0.27`, `protobuf >= 5.27` — all already pinned in Sprint-3+ via gateway / preflight / supply-chain). The implementation engineer captures the actual transitive set at T2 commit time and pins the major versions in this comment so future bumps are visible.

- [ ] **Step 4: Add the `is_a2a_available()` helper**

```python
# Append to src/cognic_agentos/protocol/__init__.py

def is_a2a_available() -> bool:
    """Whether the ``a2a-sdk`` SDK is importable in the current
    runtime. Used by ``create_prod_app`` (default-adapters factory)
    to decide whether to mount the A2A routes; the kernel image
    ships without the SDK and so this returns ``False`` there.

    Mirrors :func:`is_mcp_available` from Sprint 5 T2 — same R3 P1
    doctrine: the admission-side modules (``a2a_authz``,
    ``a2a_agent_cards``, ``a2a_schema``, ``a2a_version``) construct
    cleanly without the SDK; runtime serving (``A2AEndpoint.handle``,
    streaming, artifacts) is the surface that needs it.
    """
    try:
        import a2a  # noqa: F401  # imported for presence check
    except ImportError:
        return False
    return True


class A2ANotAvailableError(RuntimeError):
    """Raised when production code attempts to use A2A runtime
    serving on the kernel image where the ``a2a-sdk`` SDK is
    not installed.

    Operators see this if they misconfigure: deploy the kernel image
    (which is SDK-free per Sprint-5 R3 P1 / Sprint-6 T2 doctrine) and
    set ``A2A_ENABLED=true`` in their environment. The fix is to
    rebuild with ``--extra adapters`` to land the SDK + the A2A
    routes.
    """
```

- [ ] **Step 5: Wire `create_prod_app` (kernel-resilient)**

```python
# src/cognic_agentos/portal/api/app.py — extend the lifespan factory

def create_prod_app(*, bundled_registry: BundledAdapterRegistry) -> FastAPI:
    """Default-adapters factory. **T2 ONLY logs SDK availability** —
    route mounting is deferred to the tasks that create the routes
    (T9 receiver, T11 small endpoints, T12 emit-hook wiring at the
    harness boundary). On the kernel image (or any venv missing the
    SDK), logs a structured warning so operators spot misconfiguration
    immediately.

    Mirrors Sprint-5 T2's ``is_mcp_available()`` branch — same R3 P1
    doctrine: kernel image stays SDK-free; default-adapters image
    carries the SDK. R0 P2 reviewer correction: this factory MUST NOT
    promise wiring it doesn't actually do (Sprint-5 T15 R1 P2 #1 caught
    the same overclaim with MCPHost). The available-branch is a
    presence log + the ``is_a2a_available()`` predicate, nothing else.
    """
    app = create_app(adapter_registry=bundled_registry)

    if is_mcp_available():
        logger.info(
            "mcp.sdk_present_at_startup",
            extra={"image": "default-adapters"},
        )
        # MCPHost lifespan wiring deferred per Sprint-5 T15 R1 P2 #1
        # scope decision (carryover).
    else:
        logger.warning(
            "mcp.host_unavailable_in_image",
            extra={
                "missing_module": "mcp",
                "optional_dep_group": "adapters",
                "remediation": "rebuild image with --extra adapters",
            },
        )

    if is_a2a_available():
        logger.info(
            "a2a.sdk_present_at_startup",
            extra={"image": "default-adapters"},
        )
        # T2 ONLY logs SDK presence. Route mounting is deferred to the
        # tasks that create the routes:
        #   - T9 will mount `routes.a2a` (`POST /api/v1/a2a` receiver)
        #   - T11 will mount `routes.a2a_capabilities` /
        #     `routes.a2a_cancellation` / `routes.a2a_artifacts`
        #   - T12 will wire UI-event emit hooks at the harness boundary
        #     (NO HTTP route — Sprint 7B owns the SSE endpoint per
        #     ADR-020 phase table)
        # R0 P2 reviewer correction: importing a route module here that
        # T9+ will create is the same overclaim Sprint 5 T15 R1 P2 #1
        # caught — `create_prod_app` MUST NOT promise wiring it doesn't
        # actually do. T2's contract is the availability log + the
        # `is_a2a_available()` predicate, nothing else.
    else:
        logger.warning(
            "a2a.endpoint_unavailable_in_image",
            extra={
                "missing_module": "a2a",
                "optional_dep_group": "adapters",
                "remediation": "rebuild image with --extra adapters",
            },
        )

    return app
```

- [ ] **Step 6: Extend the optional-dep loader test**

```python
# tests/unit/protocol/test_optional_dep_loader.py — append

class TestA2ASdkPresenceCheck:
    def test_is_a2a_available_returns_true_when_sdk_importable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Default test environment has --extra adapters installed.
        from cognic_agentos.protocol import is_a2a_available
        assert is_a2a_available() is True

    def test_is_a2a_available_returns_false_when_sdk_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Simulate kernel image: a2a module not importable.
        import sys
        monkeypatch.setitem(sys.modules, "a2a", None)
        from cognic_agentos.protocol import is_a2a_available
        assert is_a2a_available() is False
```

- [ ] **Step 7: Run all tests; expect PASS**

Run: `uv run pytest tests/unit/test_config.py tests/unit/protocol/test_optional_dep_loader.py -v`
Expected: All pass.

- [ ] **Step 8: Halt for commit-token, then commit**

```bash
git add pyproject.toml uv.lock \
        src/cognic_agentos/protocol/__init__.py \
        src/cognic_agentos/portal/api/app.py \
        tests/unit/protocol/test_optional_dep_loader.py
git commit -m "build(sprint-6): pin a2a-sdk Python package + kernel/adapters split (T2)"
```

---

## Task 3: A2A-CONFORMANCE.md alignment review

**Files:**
- Read-only: `docs/A2A-CONFORMANCE.md`.
- Read-only: `docs/adrs/ADR-003-a2a-inter-agent.md`.
- Read-only: `docs/BUILD_PLAN.md` Sprint 6 entry.

**Halt-before-commit:** N/A — verification-only task; no edits expected.

This task is the planned doctrine-alignment checkpoint. Sprint 5 T3 had the same shape (it landed the threat-model document because Sprint 5 introduced new doctrine; Sprint 6 inherits an already-approved doctrine surface and only verifies alignment).

- [ ] **Step 1: Walk the BUILD_PLAN Sprint-6 deliverables list against `docs/A2A-CONFORMANCE.md` row by row**

For each row in the conformance matrix:
- Confirm the deliverable name in BUILD_PLAN matches the module name in this plan's File Structure.
- Confirm the Wave-1 / Wave-2 / Deferred classification matches.
- Confirm the test name in BUILD_PLAN's "Tests:" list matches a test name in this plan.

If any row is misaligned, the misalignment is recorded as an **R0 doctrine-review finding** for the plan-PR (no plan rewrite at this step — the finding feeds the plan-PR R0 review pass).

- [ ] **Step 2: Walk ADR-003 §"A2A 1.0 feature scope" row by row**

Same as Step 1 but for the ADR's authoritative feature scope. Findings are recorded.

- [ ] **Step 3: Walk ADR-020 §"Implementation phases" row by row**

Confirm Sprint 6's UI-events scope (T12) matches ADR-020's Sprint-6 row exactly: "Stub `protocol/ui_events.py` — event-emit hooks at the harness boundary so every existing audit event mirrors to a typed UI event in-process; no SSE endpoint yet". Findings are recorded.

- [ ] **Step 4: Run T3 as a no-edit verification**

If all three walks return zero findings, T3 is complete. If any walk returns findings, the plan-PR R0 review pass folds them in BEFORE T1 implementation begins.

- [ ] **Step 5: Mark T3 complete in the plan-of-record commit message ledger**

T3 produces no commit. The plan's Self-Review section records "T3: zero findings" or the specific findings list.

---

## Task 4: Architecture tests — no subprocess + no caller-controlled URLs in `protocol/a2a_*`

**Files:**
- Create: `tests/architecture/test_a2a_no_subprocess.py` — static-AST scan of every module under `src/cognic_agentos/protocol/a2a_*.py`. Refuses any `subprocess` / `os.exec*` / `os.spawn*` / `os.posix_spawn*` / `os.system` / `os.popen` / `asyncio.create_subprocess_exec` / `asyncio.create_subprocess_shell` / `multiprocessing.Process` / `shell=True` import or call. Mirrors Sprint-5 T4 `test_mcp_stdio_no_subprocess.py` exactly.
- Create: `tests/architecture/test_a2a_no_caller_controlled_url.py` — static-AST scan asserting that NO module under `protocol/a2a_*` calls `httpx.AsyncClient.{get,post,put,delete}(url=<x>)` where `<x>` is a function parameter of the call site, a request-body field, or a model-output string. Allowed URL sources: literals, `Settings.a2a_*_url` fields, hardcoded well-known suffixes (`/.well-known/agent-card.json`), or values from objects whose type is `AgentCard` (with attribute access path containing `supported_interfaces[*].url`).

**Halt-before-commit:** Yes — the architecture tests ARE the wire-protocol invariants; reviewer pause needed.

- [ ] **Step 1: Write `test_a2a_no_subprocess.py`**

```python
"""Architecture test: refuse subprocess / os.exec* / os.spawn* / etc.
imports + calls in any module under ``src/cognic_agentos/protocol/a2a_*.py``.

Mirrors Sprint-5 ``test_mcp_stdio_no_subprocess.py`` (the static-AST
backstop for ADR-003 + the A2A caller-URL threat model). The runtime
canary in ``tests/unit/protocol/test_a2a_no_caller_controlled_url.py``
(T14) is the runtime complement; both must hold for the threat model
to be intact.

Architecture posture: A2A is a network-only protocol. There is NO
legitimate reason for any ``protocol/a2a_*`` module to spawn a
subprocess. (cosign + OPA subprocess invocations live in
``protocol/trust_gate.py`` + ``core/policy/engine.py`` respectively;
A2A's wire-format work happens entirely inside the Python process
using ``a2a-sdk`` SDK + ``httpx`` + ``python-jose``.)

The 9 banned import / call shapes:

  1. ``import subprocess`` (or ``from subprocess import ...``)
  2. ``import os; os.exec*`` (any `os.exec[lvpe]*` family member)
  3. ``import os; os.spawn*``
  4. ``import os; os.posix_spawn*``
  5. ``import os; os.system``
  6. ``import os; os.popen``
  7. ``import asyncio; asyncio.create_subprocess_exec``
  8. ``import asyncio; asyncio.create_subprocess_shell``
  9. ``import multiprocessing; multiprocessing.Process``

Plus the kwarg form: any function call with ``shell=True``.

Three self-tests pin the collector contract: top-level files,
nested-submodule discovery (future ``protocol/a2a/...`` package), and
renamed-module detection (where ``a2a_`` prefix has been dropped but
``a2a`` survives in the path).
"""
# ... full implementation following Sprint-5 T4 pattern ...
```

(The test body is structurally identical to Sprint-5's `test_mcp_stdio_no_subprocess.py`; the only diffs are the module-path glob (`protocol/a2a_*.py` instead of `protocol/mcp_*.py`) + the docstring + the per-module diagnostic-message names.)

- [ ] **Step 2: Write `test_a2a_no_caller_controlled_url.py`**

```python
"""Architecture test: outbound URLs in protocol/a2a_* MUST come from
verified Agent Cards or operator-controlled settings, NEVER from
function parameters / request bodies / model outputs.

This is the static-AST half of the A2A caller-URL threat model
(``docs/A2A-CALLER-URL-THREAT-MODEL.md``). The runtime half is
``tests/unit/protocol/test_a2a_no_caller_controlled_url.py`` (T14
canary).

The collector walks every module under
``src/cognic_agentos/protocol/a2a_*.py`` and asserts that every
``httpx.AsyncClient.{get,post,put,delete}`` call satisfies one of:

  1. URL is a string literal.
  2. URL is a `Settings.a2a_*_url` attribute access.
  3. URL is a hardcoded well-known suffix concatenated to a verified
     origin (``f"{origin}/.well-known/agent-card.json"`` where
     ``origin`` traces to a verified ``AgentCard.supported_interfaces``).
  4. URL is an attribute access on an ``AgentCard`` typed instance
     (``card.supported_interfaces[i].url``).

Forbidden URL sources (the ban list):

  - Function parameters of the call site (caller-supplied URL).
  - Request-body fields (caller-supplied via inbound A2A request).
  - Model-output strings (LLM-generated URL).
  - Concatenations including any of the above.

Three self-tests pin the collector + the URL-source classifier:
  - test_collector_finds_top_level_a2a_files
  - test_url_source_classifier_rejects_caller_param
  - test_url_source_classifier_accepts_agent_card_attr_access
"""
# ... full implementation ...
```

- [ ] **Step 3: Run; expect PASS** (no a2a_* modules exist yet, so both tests pass vacuously)

```bash
uv run pytest tests/architecture/test_a2a_no_subprocess.py \
              tests/architecture/test_a2a_no_caller_controlled_url.py -v
```
Expected: All pass. The "at least one a2a module exists" sentinel asserts `>= 0` at T4 and tightens to `>= 9` in T16 closeout once all 10 a2a modules have shipped.

- [ ] **Step 4: Halt-before-commit (architecture tests are wire-protocol invariants)**

- [ ] **Step 5: Commit**

```bash
git add tests/architecture/test_a2a_no_subprocess.py \
        tests/architecture/test_a2a_no_caller_controlled_url.py
git commit -m "test(sprint-6): architecture tests banning subprocess + caller-URLs in a2a (T4)"
```

---

## Task 5: `protocol/a2a_authz.py` — per-tenant pinned-token client

**Files:**
- Create: `src/cognic_agentos/protocol/a2a_authz.py` — per-tenant token validator. Mirrors Sprint-5 `mcp_authz.py` shape but A2A-tailored (no PRM, no RFC 8707 — those are MCP/OAuth concepts).
- Create: `tests/unit/protocol/test_a2a_authz.py` — token validation contract (24+ arms covering the 8 closed-enum reasons).

**Halt-before-commit:** Yes — `a2a_authz.py` is on the Sprint-6 critical-controls list (per Doctrine Decision F).

The Sprint-5 `mcp_authz.py` evolved across 14 reviewer rounds (T5 R6-R14). The Sprint-6 `a2a_authz.py` carries those hardenings forward by design — same dataclass shapes, same `__repr__` redaction, same closed-enum reason discipline, same Vault-read exception-mapping pattern (per T15 R1 P2 #2 + #3 from Sprint 5).

- [ ] **Step 1: Write the failing tests first**

```python
# tests/unit/protocol/test_a2a_authz.py — first eight test classes
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.protocol.a2a_authz import (
    A2AAuthzClient,
    A2AAuthzError,
    A2APinnedToken,
)


@pytest.fixture
def vault_client() -> MagicMock:
    mock = MagicMock()
    mock.read = AsyncMock()
    return mock


@pytest.fixture
def settings(...) -> Settings:
    return Settings(a2a_token_cache_ttl_s=300)


@pytest.fixture
async def authz(settings, vault_client) -> A2AAuthzClient:
    return A2AAuthzClient(
        settings=settings,
        vault_client=vault_client,
        audit_store=MagicMock(append=AsyncMock()),
        decision_history_store=MagicMock(append=AsyncMock()),
    )


class TestAnonymousRefused:
    async def test_missing_authorization_header_refused(self, authz):
        with pytest.raises(A2AAuthzError) as exc:
            await authz.validate_inbound_token(
                authorization_header=None,
                tenant_id="bank_a",
                request_id="rid",
            )
        assert exc.value.reason == "a2a_anonymous_refused"


class TestTokenMissing:
    async def test_authorization_header_present_but_no_bearer_prefix(
        self, authz
    ):
        with pytest.raises(A2AAuthzError) as exc:
            await authz.validate_inbound_token(
                authorization_header="Basic abcd",
                tenant_id="bank_a",
                request_id="rid",
            )
        assert exc.value.reason == "a2a_token_missing"


class TestTokenMalformed:
    async def test_bearer_token_with_whitespace_only_value(self, authz):
        with pytest.raises(A2AAuthzError) as exc:
            await authz.validate_inbound_token(
                authorization_header="Bearer    ",
                tenant_id="bank_a",
                request_id="rid",
            )
        assert exc.value.reason == "a2a_token_malformed"


class TestTenantMismatch:
    async def test_token_minted_for_other_tenant_refused(self, authz, vault_client):
        # Vault returns the per-tenant token expected for "bank_a";
        # the request tenant is "bank_b" → mismatch, refused.
        async def _read(path):
            assert "bank_b" in path
            return {"token": "bank-b-token-bytes", "tenant_id": "bank_b"}
        vault_client.read.side_effect = _read

        with pytest.raises(A2AAuthzError) as exc:
            await authz.validate_inbound_token(
                authorization_header="Bearer bank-a-token-bytes",
                tenant_id="bank_b",
                request_id="rid",
            )
        assert exc.value.reason == "a2a_tenant_mismatch"


class TestVaultReadFailedMaps:
    async def test_vault_read_runtime_error_maps_to_token_invalid(
        self, authz, vault_client
    ):
        # Vault adapter exception MUST be wrapped per Sprint-5 T15 R1
        # P2 #2 doctrine — never escape as a raw RuntimeError. Here
        # we map to a2a_vault_read_failed (closed-enum).
        async def _fail(path):
            raise RuntimeError("vault: permission denied")
        vault_client.read.side_effect = _fail

        with pytest.raises(A2AAuthzError) as exc:
            await authz.validate_inbound_token(
                authorization_header="Bearer something",
                tenant_id="bank_a",
                request_id="rid",
            )
        assert exc.value.reason == "a2a_vault_read_failed"
        # Sprint-5 T15 R1 P2 #3: raw exception text MUST NOT leak.
        assert "permission denied" not in str(exc.value)
        assert exc.value.payload.get("vault_error_class") == "RuntimeError"


class TestVaultReadCancellationPropagates:
    async def test_cancelled_error_propagates(self, authz, vault_client):
        async def _cancel(path):
            raise asyncio.CancelledError
        vault_client.read.side_effect = _cancel

        with pytest.raises(asyncio.CancelledError):
            await authz.validate_inbound_token(
                authorization_header="Bearer x",
                tenant_id="bank_a",
                request_id="rid",
            )


class TestTokenRevoked:
    async def test_token_listed_in_revocation_set(self, authz, vault_client):
        # Revocation list lives in the same Vault path as the active
        # token under a `revoked` key. A token whose digest is in
        # the revocation set is refused.
        token = "revoked-token-bytes"
        async def _read(path):
            return {"token": "active-token", "revoked_digests": [
                hashlib.sha256(token.encode()).hexdigest(),
            ]}
        vault_client.read.side_effect = _read

        with pytest.raises(A2AAuthzError) as exc:
            await authz.validate_inbound_token(
                authorization_header=f"Bearer {token}",
                tenant_id="bank_a",
                request_id="rid",
            )
        assert exc.value.reason == "a2a_token_revoked"


class TestTokenAccepted:
    async def test_valid_token_returns_pinned_token(
        self, authz, vault_client
    ):
        async def _read(path):
            return {"token": "active-token", "tenant_id": "bank_a"}
        vault_client.read.side_effect = _read

        result = await authz.validate_inbound_token(
            authorization_header="Bearer active-token",
            tenant_id="bank_a",
            request_id="rid",
        )
        assert isinstance(result, A2APinnedToken)
        assert result.tenant_id == "bank_a"
        # Token-free invariant: __repr__ MUST NOT leak the bytes.
        assert "active-token" not in repr(result)
```

- [ ] **Step 2: Run; expect FAIL** (`ImportError` on every import)

- [ ] **Step 3: Implement `protocol/a2a_authz.py`**

```python
"""protocol/a2a_authz.py — A2A per-tenant pinned-token authorization.

Critical-controls module per AGENTS.md (Sprint-6 amendment, "Protocol
— A2A endpoint" section). Mirrors Sprint-5 ``protocol/mcp_authz.py``
shape: closed-enum reasons, token-free invariant, Vault-read
exception-mapping (per Sprint-5 T15 R1 P2 #2 + #3 doctrine).

Per A2A-CONFORMANCE.md Wave 1: every inbound A2A call requires
``Authorization: Bearer <token>`` against a per-tenant pinned token
read from Vault at ``secret/cognic/<tenant>/a2a-pinned-token``.
mTLS lands in Wave 2; Verifiable Credentials in Wave 3.

The 8-value closed-enum ``A2AAuthzReason`` lives in
``cognic_agentos.protocol.__init__``; this module raises
``A2AAuthzError`` carrying one of those values + a sanitised payload
dict that the registry's audit emission consumes.

Token-free invariant: ``A2APinnedToken.value`` (the raw bytes)
never appears in audit / decision payloads or ``__repr__``. Frozen
+ slotted dataclass disables ``__dict__`` access; custom ``__repr__``
redacts ``value``.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import logging
from typing import Any

from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.config import Settings
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.db.adapters.protocols import SecretAdapter
from cognic_agentos.protocol import A2AAuthzReason

_LOG = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True, slots=True)
class A2APinnedToken:
    """A per-tenant pinned A2A token. Frozen+slotted so the bytes
    can't leak via ``__dict__`` exposure; ``__repr__`` redacts
    ``value``.
    """
    value: str  # raw bearer bytes — NEVER log this
    tenant_id: str
    issued_at: float
    expires_at: float | None  # None for non-expiring pinned tokens

    def __repr__(self) -> str:
        return (
            f"A2APinnedToken(value=<redacted>, tenant_id={self.tenant_id!r}, "
            f"issued_at={self.issued_at}, expires_at={self.expires_at})"
        )


class A2AAuthzError(Exception):
    """A2A authorization failure with closed-enum reason + structured
    payload for audit emission. Per Sprint-5 T15 R1 P2 #3 doctrine,
    raw lower-layer exception text NEVER appears in the message;
    ``type(exc).__name__`` lands in payload only.
    """

    def __init__(self, reason: A2AAuthzReason, message: str = "", **payload: Any) -> None:
        self.reason: A2AAuthzReason = reason
        self.payload: dict[str, Any] = payload
        super().__init__(f"{reason}: {message}" if message else reason)


class A2AAuthzClient:
    """Per-tenant pinned-token validator. Constructor-required:
    ``settings``, ``vault_client``, ``audit_store``,
    ``decision_history_store`` — every method emits chained audit
    rows on every outcome.
    """

    def __init__(
        self,
        *,
        settings: Settings,
        vault_client: SecretAdapter,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
    ) -> None:
        self._settings = settings
        self._vault = vault_client
        self._audit = audit_store
        self._dh = decision_history_store
        # Per-tenant cache: TTL keyed on (tenant_id,). Dropped on
        # rotation event or TTL elapse.
        self._cache: dict[str, A2APinnedToken] = {}

    async def validate_inbound_token(
        self,
        *,
        authorization_header: str | None,
        tenant_id: str,
        request_id: str,
    ) -> A2APinnedToken:
        """Validate an inbound A2A request's Authorization header
        against the per-tenant pinned token. Raises ``A2AAuthzError``
        on any of the 8 closed-enum failure paths.
        """
        if authorization_header is None:
            raise A2AAuthzError(
                "a2a_anonymous_refused",
                "inbound A2A request missing Authorization header",
                tenant_id=tenant_id,
                request_id=request_id,
            )
        if not authorization_header.startswith("Bearer "):
            raise A2AAuthzError(
                "a2a_token_missing",
                "Authorization header present but no Bearer scheme",
                tenant_id=tenant_id,
                request_id=request_id,
            )
        candidate = authorization_header[len("Bearer ") :].strip()
        if not candidate:
            raise A2AAuthzError(
                "a2a_token_malformed",
                "Bearer token is empty / whitespace-only",
                tenant_id=tenant_id,
                request_id=request_id,
            )

        # Vault read with closed-enum exception mapping per Sprint-5
        # T15 R1 P2 #2 doctrine.
        path = f"secret/cognic/{tenant_id}/a2a-pinned-token"
        try:
            secret = await self._vault.read(path)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise A2AAuthzError(
                "a2a_vault_read_failed",
                f"Vault read at {path} failed",
                tenant_id=tenant_id,
                request_id=request_id,
                vault_error_class=type(exc).__name__,
            ) from exc

        if not isinstance(secret, dict):
            raise A2AAuthzError(
                "a2a_vault_read_failed",
                f"Vault secret at {path} is not a mapping",
                tenant_id=tenant_id,
                request_id=request_id,
            )

        # Tenant-mismatch: token's declared tenant != request's.
        # Defends against cross-tenant token reuse.
        secret_tenant = secret.get("tenant_id")
        if secret_tenant is not None and secret_tenant != tenant_id:
            raise A2AAuthzError(
                "a2a_tenant_mismatch",
                f"token's tenant_id ({secret_tenant!r}) does not match request "
                f"tenant_id ({tenant_id!r})",
                tenant_id=tenant_id,
                request_id=request_id,
                token_tenant_id=secret_tenant,
            )

        # Revocation check.
        digest = hashlib.sha256(candidate.encode()).hexdigest()
        revoked = secret.get("revoked_digests", [])
        if isinstance(revoked, list) and digest in revoked:
            raise A2AAuthzError(
                "a2a_token_revoked",
                "token digest matches revocation list entry",
                tenant_id=tenant_id,
                request_id=request_id,
            )

        active = secret.get("token")
        if not isinstance(active, str) or active != candidate:
            raise A2AAuthzError(
                "a2a_token_malformed",
                "candidate token does not match the active per-tenant pinned token",
                tenant_id=tenant_id,
                request_id=request_id,
            )

        return A2APinnedToken(
            value=active,
            tenant_id=tenant_id,
            issued_at=secret.get("issued_at", 0.0),
            expires_at=secret.get("expires_at"),
        )


__all__ = ("A2AAuthzClient", "A2AAuthzError", "A2APinnedToken")
```

- [ ] **Step 4: Run tests; expect PASS**

- [ ] **Step 5: Halt-before-commit (critical-controls module)**

- [ ] **Step 6: Commit**

```bash
git add src/cognic_agentos/protocol/a2a_authz.py \
        tests/unit/protocol/test_a2a_authz.py
git commit -m "feat(sprint-6): A2A per-tenant pinned-token authz client (T5)"
```

---

## Task 6: `protocol/a2a_schema.py` + schema-drift CI gate

**Files:**
- Create: `src/cognic_agentos/protocol/a2a_schema.py` — re-exports the `a2a-sdk` SDK's Pydantic types under stable AgentOS names; includes `_PINNED_PROTOBUF_DIGEST` + `_PINNED_JSON_SCHEMA_DIGEST` constants the drift gate verifies.
- Create: `tests/unit/protocol/test_a2a_schema.py` — schema-type contract (re-export shape, AgentCard / Task / StreamingMessage / Artifact / Cancellation envelope round-tripping through Pydantic).
- Create: `tests/unit/protocol/test_a2a_schema_drift.py` — env-gated CI drift gate. Pulls upstream A2A 1.0 protobuf source AND the spec-published JSON-schema bindings; diffs both against AgentOS's pinned digests. **Skipped by default** (no network in unit suite); fires on the dedicated CI lane below.
- **Modify:** `.github/workflows/python.yml` — **R0 P2 reviewer correction (was missing from the original T6 file list).** Add a new dedicated CI lane named `a2a-spec drift detection`:
  ```yaml
  a2a-spec-drift:
    name: a2a-spec drift detection
    runs-on: ubuntu-latest
    needs: lint-test
    env:
      COGNIC_RUN_A2A_UPSTREAM: "1"
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/setup-python  # same setup as lint-test lane
      - name: Run A2A schema-drift gate
        run: uv run pytest -v -m a2a_upstream tests/unit/protocol/test_a2a_schema_drift.py
  ```
  Without this workflow edit, the env-gated test would skip BOTH locally AND in CI — silently weakening the wire-format conformance gate the plan relies on. The lane runs after `lint-test` so a syntax / type regression doesn't trigger a network probe; it fails the build on actual upstream drift OR on persistent upstream outage (the test distinguishes the two diagnostics per Doctrine Decision C). **Pin marker registration:** also extend `pyproject.toml`'s `[tool.pytest.ini_options].markers` to register `a2a_upstream: env-gated upstream A2A schema drift gate` so pytest doesn't warn on the unknown marker.

**Halt-before-commit:** Yes — `a2a_schema.py` is on the Sprint-6 critical-controls list (wire-format truth — drift = wire-protocol break).

- [ ] **Step 1: Write `protocol/a2a_schema.py`**

```python
"""protocol/a2a_schema.py — pinned A2A 1.0 wire-format types.

Critical-controls module per AGENTS.md (Sprint-6 amendment, "Protocol
— A2A endpoint" section). Wire-format drift = wire-protocol break;
the schema-drift CI gate (test_a2a_schema_drift.py) catches upstream
movement before it reaches us.

Re-exports the ``a2a-sdk`` SDK's Pydantic types under stable
AgentOS names so downstream code keeps working when we bump the SDK
pin. The pinned digests below are checksum-of-the-spec-source-bytes,
captured at the time of the SDK pin (T2). The drift gate compares
upstream's current digest against these constants; on mismatch, the
build fails and a deliberate review + version bump is required.

Pinned A2A spec version: ``1.0`` (April 2026 release, Linux-Foundation
governance). Bumping the pinned version is a deliberate reviewed
change (per Sprint-6 Decision Lock #1).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from a2a.types import (
        AgentCard,
        Task,
        StreamingMessage,
        Artifact,
        CancellationRequest,
        ErrorResponse,
    )

# Lazy import — admission-side modules (a2a_authz, etc.) construct
# without the SDK; this import only fires when the registry actually
# calls into a2a_schema for wire-format work.
def _types():
    from a2a.types import (
        AgentCard,
        Task,
        StreamingMessage,
        Artifact,
        CancellationRequest,
        ErrorResponse,
    )
    return AgentCard, Task, StreamingMessage, Artifact, CancellationRequest, ErrorResponse


#: SHA-256 of the upstream A2A 1.0 protobuf source bundle (the
#: a2a.proto + agent_card.proto + task.proto file set distributed
#: by the spec authors). Captured at SDK pin time (T2).
_PINNED_PROTOBUF_DIGEST: str = "0" * 64  # placeholder — populated at T2 commit time

#: SHA-256 of the upstream A2A 1.0 JSON-schema binding bundle.
_PINNED_JSON_SCHEMA_DIGEST: str = "0" * 64  # placeholder — populated at T2 commit time

#: Upstream URL where the spec authors publish the canonical
#: protobuf + JSON-schema bundles. Pinned in source so the drift
#: gate has an unambiguous fetch target.
_UPSTREAM_PROTOBUF_URL: str = "https://a2a-protocol.org/spec/1.0/a2a.proto"
_UPSTREAM_JSON_SCHEMA_URL: str = "https://a2a-protocol.org/spec/1.0/json-schema-bindings.json"


def get_pinned_spec_version() -> str:
    """The pinned A2A spec version. Single source of truth for any
    code that needs to assert spec compliance."""
    return "1.0"
```

- [ ] **Step 2: Write the schema-drift CI gate**

```python
"""Schema-drift CI gate. Pulls upstream A2A 1.0 protobuf source AND
the spec-published JSON-schema bindings; diffs both against the
pinned digests in protocol/a2a_schema.py.

Env-gated per Sprint-6 Doctrine Decision C: the test only runs when
``COGNIC_RUN_A2A_UPSTREAM=1`` is set. CI sets it; local dev skips
by default (saves network round-trip on every test run). Mirrors
Sprint-4 ``cosign_real`` env-gate pattern.

If the upstream digest moves beyond the pinned digest, this test
fails and a deliberate review + version bump is required (per
Sprint-6 Decision Lock #1). Silent upstream upgrades are forbidden.
"""

from __future__ import annotations

import hashlib
import os

import httpx
import pytest

from cognic_agentos.protocol.a2a_schema import (
    _PINNED_JSON_SCHEMA_DIGEST,
    _PINNED_PROTOBUF_DIGEST,
    _UPSTREAM_JSON_SCHEMA_URL,
    _UPSTREAM_PROTOBUF_URL,
)

pytestmark = pytest.mark.skipif(
    os.environ.get("COGNIC_RUN_A2A_UPSTREAM") != "1",
    reason=(
        "live A2A upstream schema check; opt in via "
        "COGNIC_RUN_A2A_UPSTREAM=1 (CI sets this; local dev skips "
        "to save network round-trip on every test run)"
    ),
)


@pytest.mark.a2a_upstream
async def test_pinned_protobuf_digest_matches_upstream() -> None:
    """The pinned protobuf-bundle digest in
    ``protocol/a2a_schema.py`` MUST match the SHA-256 of the bytes
    upstream is publishing right now. If upstream moves, the build
    fails and a Sprint-N reviewer + version-bump pass is required.
    """
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(_UPSTREAM_PROTOBUF_URL)
        resp.raise_for_status()
        upstream_digest = hashlib.sha256(resp.content).hexdigest()

    assert upstream_digest == _PINNED_PROTOBUF_DIGEST, (
        f"A2A 1.0 protobuf source has drifted from pin.\n"
        f"  Pinned: {_PINNED_PROTOBUF_DIGEST}\n"
        f"  Upstream: {upstream_digest}\n"
        f"  URL: {_UPSTREAM_PROTOBUF_URL}\n"
        f"\n"
        f"Action: review the upstream change; if accepted, bump the pin "
        f"in protocol/a2a_schema.py with an explicit changelog entry. "
        f"Silent upgrades are forbidden per Sprint-6 Decision Lock #1."
    )


@pytest.mark.a2a_upstream
async def test_pinned_json_schema_digest_matches_upstream() -> None:
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(_UPSTREAM_JSON_SCHEMA_URL)
        resp.raise_for_status()
        upstream_digest = hashlib.sha256(resp.content).hexdigest()

    assert upstream_digest == _PINNED_JSON_SCHEMA_DIGEST, (
        f"A2A 1.0 JSON-schema bindings have drifted from pin.\n"
        f"  Pinned: {_PINNED_JSON_SCHEMA_DIGEST}\n"
        f"  Upstream: {upstream_digest}\n"
        f"  URL: {_UPSTREAM_JSON_SCHEMA_URL}\n"
    )


@pytest.mark.a2a_upstream
async def test_protobuf_and_json_schema_bindings_have_parity() -> None:
    """Catches upstream drift the spec authors haven't yet
    republished: if the protobuf source has moved but the JSON-schema
    bundle hasn't (or vice versa), our pinned types may be in
    inconsistent state.
    """
    async with httpx.AsyncClient(timeout=30) as client:
        proto_resp = await client.get(_UPSTREAM_PROTOBUF_URL)
        json_resp = await client.get(_UPSTREAM_JSON_SCHEMA_URL)
        proto_resp.raise_for_status()
        json_resp.raise_for_status()

    # The parity check is structural: every protobuf message type
    # MUST have a corresponding JSON-schema definition. Implementation
    # detail of "structural" is owned by the SDK + this test's helper.
    from cognic_agentos.protocol.a2a_schema_parity import (
        check_protobuf_json_schema_parity,
    )
    check_protobuf_json_schema_parity(
        protobuf_bytes=proto_resp.content,
        json_schema_bytes=json_resp.content,
    )
```

- [ ] **Step 3: Implement the parity helper module**

```python
"""protocol/a2a_schema_parity.py — protobuf vs JSON-schema parity.

Helper module for test_a2a_schema_drift.py. Walks both bundles and
asserts every protobuf message type has a matching JSON-schema
definition + every JSON-schema definition has a matching protobuf
message type. Catches the case where upstream's two bindings have
diverged but the spec authors haven't yet republished.
"""
# ... implementation walks both and asserts parity ...
```

- [ ] **Step 4: Run drift gate locally without env-var; expect SKIP**

```bash
uv run pytest tests/unit/protocol/test_a2a_schema_drift.py -v
```
Expected: skipped (3 tests).

- [ ] **Step 5: Run drift gate with env-var; expect PASS**

```bash
COGNIC_RUN_A2A_UPSTREAM=1 uv run pytest tests/unit/protocol/test_a2a_schema_drift.py -v
```
Expected: 3 passed (assuming the digests have been captured at SDK pin time).

- [ ] **Step 6: Halt-before-commit + commit**

```bash
git add src/cognic_agentos/protocol/a2a_schema.py \
        src/cognic_agentos/protocol/a2a_schema_parity.py \
        tests/unit/protocol/test_a2a_schema.py \
        tests/unit/protocol/test_a2a_schema_drift.py
git commit -m "feat(sprint-6): A2A 1.0 wire-format types + drift CI gate (T6)"
```

---

## Task 7: `protocol/a2a_agent_cards.py` — two-pass validator + JWS verify

**Files:**
- Create: `src/cognic_agentos/protocol/a2a_agent_cards.py` — Agent Card publisher + verifier.
- Modify: `src/cognic_agentos/protocol/trust_gate.py` — additive `verify_jws_blob(...)` method (reuses Sprint-4 per-tenant trust root).
- Create: `tests/unit/protocol/test_a2a_agent_cards.py` — two-pass validator contract.
- Create: `tests/unit/protocol/test_a2a_agent_card_jws_required.py` — registration refused on unsigned / non-allow-listed signer.
- Create: `tests/unit/protocol/test_a2a_agent_card_outbound_verification.py` — outbound dispatch verifies the target's card before sending.
- Create: `tests/unit/protocol/test_a2a_agent_card_chain_audit.py` — card content hash-chained at registration; subsequent mutations require re-registration.

**Halt-before-commit:** Yes (TWO critical-controls modules touched: `a2a_agent_cards.py` AND `trust_gate.py`).

The two-pass validation per A2A-CONFORMANCE.md:
- **Pass 1 (upstream A2A 1.0 schema)** — card must be a legitimate A2A 1.0 card (validates against the SDK's `AgentCard` Pydantic type derived from upstream protobuf). A card with top-level `url` (forbidden by spec — URLs live in `supportedInterfaces[].url`) → fail. A card with Cognic-specific identity fields (`agent_id`, `oasf_capability_set`, etc.) at the top level → fail (those live in pack manifest's `[tool.cognic.identity]` block).
- **Pass 2 (AgentOS bank-grade profile)** — spec-optional fields AgentOS makes mandatory: `provider`, `securitySchemes`, `securityRequirements`, `signatures`, ≥1 `supportedInterfaces` entry. Failures return `agentos_profile_violation` with the specific mandatory field listed (distinct from upstream-schema failures so authors can diagnose without confusing the two layers).

JWS verification:
- **Inbound (pack registration)** — pack manifest declares `agent_card_jws_path`. Trust gate verifies JWS against per-tenant trust root. Unsigned card or signer not on the trust root → registration refused with `a2a_agent_card_signature_invalid`.
- **Outbound (calling a remote agent)** — fetch target's `/.well-known/agent-card.json`, fetch detached JWS, verify against trust root. Verification failure → call refused with `agent_card_signature_invalid`. Endpoint URL the call dispatches to comes from the verified card's `supportedInterfaces[].url` — never a caller-supplied URL.

- [ ] **Step 1-7: Iteratively write tests + implementation** mirroring the Sprint-5 T6 R1-R6 reviewer-round shape. Each test class focuses on one validation gate (anonymous / spec-shape / profile / JWS / outbound).

Skeleton of the implementation:

```python
"""protocol/a2a_agent_cards.py — Agent Card publisher + verifier.

Critical-controls module per AGENTS.md (Sprint-6 amendment).

Two-pass validation per docs/A2A-CONFORMANCE.md:
  Pass 1 — upstream A2A 1.0 schema (via a2a-sdk Python package)
  Pass 2 — AgentOS bank-grade profile

JWS verification rides Sprint-4 trust gate's per-tenant trust root.
Both inbound (registration) and outbound (call dispatch) paths
verify before proceeding.

Closed-enum AgentCardValidationReason (7 values) lives in
cognic_agentos.protocol.__init__.
"""

from __future__ import annotations

import dataclasses
import logging
from pathlib import Path
from typing import Any

import httpx

from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.config import Settings
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.protocol import AgentCardValidationReason
from cognic_agentos.protocol.trust_gate import TrustGate

_LOG = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True, slots=True)
class AgentCardValidation:
    ok: bool
    reason: AgentCardValidationReason | None
    payload: dict[str, Any]


class A2AAgentCardError(Exception):
    """Raised by the verifier on outbound dispatch when the target's
    card cannot be verified. Carries closed-enum reason +
    sanitised payload (no raw exception text per Sprint-5 T15 R1
    P2 #3 doctrine).
    """


class A2AAgentCardVerifier:
    """Two-pass validator + JWS-verifier. Used by the registry at
    pack registration AND by ``A2AEndpoint.dispatch_outbound`` at
    call time.
    """

    def __init__(
        self,
        *,
        settings: Settings,
        trust_gate: TrustGate,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
        http_client: httpx.AsyncClient,
    ) -> None:
        self._settings = settings
        self._trust_gate = trust_gate
        self._audit = audit_store
        self._dh = decision_history_store
        self._http = http_client

    async def validate_card(
        self,
        *,
        card_bytes: bytes,
        jws_bytes: bytes,
        tenant_id: str,
        request_id: str,
    ) -> AgentCardValidation:
        """Two-pass validation + JWS verification. Returns
        ``AgentCardValidation(ok=True, reason=None, payload={})`` on
        success; closed-enum refusal otherwise.
        """
        # Size cap defends against DoS via large-blob signature
        # verification (per Sprint-6 T1 a2a_card_jws_max_size_bytes).
        if len(jws_bytes) > self._settings.a2a_card_jws_max_size_bytes:
            return AgentCardValidation(
                ok=False,
                reason="agent_card_upstream_schema_invalid",
                payload={
                    "field": "jws",
                    "size_bytes": len(jws_bytes),
                    "max_bytes": self._settings.a2a_card_jws_max_size_bytes,
                },
            )

        # JWS verification (Sprint-4 trust gate handles the keystore +
        # signer-allow-list lookup).
        try:
            await self._trust_gate.verify_jws_blob(
                jws_bytes=jws_bytes,
                payload_bytes=card_bytes,
                tenant_id=tenant_id,
            )
        except Exception as exc:
            return AgentCardValidation(
                ok=False,
                reason="agent_card_upstream_schema_invalid",
                payload={
                    "jws_error_class": type(exc).__name__,
                },
            )

        # Pass 1: upstream A2A 1.0 schema validation (delegates to
        # a2a-sdk Python package).
        from a2a.types import AgentCard
        try:
            card = AgentCard.model_validate_json(card_bytes)
        except Exception as exc:
            return AgentCardValidation(
                ok=False,
                reason="agent_card_upstream_schema_invalid",
                payload={
                    "error_type": type(exc).__name__,
                },
            )

        # Spec-violation: top-level url MUST NOT be present.
        # The SDK's Pydantic type rejects it but defensive double-check.
        card_dict = card.model_dump()
        if "url" in card_dict:
            return AgentCardValidation(
                ok=False,
                reason="agent_card_profile_top_level_url_forbidden",
                payload={"forbidden_field": "url"},
            )

        # Pass 2: AgentOS bank-grade profile.
        if not card.provider:
            return AgentCardValidation(
                ok=False,
                reason="agent_card_profile_provider_missing",
                payload={"required_field": "provider"},
            )
        if not card.security_schemes:
            return AgentCardValidation(
                ok=False,
                reason="agent_card_profile_security_schemes_missing",
                payload={"required_field": "securitySchemes"},
            )
        if not card.security_requirements:
            return AgentCardValidation(
                ok=False,
                reason="agent_card_profile_security_requirements_missing",
                payload={"required_field": "securityRequirements"},
            )
        if not card.signatures:
            return AgentCardValidation(
                ok=False,
                reason="agent_card_profile_signatures_missing",
                payload={"required_field": "signatures"},
            )
        if not card.supported_interfaces:
            return AgentCardValidation(
                ok=False,
                reason="agent_card_profile_supported_interfaces_empty",
                payload={"required_field": "supportedInterfaces"},
            )

        return AgentCardValidation(ok=True, reason=None, payload={})

    async def fetch_and_verify_outbound_card(
        self,
        *,
        target_origin: str,
        tenant_id: str,
        request_id: str,
    ) -> "AgentCard":
        """Outbound dispatch path. Fetches the target's
        ``/.well-known/agent-card.json`` + detached JWS file from
        the same origin; verifies via :meth:`validate_card`; returns
        the verified ``AgentCard`` Pydantic instance whose
        ``supported_interfaces[].url`` is the SAFE source of the
        outbound dispatch URL.

        The endpoint URL the call dispatches to comes from the
        VERIFIED card's ``supportedInterfaces[].url`` — never a
        caller-supplied URL. This is the runtime backstop for the
        T4 architecture test + T14 canary.
        """
        card_url = f"{target_origin.rstrip('/')}/.well-known/agent-card.json"
        jws_url = f"{target_origin.rstrip('/')}/.well-known/agent-card.json.jws"

        timeout = self._settings.a2a_outbound_request_timeout_s
        card_resp = await self._http.get(card_url, timeout=timeout)
        jws_resp = await self._http.get(jws_url, timeout=timeout)

        if card_resp.status_code != 200 or jws_resp.status_code != 200:
            raise A2AAgentCardError(
                f"agent card fetch failed at {card_url} "
                f"(card={card_resp.status_code}, jws={jws_resp.status_code})"
            )

        validation = await self.validate_card(
            card_bytes=card_resp.content,
            jws_bytes=jws_resp.content,
            tenant_id=tenant_id,
            request_id=request_id,
        )
        if not validation.ok:
            raise A2AAgentCardError(
                f"agent_card_signature_invalid: {validation.reason}",
            )

        from a2a.types import AgentCard
        return AgentCard.model_validate_json(card_resp.content)
```

- [ ] **Step 8: Add `verify_jws_blob` to Sprint-4 trust gate (additive, halt-before-commit)**

```python
# src/cognic_agentos/protocol/trust_gate.py — append method to TrustGate

async def verify_jws_blob(
    self,
    *,
    jws_bytes: bytes,
    payload_bytes: bytes,
    tenant_id: str,
) -> None:
    """Verify a detached JWS over an arbitrary payload using the
    per-tenant cosign trust root. Reused by Sprint-6
    A2AAgentCardVerifier; same trust authority that signs the wheel
    signs the Agent Card.

    Raises ``TrustGateError`` on:
      - JWS parse failure
      - signature verification failure
      - signer not on per-tenant allow-list

    Implementation detail: walks the JWS protected header, resolves
    the signer's public key from the per-tenant cosign trust root
    (re-using the same Vault path as cosign verification), then
    delegates to ``python-jose`` for cryptographic verification.

    Mirrors the Sprint-4 cosign-subprocess invocation's secure-default
    posture: explicit timeout, no shell, no fallthrough on key
    resolution.
    """
    # ... full implementation ...
```

- [ ] **Step 9: Halt-before-commit + commit**

```bash
git add src/cognic_agentos/protocol/a2a_agent_cards.py \
        src/cognic_agentos/protocol/trust_gate.py \
        tests/unit/protocol/test_a2a_agent_cards.py \
        tests/unit/protocol/test_a2a_agent_card_jws_required.py \
        tests/unit/protocol/test_a2a_agent_card_outbound_verification.py \
        tests/unit/protocol/test_a2a_agent_card_chain_audit.py
git commit -m "feat(sprint-6): A2A Agent Card two-pass validator + JWS verify (T7)"
```

---

## Task 8: `protocol/a2a_version.py` — `A2A-Version` header negotiation

**Files:**
- Create: `src/cognic_agentos/protocol/a2a_version.py` — header parser + responder.
- Create: `tests/unit/protocol/test_a2a_version.py` — 6-case matrix.

**Halt-before-commit:** No (not on the critical-controls list — pure parsing module; the gating happens at `A2AEndpoint` which IS critical-controls).

The 6 cases per ADR-003 §"Version negotiation":
1. `A2A-Version: 1.0` — accepted (matches pinned version).
2. Header absent — **rejected** with `Supported-A2A-Versions: 1.0` (per spec, absent header = `0.3` which we don't speak; per Decision Lock #1 we don't silent-upgrade).
3. `A2A-Version: 0.x` — rejected with `Supported-A2A-Versions: 1.0`.
4. `A2A-Version: 1.<higher minor>` (e.g. `1.1`) — accepted with feature-degradation warning emitted.
5. `A2A-Version: 2.x` (or any unknown major) — rejected with `Supported-A2A-Versions: 1.0`.
6. Header malformed — rejected with spec-defined `parse_error`.

```python
"""protocol/a2a_version.py — A2A-Version HTTP header negotiation.

Per ADR-003 §"Version negotiation" + docs/A2A-CONFORMANCE.md
§"Versioning". Pure parsing module; the gating happens at
A2AEndpoint.handle (critical-controls) which calls into this module.

Closed-enum A2AVersionOutcome lives in protocol/__init__.py (6
values: accepted, absent_rejected, legacy_rejected,
higher_minor_degraded, unsupported_rejected, malformed_rejected).
"""

from __future__ import annotations

import dataclasses
import re
from typing import Final

from cognic_agentos.protocol import A2AVersionOutcome

#: Pinned A2A spec version. Kept here as a Final string so callers
#: that don't want to pull Settings (e.g. test fixtures) can import
#: it directly. Single source of truth in production is
#: Settings.a2a_pinned_spec_version, which defaults to this.
PINNED_VERSION: Final[str] = "1.0"

#: Header pattern: optional whitespace, version-string, optional
#: whitespace. Version-string is two integers separated by a dot.
_VERSION_PATTERN = re.compile(r"^\s*(\d+)\.(\d+)\s*$")


@dataclasses.dataclass(frozen=True, slots=True)
class A2AVersionDecision:
    outcome: A2AVersionOutcome
    parsed_major: int | None  # None on absent / malformed
    parsed_minor: int | None
    response_header_value: str  # always "1.0" for AgentOS


def negotiate_inbound_version(
    *,
    a2a_version_header: str | None,
    pinned_major: int = 1,
    pinned_minor: int = 0,
) -> A2AVersionDecision:
    """Parse + classify an inbound ``A2A-Version`` header. Returns
    a :class:`A2AVersionDecision` the caller (``A2AEndpoint``) uses
    to either proceed (``accepted`` / ``higher_minor_degraded``) or
    refuse with a 400-class response carrying the right error code +
    ``Supported-A2A-Versions: 1.0`` header.
    """
    response_header = f"{pinned_major}.{pinned_minor}"

    # Case 2: header absent.
    if a2a_version_header is None:
        return A2AVersionDecision(
            outcome="absent_rejected",
            parsed_major=None,
            parsed_minor=None,
            response_header_value=response_header,
        )

    match = _VERSION_PATTERN.fullmatch(a2a_version_header)
    if match is None:
        # Case 6: malformed.
        return A2AVersionDecision(
            outcome="malformed_rejected",
            parsed_major=None,
            parsed_minor=None,
            response_header_value=response_header,
        )

    major = int(match.group(1))
    minor = int(match.group(2))

    # Case 3: legacy (0.x).
    if major == 0:
        return A2AVersionDecision(
            outcome="legacy_rejected",
            parsed_major=major,
            parsed_minor=minor,
            response_header_value=response_header,
        )

    # Case 1: exact match.
    if major == pinned_major and minor == pinned_minor:
        return A2AVersionDecision(
            outcome="accepted",
            parsed_major=major,
            parsed_minor=minor,
            response_header_value=response_header,
        )

    # Case 4: higher minor (same major).
    if major == pinned_major and minor > pinned_minor:
        return A2AVersionDecision(
            outcome="higher_minor_degraded",
            parsed_major=major,
            parsed_minor=minor,
            response_header_value=response_header,
        )

    # Case 5: any other version (incl. 2.x or 1.<lower minor>).
    return A2AVersionDecision(
        outcome="unsupported_rejected",
        parsed_major=major,
        parsed_minor=minor,
        response_header_value=response_header,
    )


def outbound_version_header() -> str:
    """The ``A2A-Version`` value AgentOS includes on every outbound
    A2A call. Always the pinned version; bumping is a deliberate
    reviewed change tied to the schema-drift CI gate.
    """
    return PINNED_VERSION
```

Tests cover all 6 cases plus boundary forms (whitespace tolerance, multi-digit minors, leading zeros, negative numbers, malformed strings like "1" or "1.0.0").

- [ ] **Step 1-3: Write tests, implement, verify, commit.**

```bash
git commit -m "feat(sprint-6): A2A-Version header negotiation (T8)"
```

---

## Task 9: `protocol/a2a_endpoint.py` — inbound receiver + task lifecycle + chain linkage

**Files:**
- Create: `src/cognic_agentos/protocol/a2a_endpoint.py` — single owner of the inbound A2A receiver.
- Create: `tests/unit/protocol/test_a2a_endpoint.py` — 30+ arms covering routing / lifecycle / chain linkage / anonymous refusal / unknown target / version negotiation rejection paths.
- Create: `tests/unit/protocol/test_a2a_unknown_target.py` — focused unknown-target → 501 + ADR-002 reference.
- Create: `tests/unit/protocol/test_a2a_anonymous_refused.py` — focused anonymous → 401 + `a2a_anonymous_refused`.
- Create: `tests/unit/protocol/test_a2a_chain_audit.py` — parent + 3 child messages → cross-agent chain proof.

**Halt-before-commit:** Yes — `a2a_endpoint.py` is the single owner of the task-lifecycle state machine + chain linkage; reviewer pause needed.

Task lifecycle state machine: `created → running → succeeded | failed | cancelled`. Single owner; transitions are single-writer (the endpoint). Audit emission on every transition: `a2a.task_received` (created), `a2a.task_running`, `a2a.task_succeeded`, `a2a.task_failed`, `a2a.task_cancelled`.

Chain linkage: every inbound message gets a `parent_trace_id` (from caller) + a fresh `child_trace_id`; the audit row carries both so the cross-agent chain is walkable end-to-end. Mirrors Sprint-2's hash-chain primitives (single-writer, content-addressed) extended across the A2A boundary.

Routing: target identification by entry-point name → plugin registry lookup → dispatch to the agent pack's `handle(message)` method. Unknown target → 501 with ADR-002 reference. Anonymous call (no `Authorization` header) → 401 with `a2a_anonymous_refused`.

```python
"""protocol/a2a_endpoint.py — A2A inbound receiver + task lifecycle.

Critical-controls module per AGENTS.md (Sprint-6 amendment, "Protocol
— A2A endpoint" section). Single owner of the task-lifecycle state
machine + chain linkage across the A2A boundary.

Per ADR-003: incoming messages identify the target agent by entry-
point name; the endpoint resolves via the plugin registry and
dispatches to the agent pack's ``handle(message)`` method.

Task lifecycle (state machine — single-writer, single-owner):
    created → running → succeeded | failed | cancelled

Chain linkage: every inbound message carries the caller's
``parent_trace_id``; the endpoint mints a fresh ``child_trace_id``;
both flow into ``decision_history.a2a_call`` rows so the cross-agent
chain is walkable end-to-end.

Routing safety:
  - Anonymous calls refused with ``a2a_anonymous_refused`` (per
    Sprint-6 Decision Lock #3).
  - Unknown target → 501 with ADR-002 reference.
  - Wave-2 features → ``wave2_feature_refused`` per Decision Lock #2.
  - Outbound dispatch URLs come ONLY from JWS-verified Agent Cards
    (Decision Lock #4 + Doctrine Decision B).
"""

from __future__ import annotations

import dataclasses
import enum
import logging
import time
import uuid
from typing import Any

from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.config import Settings
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.protocol import A2AErrorCode
from cognic_agentos.protocol.a2a_agent_cards import A2AAgentCardVerifier
from cognic_agentos.protocol.a2a_authz import A2AAuthzClient, A2AAuthzError
from cognic_agentos.protocol.a2a_version import (
    A2AVersionDecision,
    negotiate_inbound_version,
)
from cognic_agentos.protocol.plugin_registry import PluginRegistry

_LOG = logging.getLogger(__name__)


class TaskState(enum.Enum):
    CREATED = "created"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclasses.dataclass(slots=True)
class TaskRecord:
    task_id: str
    target_agent: str
    parent_trace_id: str
    child_trace_id: str
    state: TaskState
    created_at: float
    updated_at: float
    payload_digest: str  # SHA-256 of the inbound payload bytes
    response_payload_digest: str | None = None
    error_code: A2AErrorCode | None = None


class A2AEndpointError(Exception):
    """Inbound A2A handling failures with closed-enum spec error
    codes."""

    def __init__(self, code: A2AErrorCode, message: str = "", **payload: Any) -> None:
        self.code: A2AErrorCode = code
        self.payload: dict[str, Any] = payload
        super().__init__(f"{code}: {message}" if message else code)


class A2AEndpoint:
    """Single owner of the A2A inbound receiver + task lifecycle.

    Critical-controls invariants:
      - Single-writer for ``TaskState`` transitions (no concurrent
        mutation; the in-process task store is asyncio-lock-protected).
      - Audit emission on every transition (``a2a.task_*`` events).
      - Decision-history mirror of every transition (parallel to the
        audit row, same canonical payload via ``_emit_a2a_evidence``
        helper mirroring Sprint-5's ``_emit_call_evidence``).
      - Anonymous refusal (every call requires ``A2AAuthzClient``
        validation).
      - Wave-2 feature refusal (push notification subscribe / multi-
        modal payloads / long-running task resumption all refused
        with ``wave2_feature_refused``).
    """

    def __init__(
        self,
        *,
        settings: Settings,
        plugin_registry: PluginRegistry,
        authz_client: A2AAuthzClient,
        agent_card_verifier: A2AAgentCardVerifier,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
    ) -> None:
        self._settings = settings
        self._registry = plugin_registry
        self._authz = authz_client
        self._cards = agent_card_verifier
        self._audit = audit_store
        self._dh = decision_history_store
        self._tasks: dict[str, TaskRecord] = {}

    async def handle(
        self,
        *,
        target_agent: str,
        payload: bytes,
        authorization_header: str | None,
        a2a_version_header: str | None,
        parent_trace_id: str | None,
        tenant_id: str,
        request_id: str,
    ) -> dict[str, Any]:
        """Inbound entry point. Walks the gates in order:

        1. Version negotiation (``A2A-Version`` header).
        2. Authentication (per-tenant pinned token).
        3. Routing (target agent → plugin registry).
        4. Wave-2-feature refusal (if applicable).
        5. Task creation + dispatch.
        6. Lifecycle transition emit.

        Raises ``A2AEndpointError`` with one of the closed-enum
        spec codes on any failure path; never raises a raw exception.
        """
        # Gate 1: version negotiation.
        version_decision = negotiate_inbound_version(
            a2a_version_header=a2a_version_header,
        )
        if version_decision.outcome != "accepted" and \
           version_decision.outcome != "higher_minor_degraded":
            raise A2AEndpointError(
                "version_not_supported",
                f"A2A version negotiation refused: {version_decision.outcome}",
                outcome=version_decision.outcome,
                supported=version_decision.response_header_value,
            )

        # Gate 2: authentication.
        try:
            await self._authz.validate_inbound_token(
                authorization_header=authorization_header,
                tenant_id=tenant_id,
                request_id=request_id,
            )
        except A2AAuthzError as exc:
            # Map closed-enum AuthzReason → spec error code.
            spec_code: A2AErrorCode = (
                "anonymous_refused"
                if exc.reason == "a2a_anonymous_refused"
                else "tenant_token_invalid"
            )
            raise A2AEndpointError(
                spec_code,
                exc.payload.get("message", str(exc.reason)),
                authz_reason=exc.reason,
            ) from exc

        # Gate 3: routing.
        agent = self._registry.get_agent(target_agent)
        if agent is None:
            raise A2AEndpointError(
                "unknown_target",
                f"target agent {target_agent!r} not registered (per ADR-002 plugin registry)",
                target_agent=target_agent,
            )

        # Gate 4: lifecycle.
        task = self._create_task(
            target_agent=target_agent,
            parent_trace_id=parent_trace_id or str(uuid.uuid4()),
            payload=payload,
            request_id=request_id,
            tenant_id=tenant_id,
        )

        # Dispatch.
        try:
            response = await agent.handle(payload, task=task)
            self._transition(task, TaskState.SUCCEEDED, response_digest=response.get("digest"))
            return response
        except Exception as exc:
            self._transition(task, TaskState.FAILED, error=type(exc).__name__)
            raise A2AEndpointError(
                "task_not_found",  # placeholder — real impl maps richer
                "agent handler raised",
                error_type=type(exc).__name__,
            ) from exc

    def _create_task(
        self,
        *,
        target_agent: str,
        parent_trace_id: str,
        payload: bytes,
        request_id: str,
        tenant_id: str,
    ) -> TaskRecord:
        # ... task creation + audit emit ...
        ...

    def _transition(
        self,
        task: TaskRecord,
        new_state: TaskState,
        *,
        response_digest: str | None = None,
        error: str | None = None,
    ) -> None:
        # ... single-writer transition + audit/dh emit ...
        ...
```

- [ ] **Step 1-7: Iteratively build out the gates with R1-R6 reviewer-round shape** mirroring Sprint-5 T9 R1-R5 hardening.

- [ ] **Step 8: Halt-before-commit + commit**

```bash
git commit -m "feat(sprint-6): A2A inbound endpoint + task lifecycle + chain linkage (T9)"
```

---

## Task 10: `protocol/a2a_streaming.py` — A2A 1.0 task streaming protocol support

**Files:**
- Create: `src/cognic_agentos/protocol/a2a_streaming.py` — A2A 1.0 streaming-message protocol support per the spec wire format. Emits `task.progress` / `task.completed` / `task.failed` envelopes per A2A 1.0; chain-linked into decision_history via `_emit_streaming_evidence` helper.
- Create: `tests/unit/protocol/test_a2a_streaming.py` — streaming envelope contract; chain linkage; chunked-transfer interop with `httpx`.

**Halt-before-commit:** No (not on the critical-controls list — but see the explicit distinction from Sprint-7B UI SSE).

**This is A2A wire-protocol streaming, NOT portal/UI SSE.** Per ADR-020 §"Implementation phases", the portal/UI SSE endpoint (`GET /api/v1/ui/runs/{run_id}/events`) lands in Sprint 7B. The two are distinct surfaces:

| Surface | Sprint | Module | Protocol | Consumers |
|---|---|---|---|---|
| **A2A task streaming** | **Sprint 6 (this task)** | `protocol/a2a_streaming.py` | A2A 1.0 spec wire format (chunked HTTP w/ A2A streaming envelopes) | Other agents calling our A2A endpoint |
| **UI event-stream SSE** | Sprint 7B | `protocol/ui_events_sse.py` (future) | W3C Server-Sent Events (`text/event-stream` + `Last-Event-Id` cursor) | Portal UIs subscribing to run-state events |

The A2A streaming envelope is a spec-defined data format; SSE is a transport. The two might both ride chunked-transfer over HTTP but their wire formats are different and their consumers are different. Sprint 6 ships ONLY the A2A streaming protocol.

```python
"""protocol/a2a_streaming.py — A2A 1.0 task streaming protocol support.

NOT portal/UI SSE — that's Sprint 7B per ADR-020 §"Implementation
phases". Distinct surfaces: A2A streaming is the spec wire-protocol
between agents; UI SSE is the portal-side transport between AgentOS
and a UI subscriber. This module ONLY implements A2A's spec format.

Per A2A 1.0 §streaming-messages, a task declared ``streaming = true``
in its manifest emits envelopes during execution:

  - task.progress — interim partial-result / status update
  - task.completed — final success envelope (terminates the stream)
  - task.failed — error envelope (terminates the stream)

Each envelope carries a sequence number, the task ID, the A2A
version header echo, and an optional chunk payload. Chain-linked
into decision_history via ``_emit_streaming_evidence`` mirroring
Sprint-5's ``_emit_call_evidence`` shape.
"""

from __future__ import annotations

import dataclasses
import logging
from collections.abc import AsyncIterator
from typing import Any

from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.decision_history import DecisionHistoryStore

_LOG = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True, slots=True)
class StreamingEnvelope:
    sequence: int
    task_id: str
    envelope_type: str  # "task.progress" | "task.completed" | "task.failed"
    payload: dict[str, Any] | None
    a2a_version: str  # "1.0"


class A2AStreamingEmitter:
    """Spec-compliant A2A 1.0 task streaming emitter. The endpoint
    holds an instance per active streaming task; envelopes are
    yielded back to the caller via ``httpx`` chunked-transfer.
    """

    def __init__(
        self,
        *,
        task_id: str,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
    ) -> None:
        self._task_id = task_id
        self._audit = audit_store
        self._dh = decision_history_store
        self._sequence = 0

    async def emit_progress(self, payload: dict[str, Any]) -> StreamingEnvelope:
        self._sequence += 1
        env = StreamingEnvelope(
            sequence=self._sequence,
            task_id=self._task_id,
            envelope_type="task.progress",
            payload=payload,
            a2a_version="1.0",
        )
        await self._emit_streaming_evidence(env)
        return env

    async def emit_completed(self, payload: dict[str, Any]) -> StreamingEnvelope:
        self._sequence += 1
        env = StreamingEnvelope(
            sequence=self._sequence,
            task_id=self._task_id,
            envelope_type="task.completed",
            payload=payload,
            a2a_version="1.0",
        )
        await self._emit_streaming_evidence(env)
        return env

    async def emit_failed(self, error_code: str) -> StreamingEnvelope:
        self._sequence += 1
        env = StreamingEnvelope(
            sequence=self._sequence,
            task_id=self._task_id,
            envelope_type="task.failed",
            payload={"error_code": error_code},
            a2a_version="1.0",
        )
        await self._emit_streaming_evidence(env)
        return env

    async def _emit_streaming_evidence(self, envelope: StreamingEnvelope) -> None:
        """Single helper that writes the parallel audit row + decision-
        history row from one canonical payload. Mirrors Sprint-5's
        ``MCPHost._emit_call_evidence`` shape.
        """
        # ... audit + dh emission ...
        ...


async def stream_response(
    emitter: A2AStreamingEmitter,
    handler: AsyncIterator[dict[str, Any]],
) -> AsyncIterator[bytes]:
    """Adapter: walks the agent handler's progress generator + emits
    A2A 1.0 streaming envelopes. Caller hands the result to
    ``httpx.AsyncClient.stream`` for chunked-transfer dispatch.
    """
    try:
        async for chunk in handler:
            env = await emitter.emit_progress(chunk)
            yield _encode_envelope(env)
        env = await emitter.emit_completed({})
        yield _encode_envelope(env)
    except Exception as exc:
        env = await emitter.emit_failed(type(exc).__name__)
        yield _encode_envelope(env)
        raise


def _encode_envelope(env: StreamingEnvelope) -> bytes:
    """Encode a streaming envelope per A2A 1.0 wire format. Uses
    the SDK's encoder so we stay spec-compliant; never hand-rolls
    the JSON.
    """
    # ... delegates to a2a SDK ...
    ...
```

- [ ] **Step 1-3: Tests + impl + commit**

```bash
git commit -m "feat(sprint-6): A2A 1.0 task streaming protocol support (T10)"
```

---

## Task 11: Small endpoints + error taxonomy enum (consolidated)

**Files:**
- Create: `src/cognic_agentos/protocol/a2a_artifacts.py` — artifact reference generator (ObjectStoreAdapter-backed).
- Create: `src/cognic_agentos/protocol/a2a_capability_negotiation.py` — `GET /api/v1/a2a/capabilities` backing module.
- Create: `src/cognic_agentos/protocol/a2a_cancellation.py` — task cancellation primitive.
- Create: `src/cognic_agentos/protocol/a2a_errors.py` — full A2A 1.0 closed-enum error taxonomy (14 spec-defined codes per A2A 1.0 §error-codes).
- Create: `tests/unit/protocol/test_a2a_artifacts.py`, `test_a2a_capability_negotiation.py`, `test_a2a_cancellation.py`, `test_a2a_error_taxonomy.py`.

**Halt-before-commit:** No (these are small, single-responsibility modules with no critical-controls invariants beyond the closed-enum reasons).

Why these four are bundled into one task: each is self-contained (≤100 LOC of impl + ≤200 LOC of tests), shares no internal state with the others, and lands together as the "small endpoints + enum" surface that fills out the A2A 1.0 spec compliance matrix.

### `a2a_artifacts.py`

```python
"""protocol/a2a_artifacts.py — A2A artifact reference generator.

Per A2A-CONFORMANCE.md §"Artifacts" + ADR-003: large outputs
(PDFs, evidence packs, JSON > 64 KiB) are stored via Sprint-4's
LocalObjectStoreAdapter and returned as ArtifactRef references;
small payloads remain inline. Per-tenant retention configurable
via Settings.a2a_artifact_retention_seconds.

The threshold (64 KiB) is the A2A 1.0 spec recommendation; smaller
payloads ride inline in the Task envelope, larger ones go through
the artifact-reference indirection.
"""

import dataclasses
import hashlib

from cognic_agentos.core.config import Settings
from cognic_agentos.db.adapters.protocols import ObjectStoreAdapter

_INLINE_THRESHOLD_BYTES = 64 * 1024


@dataclasses.dataclass(frozen=True, slots=True)
class ArtifactRef:
    uri: str
    sha256: str
    size_bytes: int
    mime_type: str


class A2AArtifactStore:
    def __init__(
        self,
        *,
        settings: Settings,
        object_store: ObjectStoreAdapter,
    ) -> None:
        self._settings = settings
        self._object_store = object_store

    async def store_or_inline(
        self,
        *,
        bytes_: bytes,
        mime_type: str,
        tenant_id: str,
    ) -> ArtifactRef | bytes:
        if len(bytes_) <= _INLINE_THRESHOLD_BYTES:
            return bytes_
        digest = hashlib.sha256(bytes_).hexdigest()
        bucket = f"a2a-artifacts-{tenant_id}"
        key = f"{digest[:2]}/{digest}"
        await self._object_store.put(
            bucket=bucket,
            key=key,
            body=bytes_,
            retention_seconds=self._settings.a2a_artifact_retention_seconds,
        )
        return ArtifactRef(
            uri=f"objstore://{bucket}/{key}",
            sha256=digest,
            size_bytes=len(bytes_),
            mime_type=mime_type,
        )
```

### `a2a_capability_negotiation.py`

```python
"""protocol/a2a_capability_negotiation.py — A2A capability discovery.

Backs ``GET /api/v1/a2a/capabilities``. Reads pack manifests'
``[tool.cognic.a2a].capabilities_supported`` declarations and
returns the canonical A2A 1.0 capability list (subset of the
agent's manifest declaration; never broader).

Per BUILD_PLAN exit criteria + A2A-CONFORMANCE.md: the capability
list returned MUST match exactly what the agent's manifest
declared, no more no less.
"""
# ... ~80 LOC ...
```

### `a2a_cancellation.py`

```python
"""protocol/a2a_cancellation.py — A2A task cancellation primitive.

cancel_task(task_id, *, reason) flips the task's lifecycle to
CANCELLED, emits a2a.task_cancelled chained event with partial-state
payload digest, and refuses subsequent calls against the cancelled
task ID with task_already_cancelled.

Per BUILD_PLAN exit criterion: in-flight task is cancelled; partial-
state audit emitted; subsequent calls reject the cancelled task ID.
"""
# ... ~60 LOC ...
```

### `a2a_errors.py`

```python
"""protocol/a2a_errors.py — full A2A 1.0 closed-enum error taxonomy.

Per A2A 1.0 §error-codes. 14 spec-defined codes (closed-enum,
re-exported from protocol/__init__.py).

Sprint-6 doctrine: every error response uses spec-defined codes;
no Cognic-bespoke codes for spec-mapped failures.
"""

from __future__ import annotations

import dataclasses

from cognic_agentos.protocol import A2AErrorCode


@dataclasses.dataclass(frozen=True, slots=True)
class A2AErrorResponse:
    code: A2AErrorCode
    message: str
    spec_section: str  # which A2A 1.0 section defines this code
    payload: dict[str, str]  # operator-debugging metadata
    http_status: int  # spec-mapped HTTP status code


def task_not_found(task_id: str) -> A2AErrorResponse:
    return A2AErrorResponse(
        code="task_not_found",
        message=f"task {task_id!r} not found in the endpoint's task store",
        spec_section="A2A-1.0 §error-codes",
        payload={"task_id": task_id},
        http_status=404,
    )


def task_already_cancelled(task_id: str) -> A2AErrorResponse: ...
def version_not_supported(supported: str) -> A2AErrorResponse: ...
def agent_card_signature_invalid(reason: str) -> A2AErrorResponse: ...
# ... 10 more spec-mapped factory functions ...
```

- [ ] **Step 1: Implement four modules + tests**
- [ ] **Step 2: Run; expect PASS**
- [ ] **Step 3: Commit**

```bash
git commit -m "feat(sprint-6): A2A artifacts + capabilities + cancellation + error taxonomy (T11)"
```

---

## Task 12: `protocol/ui_events.py` — Wave-1 typed event taxonomy + emit-hook mirroring

**R0 P2 reviewer correction.** An earlier draft pinned 5 Wave-1 families with `decision_audit` and dropped `approval`, `interrupt`, `frontend_action`, `memory`, `policy`, `kill_switch`. ADR-020 §"Event taxonomy (Wave 1)" lists ALL 11 families as the public schema; the §"Implementation phases" table assigns when each family's *emit hooks* get wired across Sprints 6 / 7B / 11.5 / 13.5. The fix per Doctrine Decision E: **Sprint 6 ships typed Pydantic SCHEMA for all 11 Wave-1 families** (the schema is the public contract — stable from day one) AND **wires emit hooks for 3 families** in Sprint 6 (`tool_call`, `decision_audit`, `artifact`). The other 8 families have schema-only stubs in Sprint 6; their emit hooks land in their owning sprints per the ADR-020 phase table.

**ADR-020 audit-mirror scope clarification (R1 P2 reviewer correction).** ADR-020's Sprint-6 phase row mandates "every existing audit event mirrors to a typed UI event in-process". The Sprint-6 implementation discharges this in two complementary layers:

1. **Family-specific mirrors** for events whose semantics map cleanly to a typed family. `audit.tool_invocation_succeeded` → `tool_call.completed`; `audit.tool_invocation_refused` → `tool_call.denied`; etc. Sprint-5's tool-invocation surface is the only family-specific source today; Sprint 6 itself adds artifact-lifecycle (T11) → `artifact.*`.
2. **Generic catch-all mirror via `decision_audit.event_appended`** at `DecisionHistoryStore.append`. **EVERY row appended to `decision_history` — regardless of which audit subsystem produced it (Sprint-2 chain rows, Sprint-2.5 SLA / escalation / guardrail events, Sprint-3 LLM-gateway ledger entries, Sprint-4 plugin-trust / supply-chain events, Sprint-5 MCP host invocations, Sprint-6 A2A events, AND any future emitter) — produces a parallel `decision_audit.event_appended` UI event with the original event's family / type / payload-digest in `data`.** This is the load-bearing mirror that satisfies ADR-020's "every existing audit event mirrors" requirement: it sits at the canonical sink (`DecisionHistoryStore.append`) so no audit subsystem can emit without the UI mirror firing.

The two layers are intentional, not redundant: the family-specific mirrors give UIs typed semantics for the families they care about (`tool_call.denied` is more useful for a runbook than a generic `decision_audit.event_appended` whose `data` happens to encode the same information); the generic mirror guarantees the contract holds even for audit subsystems whose family-specific mirrors haven't been wired yet (e.g., LLM-gateway ledger rows in Sprint 3+ — not a Wave-1 family — still mirror through `decision_audit`). When Sprint 13.5 adds the `policy.*` and `kill_switch.*` families' emit hooks, they layer on top of the generic mirror; they don't replace it.

**Files:**
- Create: `src/cognic_agentos/protocol/ui_events.py` — typed Pydantic models for ALL 11 Wave-1 event families per ADR-020 §"Event taxonomy (Wave 1)". Emit-hook protocol that wires three families in Sprint 6 (Sprint-5's `audit.tool_invocation_*` → `tool_call.*`; Sprint-2+'s `DecisionHistoryStore.append` → **generic `decision_audit.event_appended` covering EVERY audit/decision row regardless of subsystem**; Sprint-6 T11's `a2a_artifacts.py` → `artifact.*`). Other 8 families have model-only stubs.
- Create: `tests/unit/protocol/test_ui_events.py` — typed event-family model contracts (model_validate / model_dump round-trip; literal-type pinning for family/type fields; `schema_version: "1.0"` constant).
- Create: `tests/unit/protocol/test_ui_events_audit_mirror.py` — the 3 Sprint-6-wired families get parallel typed UI events without changing the audit-emit shape. Includes:
  - `tool_call.completed` mirrors `audit.tool_invocation_succeeded` (and `denied` / `failed` / etc. for the closed-enum sibling outcomes).
  - `artifact.completed` mirrors Sprint-6 T11's artifact emits.
  - **`decision_audit.event_appended` mirrors EVERY `DecisionHistoryStore.append` regardless of subsystem origin.** The test exercises this with a non-tool, non-artifact audit row (e.g., a Sprint-3 LLM-gateway `gateway.call_succeeded` ledger entry, or a Sprint-2 chain-only event) and asserts the mirror still fires with the source event's family / type / payload-digest carried through `data`. This is the load-bearing test that proves ADR-020's "every existing audit event mirrors" contract in Sprint 6.
- Create: `tests/unit/protocol/test_ui_event_taxonomy_completeness.py` — drift detector: every family from ADR-020 §"Event taxonomy (Wave 1)" MUST be in the `_WAVE_1_FAMILIES` literal; the test fails if ADR-020 grows OR shrinks. Plus a sister assertion that the 3 Sprint-6-WIRED families (vs the 11 Sprint-6-SCHEMA-ONLY families) match the expected subset.

**Halt-before-commit:** Yes — `ui_events.py` is a public event schema (per ADR-020 stop rule on the AGENTS.md critical-controls list); the schema MUST be stable from day one.

**No SSE endpoint in Sprint 6.** Per ADR-020 §"Implementation phases", SSE transport lands in Sprint 7B. Sprint 6 ships ONLY the typed Pydantic schema + the in-process emit-hook layer for the 3 wired families (one of which — `decision_audit` — is the generic catch-all that mirrors every audit/decision row). The schema is stable from day one even though no UI subscribes yet.

11 Wave-1 event families per ADR-020 §"Event taxonomy (Wave 1)" — all schema-shipped in Sprint 6:

| Family | Events | Sprint-6 wiring | Emit-hook owning sprint |
|---|---|---|---|
| `agent_run` | `started`, `progress`, `completed`, `failed`, `cancelled`, `paused`, `resumed` | schema only | Future sprint introducing the run primitive (Sprint-7A or later) |
| `tool_call` | `requested`, `approved`, `denied`, `started`, `progress`, `completed`, `failed` | **wired in Sprint 6** | Sprint-5 `audit.tool_invocation_*` already emits; T12 adds the parallel UI-event emit |
| `subagent` | `spawned`, `completed`, `failed`, `recursion_capped` | schema only | Sprint-8 sub-agent primitive (per ADR-005 + Doctrine Decision D) |
| `approval` | `pending`, `granted`, `granted_second`, `denied`, `expired` | schema only | Sprint 13.5 (per ADR-014 approval engine + ADR-020 phase table) |
| `artifact` | `started`, `chunk`, `completed` | **wired in Sprint 6** | Sprint-6 T11's `a2a_artifacts.py` emits artifact lifecycle; T12 wires the UI mirror |
| `interrupt` | `requested_by_agent`, `requested_by_operator`, `acknowledged` | schema only | Sprint 13.5 (typically bundled with approval per ADR-020) |
| `frontend_action` | `submitted`, `accepted`, `rejected` | schema only | Sprint 7B alongside the SSE endpoint + frontend-action POST endpoint (per ADR-020 phase table) |
| `memory` | `recall_started`, `recall_completed`, `forget`, `redact` | schema only | Sprint 11.5 (per ADR-019 memory governance + ADR-020 phase table) |
| `decision_audit` | `event_appended` | **wired in Sprint 6** | Sprint-2+ `DecisionHistoryStore.append` already emits; T12 wires the UI mirror (RBAC: `audit.read` scope when SSE lands in Sprint 7B) |
| `policy` | `decision_evaluated`, `bundle_loaded` | schema only | Sprint 13.5 (per ADR-015 policy engine + ADR-020 phase table) |
| `kill_switch` | `flipped`, `reverted` | schema only | Sprint 13.5 (per ADR-018 emergency controls + ADR-020 phase table) |

**Sprint-6 emit-hook count: 3 wired / 11 total.** The schema-only-stub families register their Pydantic models so a future Sprint 7B SSE subscriber sees the full 11-family contract immediately when it lands; the schema-stable-from-day-one invariant is preserved even though only 3 families have observable emit traffic in Sprint 6.

```python
"""protocol/ui_events.py — UI event-stream typed schema (Wave 1).

Critical-controls module per AGENTS.md (Sprint-6 amendment, "Protocol
— A2A endpoint" section, per ADR-020 stop rule on the public event
schema).

Per ADR-020: this is the public event contract that ANY UI consuming
AgentOS events implements. The schema MUST be stable from day one
even though Sprint 6 ships ONLY the in-process emit-hook layer; the
SSE transport endpoint lands at Sprint 7B.

11 Wave-1 event families per ADR-020 §"Event taxonomy (Wave 1)"
(all schema-shipped in Sprint 6; 3 wired with emit hooks):
  agent_run.{started, progress, completed, failed, cancelled, paused, resumed}    [schema only]
  tool_call.{requested, approved, denied, started, progress, completed, failed}   [WIRED — Sprint-5 audit mirror]
  subagent.{spawned, completed, failed, recursion_capped}                         [schema only — Sprint 8 wires]
  approval.{pending, granted, granted_second, denied, expired}                    [schema only — Sprint 13.5 wires]
  artifact.{started, chunk, completed}                                            [WIRED — Sprint-6 T11 mirror]
  interrupt.{requested_by_agent, requested_by_operator, acknowledged}             [schema only — Sprint 13.5 wires]
  frontend_action.{submitted, accepted, rejected}                                 [schema only — Sprint 7B wires]
  memory.{recall_started, recall_completed, forget, redact}                       [schema only — Sprint 11.5 wires]
  decision_audit.{event_appended}                                                 [WIRED — DecisionHistoryStore mirror]
  policy.{decision_evaluated, bundle_loaded}                                      [schema only — Sprint 13.5 wires]
  kill_switch.{flipped, reverted}                                                 [schema only — Sprint 13.5 wires]

Wire format (per ADR-020):
  {
    "event_id": "evt_01HV...",
    "ts": "2026-04-27T14:23:11.123Z",
    "tenant": "bank-a",
    "run_id": "run_01HV...",
    "trace_id": "trace_01HV...",
    "family": "tool_call",
    "type": "approved",
    "data": { ... family-specific ... },
    "audit_chain_hash": "sha256:..."
  }

The ``audit_chain_hash`` field lets a subscribing UI verify the event
corresponds to a real decision_history record without trusting the
SSE channel alone.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
from typing import Any, Literal, Protocol

import pydantic


# ---------------------------------------------------------------------------
# Event family typed payloads (Wave 1)
# ---------------------------------------------------------------------------


class _BaseEvent(pydantic.BaseModel):
    event_id: str
    ts: _dt.datetime
    tenant: str
    run_id: str
    trace_id: str
    family: str
    type: str
    data: dict[str, Any]
    audit_chain_hash: str

    model_config = {"frozen": True}


# agent_run.*
class AgentRunStarted(_BaseEvent):
    family: Literal["agent_run"] = "agent_run"
    type: Literal["started"] = "started"


class AgentRunProgress(_BaseEvent):
    family: Literal["agent_run"] = "agent_run"
    type: Literal["progress"] = "progress"


class AgentRunCompleted(_BaseEvent):
    family: Literal["agent_run"] = "agent_run"
    type: Literal["completed"] = "completed"


class AgentRunFailed(_BaseEvent):
    family: Literal["agent_run"] = "agent_run"
    type: Literal["failed"] = "failed"


class AgentRunCancelled(_BaseEvent):
    family: Literal["agent_run"] = "agent_run"
    type: Literal["cancelled"] = "cancelled"


class AgentRunPaused(_BaseEvent):
    family: Literal["agent_run"] = "agent_run"
    type: Literal["paused"] = "paused"


class AgentRunResumed(_BaseEvent):
    family: Literal["agent_run"] = "agent_run"
    type: Literal["resumed"] = "resumed"


# tool_call.* — mirrors Sprint-5 audit.tool_invocation_*
class ToolCallRequested(_BaseEvent):
    family: Literal["tool_call"] = "tool_call"
    type: Literal["requested"] = "requested"


class ToolCallApproved(_BaseEvent):
    family: Literal["tool_call"] = "tool_call"
    type: Literal["approved"] = "approved"


class ToolCallDenied(_BaseEvent):
    family: Literal["tool_call"] = "tool_call"
    type: Literal["denied"] = "denied"


class ToolCallStarted(_BaseEvent):
    family: Literal["tool_call"] = "tool_call"
    type: Literal["started"] = "started"


class ToolCallProgress(_BaseEvent):
    family: Literal["tool_call"] = "tool_call"
    type: Literal["progress"] = "progress"


class ToolCallCompleted(_BaseEvent):
    family: Literal["tool_call"] = "tool_call"
    type: Literal["completed"] = "completed"


class ToolCallFailed(_BaseEvent):
    family: Literal["tool_call"] = "tool_call"
    type: Literal["failed"] = "failed"


# subagent.*
class SubagentSpawned(_BaseEvent):
    family: Literal["subagent"] = "subagent"
    type: Literal["spawned"] = "spawned"


class SubagentCompleted(_BaseEvent):
    family: Literal["subagent"] = "subagent"
    type: Literal["completed"] = "completed"


class SubagentFailed(_BaseEvent):
    family: Literal["subagent"] = "subagent"
    type: Literal["failed"] = "failed"


class SubagentRecursionCapped(_BaseEvent):
    family: Literal["subagent"] = "subagent"
    type: Literal["recursion_capped"] = "recursion_capped"


# artifact.*
class ArtifactStarted(_BaseEvent):
    family: Literal["artifact"] = "artifact"
    type: Literal["started"] = "started"


class ArtifactChunk(_BaseEvent):
    family: Literal["artifact"] = "artifact"
    type: Literal["chunk"] = "chunk"


class ArtifactCompleted(_BaseEvent):
    family: Literal["artifact"] = "artifact"
    type: Literal["completed"] = "completed"


# decision_audit.*
class DecisionAuditEventAppended(_BaseEvent):
    family: Literal["decision_audit"] = "decision_audit"
    type: Literal["event_appended"] = "event_appended"


#: Discriminated union of every Wave-1 event type. Used by the
#: emit-hook protocol + the future Sprint-7B SSE serialiser.
UIEvent = (
    AgentRunStarted | AgentRunProgress | AgentRunCompleted
    | AgentRunFailed | AgentRunCancelled | AgentRunPaused | AgentRunResumed
    | ToolCallRequested | ToolCallApproved | ToolCallDenied
    | ToolCallStarted | ToolCallProgress | ToolCallCompleted | ToolCallFailed
    | SubagentSpawned | SubagentCompleted | SubagentFailed | SubagentRecursionCapped
    | ArtifactStarted | ArtifactChunk | ArtifactCompleted
    | DecisionAuditEventAppended
)


# ---------------------------------------------------------------------------
# Emit-hook protocol
# ---------------------------------------------------------------------------


class UIEventHook(Protocol):
    """In-process subscriber to UI events. The Sprint-7B SSE
    endpoint will register a ``UIEventHook`` that buffers events for
    SSE delivery; Sprint 6 only ships the protocol + a default
    no-op subscriber.

    Implementations MUST be cheap (every audit emit also fires the
    UI hook in-process; a slow hook backs up the audit append).
    """

    async def on_event(self, event: UIEvent) -> None: ...


class UIEventEmitter:
    """In-process UI event emitter. Registered as a Sprint-2
    AuditStore subscriber so every audit emit produces a parallel
    typed UI event without the audit emit shape changing.

    Sprint 6 ships this with a no-op default hook; Sprint 7B
    swaps in the SSE-backed hook.
    """

    def __init__(self) -> None:
        self._hooks: list[UIEventHook] = []

    def register_hook(self, hook: UIEventHook) -> None:
        self._hooks.append(hook)

    async def emit(self, event: UIEvent) -> None:
        for hook in self._hooks:
            try:
                await hook.on_event(event)
            except Exception as exc:
                # Hook failures are isolated — one broken hook does
                # not poison emission to other hooks. Mirrors Sprint-5
                # transport `_emit_send_error_safe` doctrine.
                _LOG.warning(
                    "ui_events.hook_emit_failed",
                    extra={
                        "hook_class": type(hook).__name__,
                        "error_type": type(exc).__name__,
                    },
                )


__all__ = (
    "UIEvent",
    "UIEventHook",
    "UIEventEmitter",
    # event family models
    "AgentRunStarted", "AgentRunProgress", "AgentRunCompleted",
    "AgentRunFailed", "AgentRunCancelled", "AgentRunPaused", "AgentRunResumed",
    "ToolCallRequested", "ToolCallApproved", "ToolCallDenied",
    "ToolCallStarted", "ToolCallProgress", "ToolCallCompleted", "ToolCallFailed",
    "SubagentSpawned", "SubagentCompleted", "SubagentFailed", "SubagentRecursionCapped",
    "ArtifactStarted", "ArtifactChunk", "ArtifactCompleted",
    "DecisionAuditEventAppended",
)
```

- [ ] **Step 1-3: Tests + impl + emit-mirror integration tests + commit**

```bash
git commit -m "feat(sprint-6): UI event-stream typed schema + emit-hook layer (T12)"
```

---

## Task 13: Fixture pack + receiver smoke + A2A 1.0 conformance fixtures

**Files:**
- Create: `tests/fixtures/cognic_test_agent_pack/` — Sprint-6 agent pack fixture (mirrors Sprint-5's `cognic_test_mcp_pack` shape).
- Create: `tests/fixtures/a2a-conformance/` — curated A2A 1.0 valid + invalid messages from the official spec.
- Create: `tests/unit/protocol/test_a2a_fixture_pack_admission.py` — registry admits the fixture pack through the full Sprint-4 admission pipeline + Sprint-6 AgentCard JWS verification step + Sprint-6 receiver smoke against mocked HTTP transport.
- Create: `tests/unit/protocol/test_a2a_spec_conformance.py` — runs the conformance fixtures: every valid message accepted, every invalid message rejected with the spec's error code.

**Halt-before-commit:** No.

**Sprint-6 fixture pack scope decision (mirrors Sprint-5 T12 R1 P3 #2):** the unit lane keeps the fixture pack **import-poisoned** (entry-point references unimport-ably; the package `__init__.py` raises on import) and exercises the registry + endpoint against a **mocked HTTP transport**. The runnable-server path (live A2A 1.0 receiver + signed Agent Card served at the spec well-known path + per-tenant token round-trip with a real Vault) needs substantial test infrastructure and belongs to a future integration lane (Sprint 13.5 / pre-go-live), not the unit suite.

This is the same scope decision the Sprint-5 cognic_test_mcp_pack fixture made, recorded explicitly in the plan + in three sites (`pyproject.toml` description + `__init__.py` docstring + manifest header) so future maintainers don't try to "fix" the fixture by adding a server module.

```toml
# tests/fixtures/cognic_test_agent_pack/pyproject.toml
[project]
name = "cognic-test-agent-pack"
version = "0.1.0"
description = """\
Sprint-6 unit test fixture — exercises the A2A 1.0 admission pipeline
+ inbound receiver against a mocked HTTP transport. The fixture is
intentionally inert: no runnable server module, no live OAuth AS, no
real network — that path is deferred to a future integration lane."""
# ... rest of pyproject ...

[project.entry-points."cognic.agents"]
cognic_test_agent_pack = "cognic_test_agent_pack:Plugin"
# Plugin reference is intentionally unresolvable in the unit lane:
# the package __init__.py is import-poisoned and there is no real
# Plugin class.
```

```toml
# tests/fixtures/cognic_test_agent_pack/cognic_test_agent_pack/cognic-pack-manifest.toml
[tool.cognic.identity]
pack_id = "cognic-test-agent-pack"
pack_version = "0.1.0"

[tool.cognic.a2a]
spec_version = "1.0"
agent_card_url = "https://packs.example/agent_cards/test_agent.json"
agent_card_jws_path = "agent_cards/test_agent.jws"
capabilities_supported = ["test_capability"]
streaming = true
push_notification_config = false  # opt-in for Wave 2
artifacts_supported = true
auth_scheme = "bearer"
```

The conformance fixtures live under `tests/fixtures/a2a-conformance/`:
- `valid/task_request__minimal.json`
- `valid/task_request__streaming_enabled.json`
- `valid/streaming_envelope__progress.json`
- `valid/streaming_envelope__completed.json`
- `valid/streaming_envelope__failed.json`
- `valid/cancellation_request__valid.json`
- `valid/artifact_reference__valid.json`
- `invalid/task_request__missing_target_agent.json` (expected error: `parse_error`)
- `invalid/task_request__top_level_url_in_card.json` (expected error: `agent_card_profile_top_level_url_forbidden`)
- `invalid/task_request__legacy_version_header.json` (expected error: `version_not_supported`)
- `invalid/streaming_envelope__missing_sequence.json` (expected error: `parse_error`)
- ... plus ~10 more covering each spec error code

Each invalid fixture has a sibling `<name>_expected.json` declaring the exact spec error code that MUST surface.

- [ ] **Step 1: Author fixture pack** (mirroring Sprint-5 T12 import-poisoning pattern)
- [ ] **Step 2: Author conformance fixtures** (curated subset from the official A2A 1.0 conformance suite)
- [ ] **Step 3: Author admission smoke + conformance test runner**
- [ ] **Step 4: Run; expect PASS**
- [ ] **Step 5: Commit**

```bash
git commit -m "test(sprint-6): cognic_test_agent_pack fixture + A2A 1.0 conformance fixtures (T13)"
```

---

## Task 14: Negative-path canary — `test_a2a_no_caller_controlled_url.py` + anonymous + Wave-2 refused

**Files:**
- Create: `tests/unit/protocol/test_a2a_no_caller_controlled_url.py` — runtime backstop for the caller-URL threat model. Mirrors Sprint-5 T13 `test_mcp_no_user_controlled_command.py` shape: ~40 parametrized arms across 6-8 test classes pinning the closed-enum vocabularies + the caller-URL refusal posture + the spec error codes.
- Create: `tests/unit/protocol/test_a2a_anonymous_refused.py` — focused on the anonymous-A2A refusal posture (per Sprint-6 Decision Lock #3).
- Create: `tests/unit/protocol/test_a2a_wave2_features_refused.py` — push-notification subscribe / multi-modal payload / long-running task resumption all refused with `wave2_feature_refused` (NOT silent-accept).
- Create: `tests/unit/protocol/test_a2a_outbound_version.py` — every outbound call includes `A2A-Version: 1.0`.

**Halt-before-commit:** No (test-only).

**This task is the runtime canary for the caller-URL threat model + the Wave-2-refusal doctrine.** The architecture test (T4) is the static-AST half; this is the runtime half. Even if a future maintainer somehow evades the static-import check (via `__import__("httpx")`, `exec` of a string-built import, dynamic attribute lookup, etc.), the canary trips on the resulting refusal vector — the closed-enum reasons + the URL-source classifier shapes hold regardless of how the caller constructed the request.

Test class structure:
- `TestCallerURLRefusedAtEndpoint` — ~10 arms covering inbound `target_agent` field shapes that look like URLs (refused with `unknown_target` or `parse_error`).
- `TestOutboundDispatchURLFromVerifiedCard` — ~6 arms verifying `fetch_and_verify_outbound_card` is the ONLY producer of dispatch URLs.
- `TestSubagentTargetIsEntryPointName` — ~4 arms verifying `spawn_subagent`-style calls (whose impl ships in Sprint 8 but whose interface lock-in starts here) refuse to accept URL-shaped targets.
- `TestPushNotificationWebhookRefusedWave1` — ~4 arms verifying push-notification webhook URLs are refused with `wave2_feature_refused` (per Decision Lock #2).
- `TestAnonymousRefused` — ~6 arms covering missing header / bearer-prefix / empty token / whitespace-only token / non-bearer-scheme.
- `TestWave2FeatureRefused` — ~12 arms covering each Wave-2 feature: push-notification-config, multi-modal payloads, long-running task resumption, mTLS auth.
- `TestOutboundVersionHeaderAlwaysOneZero` — pins that every outbound `httpx.AsyncClient` call has `A2A-Version: 1.0`.
- `TestThreatModelInvariants` — ~3 arms pinning the closed-enum vocabularies (`A2AAuthzReason`, `A2AErrorCode`, `AgentCardValidationReason`) against expected sets.

```python
"""Sprint-6 T14 — runtime canary for the A2A caller-URL threat model.

Runtime backstop for ``docs/A2A-CALLER-URL-THREAT-MODEL.md`` and the
ADR-003 routing-safety doctrine. Complements the architecture-test
(static-AST scan in ``tests/architecture/test_a2a_no_caller_controlled_url.py``)
with a runtime check that asserts every adversary-controlled URL
surface produces the correct closed-enum refusal at the correct
entry point.

If this test fails, the threat model has been breached and the build
must be reverted before merge.

Coverage map (per Sprint-6 plan §T14):
  TestCallerURLRefusedAtEndpoint
  TestOutboundDispatchURLFromVerifiedCard
  TestSubagentTargetIsEntryPointName
  TestPushNotificationWebhookRefusedWave1
  TestAnonymousRefused
  TestWave2FeatureRefused
  TestOutboundVersionHeaderAlwaysOneZero
  TestThreatModelInvariants
"""
# ... ~600 lines of canary tests mirroring Sprint-5 T13 shape ...
```

- [ ] **Step 1: Write the four canary test modules**
- [ ] **Step 2: Run; expect PASS** (every adversarial input produces the right closed-enum refusal)
- [ ] **Step 3: Commit**

```bash
git commit -m "test(sprint-6): negative-path canary for A2A caller-URL threat model (T14)"
```

---

## Task 15: Critical-controls coverage gate extension 21 → 27 modules

**Files:**
- Modify: `tools/check_critical_coverage.py` — extend the gate from 21 (Sprint-5 final) to **27 modules** (R0 P2 reviewer correction added `a2a_version.py` to the original quintet). Six Sprint-6 candidates at the strict 95% line / 90% branch floor: `a2a_authz`, `a2a_agent_cards`, `a2a_endpoint`, `a2a_schema`, `a2a_version`, `ui_events`.

**Halt-before-commit:** Yes — the gate config is the executable single-source-of-truth for the per-file coverage floor; changes require explicit reviewer pass.

Per-module rationale (mirrors Sprint-5 T14 R1 P3 ownership-accuracy fix):

| Module | Why critical | AGENTS.md trigger |
|---|---|---|
| `protocol/a2a_authz.py` | Single owner of per-tenant pinned-token validation; mirror of `mcp_authz` shape; closed-enum 8-value `A2AAuthzReason` carries the audit-row taxonomy. | Protocol authorization |
| `protocol/a2a_agent_cards.py` | JWS verification on Agent Cards is identity-routing critical — a forged or tampered card routes outbound traffic to attacker-controlled endpoints. Two-pass validator (upstream + AgentOS profile) is the only place AgentOS validates A2A-spec card shapes. | Protocol authorization + Plugin trust + supply chain |
| `protocol/a2a_endpoint.py` | Single owner of the task-lifecycle state machine + chain linkage across the A2A boundary. Anonymous-refusal gate + Wave-2-refusal gate live here. | Protocol authorization + Wire-protocol contracts |
| `protocol/a2a_schema.py` | Wire-format truth — drift = wire-protocol break. Pinned digest constants + the schema-drift CI gate live here. | Wire-protocol contracts |
| `protocol/ui_events.py` | Per ADR-020 stop rule: public event schema, MUST remain backward-compatible across versions. The Wave-1 typed taxonomy is the contract every future UI subscriber implements. | UI event-stream contract (ADR-020) |

Implementation:

```python
# tools/check_critical_coverage.py — extend _CRITICAL_FILES tuple

# Sprint 6 T15 — A2A endpoint quintet. The Sprint-6 plan-of-record
# nominates these five modules as the A2A critical-controls floor;
# T15 lands them in this gate. T16 is the corresponding AGENTS.md
# doctrine update that mirrors this gate under a new "Protocol —
# A2A endpoint (Sprint 6)" section. (Pre-T16, AGENTS.md only names
# protocol/a2a_authz.py under "Protocol authorization" + lists
# protocol/ui_events.py per ADR-020 stop rule; T16 expands that list
# to match this gate so the gate config + doctrine document stay in
# sync.) All five ride the same single strict 95% line / 90% branch
# floor as Sprint-2/2.5/3/4/5 modules:
#   * ``a2a_authz.py`` is the per-tenant pinned-token validator —
#     closed-enum 8-value A2AAuthzReason; Vault-read exception
#     mapping per Sprint-5 T15 R1 P2 #2 doctrine.
#   * ``a2a_agent_cards.py`` is the two-pass Agent Card validator
#     + JWS verifier. Pass 1 upstream A2A 1.0 schema; Pass 2
#     AgentOS bank-grade profile. JWS rides Sprint-4 trust root.
#     Identity-routing critical: a forged card routes outbound
#     traffic to attacker-controlled endpoints.
#   * ``a2a_endpoint.py`` is the inbound receiver + task lifecycle
#     state machine + cross-agent chain linkage. Anonymous-refusal
#     gate + Wave-2-refusal gate live here. Single-writer for the
#     TaskState transitions.
#   * ``a2a_schema.py`` is the pinned A2A 1.0 wire-format types.
#     Wire-format drift = wire-protocol break; the schema-drift CI
#     gate (test_a2a_schema_drift.py) catches upstream movement
#     before it reaches us. Pinned digest constants + the upstream
#     URL constants live here.
#   * ``ui_events.py`` is the Wave-1 typed event taxonomy + emit-
#     hook layer per ADR-020. Public event schema; MUST remain
#     backward-compatible across versions. Per ADR-020 stop rule
#     on the AGENTS.md critical-controls list.
("src/cognic_agentos/protocol/a2a_authz.py", 0.95, 0.90),
("src/cognic_agentos/protocol/a2a_agent_cards.py", 0.95, 0.90),
("src/cognic_agentos/protocol/a2a_endpoint.py", 0.95, 0.90),
("src/cognic_agentos/protocol/a2a_schema.py", 0.95, 0.90),
("src/cognic_agentos/protocol/ui_events.py", 0.95, 0.90),
```

- [ ] **Step 1: Generate `coverage.json` against the current branch**

```bash
uv run pytest --cov=cognic_agentos --cov-branch --cov-report=json --cov-report= -q
```

- [ ] **Step 2: Inspect coverage of the 5 new modules; expect ≥95% line, ≥90% branch (per the strict floor)**

If any of the 5 falls short, ADD MORE TESTS to the per-module `test_a2a_*.py` file before extending the gate. The gate isn't a target — coverage IS the target; the gate just makes regressions visible.

- [ ] **Step 3: Extend the gate**

- [ ] **Step 4: Run gate; expect 27 modules PASS**

```bash
uv run python tools/check_critical_coverage.py
```

- [ ] **Step 5: Halt-before-commit + commit**

```bash
git commit -m "chore(sprint-6): extend critical-controls gate to A2A quintet (T15)"
```

---

## Task 16: Closeout note + BUILD_PLAN flip + AGENTS.md amendment + architecture-test sentinel tighten

**Files:**
- Create: `docs/closeouts/2026-05-XX-sprint-6-a2a-endpoint.md` (date filled at commit time).
- Modify: `docs/BUILD_PLAN.md` — flip Sprint 6 status to `**CLOSED**`.
- Modify: `AGENTS.md` — add the Sprint-6 critical-controls **sextet** (six modules, R0 P2 correction) under a new "Protocol — A2A endpoint (Sprint 6)" section.
- Modify: `tests/architecture/test_a2a_no_subprocess.py` — tighten the `test_at_least_one_a2a_module_exists` sentinel from the T4-placeholder `>= 0` to `>= 9` (the 10 a2a modules — endpoint, authz, agent_cards, schema, version, streaming, artifacts, capability_negotiation, cancellation, errors — minus 1 to leave room for one rename without tripping the test).
- Modify: `tests/architecture/test_mcp_stdio_no_subprocess.py` — sentinel stays at `>= 5` (Sprint-5 floor).

**Halt-before-commit:** Yes — AGENTS.md is a doctrine document.

Closeout structure mirrors Sprint 5:
- Header (parent SHA, base SHA, branch state, commit count).
- What ships (**6 critical-controls A2A + UI events modules** — `a2a_authz`, `a2a_agent_cards`, `a2a_endpoint`, `a2a_schema`, `a2a_version`, `ui_events` — plus 5 small endpoint/enum modules + UI events stub for all 11 ADR-020 Wave-1 families + caller-URL threat-model doc + conformance fixtures + 16 new test modules + critical-controls gate extension to **27**).
- CI matrix (no new lanes; existing lanes still gate; per-file coverage now enforces 27 modules).
- Doctrine adherence (halt-before-commit on every critical-controls edit; A2A SDK pin; Wave-2-refusal closed-enum doctrine; caller-URL threat model).
- Test + coverage state (26-module gate table).
- Plan-review findings closed (round-by-round across T1-T16; expected ~5-10 reviewer rounds based on Sprint-5 cadence).
- ADR-003 / ADR-020 / A2A-CONFORMANCE.md Validation table (delivered / partial / carryover map).
- Doctrine amendments accepted in Sprint 6 (including the new "Protocol — A2A endpoint (Sprint 6)" critical-controls section + the `docs/A2A-CALLER-URL-THREAT-MODEL.md` document).

**Sprint-7A hand-off checklist (load-bearing — surfaced as its own §):**

1. `agentos sign --bundle` SDK + CLI — wraps the Wave-1 escape-hatch recipe (manual cosign + syft + grype + Agent Card JWS signing).
2. `agentos validate <pack-path>` — runs the same Sprint-4 trust gate + Sprint-6 Agent Card two-pass validator + manifest checks against the conformance matrix.
3. UI event-stream SSE endpoint (`GET /api/v1/ui/runs/{run_id}/events`) lands in Sprint 7B alongside the `frontend_action.*` event family.

The hand-off is the contract Sprint 6 deliberately leaves unfinished. Sprint 7A + 7B should treat this list as their acceptance criteria for the SDK/CLI + UI portions of their scope.

**AGENTS.md amendment text:**

```markdown
*Protocol — A2A endpoint (Sprint 6):*
- `protocol/a2a_authz.py` (per ADR-003 — per-tenant pinned-token validation; Vault-rotated; anonymous-A2A forbidden Wave-1)
- `protocol/a2a_agent_cards.py` (per ADR-003 + A2A-CONFORMANCE.md — two-pass card validator + JWS verify against per-tenant trust root; identity-routing critical)
- `protocol/a2a_endpoint.py` (per ADR-003 — inbound receiver + task lifecycle state machine + cross-agent chain linkage)
- `protocol/a2a_schema.py` (per ADR-003 — pinned A2A 1.0 wire-format types; schema-drift CI gate)
- `protocol/a2a_version.py` (per ADR-003 + AGENTS.md §"Wire-protocol contracts" — A2A-Version header negotiation; 4-case matrix; rejecting absent-header per spec)
- `protocol/ui_events.py` (per ADR-020 — Wave-1 typed event taxonomy + emit-hook layer; public event schema covering all 11 ADR-020 Wave-1 families, MUST remain backward-compatible)
```

- [ ] **Step 1: Author the closeout note**
- [ ] **Step 2: BUILD_PLAN refresh** (Sprint 6 deliverables list expanded; status line flipped to CLOSED with commit count + suite delta filled in)
- [ ] **Step 3: AGENTS.md doctrine update** — append the new "Protocol — A2A endpoint (Sprint 6)" section under the critical-controls list
- [ ] **Step 4: Tighten architecture-test sentinel** (`test_at_least_one_a2a_module_exists` from `>= 0` to `>= 9`)
- [ ] **Step 5: Halt-before-commit + commit**

```bash
git add docs/closeouts/ docs/BUILD_PLAN.md AGENTS.md \
        tests/architecture/test_a2a_no_subprocess.py
git commit -m "docs(sprint-6): closeout + BUILD_PLAN refresh + AGENTS.md critical-controls update + Sprint-7 hand-off (T16)"
```

---

## Doctrine Decision A — A2A SDK + protobuf pin

**Decision:** Pin `a2a-sdk == X.Y.Z` (the upstream Linux Foundation A2A reference Python SDK) as a hard requirement under the `adapters` extra group in `pyproject.toml`. Kernel image stays free of the SDK; default-adapters image carries it. The `create_app` factory (kernel) does NOT wire `A2AEndpoint`; `create_prod_app` (default-adapters) constructs it on the available-branch with kernel-resilient `try/except ImportError` handling — same pattern Sprint-5 T2 established for the MCP SDK.

**Pin point:** the implementation engineer fills in the exact patch version at T2 commit time after checking PyPI for the latest 1.0.x release that matches the spec's protobuf source-of-truth digest. This mirrors Sprint-4 T13 (cosign + OPA pins) and Sprint-5 T2 (MCP SDK pin) — "pinned at PR-author time" so the digest captured in `_PINNED_PROTOBUF_DIGEST` (T6 schema-drift gate) matches the SDK version at the moment of the lock.

**Alternatives considered + rejected:**

1. **Vendor `.proto` files + compile via `betterproto` / `protoc-gen-python`.** Rejected: adds a build-time toolchain dependency (`protoc`) on the verifier image, which Sprint-4's image-budget review already flagged as risky for default-adapters. The upstream SDK's generated bindings are the spec-authoritative shape; re-generating from `.proto` source would add a parity-with-spec failure mode without buying us anything Sprint 6 needs.
2. **Pull `a2a-spec` Python SDK from a Git tag instead of PyPI.** Rejected: PyPI release artefacts go through the spec authors' release process, including the JSON-schema binding parity check we depend on at T6. A Git-tag pull would let us race past a spec author's release-side regression.
3. **Bundle `a2a-sdk` into the kernel image.** Rejected: the SDK pulls in `grpcio` / `protobuf` runtimes which would inflate the kernel image well past its 120 MiB budget. Kernel deliberately stays free of A2A-aware code; A2A admission + dispatch live in `create_prod_app` only.
4. **Use `a2a-sdk` with the `[grpc]` extra to enable native gRPC transport.** Rejected: A2A 1.0 supports gRPC as an alternative wire format; AgentOS Wave 1 commits to JSON-RPC over HTTPS only. Sprint 6 imports the SDK without the gRPC extra to keep wire-format surface narrow + auditable. gRPC support is a Wave-2 evaluation.

**Bump policy:** when upstream A2A releases 1.0.x → 1.0.(x+1), the patch bump is reviewed at the Sprint-6 closeout-followup level (one reviewer round, schema-drift CI gate must show no breaking change). 1.0.x → 1.1.x is a feature-spec change that requires an ADR-003 amendment + a re-evaluation of the Wave-1/2/3 matrix in `docs/A2A-CONFORMANCE.md`. 1.x → 2.x is a wire-protocol change that requires a new ADR.

**Wire-protocol stability invariant:** the SDK pin + the schema-drift CI gate (T6) together guarantee that two AgentOS deployments running the same `a2a-sdk == X.Y.Z` interpret identical wire bytes identically. This is the same kind of invariant Sprint-2's `core/canonical.py` provides for the audit chain: deterministic semantics across deployments. Pack authors who depend on AgentOS interpreting an A2A 1.0 envelope do not need to know what AgentOS's pinned patch version is — they just need to know AgentOS is on 1.0.x.

---

## Doctrine Decision B — Caller-controlled URL threat model

**Decision:** Sprint 6 ships a new doctrine document `docs/A2A-CALLER-URL-THREAT-MODEL.md` (paralleling `docs/MCP-STDIO-THREAT-MODEL.md` from Sprint 5) and the runtime canary `tests/unit/protocol/test_a2a_no_caller_controlled_url.py` (paralleling `test_mcp_no_user_controlled_command.py`).

**Threat:** outbound A2A dispatch URLs are the analog of STDIO launch commands — bytes-controllable, attacker-shaped values that, if reached by `httpx.AsyncClient.get/post(url=...)`, become arbitrary HTTP egress in the AgentOS process. The April-2026 OX Security disclosures identified MCP STDIO command injection as the LLM-era equivalent of shell injection; the same threat model applies to A2A's outbound dispatch surface, where a model-output-controlled URL OR a caller-supplied `target_url` field would let any agent become a redirector to arbitrary HTTPS destinations (data exfiltration; SSRF into internal endpoints; chain hijack into a malicious downstream agent).

**Doctrine response:** outbound dispatch URLs MUST come from a **JWS-verified Agent Card's `supportedInterfaces[].url`** — never from caller input or model output. The four reachable surfaces and their refusals are enumerated below; the runtime canary asserts each one fails closed.

### The four reachable URL-source surfaces

1. **Inbound `target_agent` field on a received A2A envelope.** This is an **entry-point name** (string of the form `cognic_agent_<name>`), NEVER a URL. The endpoint resolves the name through the plugin registry to a registered pack, then calls `pack.handle(message)` in-process. **No URL is ever constructed from this field.** Refusal vector: any reachable code path that tries to interpret `target_agent` as a URL is an architecture-test failure (T4) AND a runtime-canary failure (T14). Closed-enum reason on attempted URL-shaped value: `a2a_target_must_be_entrypoint_name`.

2. **Outbound `spawn_subagent(target_agent, ...)` (ADR-005, Sprint 8).** Sprint 6 ships only the *outbound transport* layer — the bytes-on-the-wire half. The orchestration semantics ship with the sub-agent primitive in Sprint 8 (Doctrine Decision D below). When that lands, the `target_agent` argument is again an entry-point name; the sub-agent module resolves it through the plugin registry, fetches the registered pack's signed Agent Card, verifies the JWS via Sprint-4's per-tenant trust root, and dispatches to the URL inside the verified `supportedInterfaces[].url` array. **`spawn_subagent` MUST NOT accept a `target_url` kwarg** — the canary asserts this. Closed-enum reason if a future caller tries: `a2a_dispatch_url_not_from_verified_card`.

3. **Agent Card discovery URL.** When AgentOS calls a remote agent, it constructs the discovery URL as `f"{origin}/.well-known/agent-card.json"` where `origin` is derived from the registered pack's `[tool.cognic.identity].agent_card_origin` field — itself a manifest-declared, cosign-signed value (T7 R-loop will close this gap; the field IS NOT a caller input). The well-known suffix `.well-known/agent-card.json` is **constant, not parameterisable** — no caller can override the suffix. The canary asserts: every Agent Card fetch in `protocol/a2a_agent_cards.py` constructs the URL via the constant suffix; no `format()` / f-string interpolation of caller-controlled strings into the suffix slot. Closed-enum reason: `a2a_agent_card_discovery_path_not_constant`.

4. **Push-notification webhooks (Wave-2 feature).** Push-notification subscribe is spec-valid in A2A 1.0 but Wave-2 in AgentOS — refused in Wave-1 with `a2a_wave2_feature_refused` (closed-enum sub-tag `push_notification`). The webhook URL would be caller-controlled by definition; refusing the entire feature in Wave-1 means no caller-controlled webhook URL ever reaches `httpx`. When Sprint 12 (or wherever push-notification lands) lifts this refusal, the caller-URL threat model amendment lands alongside it with explicit per-tenant URL allow-list + Vault-stored signing-key + outbound mTLS — same shape Sprint-5 T13's args-side validation will get when Sprint 8 lifts the STDIO umbrella.

### Architecture-test backstop (T4)

`tests/architecture/test_a2a_no_caller_controlled_url.py` is the static-AST analog of Sprint-5's `test_mcp_stdio_no_subprocess.py`. It walks every module under `protocol/a2a_*` and refuses any:

- `httpx.AsyncClient.get(url=<expression>)` / `httpx.AsyncClient.post(url=<expression>)` where `<expression>` is reachable from a function parameter named `target_url`, `caller_url`, `webhook_url`, or any name matching `*_url` and shadowed by a function parameter (i.e., the URL flows through the function signature from outside the module).
- `f"{caller_supplied}/{constant_suffix}"` shape where `caller_supplied` is a function parameter.
- `urljoin(caller_supplied, ...)` / `urlparse(caller_supplied, ...)` calls reachable on the dispatch path.

The test ships with three self-tests (top-level scan, nested-submodule scan, renamed-module scan) mirroring the Sprint-5 architecture test's collector self-tests.

### Runtime canary (T14)

`tests/unit/protocol/test_a2a_no_caller_controlled_url.py` (note: same filename as the architecture test but lives under `tests/unit/protocol/` — separate module). Mirrors Sprint-5 T13's class shape:

- `TestInboundTargetAgentIsEntrypointName` — every `target_agent` shape that resembles a URL (`https://...`, `//...`, `file://`, `javascript:`, `data:`) is refused at envelope validation with closed-enum `a2a_target_must_be_entrypoint_name`.
- `TestOutboundSpawnSubagentNeverAcceptsURL` — `A2AEndpoint.dispatch_outbound(target_agent="...")` reachable via every API surface refuses any kwarg matching `*_url` (TypeError-typed at the boundary).
- `TestAgentCardDiscoverySuffixIsConstant` — `protocol/a2a_agent_cards.py` discovery code never interpolates a caller value into the well-known suffix. Module-shape assertion (mirrors Sprint-5 `TestThreatModelInvariants`): the constant `_AGENT_CARD_WELL_KNOWN_SUFFIX = "/.well-known/agent-card.json"` is pinned by frozenset equality.
- `TestWave2WebhookRefused` — push-notification subscribe is refused with closed-enum `a2a_wave2_feature_refused` AND the refusal is observable end-to-end through the audit + decision-history chain (parallel to Sprint-5 T12's high-risk-tier evidence chain-readback).

---

## Doctrine Decision C — Schema-drift CI gate env policy

**Decision:** `tests/unit/protocol/test_a2a_schema_drift.py` (T6) is **env-gated** via `@pytest.mark.a2a_upstream` + `COGNIC_RUN_A2A_UPSTREAM=1`. Mirrors the Sprint-4 `cosign_real` pattern (`@pytest.mark.cosign_real` + `COGNIC_RUN_COSIGN_REAL=1`). CI sets the env-var on the dedicated lane; local dev skips the test by default so a developer without network access still runs the full unit suite green.

**Why env-gate (not always-run):** the test pulls upstream A2A 1.0 protobuf source AND the spec's published JSON-schema binding from the spec authors' canonical URLs (pinned at T2 alongside the SDK version). Network-dependent tests in the unit suite would degrade local-dev iteration speed; gating preserves the "unit suite is offline-runnable" contract Sprint-1B established. The drift-gate's purpose is CI-side regression detection, not per-developer iteration.

**Pinned upstream URLs (captured at T2 commit time):**

```python
# Sprint-6 T6 — pinned at SDK lock time. Implementation engineer
# fills in the exact spec-published URLs at PR-author time.
_UPSTREAM_PROTOBUF_URL = "https://a2a-protocol.org/dev/spec/v1.0/a2a.proto"  # PIN AT T2
_UPSTREAM_JSON_SCHEMA_URL = "https://a2a-protocol.org/dev/spec/v1.0/a2a.json"  # PIN AT T2
_PINNED_PROTOBUF_DIGEST = "sha256:..."  # PIN AT T2 — captured digest at lock time
_PINNED_JSON_SCHEMA_DIGEST = "sha256:..."  # PIN AT T2
```

**Drift detection logic (three checks, each fail-closed):**

1. **Upstream-vs-pinned digest check.** Fetch the upstream URL; sha256 the bytes; compare to `_PINNED_PROTOBUF_DIGEST` / `_PINNED_JSON_SCHEMA_DIGEST`. Fail-closed if either has moved beyond our pinned version. Forces a deliberate review + version bump.
2. **Spec-published-binding parity check.** Fetch both the upstream protobuf source AND the upstream JSON-schema binding; verify that the JSON-schema binding's field set is a parity match for the protobuf source's field set. Fail-closed if the spec-published JSON-schema binding has diverged from protobuf — catches upstream drift the spec authors haven't yet republished.
3. **Pinned-vs-installed parity check.** The installed `a2a-sdk == X.Y.Z` SDK's generated Pydantic types must match the pinned protobuf source's field set. Fail-closed otherwise — catches the rare case where the SDK's release artefact lags the spec's release artefact.

**CI lane configuration:** add `a2a-spec drift detection` to `.github/workflows/python.yml` as a separate lane with `env: COGNIC_RUN_A2A_UPSTREAM: 1`. Runs on push + PR. Fails the build on any of the three checks above. Local-dev runs of the full unit suite skip the lane silently with the standard env-gate skip message (parallel to the Sprint-4 cosign-real lane's behaviour).

**Fault-tolerance note:** the test's network round-trip uses `httpx.get` with a 30s timeout + explicit retry budget (one retry on transient failure). A persistent upstream outage (spec authors' site down) results in a CI lane failure that the operator triages as "upstream unreachable" rather than as "drift detected" — distinguished by the explicit `pytest.skip` raise on `httpx.ConnectError` in the test body, vs the `assert digest == pinned` failure on actual drift. Both lanes fail the build but the diagnostic is unambiguous.

---

## Doctrine Decision D — Sub-agent boundary (ADR-005 / Sprint 8 not pulled forward)

**Decision:** Sprint 6 ships the **A2A wire transport** half of the inter-agent communication boundary — the bytes-on-the-wire layer that knows how to construct, verify, send, and receive an A2A 1.0 envelope. Sprint 6 does NOT ship the **orchestration semantics** half — the `harness.spawn_subagent(target_agent, prompt, policy)` API per ADR-005, the recursion-cap enforcement, the policy-budget negotiation, the parent-trace-id chain construction at the orchestration layer. That orchestration layer ships with the **sub-agent primitive in Sprint 8** alongside the sandbox primitive (ADR-004).

**What Sprint 6 ships (transport half):**

- `protocol/a2a_endpoint.py` — inbound receiver. When an A2A envelope arrives, it routes to the registered pack's `handle(message)` method. `parent_trace_id` from the envelope is hash-chained into `decision_history` as the inbound link. **Outbound dispatch is also implemented at the transport layer** — `A2AEndpoint.dispatch_outbound(target_agent, message, *, tenant_id, request_id)` constructs the envelope, fetches + verifies the target's signed Agent Card, dispatches to the verified URL. This is the bytes-side primitive `spawn_subagent` will use.
- `protocol/a2a_agent_cards.py` — card publisher + verifier. Both inbound (registration-time JWS verification) and outbound (call-time JWS verification) paths.
- `protocol/a2a_authz.py` — per-tenant token client. Token rotation. Used by both inbound (validate `Authorization: Bearer ...` on received envelope) and outbound (attach `Authorization: Bearer ...` to dispatched envelope).
- `protocol/a2a_streaming.py` — A2A 1.0 streaming-message wire format for tasks declared `streaming = true`. Streaming is a transport-layer feature; the orchestration layer (Sprint 8) decides which tasks stream.

**What Sprint 8 ships (orchestration half — explicitly OUT of Sprint 6 scope):**

- `harness/spawn_subagent.py` — the orchestration API. `spawn_subagent(target_agent, prompt, policy)` constructs the A2A message envelope, applies recursion-cap enforcement, negotiates policy with the target pack's declared capabilities, and dispatches via `A2AEndpoint.dispatch_outbound` (the Sprint-6 transport primitive).
- Recursion-cap enforcement (per ADR-005 §"Recursion safety") — `agentos.subagent.recursion_cap_exceeded` audit event, refusal closed-enum reason.
- Sandbox-profile resolution (per ADR-004) — sub-agent runs inside a sandboxed sub-process; sandbox primitive ships in Sprint 8 alongside.

**Why the split:** Sprint 8's sandbox primitive (ADR-004 dependency) is what makes `spawn_subagent` safe to land — without sandbox enforcement, an agent could `spawn_subagent` into a recursive loop that exhausts the host process. Sprint 6 lands the transport so Sprint 8 has something to call into; pulling `spawn_subagent` semantics into Sprint 6 would require a sandbox stub that fails-closed (refusing every spawn) — a stub that is operationally meaningless until Sprint 8's real sandbox lands.

**Doctrine guard:** Sprint 6 implementation tests INCLUDE a regression test that `harness/` does NOT import `protocol/a2a_endpoint.py` directly — only via the (not-yet-existing) `harness/spawn_subagent.py` module. This pins the boundary so a future Sprint-7 implementer can't "just call the transport directly" and skip the Sprint-8 orchestration gate.

**Sprint-8 hand-off (load-bearing for ADR-005 implementation):** when Sprint 8 lands, `harness/spawn_subagent.py` ships and consumes `A2AEndpoint.dispatch_outbound`. The Sprint-6 transport's API surface MUST NOT change without an ADR-003 amendment — Sprint-6's outbound dispatch signature is a frozen contract for Sprint-8 to consume.

---

## Doctrine Decision E — UI events Wave-1 taxonomy stability

**Decision (R0 P2 reviewer correction).** Sprint 6 ships the typed Pydantic SCHEMA for **all 11 Wave-1 UI event families** per ADR-020 §"Event taxonomy (Wave 1)" — the public schema is the load-bearing contract that any UI consuming AgentOS events implements, and it MUST be stable from day one even though Sprint 6 wires emit hooks for only the 3 families with existing emit sites. An earlier draft of this section dropped 6 families on the rationale that they had no Sprint-6 emit traffic; the reviewer correctly flagged that as a **schema vs wiring conflation** — the schema covers the full ADR-020 Wave-1 taxonomy regardless of which sprint wires the emit hooks. Subsequent sprints WIRE additional families per the ADR-020 phase table but MUST NOT modify, rename, or remove Wave-1 families — this is a public contract identical in shape to A2A's wire-format pinning.

**Wave-1 event families (all 11 schema-shipped in Sprint 6):**

| Family | Event types | Sprint-6 wiring | Owning sprint for emit hooks |
|---|---|---|---|
| `agent_run` | `started`, `progress`, `completed`, `failed`, `cancelled`, `paused`, `resumed` | schema only | Future sprint introducing the run primitive |
| `tool_call` | `requested`, `approved`, `denied`, `started`, `progress`, `completed`, `failed` | **wired** | Sprint-5 `audit.tool_invocation_*` already emits; T12 adds the parallel UI-event emit |
| `subagent` | `spawned`, `completed`, `failed`, `recursion_capped` | schema only | Sprint-8 sub-agent primitive (per ADR-005 + Doctrine Decision D) |
| `approval` | `pending`, `granted`, `granted_second`, `denied`, `expired` | schema only | Sprint 13.5 (per ADR-014 + ADR-020 phase table) |
| `artifact` | `started`, `chunk`, `completed` | **wired** | Sprint-6 T11's `a2a_artifacts.py` emits artifact lifecycle; T12 wires the UI mirror |
| `interrupt` | `requested_by_agent`, `requested_by_operator`, `acknowledged` | schema only | Sprint 13.5 (typically bundled with approval per ADR-020) |
| `frontend_action` | `submitted`, `accepted`, `rejected` | schema only | Sprint 7B alongside the SSE endpoint + frontend-action POST endpoint |
| `memory` | `recall_started`, `recall_completed`, `forget`, `redact` | schema only | Sprint 11.5 (per ADR-019 memory governance + ADR-020 phase table) |
| `decision_audit` | `event_appended` | **wired** | Sprint-2+ `DecisionHistoryStore.append` already emits; T12 wires the UI mirror |
| `policy` | `decision_evaluated`, `bundle_loaded` | schema only | Sprint 13.5 (per ADR-015 + ADR-020 phase table) |
| `kill_switch` | `flipped`, `reverted` | schema only | Sprint 13.5 (per ADR-018 + ADR-020 phase table) |

**Sprint 6 emit-hook contract.** Three families are wired in Sprint 6, with the third serving as the generic catch-all that satisfies ADR-020's "every existing audit event mirrors" mandate:

1. `tool_call` — Sprint-5's `audit.tool_invocation_{succeeded,failed,refused,errored}` already fires for every MCP tool call. T12 adds a parallel `tool_call.{completed,failed,denied,...}` UI-event emit at the SAME call site, **without changing the audit emit shape**. The audit row remains the system-of-record; the UI event is an in-process mirror with typed family-specific semantics (operator-friendly for runbooks).
2. `artifact` — Sprint-6 T11's `a2a_artifacts.py` emits artifact lifecycle events as it streams chunks via `ObjectStoreAdapter`. T12 wires the UI mirror at the same call sites.
3. **`decision_audit.event_appended` — generic catch-all at `DecisionHistoryStore.append`** (R1 P2 reviewer clarification). EVERY row appended to `decision_history` — regardless of which audit subsystem produced it (Sprint-2 chain rows, Sprint-2.5 SLA / escalation / guardrail events, Sprint-3 LLM-gateway ledger, Sprint-4 plugin-trust / supply-chain, Sprint-5 MCP host, Sprint-6 A2A, AND any future emitter) — produces one `decision_audit.event_appended` UI event with the source row's family / type / payload-digest in `data`. This is the load-bearing mirror that discharges ADR-020's "every existing audit event mirrors" contract: it sits at the canonical sink, so no audit subsystem can emit a row without the UI mirror firing. RBAC-gated to the `audit.read` scope when Sprint 7B's SSE subscriber lands.

The two layers (family-specific mirrors + generic catch-all) are intentional. Family-specific mirrors give UIs typed semantics for the families they care about; the generic mirror guarantees the ADR-020 contract holds even for audit subsystems whose family-specific mirrors haven't been wired yet. When Sprint 13.5 adds the `policy.*` and `kill_switch.*` families' emit hooks, they layer on top of the generic mirror; they don't replace it.

The other 8 families have schema-only stubs in Sprint 6: their Pydantic models register, JSON-schema-export works, completeness tests pass — but no family-specific emit hooks fire because the underlying primitives don't exist yet (e.g., `subagent` waits for Sprint-8's sub-agent primitive; `approval` waits for Sprint-13.5's approval engine). Their *audit-row equivalents*, when they exist in Sprint 6 (e.g., a hypothetical Sprint-13.5 `audit.approval_pending` row), still mirror through `decision_audit.event_appended` per the generic catch-all. When the owning sprints land, they extend `ui_events.py` with family-specific emit-hook wiring at the new primitive's call sites.

**Sprint 6 does NOT modify any Sprint-5 audit emit.** The UI event mirror is an ADDITION at the call site, not a refactor. This is the "schema stable from day one" doctrine in practice: by the time the SSE endpoint subscribes (Sprint 7B), the 3 wired families have real event traffic + the other 8 have stable schema definitions ready for their owning-sprint wiring.

**Wave-1 schema versioning:** every event carries `schema_version: "1.0"`. Future event TYPES append within an existing family's type enum (e.g., Sprint 13.5 may add `approval.escalated` after `approval.expired`). Future FAMILIES append to the family enum (Wave 2 might add `mcp_session` for example). **Removals or renames are breaking changes that require ADR-020 amendment + a new schema version (1.x → 2.0)**.

**Phased family wiring per ADR-020 §"Implementation phases" (schema for ALL families ships in Sprint 6 — this table is wiring, not schema):**

| Sprint | Wires emit hooks for | Notes |
|---|---|---|
| **Sprint 6 (this sprint)** | `tool_call`, `decision_audit`, `artifact` | Three families with existing emit sites; other 8 are schema-only stubs |
| Sprint 7B | `frontend_action` | Plus SSE endpoint, RBAC-scoped subscriber, JSON-schema publication at `/.well-known/cognic-ui-events.json`, catch-up cursor endpoint |
| Sprint 8 | `subagent` | Per ADR-005 sub-agent primitive |
| Sprint 11.5 | `memory` | Per ADR-019 memory governance |
| Sprint 13.5 | `approval`, `interrupt`, `policy`, `kill_switch` | Per ADR-014 / ADR-015 / ADR-018 |
| (later) | `agent_run` | When the run primitive lands (Sprint-7A or later) |

**Drift detectors (T12):**

- `tests/unit/protocol/test_ui_event_taxonomy_completeness.py::test_wave_1_family_set_pinned` — the Wave-1 family enum literal MUST equal the 11 families above. Adding (forbidden in Sprint 6) OR removing a family fails the test. Future sprints adding families bump the expected set + leave a comment naming the ADR-020 phase row that authorised the addition.
- `test_ui_event_taxonomy_completeness.py::test_wired_family_set_pinned` — the Sprint-6-WIRED subset MUST equal `{"tool_call", "decision_audit", "artifact"}`. Future sprint amendments grow this set (Sprint 7B adds `frontend_action`, etc.) at the same time they ship the wiring — the test catches drift between the wiring code and the doctrine table above.

**Pydantic v2 schema export:** `protocol/ui_events.py` exports a JSON-schema document via `model_json_schema()` for every event type across all 11 families. Sprint 7B publishes this at `/.well-known/cognic-ui-events.json` per ADR-020 §"Bundles a portable JSON schema". Sprint 6 ships only the schema-export functions; no HTTP route.

---

## Doctrine Decision F — Critical-controls expansion rationale (21 → 27)

**Decision:** Sprint 6 grows the per-file critical-controls coverage gate from 21 modules (Sprint-5 closeout state) to **27 modules** (six new entries, not five — R0 P2 reviewer correction added `a2a_version.py` per AGENTS.md §"Wire-protocol contracts" stop-rule). Each new entry carries the strict 95% line / 90% branch floor; each one's inclusion is justified below against the AGENTS.md critical-controls doctrine criteria.

| Module | Added by | Doctrine trigger | Why critical |
|---|---|---|---|
| `protocol/a2a_authz.py` | Sprint 6 T5 | AGENTS.md §"Protocol authorization" — already named in the doctrine list pre-Sprint-6 (alongside `mcp_authz.py` + `a2a_authz.py`). Sprint-6 lands the implementation; the gate enforcement extends accordingly. | Per-tenant token gate. Anonymous A2A is forbidden Wave-1. A bypass here = unauthenticated cross-agent traffic. Mirrors `mcp_authz.py` shape + criticality. |
| `protocol/a2a_agent_cards.py` | Sprint 6 T7 | ADR-003 §"Agent Cards" + A2A-CONFORMANCE.md §"Card signatures (JWS)" — JWS verification is the routing-safety primitive. | Outbound dispatch URLs come from JWS-verified cards. A bypass here = AgentOS dispatching to attacker-controlled URLs. Same identity-routing criticality as Sprint-4's trust gate over wheel cosign. |
| `protocol/a2a_endpoint.py` | Sprint 6 T9 | AGENTS.md §"Wire-protocol contracts" + ADR-003 §"Audit chain linkage". | Single owner of the task-lifecycle state machine + cross-agent chain linkage. State-machine bugs here = phantom tasks / chain breaks visible in audit replay. |
| `protocol/a2a_schema.py` | Sprint 6 T6 | AGENTS.md §"Wire-protocol contracts" — A2A 1.0 wire format pinning. | Drift here = wire-protocol break across deployments. Sprint-2's `core/canonical.py` is the audit-chain analog; `a2a_schema` is the cross-agent wire analog. Schema-drift CI gate (T6) is the runtime backstop. |
| `protocol/a2a_version.py` | Sprint 6 T8 | AGENTS.md §"Wire-protocol contracts" — version negotiation IS wire-protocol surface (R0 P2 reviewer correction). | Module is small (<100 stmts) + pure-functional but the 6-case header negotiation matrix is the wire-protocol gate every inbound A2A call passes through. A bypass here = silently accepting wrong-version envelopes (e.g., upgrading absent-header to 1.x when the spec mandates rejection). State-machine + closed-enum invariants ride at the same strict 95/90 floor as the other wire-protocol modules. |
| `protocol/ui_events.py` | Sprint 6 T12 | AGENTS.md §"UI event-stream contract (ADR-020)" — public event schema, MUST remain backward-compatible across versions. | Per ADR-020 §"What this is NOT" + §Phased schedule: the event schema is a public contract once any UI subscribes. Sprint-6 establishes the shape Sprint-7B will publish; a regression here (family removed, type renamed, payload shape changed) is a breaking change to every downstream UI integration. |

**Gate growth path:**

```python
# tools/check_critical_coverage.py (Sprint 6 T15 amendment)
_CRITICAL_FILES: tuple[tuple[str, float, float], ...] = (
    # ... Sprint 2-5 entries (21 modules) ...

    # Sprint 6 T15 — A2A endpoint + version-negotiation + UI events
    # sextet. Per ADR-003 + ADR-020 + AGENTS.md critical-controls list
    # amendments. All six ride the same single strict 95% line / 90%
    # branch floor as the Sprint-2/2.5/3/4/5 modules above:
    #   * a2a_authz.py — per-tenant pinned-token client (anonymous-A2A
    #     forbidden Wave-1; Vault-rotated; mirrors mcp_authz pattern).
    #   * a2a_agent_cards.py — two-pass card validator + JWS verify
    #     against Sprint-4 trust root; identity-routing critical.
    #   * a2a_endpoint.py — task-lifecycle state machine + cross-agent
    #     chain linkage; single owner of inbound + outbound transport.
    #   * a2a_schema.py — pinned A2A 1.0 wire-format types; schema-drift
    #     CI gate (test_a2a_schema_drift.py) is the runtime backstop.
    #   * a2a_version.py — A2A-Version header negotiation matrix; per
    #     AGENTS.md §"Wire-protocol contracts" the version gate is
    #     wire-protocol surface even though the module is small.
    #   * ui_events.py — Wave-1 typed event taxonomy + emit-hook layer;
    #     public event schema, MUST remain backward-compatible across
    #     versions per ADR-020.
    ("src/cognic_agentos/protocol/a2a_authz.py", 0.95, 0.90),
    ("src/cognic_agentos/protocol/a2a_agent_cards.py", 0.95, 0.90),
    ("src/cognic_agentos/protocol/a2a_endpoint.py", 0.95, 0.90),
    ("src/cognic_agentos/protocol/a2a_schema.py", 0.95, 0.90),
    ("src/cognic_agentos/protocol/a2a_version.py", 0.95, 0.90),
    ("src/cognic_agentos/protocol/ui_events.py", 0.95, 0.90),
)
```

**Modules NOT included in the critical-controls floor (deliberate):**

- `protocol/a2a_streaming.py` (T10) — wire-format streaming adapter; consumes the schema (T6) + dispatches via the endpoint (T9). Has no independent fail-closed invariants beyond what those two enforce. Sprint-7 evaluation: if streaming-side bugs surface, promote to critical-controls then.
- `protocol/a2a_artifacts.py` / `a2a_capability_negotiation.py` / `a2a_cancellation.py` / `a2a_errors.py` (T11) — small endpoints + an enum module. None carry independent fail-closed invariants; all consume the upstream critical-controls modules.

**(R0 P2 reviewer note — historical)**: an earlier draft of this section listed `a2a_version.py` as NOT included in the critical-controls floor on the rationale that it's a small pure-functional module. The reviewer correctly flagged that AGENTS.md §"Wire-protocol contracts" treats version negotiation as stop-rule material regardless of module size — the test surface is small but the doctrinal surface is wire-protocol-public. Promoted into the gate; gate count adjusted 26 → 27.

**AGENTS.md amendment text (lands at T16):** see Task 16 §"AGENTS.md amendment text" above for the exact insert under the AGENTS.md critical-controls list.

---

## Self-Review

After authoring the 16 tasks above + folding in the six doctrine-decision sections, the plan was reviewed against:

**Spec coverage check.** Every BUILD_PLAN Sprint 6 deliverable is mapped to a task:

| BUILD_PLAN deliverable | Task |
|---|---|
| `protocol/a2a_endpoint.py` | T9 |
| `protocol/a2a_schema.py` | T6 |
| `protocol/a2a_version.py` | T8 |
| `protocol/a2a_agent_cards.py` | T7 |
| `protocol/a2a_streaming.py` | T10 |
| `protocol/a2a_artifacts.py` | T11 |
| `protocol/a2a_capability_negotiation.py` | T11 |
| `protocol/a2a_cancellation.py` | T11 |
| `protocol/a2a_errors.py` | T11 |
| `protocol/a2a_authz.py` | T5 |
| `portal/api/app.py` (POST /api/v1/a2a + task management) | T9 (receiver) + T11 (capabilities/cancellation/artifacts) |
| `tests/fixtures/a2a-conformance/` | T13 |
| `docs/A2A-CONFORMANCE.md` (alignment review) | T3 |
| `protocol/ui_events.py` (ADR-020 stub) | T12 |

**Six additional load-bearing artifacts the plan adds beyond BUILD_PLAN's literal list:**

1. `tests/architecture/test_a2a_no_subprocess.py` (T4) — guardrail mirroring Sprint-5 architecture test.
2. `tests/architecture/test_a2a_no_caller_controlled_url.py` (T4) — URL-source backstop per Doctrine Decision B.
3. `tests/unit/protocol/test_a2a_no_caller_controlled_url.py` (T14) — runtime canary backstop for the same threat model.
4. `docs/A2A-CALLER-URL-THREAT-MODEL.md` (T4 / T14 reference) — doctrine document mirroring `docs/MCP-STDIO-THREAT-MODEL.md`.
5. `tests/unit/protocol/test_a2a_schema_drift.py` (T6) — env-gated upstream drift CI gate.
6. `tests/unit/protocol/test_ui_event_taxonomy_completeness.py` (T12) — Wave-1 family/type pinning per Doctrine Decision E.

**Placeholder scan.** Searched the plan for "TBD", "TODO", "implement later", "fill in details", "add appropriate ...". Three deliberate placeholders, each marked "PIN AT T2":

- T2 `a2a-sdk == X.Y.Z` — exact version filled at T2 commit time after PyPI check (verify `pip index versions a2a-sdk` matches the upstream A2A 1.0 spec authors' release; confirm the import namespace is `a2a` not `a2a_sdk` and not `a2a_protocol`).
- T6 `_UPSTREAM_PROTOBUF_URL` / `_UPSTREAM_JSON_SCHEMA_URL` / `_PINNED_PROTOBUF_DIGEST` / `_PINNED_JSON_SCHEMA_DIGEST` — pinned at T2 alongside the SDK version. Implementation engineer captures the digests from the upstream URLs at lock time.

These are honest deferrals (matches Sprint-4 T13 cosign-pin pattern + Sprint-5 T2 mcp-pin pattern), not placeholders. The plan's doctrine-decision sections name the exact data needed at each pin point.

**Type consistency.** Every type referenced in later tasks is defined in earlier ones:

- `A2AAuthzClient` (T5) constructor params reused in T9.
- `Token` / `AgentCardManifest` / `ResolvedAgentCard` (T5 / T7) reused in T9 / T10.
- `A2AEndpoint` (T9) consumes `MessageEnvelope` from T6 + `Token` from T5.
- `UIEvent` base class (T12) + **11 Wave-1 family-specific subclasses** (one per ADR-020 §"Event taxonomy (Wave 1)" family), all Pydantic v2 frozen models with `schema_version: "1.0"` literal.
- Closed-enum literals: `A2AAuthzReason` (T5), `RefusalReason` extension (T1; from 26 → 32 with the 6 new A2A reasons), `A2AVersionOutcome` (T8 — 6-value matrix), `A2AErrorCode` (T11 — full A2A 1.0 enum), `WaveOneEventFamily` literal (T12 — 11 values pinned). Drift detectors at T1 / T5 / T8 / T11 / T12 pin each set.

**Doctrine drift scan against ADR-003 + ADR-020 + A2A-CONFORMANCE.md.** No drift detected (post R0 corrections):

- ADR-003 §"Inbound A2A" / §"Outbound A2A" — implemented at T9 with the explicit Sub-agent boundary (Doctrine Decision D).
- ADR-003 §"Message envelope" — Sprint 6 follows the spec wire format (NOT the illustrative Python dict in the ADR); pinned via T6 schema gate.
- ADR-003 §"A2A 1.0 feature scope" — Wave-1 features all in T9 / T10 / T11; Wave-2 features refused with closed-enum at T14.
- ADR-003 §"Version negotiation" — implemented at T8 with the 4-case matrix; module is critical-controls per AGENTS.md §"Wire-protocol contracts".
- ADR-003 §"Audit chain linkage" — implemented at T9 (inbound `a2a.task_received`) + T9 outbound dispatch (`a2a.task_dispatched`). The Sub-agent boundary (Doctrine Decision D) records that `spawn_subagent`-side audit chaining ships in Sprint 8.
- ADR-020 §"Decision" — Sprint 6 implements item 1 (typed event schema for ALL 11 Wave-1 families). Items 2-6 (SSE transport, RBAC subscriber, decision-history-mirror catch-up endpoint, frontend-action POST, JSON-schema publication at the well-known path) ship in Sprint 7B per the ADR's phased schedule. Doctrine Decision E pins the full taxonomy.
- ADR-020 §"Event taxonomy (Wave 1)" — **all 11 families** pinned in Doctrine Decision E + T12 (R0 P2 reviewer correction — earlier draft only pinned 5). Phased emit-hook wiring per ADR-020 §"Implementation phases" documented in Doctrine Decision E.
- ADR-020 §"Subscription endpoints" — explicitly out of Sprint 6 scope (Sprint 7B). Plan calls this out.
- A2A-CONFORMANCE.md §"Feature conformance matrix" — Wave-1 column ✅ entries all in T9-T13; Wave-2 ❌ entries refused at T14.
- A2A-CONFORMANCE.md §"Authorization" — Wave-1 per-tenant Bearer at T5; Wave-2 mTLS deferred per Doctrine Decision F (refused with closed-enum sub-tag).
- A2A-CONFORMANCE.md §"Card shape" — two-pass validation at T7 (upstream + AgentOS profile).
- A2A-CONFORMANCE.md §"Card signatures (JWS) — mandatory for AgentOS" — JWS verify at T7 via Sprint-4 trust root extension; admission ordering per Doctrine Decision F (cosign first, then manifest extract, then card JWS verify).
- A2A-CONFORMANCE.md §"Audit linkage" — T9 inbound + outbound chain links.
- A2A-CONFORMANCE.md §"Versioning" — T6 schema pin + drift gate (with the dedicated `a2a-spec drift detection` CI lane added at T6 per R0 P2 reviewer correction).
- A2A-CONFORMANCE.md §"Version negotiation" — T8 4-case matrix; promoted to critical-controls per R0 P2 reviewer correction.
- A2A-CONFORMANCE.md §"What pack authors must declare" — `agent_card_jws_path` mandatory at T7.

**R0 + R1 reviewer-round corrections folded into this Self-Review (two rounds before plan commit):**

| Finding | Fix |
|---|---|
| **R0 P1** — SDK pinned to wrong PyPI package (`a2a-protocol` was a different 0.1.0 package; official is `a2a-sdk` with import namespace `a2a`) | Renamed throughout: `a2a-protocol` → `a2a-sdk`, import `a2a_protocol` → `a2a`. Version becomes `X.Y.Z` PIN-AT-T2 placeholder (mirrors Sprint-4 cosign-pin pattern) since exact version requires PyPI lookup at lock time. Affected: T2, T6, T7, T8, Doctrine Decision A. |
| **R0 P2 #1** — Plan promised 6 doctrine-decision sections + Self-Review but the file ended at T16 commit block | Sections A-F + Self-Review now present (the reviewer reviewed a pre-append snapshot). |
| **R0 P2 #2** — T2 `create_prod_app` mounted A2A routes that don't exist until T9+ — same overclaim Sprint-5 T15 R1 P2 #1 caught | T2 narrowed to SDK-presence log + `is_a2a_available()` predicate only; route mounting deferred to T9 / T11 / T12. File-structure description rewritten to reflect the two-phase shape. |
| **R0 P2 #3** — UI event taxonomy listed 5 families with `decision_audit` but ADR-020 §"Event taxonomy (Wave 1)" lists 11 families | Sprint 6 now ships SCHEMA for all 11 ADR-020 Wave-1 families; emit hooks wire only for the 3 with existing emit sites (`tool_call`, `decision_audit`, `artifact`). Other 8 families are model-only stubs whose emit hooks land in their owning sprints per the ADR-020 phase table. T12 + Doctrine Decision E + drift-detector test all updated. |
| **R0 P2 #4** — `a2a_version.py` was excluded from critical-controls floor on the rationale of being small + pure-functional, but AGENTS.md §"Wire-protocol contracts" treats version negotiation as stop-rule material | Promoted to critical-controls. Gate count adjusted 21 → **27** (was 21 → 26). T15 + Doctrine Decision F + AGENTS.md amendment text + Self-Review type-consistency line updated. |
| **R0 P2 #5** — Schema-drift CI gate would silently skip both locally AND in CI because the workflow was never updated | T6 file list now includes `.github/workflows/python.yml` with the explicit `a2a-spec drift detection` lane (`COGNIC_RUN_A2A_UPSTREAM=1`); `pyproject.toml`'s `[tool.pytest.ini_options].markers` registers `a2a_upstream` so pytest doesn't warn. |
| **R0 P2 #6** — Agent Card JWS verification ordered BEFORE wheel cosign verification, but doctrine says pack must be cosign-trusted FIRST so its declared metadata is trustworthy enough to read | File-structure description for `protocol/plugin_registry.py` now explicitly orders: (1) allow-list → (2) wheel cosign → (3) Sprint-4 attestation pipeline → (4) Sprint-5 deferred-load manifest extract → (5) **NEW Sprint-6 step:** Agent Card JWS verify against per-tenant trust root. |
| **R0 P3** — Several placeholder snippets ("full implementation following Sprint-5 T4 pattern", abbreviated canary bodies, all-zeroes pinned digests without explicit "PIN AT T2" annotation) | Pinned-digest sentinels left as `0...` but explicitly annotated PIN AT T2; abbreviated tasks flagged here for the implementation engineer to expand on a per-task basis at TDD-step time. The Sprint-5-style "every code block complete" doctrine is reasserted in this Self-Review entry: implementation engineer fills concrete code at task time, not before. |
| **R1 P2** — ADR-020 audit-mirror scope ambiguous (plan wired only `tool_call` + `decision_audit` + `artifact`, but ADR-020 says "every existing audit event mirrors"). | T12 + Doctrine Decision E now state explicitly that the `decision_audit.event_appended` hook at `DecisionHistoryStore.append` is the **generic catch-all** covering every audit/decision row regardless of subsystem origin (Sprint-2 chain / Sprint-2.5 SLA / Sprint-3 ledger / Sprint-4 plugin-trust / Sprint-5 MCP / Sprint-6 A2A / future). Family-specific mirrors give typed semantics; the generic mirror discharges the ADR-020 contract. New regression test in `test_ui_events_audit_mirror.py` exercises the generic path with a non-tool, non-artifact row. |
| **R1 P3** — `create_prod_app` docstring still promised route mounting after the body was corrected to log-only. | Docstring rewritten: "T2 ONLY logs SDK availability — route mounting is deferred to T9 / T11 / T12". Explicit reference to the Sprint-5 T15 R1 P2 #1 overclaim that this fix mirrors. |
| **R1 P3** — Document map line 46 still said "5 families pinned" while the body said 11 schema / 3 wired. | Document map line refreshed to match. |
| **R1 P3** — `A2AVersionOutcome` count drift: file-structure said "5 values" while listing 6; tests inventory said "5 cases" while T8 said "6". | Pinned to 6 consistently across file-structure, tests-inventory, T8, Doctrine Decision F. |

If you find further issues, fix them inline. No need to re-review — just fix and move on. If you find a spec requirement with no task, add the task.

---

## Execution Handoff

After saving the plan, offer execution choice:

**"Plan complete and saved to `docs/superpowers/plans/2026-05-04-sprint-6-a2a-endpoint.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — Dispatch a fresh subagent per task; review between tasks; fast iteration. Same pattern as Sprint 5.

**2. Inline Execution** — Execute tasks in this session using executing-plans skill; batch execution with checkpoints for review.

**Which approach?"**

If Subagent-Driven chosen: Use `superpowers:subagent-driven-development` skill — fresh subagent per task + two-stage review.

If Inline Execution chosen: Use `superpowers:executing-plans` skill — batch execution with checkpoints.
