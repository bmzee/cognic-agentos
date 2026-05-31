# ADR-019 — Agent Memory Governance

## Status
**APPROVED for implementation** on 2026-04-27.

## Context

Modern agent frameworks (LangGraph, Pydantic AI, Anthropic Managed Agents, OpenAI Agents SDK) treat **memory** as a first-class primitive: short-term scratch, mid-term task state, long-term cross-session knowledge. Banks need this — repeat-customer recognition, multi-day workflow continuity, learned escalation patterns, audit-friendly recall — but uncontrolled memory is a compliance liability:

- A PII fact written to long-term memory by Tool A can leak into Agent B's response in a different session
- "Forget" is not the same as "delete"; regulator-driven erasure (GDPR right-to-erasure, SBP customer-data deletion) demands provable removal
- Cross-session reuse without consent violates purpose-limitation requirements (ADR-017)
- Audit chain integrity breaks when memory state appears in a response without a chain-linked provenance event

Existing ADRs cover adjacent concerns:
- ADR-004 sandbox checkpoints (process state, not semantic memory)
- ADR-006 ISO 42001 control mapping (audit, not the memory API itself)
- ADR-007 provider honesty (LLM call ledger, not what the LLM remembered)
- ADR-014 runtime tool approval (per-call gate, not per-fact gate)
- ADR-017 data-governance contracts (declarative classification, not enforcement at write time)

**Gap:** there is no single primitive that governs *what an agent may remember*, *what it must forget*, *what it can export*, *what it must redact*, *what it can reuse across sessions*, *how memory access is audited*, and *who can see/extract a tenant's accumulated memory*.

This ADR defines that primitive.

## Decision

Add a `core/memory/` platform primitive providing a **governed memory API** that every agent in every pack uses. Banks get the same compliance guarantees on memory that they already have on tool calls and LLM invocations.

### Memory tiers

Three explicit tiers, every fact tagged with one:

| Tier | Lifetime | Cross-session | Cross-agent | Default policy |
|---|---|---|---|---|
| **`scratch`** | Single agent invocation; discarded at session close | No | No | Always allowed; not audited per-write (audited per-session) |
| **`task`** | Multi-step workflow within one session (or one resumable-sandbox lifetime per ADR-004) | No | Yes (within the same session) | Allowed by default; audited per-write with data classification |
| **`long_term`** | Cross-session, cross-agent (within a tenant) | Yes | Yes | **Default-deny** — requires explicit pack manifest declaration + tenant Rego policy + per-fact data-class consent (per ADR-017) |

Cross-tenant memory is forbidden in Wave 1; reserved as a Wave 3 concern (federated A2A + AGNTCY identity).

### Governed self-improvement

AgentOS should support Hermes-style improvement: continuous behaviour improvement through memory, feedback, evaluation evidence, and capability-promotion proposals across long-running agent deployments. The improvement loop is a governed platform capability, not uncontrolled agent self-modification. Agent packs declare what the agent is allowed to learn; AgentOS controls how learning is stored, evaluated, promoted, approved, audited, rolled back, or refused.

Three improvement classes are permitted:

1. **Memory improvement** — preferences, prior cases, resolved workflows, and escalation patterns flow through the AgentOS memory API. Private agent-owned `long_term` memory is forbidden; the governed memory store is the only persistence path.
2. **Behaviour improvement** — AgentOS records outcome metadata via `core/decision_history.py`, the gateway-call ledger, and the Sprint 12 eval harness. Routing-change recommendations are submitted as ordinary promotion proposals through the existing model lifecycle and promotion flow (ADR-013, including `POST /api/v1/models/{id}/promote`); agent-derived recommendations carry no special channel beyond the evidence they attach. Prompt/config changes surface as pack-version promotion proposals (ADR-012). No runtime mutation of routing, prompts, manifests, tools, skills, or pack contents occurs outside these named promotion gates.
3. **Capability improvement** — an agent may propose a new tool, skill, workflow, prompt, or sub-agent template, but it cannot activate that proposal silently. The proposal is a structured recommendation submitted to AgentOS with evidence such as failed cases, suggested prompt deltas, or suggested tool specs. Pack authoring and cosign signing remain developer / bank-engineering activities per ADR-008 and ADR-016; the resulting signed pack artifact or pack update must pass plugin registry admission, supply-chain checks, evaluation gates, policy review, and human approval per AGENTS.md "Human-only decisions" where required.

The pack manifest declares the allowed learning surface in `[tool.cognic.learning_surface]`: memory tiers, feedback signals, evaluation metrics, promotable artifact types, and human-approval requirements. Build-time shape validation belongs in `cli/validators/learning_surface.py`; closed-enum vocabularies belong in `cli/_governance_vocab.py`, matching the data-governance / risk-tier pattern. Attempts to self-modify outside the gate refuse with a closed-enum `learning_surface_violation` reason owned by that validator family. No runtime code rewrite, unreviewed prompt mutation, new tool activation, skill promotion, or sub-agent creation becomes active without AgentOS-mediated promotion.

Comparison with Hermes Agent (Nous Research, 2026): Hermes is a personal-AI variant where the agent may directly write local memory, skill, and persona files that affect later invocations. AgentOS implements the same capability classes — persistent memory, procedural skills, persona/configuration, scheduled execution, and feedback-driven improvement — but mediates each through governed promotion gates: signed pack artifacts (ADR-016), pack lifecycle review and allow-listing (ADR-012), runtime approval for high-risk tiers (ADR-014), scheduler admission for background work (ADR-022), and chain-linked audit (ADR-006). The trade-off is intentional: slower iteration in exchange for bank-grade auditability, rollback, and supply-chain integrity.

### Governed memory API

```python
# Layer C agent code accesses memory only via the harness-injected API:
class MemoryAPI:
    async def remember(self, key: str, value: Any, *, tier: MemoryTier,
                       data_classes: list[DataClass],
                       purpose: Purpose,
                       retention_window: timedelta | None = None,
                       consent_token: ConsentToken | None = None) -> MemoryRecordId
    async def recall(self, key: str, *, tier: MemoryTier,
                     purpose: Purpose) -> MemoryHit | None
    async def forget(self, record_id: MemoryRecordId, *, reason: ForgetReason) -> ForgetReceipt
    async def redact(self, record_id: MemoryRecordId, *, span: RedactionSpan,
                     reason: RedactionReason) -> RedactionReceipt
    async def export(self, scope: ExportScope, *, requester: Principal,
                     rbac_scope: str) -> ExportPackId
    async def list_for_subject(self, subject_id: str) -> list[MemoryRecordId]
```

Six operations; no other access path. Direct database queries against the memory store are forbidden for Layer C code (architecture-discipline test enforces).

### Per-write enforcement

Every `remember()` call goes through this gate:

1. **Tier check** — `long_term` requires pack manifest `[tool.cognic.memory] long_term_writes_allowed = true` AND tenant Rego policy `memory.long_term.allow` returns true
2. **Data-class check** — value scanned by the **Sprint 11.5 DLP seed (`core/dlp/scanner.py`, expanded in Sprint 13.5)** per ADR-017; detected restricted classes (`customer_pii` / `payment_data` / `credentials` / `regulator_communication` — the build-time vocabulary, see amendment) trigger the consent-token requirement. The seed ships with memory governance so write-time classification exists from the moment `remember()` is callable; Sprint 13.5 extends the same scanner with post-call DLP on tool outputs and custom recogniser plugins
3. **Purpose check** — declared purpose must match a purpose declared in the pack's `[tool.cognic.data_governance].purpose` list
4. **Consent check** — for restricted data classes, `consent_token` must be present AND not expired AND matching the subject; consent ledger event chain-linked
5. **Retention enforcement** — `retention_window` capped at the smaller of (declared, tenant max for the data class)
6. **Audit emission** — `memory.write` event hash-chained into `decision_history` with tier, data classes, purpose, retention, record_id, redacted-value-digest (NOT the value itself)

Failure at any step → write refused with categorised error; Layer C agent receives a typed exception, not a silent drop.

### Per-recall enforcement

Every `recall()`:

1. Authorisation: requesting agent must have a manifest-declared `memory_read.<tier>` capability
2. Purpose alignment: declared purpose must be compatible with the original write's purpose (matrix in `policies/_default/memory_purpose_matrix.rego`)
3. Subject scope: cross-subject recall (Agent reading Customer A's memory while serving Customer B) refused unless explicit `cross_subject_recall = true` declaration + tenant policy override
4. Audit emission: `memory.read` event chain-linked, including hit/miss

### Forget + redact

- **`forget(record_id, reason)`** — soft-delete record (tombstone with reason + actor + timestamp); subsequent `recall` returns miss; underlying storage purged by reaper after tenant-configured tombstone window (default 30 days for examiner traceability)
- **`redact(record_id, span, reason)`** — partial redaction (e.g. mask account number while preserving outcome reasoning); produces a new record version; old version retained (sealed) until tombstone window expires
- **Regulator-driven erasure**: `forget(reason="regulator_erasure")` triggers immediate tombstone + immediate purge (no 30-day window) AND emits `memory.regulator_erasure` event with chain-of-custody fields (regulator order id, requester RBAC scope, subject id)

### Export

Examiners and tenant admins (RBAC `memory.export.read`) can export a subject's accumulated memory for compliance review. Export produces a Sigstore-bundled archive (per ADR-016 retention rules) so tampering during transit is detectable.

### Storage

`MemoryAdapter` protocol with reference impls:
- `PostgresMemoryAdapter` — relational; per-tenant schema; tier columns + JSONB value
- `RedisMemoryAdapter` — for `scratch` tier only (sub-second TTL). **Wave-1/11.5a: fail-closed on Redis-unreachable** (raises an infrastructure error, not a governance refusal); the Postgres fallback is deferred to 11.5b once the reaper provides Postgres-scratch TTL cleanup (see the Sprint-11.5 amendment + Cut-A rule)

Vector embeddings of memory values flow through the existing `VectorStoreAdapter` (Qdrant default per ADR-009) so semantic recall reuses the search infrastructure; data-class metadata is co-stored so vector-recall results can be filtered by purpose at query time.

### Integration with ADR-014 approval

Tools that write `long_term` memory in a pack with `risk_tier >= customer_data_write` route the write through the runtime approval engine (Sprint 13.5). This means the same 4-eyes flow that gates a payment also gates a long-term-memory write of payment-related facts.

**Sprint 11.5 → Sprint 13.5 transitional rule** (mirrors the MCP-tool transitional rule in ADR-014): between the moment Sprint 11.5 ships and the moment `core/approval` lands in Sprint 13.5, `long_term` writes from packs with `risk_tier >= customer_data_write` are **refused** with error `memory_approval_engine_not_available`. The write attempt is audit-logged with declared tier so banks can plan rollout. `scratch` and `task` tier writes work normally regardless of risk tier; `long_term` writes from `read_only` / `internal_write` packs work normally. The refusal is mechanical (not configurable) and is removed by Sprint 13.5; the cutover emits a `memory_approval.engine_enabled` audit event so the moment high-risk long-term memory writes became permitted is provable.

This sequencing is identical in spirit to the MCP-tool rule: there is no safe way to allow high-risk memory writes without an approval engine; "log it and let it run" violates the threat model. The fix is not "lower the bar"; the fix is "ship Sprint 13.5 on schedule."

### Integration with ADR-018 emergency

A new kill-switch class `memory.write_freeze` (operator can freeze all `long_term` writes per tenant pending compliance investigation); existing `tenant_full` kill switch automatically freezes memory access too.

## Consequences

### Positive
- **Compliance-grade memory** — banks can prove what an agent remembered, why, with what consent, for how long
- **Right-to-erasure ready** — GDPR / SBP customer-data deletion via a single `forget(reason="regulator_erasure")` call with audited chain-of-custody
- **Cross-agent isolation** — agents cannot leak facts into each other's recall via misconfigured memory; default-deny prevents accidents
- **Reuse across sessions audited** — every recall is chain-linked, so examiners can prove which prior fact influenced which decision
- **Aligns with industry patterns** — LangGraph and Pydantic AI memory abstractions land here naturally; AgentOS exposes the policy layer they assume

### Negative
- **Layer C API surface grows** — agent authors must learn ten operations (7 core + 3 block; see amendment) + tier semantics; mitigated by SDK helpers (Sprint 7A)
- **Latency** — per-write data-class scanning + Rego policy adds ~10-30ms to `long_term` writes; `scratch` tier unchanged; banks accept the cost given the compliance value
- **Storage cost** — tombstone + redaction history adds ~2× storage for `long_term` tier; mitigated by reaper + tenant-configured tombstone windows
- **Wave 1 scope** — sub-agent durable memory inheritance is deferred to Wave 1.5 per ADR-005; Wave 1 is **strict scratch-only for sub-agents** (durable `task`/`long_term` access refused; durable memory is parent-mediated — see amendment)

### Neutral
- Memory is a platform primitive (peer of audit/decision_history/guardrails), not a plugin pack; same logic as runtime approval — every bank deployment needs it

## Implementation phases

| Sprint | Work |
|---|---|
| **Sprint 7A** (extended) | Pack manifest schema includes `[tool.cognic.memory]` block with `tiers_supported`, `long_term_writes_allowed`, `cross_subject_recall`, `memory_read_capabilities`. Validators added. |
| **Sprint 7B** (extended) | Reviewer evidence panel shows declared memory tiers + cross-subject access + a diff against tenant memory policy |
| **Sprint 9** (extended) | ISO 42001 control tags added to `memory.write` / `memory.read` / `memory.forget` / `memory.redact` events |
| **Sprint 10** (extended) | Per-tenant Vault-backed memory-adapter credentials |
| **New: Sprint 11.5a** | `core/memory/` substrate — `MemoryAPI` (10 ops; 7-op 11.5a surface), `MemoryAdapter` protocol, Postgres + Redis(scratch) impls, DLP seed, default-deny `memory.rego` + `memory_purpose_matrix.rego`, kill-switch **seam**. **DI-tested, NOT harness-injected** (harness wiring deferred — see amendment). ~2 work-units (Cut-A split). |
| **Sprint 11.5b** | lifecycle (`forget`/`redact`/`regulator_erasure` + reaper), `export`, **real Redis `memory.write_freeze`** (replaces the 11.5a seam), `learning_surface` validator, portal/UI/RBAC depth |
| **Sprint 13.5** (extended) | high-risk-tier `long_term` writes route through the approval engine (lifting the 11.5a transitional refusal); broader emergency-control set (other kill-switch classes + quotas); `memory.rego` bundle expanded (granularity) — defaults unchanged |

Sprint 11.5 inserts between Sprint 11 (sub-agent primitive) and Sprint 12 (eval harness) so eval can exercise memory-aware agents.

### Schedule impact

Phase 4 grows from 14 → 16 work-units (Sprint 11.5 = 2 wu). Phases 1-4 total: 49 → 51 work-units / ~17-21 calendar weeks.

## References
- ADR-004 (sandbox — resumable session checkpoints; memory survives across sandbox waking)
- ADR-005 (sub-agent — memory inheritance rules between parent and child)
- ADR-006 (ISO 42001 — control tags on memory events)
- ADR-014 (runtime approval — high-risk memory writes go through approval)
- ADR-015 (policy-as-code — `memory.rego` decides cross-subject + cross-purpose recall)
- ADR-017 (data governance — manifest declares purposes that memory operations must align with)
- ADR-018 (emergency controls — `memory.write_freeze` kill switch)
- [LangGraph memory docs](https://langchain-ai.github.io/langgraph/concepts/memory/)
- [Pydantic AI memory primitives](https://ai.pydantic.dev/)
- [Anthropic Managed Agents — durable session](https://www.anthropic.com/engineering/managed-agents)
- [OpenAI Agents SDK — memory](https://openai.github.io/openai-agents-python/)

## Amendment — Sprint 11.5 (2026-05-31)

Sprint 11.5 grounded the design against the codebase; this amendment records the resulting clarifications. None change the governance posture — they refine shapes + scope.

**Memory blocks (new governed shape).** A *memory block* is a bounded, labeled, **singleton** projection over a tier — NOT a fourth tier. Three OS-neutral kinds: `persona`, `user_profile`, `agent_notes` (an agent pack later maps these to a Hermes-style `SOUL.md` / `USER.md` / `MEMORY.md` experience; that experience is Layer-C, not OS). Identity is `(tenant_id, subject_ref, agent_id, block_kind)` with exactly one *active* block per tuple (superseded versions tombstoned). In Wave-1 blocks are **`long_term`-only** and go through the full default-deny write gate — a block write IS a `long_term` write, not a default-deny bypass. The API gains 3 block ops (`upsert_block` / `read_block` / `list_blocks`); `forget` / `redact` / `export` / `list_for_subject` apply to blocks because a block is a governed record. **Operative API = 7 ADR-019 core ops + 3 block ops = 10** (the §"Governed memory API" code block lists 6, omitting `recall_episodes` + the block ops; this amendment is the source of truth).

**`SubjectRef` (new subject vocabulary).** The subject is a typed `SubjectRef` = `kind ∈ {human, agent}` + `id`, canonical `human:<id>` / `agent:<id>`. Empty/unscoped subjects are refused — no tenant-wide memory can exist. `human:` subjects are data subjects (regulator-erasure applies); `agent:` subjects (an agent's own persona) carry no human data subject. The served subject is **bound at `MemoryAPI` construction**, never caller-supplied; explicit-subject ops compare their requested subject to it (mismatch → cross-subject, refused unless declared + tenant Rego).

**§143 child-inheritance clarified (strict Wave-1 rule).** Sub-agents are **`scratch`-only**: the gate refuses all durable (`task`/`long_term`) `remember`/`upsert_block`/`recall`/`read_block`/`recall_episodes` from a sub-agent context (`memory_subagent_durable_access_refused`). Durable memory is **parent-mediated only** — a child may receive an inert, parent-curated, read-only snapshot as input (the parent's reads are governed + audited at the parent boundary). The MemoryAPI snapshot-injection seam is **Wave-1.5** (rides with prompt-injection). This refines §143's "fresh task memory" default to "scratch-only; durable parent-mediated."

**Prompt-assembly + self-edit loops deferred.** Sprint 11.5 ships the governed memory *substrate* only. Loading blocks into a system prompt (context injection / prefix-cache assembly) and any agent self-edit tool-loop are **harness / Wave-1.5** concerns, out of scope here; blocks are *injection-ready*, not injected by the OS.

**DLP seed scope (§"Per-write enforcement").** The Sprint-11.5 `core/dlp/scanner.py` seed is a **real, deterministic checksum/regex/gazetteer** recogniser (PAN/Luhn, IBAN/mod-97, SWIFT/BIC with a context cue, email, phone, regulator gazetteer) over the **build-time** data-class vocabulary (`customer_pii`, `payment_data`, `credentials`, `regulator_communication` per `cli/_governance_vocab.RESTRICTED_DATA_CLASSES` — distinct from the `protocol/mcp_capabilities` runtime set's `payment_action`). **Free-text person names, addresses, and checksummable national IDs are deferred to Sprint 13.5** (Presidio + per-locale recogniser plugins) — most national IDs are format-only (high false-positive) and the few Luhn-checksummed ones collide with PAN. The seed is defense-in-depth: classification is primary-by-declaration (the `remember(data_classes=…)` argument); DLP refuses under-declaration of restricted classes.

**Scratch fail-closed (Wave-1 deviation from §"Storage").** In Wave-1/11.5a, `scratch` writes are **fail-closed** when Redis is unreachable (raise an infrastructure error — NOT a governance refusal); the Postgres fallback is deferred to 11.5b once the reaper gives Postgres-scratch TTL cleanup, since Postgres-persisted scratch without erasure would be un-erasable under the Cut-A a/b split.

**Memory events ride `decision_history`.** `memory.write` / `memory.read` (+ 11.5b `memory.forget` / `memory.redact` / `memory.regulator_erasure`) are `DecisionRecord`s appended via `DecisionHistoryStore.append_with_precondition`, carrying ISO 42001 tags on `iso_controls` and a **redacted-value-digest** (never the value) in the payload — **no `core/audit.py` schema change**, no `core/canonical.py` / `decision_history.py` schema bump (memory linkage is payload-only).

**Cut-A a/b split.** Ships as **11.5a** (governed substrate: 7-op surface, tiers/blocks, both enforcement gates, DLP seed, storage, default-deny Rego, erasure-ready schema, kill-switch *seam*) + **11.5b** (lifecycle `forget`/`redact`/`regulator_erasure` + reaper, `export`, real Redis `memory.write_freeze`, `learning_surface` validator, portal/UI, RBAC depth). The substrate is DI-tested, not harness-injected — same "primitive done, production wiring deferred" posture as the Sprint-11 sub-agent primitive.
