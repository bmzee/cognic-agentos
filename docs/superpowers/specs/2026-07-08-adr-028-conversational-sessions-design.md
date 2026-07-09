# ADR-028 — Conversational Sessions (kernel-owned conversation primitive) — Design Spec

**Date:** 2026-07-08
**Status:** DRAFT — design spec for maintainer review; the ADR itself is authored from this spec after ratification
**Depends on:** ADR-027 (governed agent loop, M8 — merged `main` @ `d2de3b9`), ADR-019 (memory governance vocabulary), ADR-020 (UI event stream), ADR-014 (approval engine), ADR-017 (data-governance contracts), ADR-018 (kill switches)
**Forward:** ADR-029 (runtime compositions / on-the-fly agents / dynamic workflows — placeholder reserved, see §11), M9 (long-term memory), M14/15A (workflow engine)

---

## 0. Program context — M8.5 Phase 1: production conversational analytical agent

This spec is the first artifact of the **M8.5 Phase-1 program**: an internal-production, bank-grade **conversational** analytical agent on AgentOS. The ratified program shape (2026-07-08):

1. **ADR-028 conversational sessions** (this spec) — the one net-new kernel primitive.
2. **Vertical slice gate before the full program:** conversation store + turn loop wrapping the M8 `AgentLoop` + proof BARs 1–3 on `kind`. Only after the slice passes does the AKS/hardening spend start.
3. **Enterprise NL-query analytical agent pack** (separate repo) — **parallel track**, with a **release-gating golden eval set** from day one (ADR-010 harness; per-agent eval scorers ship in the agent pack per the plugin discipline). Eval pass-rate gates the pack release AND doubles as the SR 11-7 documented-validation artifact.
4. **AKS deployed proof** with the real operator flow — Key Vault/ESO, workload identity, private networking.
5. **Production trust posture** — real eval/adversarial/OWASP approval gates (no proof override except an explicit accepted-risk waiver), production signing story.
6. **AI red-team against the agent** (ADR-011 harness aimed at the conversational surface — multi-turn injection and history-reference manipulation are new scope vs. M8's single-shot).
7. **Ops drills** (backup/restore, rollback, secret rotation, kill-switch intervention, incident response) and **evidence export / model-risk dossier**.

**Ratified phase-1 posture decisions:**
- **Model:** Azure OpenAI over private endpoint is the phase-1 default (via the existing LiteLLM-normalized gateway). Self-hosted vLLM is a later/alternate proof, documented but not phase-1-proven.
- **Harness:** web-first (served from the cluster behind bank SSO), NOT desktop-installed. Phase-1 harness is **three screens only: chat, approvals inbox, evidence viewer**. Agent-builder and workflow-designer UX are deferred with their kernel features (ADR-029/M14).
- **Use-case class:** phase-1 target is read-only internal analytical advisory. It must NOT be used for creditworthiness, credit scoring, insurance pricing, or other EU AI Act Annex-III decisioning without a separate high-risk classification and conformity workstream — a banking NL-query agent can drift into eligibility/risk questions, so this is a usage boundary to enforce, not a classification to assume. Traceability + human-oversight obligations apply regardless and are designed in (§8).
- **Two product lines held under pressure:** no cross-session memory in phase 1 (M9 owns it — §11); no action-taking capabilities in phase 1 (read-only analytical only).

---

## 1. Architecture framing — the two planes

AgentOS operates on two planes. This spec names them as doctrine; ADR-028 delivers the first primitive of the second plane.

**Plane A — Trust/build plane.** Slow, signed, dual-controlled. Official reusable capabilities ship as signed packs (`cognic-agent-*`, `cognic-skill-*`, `cognic-tool-*`, `cognic-hook-*`, future `cognic-workflow-*`). cosign/SLSA/SBOM attestation, the M4 operator lifecycle (submit → review → approve → allow-list → install), and per-tenant entitlement grants apply here. Plane A is where trust is *established*.

**Plane B — Runtime-composition plane.** Fast, user-driven. Conversations (this ADR); later: on-the-fly agents, task plans, dynamic workflows (ADR-029/M14). Plane-B objects are **governed kernel records, not signed artifacts**. They compose only already-trusted Plane-A capabilities. They are **validated and constrained at authoring time; dispatch remains the final authority** — every capability action is re-checked at the moment of execution against *current* state.

> **Doctrine wording (binding):** "Authoring validates and constrains; dispatch remains the final authority." It is INCORRECT to say governance is only dispatch-time — authoring-time validation is a real constraint surface (shape, policy admission, envelope pre-check) — and it is equally incorrect to treat any authoring-time check as load-bearing alone: any check material to safety is re-verifiable at dispatch (§6, invariant I-2).

**Runtime compositions must be:** bounded by the creator/current-actor entitlement envelope; constrained to installed/trusted capabilities; risk-classified; policy-checked; versioned if persisted; approval-gated if shared/reusable/scheduled/high-risk; audited; revocable.

**Execution envelope rule:**
- Private ephemeral compositions: `allowed = selected capability subset ∩ creator/current-actor entitlements ∩ policy`.
- Shared/reused compositions: `allowed = composition's declared allowed set ∩ CURRENT RUNNER's entitlements ∩ policy`. A privileged creator's composition must NEVER carry the creator's privileges when a less-privileged user runs it, absent an explicitly designed, approval-gated delegated-authority model (ADR-029 scope).

**PT-1 (named prerequisite for ADR-029):** the M8 entitlement store is data-scopes per `(tenant, subject)`; capabilities (skills/tools) are assigned to *agents*, not human subjects. The envelope rule's "runner entitlement" term is therefore well-defined for data scopes and **undefined for capabilities**. ADR-028 escapes this (conversations run over signed agent packs whose capability set is fixed at Plane A). ADR-029 cannot ship without either (a) a subject→capability entitlement axis, or (b) an explicit rule that runtime compositions may only select capabilities from agent packs the runner may converse with. Recorded here so the envelope rule is not assumed implementable as written.

**Honest scope of the "first runtime-composition primitive" claim (PT-7):** a v1 conversation composes nothing — the user picks an installed agent and converses. What ADR-028 genuinely establishes is the **runtime-record pattern**: kernel-owned record, creator-bound, envelope-evaluated per action, append-only, auditable, revocable. True capability-selection composition arrives with ADR-029. Consequently the "versioned if persisted" and "approval-gated if shared" clauses do **not** bind ADR-028: v1 conversations are private to their creator, never shared/reusable/scheduled, and their only "version" is the append-only turn sequence.

The **harness** is a client of both planes and an authority in neither. It renders kernel records, submits drafts/requests, and its approval UX drives the existing ADR-014 approval engine under the acting human's own RBAC. It holds zero authoritative state.

## 2. Why conversation is kernel-owned (not agent-owned, not harness-owned)

**Not agent-owned:** ADR-027 agent packs are declarative — persona + requested capability sets + an inert marker. There is no agent code to own state, by design; giving the agent conversation machinery would reopen exactly the trust hole M8 closed (the governed thing governing its own context and audit trail).

**Not harness-owned (client-held history):** the transcript is simultaneously (a) audit surface — what the model saw on turn N must be reconstructable; (b) a DLP/retention/erasure surface — transcripts hold customer-data results; (c) an injection surface; (d) a resource-governance surface (budgets/bounds). All four are kernel duties. Client-held history also fails the record-integrity requirement (§2.1). Industry corroboration (not the reason — the reason is the four kernel duties above): the major agent platforms have converged on platform-/server-owned conversation state addressed by a conversation identifier, with the client holding no authoritative history. This spec does not depend on any external vendor's API shape.

**The agent still owns conversation *policy*, declared not executed:** the agent-pack manifest gains a `[conversation]` block (validated by `cli/validators/agents.py`) declaring `max_turns`, `cumulative_token_budget`, `idle_expiry_s`, `context_strategy` (v1 vocabulary: `bounded_replay` only — §5), `retention_class`. The kernel enforces these, bounded by tenant policy (tighten-only, per the ADR-017 pattern).

### 2.1 The record-integrity property, stated precisely (PT-2)

Kernel ownership guarantees **integrity of the transcript record**: the context assembled for the model comes only from the kernel store; the API accepts no client-supplied history in any form; a caller cannot inject fabricated prior turns *as record*.

It does **not** guarantee **truthfulness of message content**: a user can still write "as you told me earlier, my limit is ₨10M" inside a new message, and injection can arrive via tool results. Mitigations for content-level fabrication are (a) the content-safety input boundary (§8), and (b) the structural fact that no claim made in message text can widen the envelope — entitlement and policy checks read kernel state, never message content. The ADR must not claim more than this; overclaiming invites a failed red-team finding.

## 3. Conversation data model and lifecycle

Two tables, mirroring the `runs` substrate pattern (`core/run/storage.py`), next free migration revision (expected `0015`):

**`conversations`** — `conversation_id` (UUID PK), `tenant_id` (NOT NULL — the isolation boundary), `agent_id`, `creator_subject` (the bound Actor's subject), `state` (closed-enum: `active | closed | expired | erased`), `turn_count`, `cumulative_tokens`, `created_at`, `last_turn_at`, `retention_class`, retention/erasure bookkeeping. Index on `(tenant_id, creator_subject, state)`.

**`conversation_turns`** — `turn_id` (UUID PK), `conversation_id` (FK), `seq` (monotonic int, unique per conversation), `user_message` (plaintext — erasable), `answer` (plaintext — erasable), `agent_run_id` (the correlator to the M8 `agent.run.*` evidence), per-turn token usage, `created_at`, erasure tombstone fields.

**Erasure shape doctrine (no half-erased ambiguity):** after erasure, plaintext columns are set to NULL or replaced with a fixed tombstone sentinel; digests and byte counts remain in chain/evidence only. The DB row itself remains — `seq` integrity and the `agent_run_id` correlation survive erasure so the chain join stays reconstructable even though content is gone.

**Plaintext placement doctrine (PT-3 reconciliation):** plaintext lives ONLY in these erasable tables. Hash-chain evidence rows carry **digests only** (`question_sha256`, `answer_sha256`) — the M8 digest-only doctrine extended to conversations. This is what reconciles "audit-reconstructable" with "erasable":

> Reconstruction is possible **until erasure**. After erasure, the chain proves *what happened and when* — including the erasure event itself (tombstone + `conversation.erased` chain row) — while the content is gone. Any stronger claim ("always reconstructable") is false and MUST NOT appear in the ADR or marketing material.

**Lifecycle:** `active → closed` (explicit close) `| expired` (idle-expiry, reaper-driven — the Sprint-8.5 reaper precedent) `→ erased` (redaction). `closed`/`expired` are terminal for turns — **no reopen in v1**; continuing yesterday's thread is cross-conversation continuity, which is long-term memory and therefore M9 (§11). No cross-conversation carry-over of any kind in v1.

**Terminal-state refusal contract:** posting a turn to a `closed`, `expired`, or `erased` conversation refuses with a closed-enum reason (`conversation_not_active`, carrying the current state) and **never invokes the AgentLoop** — the refusal fires at the lifecycle gate, before context assembly or any model/gateway activity.

**Chain evidence (decision types):** `conversation.created`, `conversation.turn_completed` (digests + `agent_run_id` + `seq`), `conversation.escalated`, `conversation.closed`, `conversation.expired`, `conversation.erased`. The reconstruction join is three hops, all chained: `conversation_id → agent_run_id → agent.run.dispatch` rows.

**Tenant + creator scoping:** reads and turn-posts are tenant-scoped AND creator-bound. Cross-tenant and cross-actor access wire-collapses to 404 (byte-identical to genuine not-found), per the established cross-tenant-invisibility doctrine.

## 4. Turn execution flow (wrapping the M8 loop)

```
POST turn
  → RBAC scope (conversation.post_turn)
  → load conversation (tenant + creator bound; else 404 wire-collapse)
  → atomic single-writer claim  ..................... (PT-6; concurrent turn → 409 turn_in_progress)
  → conversation-level bounds check ................. (max_turns, cumulative budget, idle expiry)
  → content-safety INPUT boundary ................... (§8; hook phase, fail-closed)
  → context assembly ................................ (§5; bounded replay from the kernel store ONLY)
  → invoke the M8 AgentLoop with assembled context
       — per-turn bounds, dual identity, and the assignment → entitlement → policy
         dispatch chokepoint run EXACTLY as proven in M8; every dispatch re-checks
         the CURRENT envelope (invariant I-2)
  → content-safety OUTPUT boundary .................. (§8; hook phase, fail-closed)
  → persist turn (plaintext) + digests; update counters
  → append conversation.turn_completed chain row; emit ADR-020 events
  → release claim
```

**Loop extension is additive:** `core/agent/loop.py` gains a prior-context input (the assembled turn messages precede the new question). The loop's internals — round-top bounds, `agent_workforce_id` stamping, per-round dispatch fan-out, refusals-feed-back-as-tool-messages, digest-only terminal rows — are unchanged in substance. Each turn produces its own `agent.run.*` evidence exactly as M8 does; the conversation layer adds the correlation, never replaces the run evidence.

**Concurrency + multi-replica (PT-6, binding for AKS):** single-writer-per-conversation is enforced by an atomic DB claim (the 14A-A3b run-claim precedent), NOT in-process locks — turn POSTs may land on any replica. Conversation state is DB-backed; streaming continuity across replicas rides ADR-020's reconnect-safe decision-history replay (that mirror exists for exactly this reason). A second concurrent POST refuses 409 with a closed-enum reason; it does not queue in v1.

## 5. Context assembly — v1 is bounded replay ONLY; summarization deferred

**v1 `context_strategy` vocabulary has exactly one value: `bounded_replay`** — the first turn (grounding) + the last N turns, under a token ceiling. Assembly reads ONLY the kernel transcript store. Proposed kernel Settings defaults (plan-time tunable; tenant ceilings tighten-only): `max_turns` 20, replay window = first turn + last 10 turns, `idle_expiry_s` 86400, cumulative budget derived from the agent's per-turn budget × max_turns. Analytical conversations are short by nature; low defaults are the point.

**Summarization is deferred to v1.1** — removed from v1 scope by ratified decision (2026-07-08) because it carries the largest design burden for the least phase-1 value. The design constraints it MUST satisfy when it lands are recorded now (PT-4) so v1.1 cannot miss them:

1. A summary is a **derived artifact of transcript content**: the summarizing LLM call runs governed — same agent workforce identity, same cloud policy, traced — never a side-channel call.
2. Summaries are stored **with provenance**: source turn range, model, digest.
3. **Erasure propagates to derived artifacts:** if any source turn is erased, every summary derived from it is invalidated (erased or regenerated from surviving turns). Otherwise erasure is a lie — the content survives in the summary.

The `[conversation].context_strategy` manifest field ships in v1 (single-value closed enum) so v1.1 extends the vocabulary without a wire break.

## 6. Governance — authoring validates, dispatch decides

**Authoring validation (create-conversation):** agent exists and is hosted; actor holds `conversation.create`; tenant match; policy admits; the `[conversation]` policy block resolves against tenant ceilings. These constrain early and cheaply — and none is load-bearing alone.

**Binding invariants:**
- **I-1 (record integrity):** model context derives exclusively from the kernel store (§2.1). The turn API has no history-accepting field; a crafted payload attempting one fails closed-enum validation (`extra="forbid"`).
- **I-2 (per-turn envelope, PT-5):** the envelope is evaluated against the actor's **current** entitlements on **every turn** — and per-dispatch inside the turn — never snapshot-at-creation, never cached across turns. Entitlement revoked mid-conversation → the next turn's affected dispatch refuses (`agent_scope_not_entitled`), audited. Kill switches bite mid-conversation with no grace. This invariant is proof-bar-pinned (BAR 3) because the temptation to cache the envelope for latency is real and would silently break revocation.
- **I-3 (v1 envelope form):** `allowed = agent pack's assigned capability set ∩ current actor's data-scope entitlements ∩ policy` — the private-ephemeral form of the §1 rule. The shared-composition form is explicitly out of scope (ADR-029, with PT-1 as its named prerequisite).

**RBAC:** new additive scope namespace `conversation.*`, disjoint from `agent.*`: `conversation.create`, `conversation.read`, `conversation.post_turn`, `conversation.close`, `conversation.export`, `conversation.redact`. `export` and `redact` are compliance-role scopes and **human-actor-gated** (the allow-list `RequireHumanActor` precedent); `redact` executes the erasure pathway (§7).

**Agent-level access control (PT-9 — accepted risk, hook reserved):** v1 deliberately relies on scope + tenant + the entitlement envelope; there is no per-agent conversation ACL ("may user U converse with agent A"). An unentitled user receives governed refusals rather than being blocked at the door. This is recorded as a **v1 accepted risk with a reserved future hook** — the create-conversation authoring gate is the single place a per-agent ACL check will later slot in — NOT as "not needed."

## 7. Transcript governance — retention, DLP, erasure, reconstruction

- **Retention:** `retention_class` from the agent's `[conversation]` block, bounded tenant-side (tighten-only). Expiry is reaper-driven (the `sandbox/reaper.py` pattern: a thin loop over an on-gate store's purge method).
- **Erasure (regulator pathway, ADR-019 vocabulary):** `conversation.redact` deletes plaintext turns, writes tombstones, emits `conversation.erased`, and **invalidates derived artifacts** (v1: none exist — summarization deferred; the rule binds v1.1). The chain remains intact and proves the erasure (§3 doctrine). ADR-028 adopts ADR-019's retention/redaction/erasure/export **verbs** without pulling in the full M9 memory subsystem — one governance vocabulary, two lifecycle primitives, so transcripts and long-term memory govern uniformly when M9 lands.
- **DLP on replay:** replayed history passes the same governed boundary as fresh input — the `conversation_input` hook phase (§8) receives the **exact assembled model context, including replayed turns and the new message, after bounded-replay selection and before any gateway call**. Scanning only the new message is a non-conforming implementation: an entitlement lost since turn 3 must not leak turn-3 content back through replay unexamined.
- **Encryption at rest:** transcripts are customer data; CMK/Key-Vault at-rest encryption is an M8.5 step-4 (AKS) infrastructure requirement, referenced here, designed there.
- **Export:** `conversation.export` produces the examiner view (transcript + chain correlation), feeding the phase-1 evidence-export deliverable (M17-shaped).

## 8. Human escalation + content-safety boundary

**Escalation is a first-class conversational move** (the EU-AI-Act / SR 11-7 "oversee, intervene, halt" triplet, mapped to existing mechanisms — oversee: evidence; intervene: escalation + approvals; halt: kill switches):

- **Trigger (a) — agent-initiated:** an `escalate_to_human` **built-in capability**, dispatch-gated exactly like `read_skill`/`remember` (policy can gate who/when; every escalation is an audited dispatch). **v1 delivery note:** the kernel/evidence surface (the built-in, the chain row, the approval-request mint, the `blocking` refusal contract) ships first; the full human-resolution UX rides the harness approval screen and may trail the kernel surface.
- **Trigger (b) — guardrail-initiated:** the safety boundary can force escalation.
- **Effect:** `conversation.escalated` chain row + an ADR-014 approval-surface request + a harness event. **v1 escalation classes (closed 2-value enum):** `blocking` — the conversation refuses further turns until a human resolves via the approval surface (resolution audited; resume or close); `advisory` — recorded + surfaced, conversation continues. Human resolution arrives through the existing approval engine under the human's own RBAC — **no new authority mechanism**.

**Content-safety boundary (PT-8 — kernel owns the boundary, packs own the scanners):** two new kernel-owned hook phases on conversation I/O — `conversation_input` (assembled context + new message, pre-loop) and `conversation_output` (answer, pre-return) — dispatched through the proven M5 hook machinery (`packs/hooks/dispatcher.py`). Actual scanners (prompt-injection, PII/leakage) ship as `cognic-hook-*` packs, fail-closed per the Wave-1 hook doctrine. The kernel does NOT embed model-based safety classifiers — that would strain the OS-only rule and bake a vendor's safety model into the OS.

## 9. Harness contract

- **HTTP:** create / post-turn / read / close, plus compliance surfaces export / redact. Request DTOs `extra="forbid"`; tenant + subject come from the bound Actor only.
- **Streaming:** ADR-020 SSE. Conversation lifecycle + turn events land as decision-history rows projected through **additive typed projectors** (the exact M8 `agent.run.*` mechanism on `protocol/ui_events.py`; wire-protocol stop-rule review applies; no breaking change to frozen families). Reconnect-safe by construction via the decision-history mirror — which is also what makes multi-replica AKS streaming work. v1 streams **event-level progress** (turn started, dispatch activity, turn completed); token-level answer streaming is a v1.1 gateway feature, deferred to keep the evidence path (answer digest at turn end) simple.
- **Phase-1 harness cut (ratified):** web app served from the cluster behind bank SSO — NOT desktop-installed. Three screens: **chat** (conversation + event-level progress), **approvals inbox** (drives the existing ADR-014 surface), **evidence viewer** (conversation → run → dispatch join). Agent-builder and workflow-designer UX are deferred with ADR-029/M14. The harness holds zero authoritative state and is not a trust boundary.

## 10. Proof bars — the first conversational production proof

Vertical-slice gate = BARs 1–3 on `kind` BEFORE the AKS/hardening program proceeds. The full set runs at the M8.5 AKS proof.

- **BAR 1 — governed multi-turn e2e:** turn N depends on turn N−1's answer (real context dependence); every turn dual-identity; every dispatch through the chokepoint; evidence joins `conversation → agent_run → dispatch` across the chain.
- **BAR 2 — record integrity (deterministic):** the API accepts no client-supplied history in any form; a crafted payload attempting it is refused by schema (`extra="forbid"`); the assembled context provably derives from the kernel store only.
- **BAR 3 — mid-conversation revocation (the I-2 pin):** entitlement removed between turns → the next turn's affected dispatch refuses `agent_scope_not_entitled`, audited; proves no envelope caching.
- **BAR 4 — bounds + lifecycle refusal:** cumulative-budget and max-turns exhaustion → governed refusal naming the bound in evidence; idle expiry transitions to `expired`; AND the terminal-state pin — close/expire/redact a conversation, then POST a turn → governed `conversation_not_active` refusal with **zero AgentLoop invocation** (asserted via absence of any new `agent.run.*` row).
- **BAR 5 — erasure:** redact → plaintext gone, tombstones + intact chain; reconstruction shows the erasure event; (v1.1 extension: derived-summary invalidation).
- **BAR 6 — safety + escalation:** hostile input refused fail-closed by the input hook pack; `escalate_to_human` produces the approval-surface request and an audited block/resume.
- **BAR 7 — harness continuity:** SSE drop + reconnect with Last-Event-ID replays without gap or duplication; on AKS, across replicas.

## 11. Explicit deferrals

| Deferred item | Owner | Note |
|---|---|---|
| Cross-session/long-term memory; any transcript→long-term distillation beyond the existing task-tier digest; cross-conversation carry-over; conversation reopen | **M9** (ADR-019) | The sharp boundary: within a conversation the agent remembers everything; across conversations is M9 — hold this line under product pressure |
| Shared/reusable/scheduled compositions ("versioned if persisted", "approval-gated if shared"); capability-selection UX; on-the-fly agents; delegated-authority model; dynamic workflows; the subject→capability entitlement axis (PT-1) | **ADR-029 / M14-15A** (placeholder reserved) | ADR-028's runtime-record pattern (§1) is the template; PT-1 is the named prerequisite |
| Context summarization (+ derived-artifact provenance & erasure propagation, PT-4) | **ADR-028 v1.1** | Constraints pre-recorded in §5 |
| Token-level answer streaming | v1.1 | Event-level progress ships in v1 |
| Per-agent conversation ACLs | Future hook (PT-9) | v1 accepted risk; the authoring gate is the reserved slot |
| Multi-agent conversations; conversation search | Unscheduled | |
| Self-hosted vLLM conversational proof | Post-phase-1 alternate proof | Azure OpenAI private endpoint is the phase-1 default |

## 12. Repo-boundary compliance check (OS-only rule)

- Conversation store + turn orchestration + hook phases + RBAC scopes + evidence types: **kernel** (`core/agent/` extension + `portal/api/` + migration) — governance/runtime primitives, correctly OS.
- Content-safety scanners: **hook packs** (outside).
- The analytical agent, its skills, schemas, eval scorers: **agent/skill pack repos** (outside).
- The harness: **separate web-app artifact** (outside; client only, never a trust boundary).
- Nothing in this design places an agent, a persona, a bank schema, or UI inside `cognic-agentos`.
