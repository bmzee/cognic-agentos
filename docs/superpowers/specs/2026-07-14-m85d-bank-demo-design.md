# M8.5-D — Bank Demo on AKS: governed read **and** governed write

**Status:** DRAFT for maintainer review
**Date:** 2026-07-14
**Supersedes:** the checklist's M8.5-D ("First bank NL-query analytical agent") and M8.5-E ("Full-stack `kind` proof"), which are merged into this milestone and re-planned in §9.
**Depends on:** M8.5-C (harness v1) closing — T3-I in flight.

---

## 0. The decision this spec encodes

The objective is **not** "complete the product." It is: **deploy to AKS and demonstrate to a bank, with a practical first use case, as fast as is honest.**

Everything below is scoped to that, with one deliberate exception: where a design choice would force a **rewrite** at the next capability shape, we make the correct choice *now* — because the correct choice is cheap today and expensive in six months. Those are called out as **[HEADROOM]** and are strictly bounded.

Two capability shapes are in scope:

1. **Governed read** — natural-language question → SQL over governed views. *Already built and proven.*
2. **Governed write** — "apply my leave" → a real write, gated by four-eyes human approval. **New. This is the milestone's centre of gravity.**

---

## 1. What the bank sees (the demo narrative)

The demo is not a feature tour. It is six moments, each of which proves a control:

| # | Moment | Control proven |
|---|---|---|
| 1 | Analyst logs in with the bank's own identity provider, asks a question in plain English, gets a real answer from bank-shaped data. | OIDC identity; NL→SQL; governed views |
| 2 | Asks for data they are **not entitled to** → **refused**, with the reason, and an audit row. | Per-human entitlement, enforced before execution |
| 3 | An admin **revokes an entitlement mid-conversation** → the very next question is refused. Live, on stage. | Enforcement is real-time, not cached |
| 4 | Analyst says **"apply my leave for next Monday"** → the agent does **not** act. It shows exactly what it *will* do and mints an approval request. | Human-in-the-loop on writes; no autonomous action |
| 5 | **Two different humans** approve (the requester cannot self-approve). The action then executes **exactly once**. | Four-eyes / maker-checker; idempotency |
| 6 | The whole thing — question, refusal, revocation, approval, write — is one **hash-chained evidence trail** an examiner can read. | ISO 42001 / EU AI Act Article 14 evidence |

Moments 1–3 and 6 work today. **Moments 4–5 are what this milestone builds.**

### 1.1 Why this matters commercially (do not skip this)

The EU AI Act's **human-oversight obligations (Article 14) become enforceable on 2 August 2026** — weeks away. The U.S. Treasury published a financial-services AI risk framework in February 2026 with 230 control objectives. Every bank in the room is about to be asked by a regulator: *"when your AI takes an action, who approved it, and can you prove it?"*

Moments 4–6 **are that answer**. The demo's thesis is not "our agent is smart." It is **"our agent cannot act without a human, and here is the cryptographic proof."**

---

## 2. Scope

### In
- **D1** Capability classes — generalize the entitlement gate off a hardcoded tool name. **[HEADROOM, bounded]**
- **D2** The governed-write path (HP-5): pause → durable state → four-eyes → resume → exactly-once execution.
- **D3** Credential brokerage — remove the plaintext Oracle password. Azure Key Vault + External Secrets Operator.
- **D4** AKS deployment of the full stack.
- **D5** `cognic-tool-hr-leave` — the write tool pack.
- **D6** Seeded bank dataset + demo script.

### Out (explicitly deferred, with honest reasons)
- **Governance-administration console** → its own milestone (§9). The demo *uses* the revocation moment to prove the mechanism, and we state plainly that the console is next.
- **RAG / knowledge-base queries** → design headroom only (§8.1). No retrieval subsystem exists (`retrieval/` is absent from the tree); building one is a milestone, not a slice.
- **General-knowledge answers** → headroom only (§8.2).
- **Dynamic tool/agent creation** → headroom only (§8.3). Industry consensus (2026) is that runtime capability *minting* is a dead end; we design the ceiling and build nothing.
- **Content-safety hooks + erasure pathway** → M8.5-F, the pilot gate. The demo is an **internal product demonstration**, not a pilot handover.
- **A generic multi-store CredentialBroker port** → the pluggability lives in the deployment overlay (§5), not in kernel code.

---

## 3. D1 — Capability classes (the gate generalization)

### 3.1 The defect

Today the entitlement gate is bound to a **hardcoded frozenset containing one tool name**:

```python
# core/agent/dispatch.py:104
_QUERY_CONTEXT_STAMPED_TOOLS: Final[frozenset[str]] = frozenset({"run_readonly_query"})
```

A tool **not** in that set dispatches with `entitlement_verified=True` **asserted but never computed** (`dispatch.py:444-446`), no scope binding, no capability token, `approval_request_id=None` (`:517`), and an intentionally open argument schema (`:707-710`).

This is harmless today because that set *is* every tool we have. It becomes a **security hole the moment a second capability exists** — which is this milestone. The 2026 literature names this exact mistake as the number-one production RAG failure: *"the agent queries the resource with a service identity instead of the user's."*

**The entitlement model is bolted to a tool *name*. It must bind to a capability *class*.**

### 3.2 The design

Every tool's **signed manifest** declares a `capability_class`. The kernel dispatcher keys its gates off that class — never off a name, never off a kernel-side list a new pack can be forgotten from.

| Class | Requires | Kernel stamps | Approval |
|---|---|---|---|
| `data_query` | a **data-scope entitlement** for the requesting human | query-context token (as today) | by risk tier |
| `action` | an **action entitlement** for the requesting human | **action-context token** (§4.3) | **always ≥ single; high-risk ⇒ four-eyes** |
| `unscoped` | nothing — but must be **explicitly declared and audited** | nothing | by risk tier |
| *(absent / unknown)* | — | — | **REFUSED** |

**The load-bearing rule: the default is refusal, not `unscoped`.** A tool whose manifest declares no capability class, or an unrecognized one, is **not dispatchable**. This inverts today's posture, where the absence of a declaration silently yields an unauthorized-but-permitted call.

`retrieval` is reserved (§8.1) and refuses until its milestone lands — declared-but-unimplemented must fail loud, never fall through to `unscoped`.

### 3.3 Contract changes

- `protocol/agent_manifest.py` / `cli/validators/` — `capability_class` becomes a required field on every tool a pack exposes; the build-time validator refuses a manifest without it (closed enum).
- `core/agent/dispatch.py` — gate 2 dispatches on the resolved class. The stamped-tools frozenset is **deleted**, not extended.
- `policies/_default/agents.rego` — the Rego input carries `capability_class`; `entitlement_verified` must be **computed** for every class that requires it, never asserted true by omission.
- Regression pins: (a) a tool with no declared class refuses; (b) an unknown class refuses; (c) `entitlement_verified=true` cannot be reached without an actual entitlement read — TM-revert proven.

### 3.4 Why this is [HEADROOM] and not scope creep

Without it, the write tool (D5) **inherits no user-scoped authorization at all**. It is not optional for this milestone; it is a prerequisite. Its generality — that RAG and any future tool land on the same gate — is a free consequence of doing it correctly rather than adding a second hardcoded name.

---

## 4. D2 — The governed-write path (HP-5)

### 4.1 What is missing today

The agent can **start** an approval and can never **finish** one:

- `core/agent/dispatch.py:517` passes `approval_request_id=None` **unconditionally**.
- The MCP host correctly mints a pending approval request and raises `MCPToolInvocationRefused` carrying the `approval_request_id` (`protocol/mcp_host.py:1325-1336`).
- The dispatcher's generic `except Exception` (`dispatch.py:519`) **collapses it to `agent_tool_dispatch_failed`** — the approval id is destroyed.
- `AgentRunTerminalState = Literal["completed", "refused", "failed"]` (`core/agent/_types.py:43`) — **there is no pending/paused state**.
- The `approval` UI-event family is a **model-only stub with no emit hook** (`protocol/ui_events.py`).

Net effect today: a high-risk agent call mints an orphan approval request, fails the turn with a generic error, and tells the user nothing. **This is the gap.**

### 4.2 The design: the conversation *is* the durable checkpoint

Every major framework (LangGraph `interrupt()`, OpenAI `needsApproval`, Google ADK tool-confirmation, Microsoft `ApprovalRequiredAIFunction`) has converged on the same shape: **pause → durable state → human approves → resume.** None of them is a standard; all of them agree.

We do not need to invent an in-run pause primitive, because **we already have a durable checkpoint: the conversation turn** (ADR-028; turns are stored, and each new turn replays prior context into a fresh single-shot run).

**The flow:**

1. **Turn N — propose.** The agent decides to call `apply_leave(...)`. Dispatch runs gates 1–3, then hits the approval gate. The MCP host mints the approval request. **Dispatch no longer swallows it**: it catches `MCPToolInvocationRefused(reason="tool_approval_pending")` explicitly and returns a typed pending outcome carrying the `approval_request_id`.
2. **The run terminates `pending_approval`** — a new value on `AgentRunTerminalState` — and the answer to the user is a **governed refusal that is also a governed answer**: *"I've requested approval to apply your leave for Monday 21 July. Request #a1b2 is pending two approvals."* The agent states **exactly what it will do** — this is the dry-run.
3. **The turn stores** `pending_approval_request_id` + the bound argument digest.
4. **Two humans approve** in the approvals screen (already built in M8.5-C; the requester is structurally barred from self-approving — ADR-014 four-eyes).
5. **Turn N+1 — resume.** The next turn (user says "go ahead", or the harness offers a resume affordance) re-dispatches **with the stored `approval_request_id`**. The kernel re-runs *every* gate — assignment, entitlement, policy — and additionally verifies the grant is **bound to the same originator** (HP-4, already shipped) and **bound to the same arguments** (§4.3).
6. **The tool executes exactly once** and returns the result. The agent formats the answer.

**Nothing is held open across the human's decision.** No in-flight run, no long-lived lock, no resumable sandbox. The conversation is the state, which is durable, replay-safe, and already evidenced.

### 4.3 The action-context token — and idempotency for free

The `action` class gets an **action-context token**, minted by the kernel exactly as the query-context token is (`core/agent/query_context.py` is the reference implementation), carrying:

`iss` · `aud` (the tool) · `sub` (**the human**) · `act` (**the agent**) · `tenant_id` · `action_id` · **`args_sha256`** · `approval_request_id` · `idempotency_key` · `jti` · `iat` · `exp`

Three properties fall out of this, and each is a control:

**(a) The approval binds the *exact arguments*.** `args_sha256` is computed over the LLM-authored arguments **before** the approval is minted. If the model — or an injected instruction — changes one field between proposal and execution, the digest changes, the grant no longer matches, and the call is refused. This closes the **TOCTOU / "rug-pull"** attack class by construction.

> This is precisely the shape Google's payments protocol (AP2) uses for its "Cart Mandate": the user's approval is cryptographically bound to the exact contents of the action, not merely to its name. **We already had the mechanism; we are pointing it at writes.**

**(b) Idempotency is free.** `idempotency_key = sha256(approval_request_id ‖ args_sha256)`. The tool persists it. A replay — a model retry, a network retry, a user double-click — matches the stored key and returns the **original result without re-executing**. The 2026 literature is unambiguous that **no agent framework provides this** and that the application must own it; leave applied twice is the canonical failure.

**(c) Grants are single-use and actor-bound.** Already shipped at HP-4 (actor-bound grant replay) — a grant issued for Amir cannot be replayed by Sara, and cannot be replayed twice.

### 4.4 Compensation — stated, not built

The 2026 answer to "the agent's third write failed after the first two committed" is the **saga pattern**: every forward step declares a compensating step. **We do not build it, and we do not need to**, because the demo's write is a **single atomic step** (one row, one transaction).

**This is a hard scope boundary, and it must be written into the pack contract:** an `action`-class tool exposes **one atomic operation**. Multi-step transactional workflows are out of scope until a compensation design exists. A tool that needs two writes to be correct is not admissible under this milestone.

### 4.5 Contract changes

- `core/agent/_types.py` — `AgentRunTerminalState` += `pending_approval`; `AgentAskResult` carries `approval_request_id`.
- `core/agent/dispatch.py` — typed catch of `MCPToolInvocationRefused`; accept and thread `approval_request_id`; mint the action-context token for `action` class.
- `core/agent/loop.py` — terminate `pending_approval`; emit the chain row.
- `core/conversation/` — the turn stores the pending approval id + argument digest; the next turn resumes with it.
- `protocol/ui_events.py` — **the `approval` family gets its emit hooks** (currently a stub). The harness cannot show a pending approval that never emits.
- `portal/api/conversations/` — the turn DTO surfaces `pending_approval`.
- **Critical-controls:** every module above is on the CC gate. Expect halt-before-commit review on each.

---

## 5. D3 — Credential brokerage (kill the plaintext password)

Today the Oracle password is a **plaintext literal in the pod spec**:

```yaml
- { name: COGNIC_ORACLE_PASSWORD, value: "cognic_dev_only" }   # infra/proof-m85c/manifests/oracle-pack.yaml
```

### The design — the store injects; the kernel never holds the secret

The pack's pod carries a **workload identity** (Kubernetes ServiceAccount → Azure Workload Identity, already shipped at 14B-Z1b-d-1). The bank's credential store authenticates *that identity* and delivers a short-lived credential **into the pod**. The pack reads a **file path** and re-reads on rotation. It never knows what a Vault is.

**Reference implementation for the demo: Azure Key Vault + External Secrets Operator** — both already built and proven (14B-Z1b-b). One adapter, not a framework.

**The pluggability lives in the deployment overlay, not in kernel code.** A bank running CyberArk swaps the injector; nothing in AgentOS or the pack changes. This is the OS/overlay boundary AGENTS.md already draws, and it is why **we deliberately do not build a `CredentialBroker` port in the kernel**.

**Rejected alternatives, for the record:**
- *Kernel leases the credential and passes it to the tool* — puts a live DB bearer credential on the MCP wire and into the tool's argument space. A capability token is safe to pass; a password is not.
- *The pack embeds a Vault/CyberArk client* — pushes bank-specific store adapters into every pack. Forbidden by the OS/overlay boundary.

**Evidence contract:** AgentOS records the credential **reference** (lease id / rotation serial — a non-secret identifier the pack reports back) and the DB proxy identity. **Never credential material.** Unchanged from ADR-004's standing rule.

### The DB identity model (ruled 2026-07-14)

- **Proxy sessions** (already shipped): the tool connects as `cognic[AN_RETAIL]`, so the database — not our code — enforces which objects are reachable. A non-granted object dies at the engine with `ORA-00942`.
- **Per-scope proxy identity is the default** (not per-user). A bank provisioning one Oracle account per analyst is a roster-sync pipeline no bank will build for a pilot. Per-user remains supported as an overlay upgrade.
- **The human is attributed via `DBMS_SESSION.SET_IDENTIFIER(<Keycloak subject>)`**, which lands in Oracle's unified audit trail's `CLIENT_IDENTIFIER`. Ten analysts behind one proxy identity still yield **per-human DB audit rows**, and that identifier is the *same* subject the kernel authorized and signed. One identity, end to end, verifiable at every hop.
- **VPD is dropped from the target profile.** It is zero lines of code in this repo, is Enterprise-Edition-only (our substrate is XE 21c), and buys nothing our scope model doesn't already express. Enforcement is **governed views + per-identity grants**, which is real and live-proven. Row-level policy is a bank-overlay extension if a deployment demands it. *The checklist and ADR-028 must be amended to say so — an honest smaller claim beats an impressive unbuilt one.*

---

## 6. D4 — AKS deployment

Not a build; a deployment exercise. The substrate exists (14B):

- Helm chart (`infra/charts/agentos/`) — OpenShift/K8s compatible, CI-gated.
- ExternalSecrets → Azure Key Vault (14B-Z1b-b).
- Workload identity hooks (14B-Z1b-d-1).
- Reference Bicep + AKS smoke (14B-Z1b-d-2).

**In-cluster for the demo:** Oracle XE (our data, not the bank's), Postgres, Redis, the LLM gateway, the harness BFF, the agent + tool packs.

**Open question for the maintainer (§10):** identity provider — **Microsoft Entra ID** (far more credible to a bank on Azure; proves "your IdP works") versus **Keycloak** (already proven in M8.5-C; zero risk). Recommendation: **Entra ID, with Keycloak as the fallback if app-registration lead time bites.**

---

## 7. D5 — `cognic-tool-hr-leave` (the write pack)

A new signed MCP pack, released exactly as `cognic-tool-approval-probe` was (cosign + SBOM + SLSA + in-toto; sha256-pinned in the proof).

- **Capability class:** `action`. **Risk tier:** `high_risk_custom` ⇒ four-eyes (ADR-014 `tools.rego`).
- **One atomic operation:** `apply_leave(start_date, end_date, leave_type, reason)` → one `INSERT` into `HR.LEAVE_REQUESTS` in the demo Oracle.
- **Verifies the action-context token** (signature, expiry, audience, `jti` replay, `args_sha256` recompute) exactly as the oracle pack verifies the query-context token.
- **Enforces exactly-once** via a persisted `idempotency_key` (unique constraint; a replay returns the original row, never a second insert).
- **Writes as the human's DB identity** via proxy session + `CLIENT_IDENTIFIER`, so the leave row's DB audit trail names the actual analyst.
- **Never handles credentials** — reads the injected path (§5).

The approval-probe pack we just released is the *rehearsal* for this: same trust pipeline, same four-eyes tier, same ledger-proven exactly-once property. **The difference is that this one performs a real business write.**

---

## 8. [HEADROOM] — the shapes we are not building

Designed for, not built. The purpose of this section is that **none of these forces a rewrite** when it lands.

### 8.1 Retrieval / knowledge base ("what's our overdraft policy?")

**Nothing exists.** There is no `retrieval/` package; the Qdrant adapter **raises `NotImplementedError` on any filter** (`db/adapters/qdrant_adapter.py:89-100`); vector payloads carry no tenant field.

**The design constraint, locked now:** retrieval **must pre-filter under the user's identity**, evaluated by the store *within* the search. The 2026 consensus is unambiguous that **post-filtering ("over-retrieve, then drop") is both a leak channel and a recall-starvation bug** — unauthorized content transits the pipeline and can steer the model even when dropped from the answer.

Capability class `retrieval` is **reserved and refuses** until that milestone. Because D1 keys authorization on class rather than tool name, it will land on the same gate — **no dispatcher rewrite**.

### 8.2 General knowledge ("what is Basel III?")

No tool, no data, no entitlement. But it must be **provably** no-tool: the run's evidence must show zero dispatches, and the transcript remains governed. This falls out of the existing loop for free — it is a run that makes no tool calls. **No design work needed; stated so nobody invents any.**

### 8.3 Dynamic workflow orchestration (agents/tools created on the fly)

**The tension, named:** our security model rests on *signed, pre-declared capability manifests* — the pack author **requests**, the operator **grants**, and anything unrequested is refused at load (`AgentGrantNotRequested`). "Capabilities created at runtime" is, on its face, the negation of that.

**The 2026 industry answer — and it is settled: nobody signs things at runtime.** Cloudflare (Code Mode), Anthropic (code execution with MCP), and Microsoft (CodeAct) all converged on the same shape: **synthesized code executes inside a pre-declared capability ceiling.** It may *compose and narrow*; it may never *extend*. Cryptographic attenuation (macaroon/biscuit-style, where a derived capability can only ever be a *narrowing* of a signed parent) is the only principled formalization — and it remains research, not deployed practice.

**Therefore, the rule this architecture adopts now, at zero build cost:**

> **A runtime-composed capability may only ever be an *attenuation* of a capability already granted by a signed manifest. There is no runtime path that mints authority.** Dynamic composition is a *record* in the kernel, never a signed artifact — a position ADR-008 already anticipated.

We hold the four existing blockers (installed-distribution discovery; cosign against an operator-deployed trust root; fail-closed per-tenant allow-list; boot-time-only registration) **as the ceiling**, and we do not weaken them for convenience later. ADR-029 will design composition *within* it.

### 8.4 Standards alignment (why we are ahead, and how to stay there)

Our capability token is, structurally, an **IETF Transaction Token** (`draft-ietf-oauth-transaction-tokens`, -08, March 2026) — short-lived, audience-bound, context-bound — and the agent extension adds exactly our two identities (`actor` = the agent, `principal` = the human). **It is a draft. We shipped it.** Our two-gate model (user ∧ agent, never union) is the standard confused-deputy mitigation. Our off-host, outside-the-model authorization is what the entire 2026 literature demands.

**The strategic instruction is therefore: stay convertible, don't rewrite.** Keep the token's wire shape mappable to the transaction-token and AuthZEN 1.0 (OpenID Final, March 2026) vocabularies as they ratify. Two concrete follow-ups, neither blocking this milestone:

1. **Re-baseline ADR-002 against the MCP 2026-07-28 specification** — its authorization section changed materially (enterprise-managed authorization via IdP-mediated grants; client registration replaced). A bank's architects *will* read this.
2. **Map the evidence pack to the U.S. Treasury FS AI RMF (Feb 2026) and EU AI Act Article 14.** Cheap now, expensive later, and it is the language examiners will use.

---

## 9. Milestone re-plan

The current checklist defers pilot readiness to M15–M17 and marks M8.5-E "must not be presented to a bank as pilot-ready." That framing is retained — **this is an internal product demonstration, not a pilot handover** — but the milestones are re-cut around the demo:

| | Was | Now |
|---|---|---|
| **M8.5-C** | Basic bank harness | *unchanged* — in flight (T3-I) |
| **M8.5-D** | First bank NL-query analytical agent | **Bank demo on AKS: governed read + governed write** (this spec; absorbs the old E) |
| **M8.5-E** | Full-stack `kind` proof | **Governance administration** — the console for entitlements / scopes / assignments |
| **M8.5-F** | Conversational governance completion | *unchanged* — the pilot gate (content safety + erasure) |

**Why governance administration is its own milestone:** the three most security-critical tables in the system (`data_scopes`, `entitlements`, `agent_assignments`) are **administered by raw SQL** — there is no API, no route, no RBAC scope, and the store layer has **no write methods at all**. Building that surface properly needs its own RBAC family, chain-row evidence, probably four-eyes on entitlement grants, and a harness screen. That rivals this milestone in size. It is *not* a corner of it.

**For the demo, we turn the gap into a strength:** revoke an entitlement live and let the agent refuse the next question. That proves the enforcement is real and instantaneous — then say plainly, *"the admin console is the next milestone; the enforcement you just watched is already built."* Banks trust that far more than a polished console over machinery that doesn't work.

### Sequencing (after M8.5-C closes)

1. **D1** capability classes (prerequisite for everything) — CC review.
2. **D2** the write path (HP-5) — the largest slice; CC review on every module.
3. **D5** the HR-leave pack (parallel with D2; it is an external repo).
4. **D3** credential brokerage — mostly wiring existing 14B machinery.
5. **D4** AKS deploy + **D6** dataset + demo rehearsal.
6. **Live proof on AKS** — the demo *is* the proof, with a browser in front of it.

---

## 10. Open questions for the maintainer

1. **Identity provider for the demo — Entra ID or Keycloak?** (Recommendation: Entra ID; Keycloak as fallback.)
2. **The leave-application backend** — a demo `HR.LEAVE_REQUESTS` table in our Oracle (recommended, zero dependencies), or an integration with something the bank recognizes?
3. **Does the harness need a "resume" affordance**, or is a natural-language *"go ahead"* in the next turn sufficient for the demo? (Recommendation: natural language — it is the more impressive moment, and it needs no new UI.)

---

## 11. Honesty boundaries (mandatory in the demo README and any bank-facing material)

1. **This is an internal product demonstration, not a pilot-ready system.** Content-safety hooks and the erasure pathway (M8.5-F) are **not** present.
2. **The data is ours, not the bank's.** A synthetic bank-shaped dataset in our Oracle container. No bank system is connected.
3. **Entitlement administration is raw SQL.** The enforcement is real; the console is the next milestone. Say it out loud before someone asks.
4. **One capability shape beyond read.** The write path proves *one atomic action* under four-eyes. Multi-step transactional workflows require a compensation design that does not exist.
5. **No retrieval, no general-knowledge grounding, no dynamic composition.** Designed for; not built.
6. **VPD is not used.** Enforcement is governed views + proxy grants — real, engine-level, and proven. Row-level policy is a bank-overlay extension.
