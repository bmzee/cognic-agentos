# ADR-014 — Runtime Tool Approval & Risk Tiers

## Status
**APPROVED for implementation** on 2026-04-26.

## Context

ADR-012 establishes pack-level approval (a tool/skill/agent goes through draft → submitted → approved → installed before it is callable at all). That gate runs **once per pack version**. It does not gate **per-invocation** decisions — and banks need that.

A pack approved for installation may still expose tools that, on a given call, do something bank-grade-risky: move money, query customer PII, modify a CBS record, send an email externally. The bank needs:

- Read-only operations: auto-run, no approval
- Write / customer-data / payment-touching operations: require human approval before execution
- Destructive / regulator-touching / cross-tenant operations: require **4-eyes approval** (two distinct reviewers) with explicit expiry

Without runtime approval, AgentOS is "pack-approved or pack-blocked" — too coarse for bank operational risk. Anthropic's Managed Agents pattern, OpenAI's Agents SDK, and Google ADK all expose runtime approval flows. AgentOS must too.

This is distinct from RBAC (who can call) and from guardrails (block obviously-bad input/output). Runtime approval is **synchronous human-in-the-loop on classified operations**.

## Decision

Add a **Runtime Tool Approval** layer between the harness and the MCP host. Every tool invocation passes through a risk classifier; high-risk tools block on approval before the underlying MCP call.

### Risk tiers

Every tool declares its risk tier in its pack manifest (Sprint 7A SDK validates this at submission; Sprint 7B reviewer sees it on approval; Sprint 5 MCP host enforces at invocation):

| Tier | Examples | Approval flow |
|---|---|---|
| `read_only` | Search circulars, query KB, read public regulation | **Auto-run.** No approval. Audit-logged like any call. |
| `internal_write` | Update internal ticket state, create a draft, log a comment | **Auto-run with audit emphasis.** No approval, but audit event includes `risk_tier=internal_write` flag for periodic review. |
| `customer_data_read` | Read customer profile, account history, KYC record | **Just-in-time approval** by a single approver with `tool.approve.customer_data` scope. Approval expires in N seconds (default 300s) — if the tool isn't called by then, approval is revoked. |
| `customer_data_write` | Modify customer record, update KYC | **Just-in-time approval** + per-call reason code. |
| `payment_action` | Initiate transfer, hold funds, release hold | **4-eyes** (two distinct approvers, both with `tool.approve.payment` scope; the second cannot be the originating user). Approval expires in N seconds (default 60s) — payments are time-sensitive. |
| `regulator_communication` | File a regulatory return, send email to SBP | **4-eyes** + categorised reason + audit-record reference (must reference a `decision_history` row that justifies the action). |
| `cross_tenant` | Any operation that crosses tenant boundary (rare) | **4-eyes** + bank legal sign-off scope. Default-disabled per tenant; operator-enabled with audit. |
| `high_risk_custom` | Pack author declares custom-tier with declared review process | Reviewer-defined approval flow per pack manifest |

### How the harness enforces it

```
agent.execute(input):
    ...
    when tool.invoke(name, args):
        manifest = plugin_registry.require("tool", name)
        tier = manifest.risk_tier
        if tier == "read_only" or tier == "internal_write":
            execute()  # no approval
        else:
            approval_request = approval.create(
                tool=name,
                args=redact_pii(args),
                tier=tier,
                requesting_agent=current_agent,
                requesting_user=session_user,
                expires_in_s=tier_default_expiry(tier)
            )
            await approval.wait(approval_request.id)  # blocks; harness yields
            if approval.granted:
                execute()
            else:
                raise ToolApprovalDenied(reason)
```

### Portal API

```
POST /api/v1/approvals                       # internal: harness creates
GET  /api/v1/approvals?status=pending        # reviewer queue
GET  /api/v1/approvals/{id}                  # detail (tool, args [PII redacted], tier, requester, expiry)
POST /api/v1/approvals/{id}/grant            # RBAC-scoped per tier
POST /api/v1/approvals/{id}/grant-second     # for 4-eyes (different user; checks distinctness)
POST /api/v1/approvals/{id}/deny             # with reason
GET  /api/v1/approvals/history?from&to       # audit trail
```

### RBAC scopes

- `tool.approve.customer_data` — single-approver scope
- `tool.approve.customer_data_write`
- `tool.approve.payment` — 4-eyes scope (must hold to grant; second grant must be different user)
- `tool.approve.regulator`
- `tool.approve.cross_tenant`
- `tool.approve.observe` — read-only into the queue (examiners)

### Audit linkage

Every approval emits hash-chained events into `decision_history`:
- `approval.requested` (with `parent_trace_id` linking to the agent invocation)
- `approval.granted_first` (and `approval.granted_second` for 4-eyes)
- `approval.denied`
- `approval.expired`

Tagged with ISO 42001 controls A.6.2.5 (operational responsibilities), A.7.4 (impact assessment), A.10.2 (transparency).

### What this is NOT

- **Not a substitute for guardrails.** Guardrails block obviously-bad input/output at parse time. Approval gates *legitimately-risky* operations on classified-tool calls.
- **Not a substitute for RBAC.** RBAC says *who can request a tool call*. Approval says *whether a specific call goes through*.
- **Not a substitute for pack approval.** Pack approval (ADR-012) gates *whether a tool is callable at all on this tenant*. Runtime approval gates *whether this specific invocation runs*.

## Consequences

### Positive
- Bank operational risk is granular: same pack, different tier per tool, different approval flow per tier
- 4-eyes for payments / regulator / cross-tenant is what every banking ops control framework demands
- Approval expiry prevents stale-approval risk (an approval granted 6 hours ago shouldn't authorise an action now)
- Audit chain captures the human decision at each tier — examiner can prove who approved what

### Negative
- Latency: approval-required tools wait on humans. UX must surface this clearly (operator queue, mobile-friendly approval).
- Reviewer workload: high-volume customer_data_read approvals can swamp reviewers. Mitigation: per-user **approval delegation** (a reviewer can pre-approve a class of operations for a session, with shorter expiry)
- 4-eyes-scoped users must be available for time-sensitive operations (payments) — operational policy concern
- Pack manifest now requires risk-tier declarations on every tool — pack authors must classify accurately. Reviewer (Sprint 7B) catches misclassification.

### Neutral
- Runtime approval lives inside AgentOS (not a plugin) because every bank deployment needs it; same logic as audit and guardrails

## Implementation phases

| Sprint | Work |
|---|---|
| **Sprint 5 (transitional rule)** | Harness ships **fail-closed** for all tiers above `internal_write` — high-risk tools register but every invocation is refused with `tool_approval_engine_not_available` and audit-logged. This is the only safe state until the approval engine exists. |
| **Sprint 11.5 (transitional rule, memory)** | Same fail-closed pattern for `long_term` memory writes from packs with `risk_tier >= customer_data_write` — refused with `memory_approval_engine_not_available`. See ADR-019 for the full statement. |
| **Sprint 7A** | Pack manifest schema includes `risk_tier` declaration on every tool |
| **Sprint 7B** | Reviewer sees risk-tier declarations + can require remediation before approval |
| **Sprint 13.5 (new)** | Approval engine + portal API + harness integration + RBAC scopes; the Sprint 5 transitional refusal is replaced by the real approval flow. Removal of the transitional rule is itself an audit event (`tool_approval.engine_enabled`) so banks can prove the cutover. |

Sprint 13.5 is a new sub-sprint introduced in Phase 4 alongside the eval/adversarial gates. ~2 work-units.

**Why the transitional rule:** there is no safe way to allow customer-data / payment / regulator tools to invoke without an approval engine. "Just log it and let it run" violates the threat model. The tradeoff is eight calendar weeks (Sprint 5 → Sprint 13.5) where banks cannot use high-risk tools at all. Fix is not "lower the bar"; fix is "ship Sprint 13.5 on schedule."

## Sprint 10.5 amendment (2026-05-27) — high-risk-tier refusal pre-13.5 mirrored in `scheduler.rego`

Sprint 10.5 (merged via PR #40, squash `6791eec`) landed `policies/_default/scheduler.rego` as a wire-protocol-public default-deny admission bundle (joined the AGENTS.md stop-rule policy bundle list). Per the Sprint 8A precedent already shipped in `policies/_default/sandbox.rego`, the bundle ships an **explicit fail-closed refusal for all six high-risk risk tiers until the approval engine lands in Sprint 13.5**.

**Mirror contract (defense-in-depth twin to `sandbox.rego`):**

| Risk tier (from §"Risk tiers" above) | `scheduler.rego` Wave-1 outcome | Closed-enum refusal_reason |
|---|---|---|
| `read_only` | Admission allowed (subject to other gates: kill_switch / quota / queue / caps) | (allow=true) |
| `internal_write` | Admission allowed | (allow=true) |
| `customer_data_read` | **Refused** | `scheduler_high_risk_tier_refused_pre_13_5` |
| `customer_data_write` | **Refused** | `scheduler_high_risk_tier_refused_pre_13_5` |
| `payment_action` | **Refused** | `scheduler_high_risk_tier_refused_pre_13_5` |
| `regulator_communication` | **Refused** | `scheduler_high_risk_tier_refused_pre_13_5` |
| `cross_tenant` | **Refused** | `scheduler_high_risk_tier_refused_pre_13_5` |
| `high_risk_custom` | **Refused** | `scheduler_high_risk_tier_refused_pre_13_5` |

The 6-tier high-risk set is **disjoint by construction** from the 2-tier safe set (`read_only` + `internal_write`); pinned by closed-enum drift detectors in `tests/unit/policies/test_scheduler_rego.py`. No escalation-token bypass exists pre-13.5 — this is the same lift-at-Sprint-13.5 contract the sandbox bundle ships (`sandbox.rego::sandbox_high_risk_tier_refused_pre_13_5`). When the Sprint 13.5 approval engine lands, the kernel default-deny on these tiers will be removed (or lifted to a "requires approval" sentinel) coordinated with `core/approval/engine.py` + ADR amendment.

**Refusal-reason precedence in `scheduler.rego`** (deterministic if/else chain per the bundle):
1. `scheduler_class_unknown` (FIRST — admission cannot evaluate tier semantics until class is in vocabulary)
2. `scheduler_high_risk_tier_refused_pre_13_5` (mirror of sandbox.rego — see table above)
3. `scheduler_default_deny` (fall-through; also the `default refusal_reason` for shape-mismatched/missing-input cases the chain cannot evaluate)

The 3-value closed-enum refusal vocabulary is wire-protocol-public + drift-detector-pinned.

**Sequencing relationship — pre-13.5 vs post-13.5:**

The sequencing changes at Sprint 13.5; Sprint 10.5 documents both states explicitly so future implementers can see the trajectory.

**Pre-13.5 (the state shipped at Sprint 10.5):** there is **no approval engine** yet. High-risk-tier work simply cannot be admitted. Both `scheduler.rego` AND `sandbox.rego` fail-close on all six high-risk tiers via the closed-enum refusal values (`scheduler_high_risk_tier_refused_pre_13_5` + `sandbox_high_risk_tier_refused_pre_13_5`). The pre-13.5 contract is intentionally narrow — banks accept that high-risk tools are unreachable until the approval engine lands, rather than admitting them through a lower bar.

**Post-13.5 (target state after Sprint 13.5 lands the approval engine + coordinated Rego amendment):**

1. The Sprint 13.5 coordinated amendment **lifts or converts** the pre-13.5 Rego denials. Two viable shapes are still open and will be locked at Sprint 13.5 design time:
   - **Lift**: the kernel default removes the hardcoded refusal entirely; admission is gated on the new `core/approval/engine.py` + tenant overlay policy. Cleanest but requires the approval engine to be the load-bearing gate.
   - **Convert**: the kernel default converts the refusal into a `requires_approval` sentinel that the harness layer interprets as "must pass approval before scheduler.submit". The harness sees the sentinel, calls `approval.engine.wait_for_grant()`, then on grant resubmits to the scheduler.
2. The new admission sequencing on the grant path: agent harness → `approval.engine.wait_for_grant(...)` (blocks; harness yields) → on grant → `SchedulerEngine.submit(submit_input, request_id=...)` → policy/quota/kill_switch/caps gates → admission outcome.
3. **Coordinated amendment**: ADR-014 + ADR-022 + this ADR section + the `scheduler.rego` + `sandbox.rego` bundles all update at the same Sprint 13.5 closeout. Until then the Sprint 10.5 pre-13.5 hardcoded refusal stands.

The scheduler does NOT short-circuit the approval flow in the post-13.5 design — it simply runs admission gates against a `SubmitInput` whose policy-permission has already been resolved by the upstream approval call. Approval is a harness-layer concern; admission control is a scheduler-layer concern; the layers compose cleanly because they operate on different inputs (approval consumes tool-call args; scheduler consumes pack/tier/budget/class).

**Bank-overlay contract** (per AGENTS.md stop-rule policy bundle convention): bank overlays may TIGHTEN the kernel defaults (refuse additional class/tier combinations, narrow per-tenant caps); **loosening the kernel defaults requires a coordinated kernel + ADR amendment** (mirrors the `elicitation.rego` / `sampling.rego` / `supply_chain.rego` / `sandbox.rego` precedents).

## Sprint 13.5a amendment (2026-06-10) — runtime approval engine core landed (`core/approval/`)

Sprint 13.5a builds the **non-blocking runtime approval engine core** — the substantive enforcement boundary this ADR specifies. It is scoped to the engine core ONLY: NO portal API and NO consumer-seam cutover (both 13.5b); NO ADR-018 quota / kill-switch (carved to 13.6). The engine is designed as the generic **Sprint-14 human-checkpoint primitive**, not a tool-only surface.

**What landed:**

- **`core/approval/engine.py`** — the `ApprovalEngine` pure decision state machine (`pending → awaiting_second` (4-eyes only) `→ granted` / `denied` / `expired`). Non-blocking API: `classify` (`engine.py:101`) / `create_request` (`:105`) / `check` (`:145`, returns `ApprovalCheckResult`) / `verify_grant_for_action` (`:150`) / `grant` (`:170`) / `grant_second` (`:188`) / `deny` (`:206`). There is **no wait loop** — the engine never blocks; callers poll `check()` and re-submit. Enforcement at the engine boundary: the **human-only guard** (`approver_not_human`, `_types.py:40`) on grant / grant_second / deny (a service-token actor is refused even with the scope — the portal `RequireHumanActor` is 13.5b defence-in-depth, not the only gate); **RBAC scope-per-tier**; **4-eyes distinctness** (second approver ≠ first ≠ originator); **tenant-binding** (a correctly-scoped approver from another tenant is refused, reusing `approver_scope_not_held`); and **lazy authoritative expiry** (a grant attempted after the flow's TTL is refused `approval_expired` and emits `approval.expired` once — a stale request can never resurrect).
- **Replay-binding gate** — `verify_grant_for_action` re-checks the granted request against the about-to-run invocation: a mismatched `args_digest` or `tool_identity` is refused `approval_binding_mismatch` (`_types.py:45`). A grant authorises exactly one action, not a class of actions.
- **Value-free envelope** — the caller supplies a redacted envelope (`args_digest` + `redacted_context` + `data_classes` + `risk_tier` + tool identity + actor + tenant + required refs); the engine validates fields/size-caps and computes its own canonical `envelope_digest` (`engine.py:297`) but **never sees or redacts raw tool args**. `args_digest` is a first-class column + chain-payload field (`storage.py:91`, `:121`). Unknown risk tiers are rejected at envelope validation (`risk_tier_unknown`, `_types.py:24`) before persistence — the Rego `default flow := "require_4_eyes"` is defence-in-depth, not the primary path.
- **`core/approval/storage.py`** — the decision-history-backed `approval_requests` store. The 5 immutable value-free chain events `approval.requested` (`storage.py:243`) / `approval.granted_first` / `approval.granted_second` / `approval.denied` / `approval.expired` (`:57-60`) are appended via `DecisionHistoryStore.append_with_precondition` (Doctrine Lock D: chain-head + row `FOR UPDATE` → `validate_transition` against the **row-locked persisted flow** (no caller-supplied flow downgrade) → state UPDATE → chain INSERT → chain-head UPDATE, one txn). ISO A.6.2.5 / A.7.4 / A.10.2 (registered via the `approval.*` wildcard hook).
- **Per-flow TTL Settings** — `approval_single_ttl_s` (default 300; `config.py:1801`) + `approval_four_eyes_ttl_s` (default 60; `config.py:1811`), both `gt=0`. Expiry is Settings-driven, not hardcoded.
- **7th RBAC scope** — `tool.approve.high_risk_custom` joins the 6 ADR-014 scopes (`portal/rbac/scopes.py`). Wave-1 maps `high_risk_custom → require_4_eyes`; a manifest-defined custom flow is Wave-2.
- **CC gate 125 → 128** — `engine.py` / `storage.py` / `policy.py` promoted to the durable per-file coverage gate (95% line / 90% branch), verified at promotion at 100/100 each on fresh `--cov-branch` data. `_types.py` stays off-gate (pure closed-enum + frozen-dataclass + `validate_transition`).

**Supersedes the Sprint-10.5 "post-13.5 target state" prose above (two claims rejected at 13.5a design time):**

1. The blocking `approval.engine.wait_for_grant(...)` shape (item 2 of the post-13.5 sequencing) is **superseded** — the locked 13.5a engine is **non-blocking** (no wait loop; harness polls `check()` and re-submits on `granted`). There is no `wait_for_grant` method.
2. The **Lift-vs-Convert fork is resolved to CONVERT** (the kernel default converts the pre-13.5 hardcoded high-risk refusal into a `requires_approval` sentinel the harness resolves through the approval engine before scheduler/sandbox admission). The coordinated `scheduler.rego` + `sandbox.rego` CONVERT amendment is deferred to **Sprint 13.5c**; until it lands, the Sprint-10.5 `*_pre_13_5` hardcoded refusals **stand** as the engine-unavailable fallback. **13.5b** wires the portal surface + the MCP-host consumer seam; **13.5c** does the remaining seams + the Rego CONVERT.

## Sprint 13.5b2 amendment (2026-06-11) — MCP-host seam cutover (`protocol/mcp_host.py`)

Sprint 13.5b2 makes `MCPHost.call_tool` the FIRST approval-engine consumer seam. Scope honesty: 13.5b2 is **seam-cutover only** — `MCPHost` is approval-capable and test-proven, but no production host construction path exists yet (the registry-walk → `MCPServerEntry` mapping → `app.state.mcp_host` wiring is a separate composition-root sprint); the engine instance is `runtime.approval_engine` (built unconditionally by `build_runtime` since 13.5b1).

1. **Wire vocabulary.** `ToolInvocationRefusalReason` is the 6-value Literal (`mcp_host.py:597`): `tool_approval_engine_not_available` / `tool_approval_pending` / `tool_approval_denied` / `tool_approval_expired` / `tool_approval_binding_mismatch` / `tool_approval_request_not_found` — wire-protocol-public, drift-pinned by `typing.get_args` in `test_mcp_approval_seam.py` + the byte-compat suite.
2. **Pending + re-call contract.** First `call_tool` on an approval-flow tool creates the request via `engine.create_request` and refuses `tool_approval_pending` carrying `approval_request_id` (exception payload + both evidence rows). After a portal grant, the caller re-calls with the new keyword-only `approval_request_id` param; the host recomputes `args_digest = sha256(canonical_bytes(dict(arguments)))` + `tool_identity` and dispatches ONLY on a `verify_grant_for_action` result of `granted` (`_approval_gate`, `mcp_host.py:1038`). `flow` rides refusal evidence only when known — included for first-call pending and the re-call states where `verify_grant_for_action` RETURNS an `ApprovalCheckResult` (`pending` / `awaiting_second` / `denied` / `expired`); omitted for `tool_approval_request_not_found` (no flow exists) and `tool_approval_binding_mismatch` (the raise carries no result; no extra store read). The consult runs INSIDE the evidence-emitting `try` before `_call_tool_inner` with a bare `except MCPToolInvocationRefused: raise` guard arm first (`mcp_host.py:1388`) — exactly one audit row + one decision row per request_id, no double emission. `ApprovalEnvelopeInvalid` (e.g. empty `originator_subject`) deliberately falls to the generic-`Exception` arm → ERRORED evidence with `mcp_orchestrator_error`, not a policy refusal.
3. **Canonical tool identity.** `tool_identity = "mcp:" + sha256(canonical_bytes({"server_id": ..., "tool_name": ...})).hexdigest()` (`_canonical_tool_identity`, `mcp_host.py:562`) — collision-proof (separator characters cannot alias: `("a:b","c")` ≠ `("a","b:c")`, test-pinned); 68 chars fits the `approval_requests.tool_identity` `String(256)` column; the SAME function serves create and verify. The sanitized human-readable pair lives in the envelope's `redacted_context` (`_approval_redacted_context`, `mcp_host.py:579`, capped at `APPROVAL_REDACTED_CONTEXT_MAX_LEN`) so the 13.5b1 portal reviewer panel shows WHICH tool. For `regulator_communication` the seam supplies `required_refs={"audit_record_ref": <invocation request_id>}` — the request_id every `call_tool` evidence row is keyed by.
4. **Engine-absent fallback.** `MCPHost(approval_engine=None)` (`mcp_host.py:667`, the default) preserves the Sprint-5 transitional gate byte-for-byte (static `{read_only, internal_write}` allow-list at `mcp_host.py:1304`; `tool_approval_engine_not_available` + `sprint_13_5_followup=True`). The wired path NEVER consults the static set — classification is engine-authoritative via `tools.rego` through `create_request` (catch `auto_tier_no_approval_required` → dispatch), so a bank overlay that TIGHTENS `tools.rego` (e.g. `internal_write → require_single_approval`) is honoured; both directions test-pinned. `MCPServerEntry.data_classes` (`mcp_host.py:270`, default `()`) carries the manifest `[data_governance].data_classes` into the value-free envelope at registration time.
5. **Wave-1 non-goal.** Grants are NOT single-use: a granted request remains dispatchable (subject to the replay-binding gate) until expiry. Single-use consumption requires an engine-side `consume` transition — a deliberate 13.5c/14 follow-up, not approximated at the seam.

## Sprint 13.5c1 amendment (2026-06-11) — sandbox admission seam cutover (`sandbox/admission.py` + `sandbox.rego` CONVERT)

Sprint 13.5c1 makes `admit_policy` the SECOND approval-engine consumer seam (after the 13.5b2 MCP host) and ships the FIRST half of the coordinated Rego CONVERT the 13.5a amendment deferred to 13.5c: `sandbox.rego` converts in this sprint; `scheduler.rego` converts in 13.5c2. Scope honesty: 13.5c1 is **seam-cutover only** — no production caller wires `approval_engine` into `admit_policy` yet (the backends call `admit_policy` through their existing signatures; the Runtime-owned wiring is the separate composition-root sprint); the engine instance to wire is `runtime.approval_engine` (built unconditionally by `build_runtime` since 13.5b1).

1. **Wire vocabulary.** `SandboxRefusalReason` grows 37 → 42 (`sandbox/protocol.py:276-280`): `sandbox_approval_pending` / `sandbox_approval_denied` / `sandbox_approval_expired` / `sandbox_approval_binding_mismatch` / `sandbox_approval_request_not_found`. The engine-absent fallback value `sandbox_high_risk_tier_refused_pre_13_5` is KEPT — the static `_HIGH_RISK_TIERS_PRE_13_5` set (`admission.py:265`) is consulted ONLY on the engine-absent arm (`admission.py:682-683`). `SandboxLifecycleRefused` gains the additive keyword-only `approval_request_id: str | None = None` ctor param + attr (`protocol.py:442`, `:449`) — the caller-visible correlator on pending refusals; existing raise sites unchanged.
2. **Pending + re-admit contract.** `admit_policy` gains keyword-only `approval_engine: ApprovalEngine | None = None` (`admission.py:470`) + `approval_request_id: uuid.UUID | None = None`. Wired first admission consults the engine at Step 4 via `_consult_approval_engine` (`admission.py:337`): classification is engine-authoritative via `tools.rego` through `create_request` (catch `auto_tier_no_approval_required` → proceed with `approval_verified=False`), so an overlay-TIGHTENED `tools.rego` is honoured on safe tiers and the static pre-13.5 set is NEVER consulted on the wired path — both directions test-pinned. A required flow refuses `sandbox_approval_pending` carrying the request id. After a portal grant (13.5b1), the harness re-admits with `approval_request_id`; the seam recomputes the binding and proceeds ONLY on a `verify_grant_for_action` result of `granted` — which sets the `approval_verified=True` attestation. A grant authorises exactly one admission **shape**, not single-use consumption (`consume` stays the deliberate non-goal per 13.5b2 item 5 — and was deferred OUT of the whole 13.5c series at the c-series reconciliation, superseding that item's "13.5c/14" pointer; it is a Sprint-14-or-later engine transition). `ApprovalEnvelopeInvalid` propagates RAW (fail-loud) — unlike the MCP seam there is no evidence-emitting envelope at this seam to translate it.
3. **Binding digests.** `tool_identity = "sandbox:" + sha256(canonical_bytes({"pack_id", "pack_artifact_digest"}))` (`_canonical_sandbox_identity`, `admission.py:277`) — immutable pack identity (the cosign-verified artifact digest; human-mutable `pack_version` deliberately excluded); 72 chars fits the `approval_requests.tool_identity` `String(256)` column. `args_digest` binds `{"policy": _policy_binding_projection(policy), "pack_context": <6-key projection>}`; the binding projection (`admission.py:289`) covers EVERY `SandboxPolicy` field except `warm_pool_key` and is deliberately a SUPERSET of the narrower 5-key Step-9 Rego projection — an image swap, a root-fs writability flip, or a mount change between grant and re-admit MUST refuse `sandbox_approval_binding_mismatch` (drift-pinned via `dataclasses.fields`). The new `PackAdmissionContext.data_classes` field (`policy.py:131`, default `()`) rides the envelope first-class and is in NEITHER digest (immutable-by-identity: same artifact digest ⇒ same manifest ⇒ same data classes). The reviewer-facing `redacted_context` (`_admission_redacted_context`, `admission.py:321`) carries pack_id/version/image capped at `APPROVAL_REDACTED_CONTEXT_MAX_LEN`. For `regulator_communication` the seam mints `admission_correlation_id = "sandbox-admit-<uuid>"` (`admission.py:419`) as `required_refs["audit_record_ref"]` — admission runs pre-session, so no session_id exists to reference.
4. **`sandbox.rego` CONVERT — THE coordinated loosening amendment.** The allow rule's tier conjunct is now `_tier_admissible` (`sandbox.rego:126`): arm 1 (`:135`) admits the 2 safe tiers; arm 2 (`:145`) admits a high-risk tier ONLY on strict `input.approval_verified == true` (`:147`) — falsy-by-absence fail-closed; the Python seam ALWAYS threads the key (`admission.py:857`; `False` on unwired/auto paths). This section + the bundle change together ARE the "coordinated kernel + ADR amendment" the Sprint-10.5 bank-overlay contract requires for loosening `sandbox.rego`; the `scheduler.rego` pre-13.5 refusal STANDS until 13.5c2. Approval does NOT bypass the other conjuncts — a verified grant still runs tenant-caps + credential precondition + image authorisation + egress (Steps 5–9); pinned by the live-OPA CONVERT suite (`tests/unit/policies/test_sandbox_rego.py:469`).
5. **Cutover evidence (the one-shot `engine_enabled` promise superseded).** The pre-c1 `sandbox.rego` comments promised a one-shot `sandbox_approval.engine_enabled` audit event; that is EXPLICITLY superseded, not silently dropped — `admit_policy` is a stateless pure function holding no `DecisionHistoryStore`, and admission refusal happens BEFORE session creation with no backend catch-and-emit around `admit_policy`. c1 cutover evidence = the engine's own value-free `approval.*` chain rows (sandbox-originated requests examiner-isolable via the `sandbox:` tool_identity prefix + the correlation id), the correlator-bearing refusals, and the live-OPA Rego suite proving `approval_verified` is REQUIRED for high tiers. `SandboxLifecycleEvent` is NOT extended in c1; the per-decision `approval_gated_admission` lifecycle event lands with the backend/composition wiring sprint that gives it an emission seam.

Test surface: `tests/unit/sandbox/test_approval_seam.py` (21 seam tests incl. the PINNED engine-absent byte-compat + the dangling-correlator-inert choice), the live-OPA CONVERT suite above, and the cross-surface e2e `tests/integration/approval/test_sandbox_seam_e2e.py` (admission pending → 13.5b1 HTTP grant → re-admit attests `approval_verified=True`).

## References
- ADR-002 (MCP plugin protocol — pack manifests)
- ADR-005 (sub-agent — sub-agent calls also flow through approval)
- ADR-006 (ISO 42001 — control mappings)
- ADR-012 (pack lifecycle — pack approval is the upstream gate)
- ADR-022 (runtime scheduler — Sprint 10.5 mirrored the pre-13.5 high-risk-tier refusal in `scheduler.rego`)
- [Anthropic — Managed Agents tool approval flows](https://www.anthropic.com/engineering/managed-agents)
- [OpenAI Agents SDK — approval flows](https://openai.github.io/openai-agents-python/)
