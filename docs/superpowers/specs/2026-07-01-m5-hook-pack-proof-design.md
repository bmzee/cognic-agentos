# M5 — Real Hook Pack Proof — Design

**Date:** 2026-07-01
**Milestone:** M5 (production-grade milestone checklist, `docs/PRODUCTION_GRADE_MILESTONE_CHECKLIST.md`)
**Status:** design approved; implementation-plan review accepted the two-hook `v0.2.0` BAR 3 binding
**Depends on:** M3 (first separate-repo tool pack, deployed) + M4 (operator-grade install flow) — both merged to `main`.

---

## 1. Goal

Ship the **first separately-released signed `cognic-hook-*` pack** and prove it is **installed, trusted, ordered, and enforced at runtime** in a deployed AgentOS: a live MCP `call_tool` request triggers a real hook, and the load-bearing proof is a **fail-closed `dlp_pre` refusal** — a forbidden tool-call argument is refused *before the tool executes*, with digest-only evidence and no payload leakage.

This is the hook analog of M3/M4, and it reuses their proven spine (released signed pack → boot trust-registration → operator install → governed MCP invocation).

## 2. Pivotal finding — the hook subsystem is built but dormant

The Sprint-7A2 hook kernel exists and is heavily tested + on the critical-controls floor (`packs/hooks/registry.py`, `packs/hooks/dispatcher.py`, `packs/hooks/dlp_integration.py`, `cli/validators/hooks.py`), **but it is never invoked in the deployed runtime:**

- `dispatch_for_pack` / `DLPGuard` have **zero non-test call sites** — only the hook modules themselves and tests reference them.
- `HookRegistry(` is **never constructed** outside tests; no app/runtime/mcp builder wires it.
- `[data_governance].dlp_pre_hooks` / `dlp_post_hooks` are only **validated** (CLI), **projected** for reviewers (evidence panels), and **conformance-checked** — never **executed** at runtime.
- `MCPServerEntry` (`protocol/mcp_host.py`) carries `data_classes` but **no `dlp_pre_hooks`** binding.

Therefore M5 is **not** "prove existing machinery." It has three parts: (1) ship the signed hook pack, (2) **wire the dormant hook path from boot to the `call_tool` boundary** (the substantive kernel gap), and (3) the deployed proof + load-bearing refusal.

## 3. Scope decisions (locked in brainstorming)

| # | Decision | Choice |
|---|---|---|
| Trigger | Where the hook fires | **Wire `DLPGuard` onto `MCPHost.call_tool`** (reuse the M3/M4 loop; smallest real trigger; keeps M8 from ballooning). |
| Proof kind | Load-bearing shape | **Fail-closed `dlp_pre` refusal = the milestone closer**; **fail-closed-on-hook-failure = second bar**; redaction/masking = follow-up. |
| Install | Hook-pack install posture | **Boot trust-register + `HookRegistry` admission** (hooks have no MCP carve-outs to materialize; no operator lifecycle). |
| Binding | Tool→hook binding | **Re-release `cognic-tool-oracle-schema@v0.2.0`** with an ADR-017 `[data_governance]` block declaring `dlp_pre_hooks`; `v0.1.0` stays the M3/M4 evidence artifact. |
| Phase | `scan_pre` vs `scan_post` | **`scan_pre` only** for M5; `scan_post`/redaction deferred (they raise result-shaping questions not needed to close M5). |

## 4. Architecture — the runtime wiring

Five pieces, from boot to the invocation boundary:

1. **Boot: construct + populate the `HookRegistry`.** In the `create_app` lifespan, SDK-gated alongside the MCP host (same invoke surface), build a `HookRegistry` and admit each **trusted** hook pack's verified `HookDeclaration`, digest-pinned against the trust-gate bundle. Parallels the MCP boot trust-registration proved in M3.
2. **Boot: construct the `DLPGuard`** wrapping the `HookDispatcher` (which reads the `HookRegistry`); attach it to the MCP host as the consumer.
3. **Mapper: `MCPServerEntry` gains the DLP invocation metadata.** The off-gate `harness/mcp_host.py` manifest→entry mapper extracts `[data_governance].dlp_pre_hooks` plus the manifest purpose onto the entry (additive fields). `data_classes` already exists on the entry; M5 extends the same snapshot so `MCPHost` can build a complete `HookContext` without reparsing the manifest at invocation time.
4. **`MCPHost.call_tool` calls `DLPGuard.scan_pre` before `transport.send`.** If `entry.dlp_pre_hooks` is non-empty:
   - Serialize the tool-call arguments to **canonical bytes** (reproducible digest — reuse the dispatcher's existing `policy_input_digest` path / canonical helper).
   - Build a `HookContext` template with `hook_id=""`, `phase="dlp_pre"`, `pack_id=entry.server_id` (the calling tool pack), `tenant_id`, `request_id`, `manifest_data_classes=entry.data_classes`, and the entry's manifest purpose.
   - `outcome = await dlp_guard.scan_pre(payload=<canonical args>, declared_hook_ids=entry.dlp_pre_hooks, context_template=<template>)` (matching the existing `DLPGuard` API).
   - `outcome.refusal_reason == "dlp_dispatcher_refused"` (hook policy-refused) → **refuse before token/session/transport work reaches the tool**, tool never invoked.
   - `outcome.refusal_reason == "dlp_dispatcher_failed"` (hook timed out / threw) → **also refuse** (Wave-1 fail-closed; the second bar).
   - `outcome.refusal_reason is None` → proceed to the tool unchanged.
5. **Refusal mapping.** New closed-enum `MCPToolInvocationRefused` reasons distinguish DLP policy refusal from DLP infrastructure failure: `dlp_pre_refused` (hook policy-refused, carries `policy_reason`) maps to **403**; `dlp_pre_failed` (timeout/exception/malformed hook outcome routed through `dlp_dispatcher_failed`) maps to **409**. Both are distinct from transport/auth refusals and are never leaked as a generic 500. A non-empty hook binding with an absent/unwired `dlp_guard` fails closed as an explicit service-misconfiguration refusal (e.g. `dlp_pre_guard_unavailable`, deliberate 503), never as a silent skip.

### 4.1 Invariants (hard pins, all test-enforced)

- **Canonical-bytes payload:** scan the serialized argument bytes (stable JSON canonicalization / the existing canonical helper), not arbitrary Python objects, so the hook digest + audit are reproducible.
- **Digest-only evidence:** logs and audit rows carry only the payload **digest** + hook metadata — **never** the payload plaintext. Hard test invariant.
- **No-op for un-bound packs:** empty `dlp_pre_hooks` → the `call_tool` path is **byte-identical** to today (pinned no-op regression). Every existing tool pack is completely unaffected.
- **Fail-closed on absent guard (the sharp pin):** if `dlp_pre_hooks` is **non-empty** and `dlp_guard` is **absent/unwired**, `call_tool` **fails closed** (refuses) — it MUST NOT silently skip. If `dlp_pre_hooks` is empty and `dlp_guard` is absent, behavior is unchanged (true no-op).
- **Trusted-pack-only admission:** the hook is admitted into the `HookRegistry` from the **same boot trust-registration artifact set** as other packs (digest-pinned against the verified bundle), **not** from raw entry-point discovery alone — mirroring the MCP `_mcp_admit` doctrine.
- **HookContext completeness:** `MCPHost` constructs all 9 `HookContext` fields: the empty `hook_id` template sentinel, `phase="dlp_pre"`, calling tool pack identity (`entry.server_id`), tenant, request id, nullable `trace_id` / `parent_trace_id` (both `None` for M5 unless the invocation path already has trace context), manifest data classes as a tuple, and manifest purpose. Hook code never has to parse the tool manifest at runtime.

### 4.2 CC posture

`protocol/mcp_host.py` is **on the critical-controls gate** (95% line / 90% branch), and `call_tool` + `MCPServerEntry` are the change site — so **M5 is a CC-touching kernel change** requiring strict review + coverage. The hook kernel (`packs/hooks/*`) is **consumed, not modified** (no new CC surface there). Boot wiring (`portal/api/app.py`, `harness/mcp_host.py`) is off-gate. `protocol/mcp_authz.py` is untouched.

## 5. The two pack releases (separate public repos)

### 5.1 `cognic-hook-schema-guard` — new signed hook pack

A Sprint-7A2 hook pack with **two real registered hook entries** (no mocks):

- `refuse_forbidden_schema_arg` — the **policy-refusal** hook: inspects the canonical tool-call args and policy-refuses when a forbidden value is present (→ `HookFailureMode.hook_policy_refused` → `DLPRefusalReason.dlp_dispatcher_refused`).
- `explode_schema_guard` — the **fail-closed-on-failure** hook: deterministically throws/times out (→ `dlp_dispatcher_failed`), used to prove a broken hook is refused, not bypassed.

Both declared in `[project.entry-points."cognic.hooks"]` + a `[hooks]` block: `hook_id` / `phase = dlp_pre` / `ordering_class` / `timeout_seconds` / `fail_policy = fail_closed` (Wave-1 only). **No-LLM**, deterministic. Release shape identical to M3: wheel + 7 attestations + `cosign.pub` + independent CI.

### 5.2 `cognic-tool-oracle-schema@v0.2.0` — re-release of the M3/M4 tool

Add a **validator-clean, honest** `[data_governance]` block (the validator requires more than `dlp_pre_hooks`):

```toml
[data_governance]
data_classes    = ["internal"]
purpose         = "operational_telemetry"
retention_policy = "none"
dlp_pre_hooks   = ["refuse_forbidden_schema_arg", "explode_schema_guard"]
```

Cross-checked against `[risk_tier].tier = "read_only"`. Both hooks are argument-gated in the hook pack: normal args pass both, the forbidden sentinel triggers `refuse_forbidden_schema_arg`, and the explode sentinel passes the first hook then triggers `explode_schema_guard`. Bump to `0.2.0`, re-sign, new signed release. **`v0.1.0` remains the M3/M4 evidence artifact**; `v0.2.0` is the M5 DLP-governed release. The two coexist.

## 6. The deployed proof (kind)

A new `infra/proof-m5/` reusing the proof-m4 harness (multi-actor proof app + the operator install flow). Boot **trust-registers both** released packs (hook → `HookRegistry` admission; tool → plugin registry); the tool is **operator-installed via the M4 flow**; the hook is **only trust-registered / registry-admitted** (decision B).

- **BAR 1 — happy path (hook fires, allows):** `call_tool(describe_table, owner=COGNIC, table=EMPLOYEES)` with a **permitted** arg → hook runs → allows → tool executes → `FULL_NAME` (proves the hook fires *and* a clean call passes unchanged).
- **BAR 2 — load-bearing refusal (the closer):** `call_tool` with a **forbidden** arg → `refuse_forbidden_schema_arg` policy-refuses → `dlp_pre_refused` → **403, tool never invoked**, audit row **digest-only**. The **per-argument binary** (BAR 1 permitted vs BAR 2 forbidden, same deployed `v0.2.0`, hook decision the only variable) proves the control matters.
- **BAR 3 — second bar (fail-closed on hook failure):** bind/exercise `explode_schema_guard` → `dlp_dispatcher_failed` → **`dlp_pre_failed` / 409** (broken hook ≠ silent bypass).
- **Optional/preliminary evidence** (not a milestone requirement): a `v0.1.0` (no-hook) run reaching the tool with the same forbidden arg — recorded only if it does not make the runner materially heavier.

`RUNNER_EXIT=0`; evidence in a `docs/VALIDATION-RESULTS.md` "M5 — Real hook pack proof — PASS" section.

## 7. Testing + gate posture

**In-repo unit tests (the CC-critical wiring):**
- `MCPHost.call_tool` × `scan_pre`: permitted → tool invoked; `dlp_dispatcher_refused` → `dlp_pre_refused` + no token/session/transport work reaches the tool; `dlp_dispatcher_failed` → `dlp_pre_failed` + also refused; **empty `dlp_pre_hooks` → byte-identical no-op**; **non-empty `dlp_pre_hooks` + absent guard → explicit fail-closed misconfiguration**; **digest-only invariant** (no plaintext in audit/logs); policy/failure DLP outcomes → 403/409 never 5xx (portal route).
- `MCPServerEntry.dlp_pre_hooks` + manifest-purpose fields and the off-gate mapper extraction; canonical-arg serialization → reproducible digest; `HookContext` template fields match `sdk.hook.HookContext`.
- Boot: `HookRegistry` constructed + verified hook admitted (trusted-pack-only); `DLPGuard` wired to the MCP host.
- **CC coverage:** `protocol/mcp_host.py` holds 95/90 with the new `call_tool` branches; `packs/hooks/*` consumed-not-modified.

**Separate-repo CI:** the hook pack (validate/sign/verify + the two hooks' deterministic logic) and oracle-schema `v0.2.0` (data_governance block validates clean).

**Deployability / no-regression:** the hook path is SDK-gated alongside the MCP host; the no-op invariant means merging M5 does not disturb M3/M4 (existing tool packs have no `dlp_pre_hooks` → no-op), so `main` stays deployable.

## 8. Out of scope / follow-ups

- **`scan_post` + redaction/masking** — a symmetric second application, deferred (raises result-shaping questions M5 does not need).
- **Operator lifecycle for hook packs** (enable/disable through the M4-style flow) — a later uniform-governance feature; M5 uses trust-register + registry-admit, the correct mechanism for in-process hook code.
- **AKS** — M5 is a `kind` proof; the AKS bar is M15/M24.
- **The `v0.1.0` no-hook baseline comparison** — optional/preliminary evidence only.

## 9. Open risks

- **Canonical serialization choice** — reuse the dispatcher's existing `policy_input_digest` mechanism vs `core/canonical.canonical_bytes`; must match whatever the dispatcher already digests so the audit correlates. (Do not silently introduce a second canonical form.)
- **Where exactly in `call_tool`** `scan_pre` inserts relative to the approval gate must be finalized in the plan. It must run **after** the existing static/approval gates (so already-refused calls do not invoke hooks) and **before** token acquisition / session open / `transport.send` (so a DLP refusal does not reach the AS or tool server).
- **The forbidden-arg definition** in `refuse_forbidden_schema_arg` must be deterministic + documented (e.g., a forbidden owner/table or a sensitive-data pattern) so the proof and the pack tests agree.
