# M8 — Governed Agent Loop — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Implement this plan in the long-running batches named below, then return a complete report per batch for controller review. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove — live on a deployed `kind` AgentOS — that a declarative, cosign-signed **`cognic-agent-bank-analyst`** pack answers a natural-language banking question by reasoning on a cloud model through the governed LLM gateway, consuming its **assigned** instruction skills, and executing SQL over **governed views** through one governed `run_readonly_query` tool under the **asking user's** data entitlements — with unassigned capabilities, unentitled scopes, and SQL escapes all refused, audited, and gracefully messaged.

**Architecture:** Declarative agent pack (inert `cognic.agents` marker; zero executable loop code) + kernel-owned reasoning loop (`core/agent/loop.py`, CC — frames and interprets the untrusted LLM) + a single dispatch chokepoint (`core/agent/dispatch.py`, CC — assignment gate, entitlement gate, `agents.rego`, kernel-minted signed query-context token). The gateway gains a typed tool-calling contract over its single LiteLLM-normalized OpenAI wire. Data access = data-scope (governed-view-set) m:n entitlements; the tool verifies the kernel-signed token, parses SQL with sqlglot, and executes via Oracle proxy auth as the user's DB identity (engine grants = the backstop). Single-shot; task-tier digest-only memory; dual identity (`sub`=user, `act`=agent) on every evidence row.

**Tech Stack:** Python 3.12, FastAPI, LiteLLM proxy (OpenAI chat-completions wire), joserfc RS256 JWS, OPA/Rego, sqlglot 30.12.0 (pack-side), Oracle proxy authentication, cosign/syft/grype supply chain, kind/Helm deployed proof.

## Global Constraints

- Source spec: `docs/superpowers/specs/2026-07-04-m8-governed-agent-loop-design.md` (@`9cb388d`). Every task's requirements implicitly include the spec. New ADR: **ADR-027** (ADR-026 is taken).
- **§9 resolutions are LOCKED INPUTS** (controller recon 2026-07-05; maintainer ratification rides THIS plan review): (1) `GatewayToolSpec`/`GatewayToolCall` frozen+slots over the single LiteLLM-normalized OpenAI wire + 3 respx provider-family fixtures; (2) query-context token = joserfc RS256 compact JWS, `args_sha256`-bound, 120 s expiry, tool-side jti cache, `Settings.agent_query_context_signing_key_path`, two-key rotation window; (3) `agents.rego` bool-only `data.cognic.agents.dispatch.allow`, 11-key input incl. `assignment_verified`/`entitlement_verified` strict-`== true` defense-in-depth, `core/agent/policy.py` mirroring `core/scheduler/policy.py`; (4) `[agent]` manifest block + `cli/validators/agents.py` + `LoadedAgentRecord`/`harness/agent_host.py` + `[skill].mode = "instruction"` + `agent-packs/<pack_id>/cosign.pub` trust root; (5) migration `20260705_0014_agent_entitlements` (rev `0014`, down `0013`); (6) `sqlglot==30.12.0` pure-Python (no `sqlglotrs`), pack-side only — the kernel stays parser-free.
- **Spec deltas folded** (flagged to the maintainer): (a) the dispatch refusal vocabulary gains `agent_policy_denied` (rego deny had no value in the spec's initial list); (b) the gateway null-content-when-tool-calls relaxation is a behavior change on the stop-rule `llm/gateway.py` — CC-grade, pinned both directions.
- **`protocol/mcp_authz.py` MUST stay byte-identical** — verify at EVERY commit (`git diff --stat src/cognic_agentos/protocol/mcp_authz.py` empty; the standing guard `tests/unit/architecture/test_mcp_authz_untouched.py`).
- **Critical-controls discipline:** new gate entries at 95% line / 90% branch: `core/agent/loop.py`, `core/agent/dispatch.py`, `core/agent/assignments.py`, `core/agent/policy.py`, `core/agent/query_context.py`, `core/entitlements/store.py` (gate 143 → 149). `llm/gateway.py` + `protocol/ui_events.py` are ALREADY on the gate (`tools/check_critical_coverage.py:743`, `:891`) — their edits ride the existing floor. Every security-relevant test is threat-model-revert-proven load-bearing (weaken → matching test FAILS → restore byte-identical, sha-documented) per `feedback_security_regression_hardening`.
- **On-gate status is VERIFIED, never assumed** (per `feedback_verify_on_gate_status_not_plan_claim`): before each commit touching an existing src module, `grep _CRITICAL_FILES` for it. Known now: `harness/registry_boot.py`, `harness/skill_host.py`, `cli/validators/skills.py` are NOT in `_CRITICAL_FILES` (verified 2026-07-05) — they still carry stop-rule/strict-review scrutiny where marked.
- **All six bars are MANDATORY** (spec §5 — no escape hatches). The parser is never weakened for testing; the DB backstop is proven by a separate direct probe (BAR 4b).
- **Separation:** Part A is in-repo kernel work on branch `feat/m8-governed-agent-loop`. Part B is external pack releases (oracle v0.3.0 in the EXISTING `cognic-tool-oracle-schema` repo; three NEW instruction-skill repos; one NEW agent-pack repo) — named here, not built in this repo. Part C is the deployed proof consuming ONLY released, digest-pinned assets. Cloud key is operator-supplied env-gated; never committed; CI never runs the proof.
- Full CC gate at each CC commit: `uv run ruff check && uv run ruff format --check && uv run mypy src tests && uv run pytest --cov=cognic_agentos --cov-branch --cov-report=json -q && uv run python tools/check_critical_coverage.py`.
- Per-task commit-token gating: guard-stage the EXACT named files (assert `git diff --cached --name-only` equals the expected set), halt for the maintainer's one-word token before every commit. Never stage `.claude/settings.json` or the protected untracked paths.
- Execution mode (maintainer-locked): **long-running Fable batches for off-gate / external-pack / proof work; every CC batch = controller review + fresh full gate + `mcp_authz.py` byte-identical + commit token.** Suggested batches: A1 | A2 | A3–A4 | A5–A6 | A7–A9 | A10 | A11 | A12–A13 | B1 | B2 | B3 | C1–C2 | C3.
- This plan and its spec are docs-only on `docs/m8-governed-agent-loop-spec`. **Do NOT cut `feat/m8-governed-agent-loop` until Task A1's code phase begins** (and only after the spec+plan PR/merge posture is settled by the maintainer).

---

## File Structure

**In-repo kernel (Part A):**
- `docs/adrs/ADR-027-governed-agent-loop.md` — NEW. Doctrine: declarative agents, loop/dispatch split, query-context trust seam, rotation posture, deferrals (M9 memory, RFC-8693 Wave-2, portal entitlement CRUD, pure-declarative discovery, Redis nonce store).
- `src/cognic_agentos/llm/gateway.py` — MODIFY (on-gate, stop-rule). `GatewayToolSpec` / `GatewayToolCall` / tools serialization / `tool_calls` parse / `GatewayResponse.tool_calls` / trace outcome `malformed_tool_call`.
- `src/cognic_agentos/db/migrations/versions/20260705_0014_agent_entitlements.py` — NEW. `data_scopes` + `entitlements` + `agent_assignments` tables (rows are proof-side seed).
- `src/cognic_agentos/core/entitlements/__init__.py`, `store.py` — NEW (CC). `EntitlementStore` reads: entitled scopes per subject, scope resolution.
- `src/cognic_agentos/core/agent/__init__.py`, `_types.py` (off-gate types), `assignments.py` (CC), `policy.py` (CC), `query_context.py` (CC), `dispatch.py` (CC), `loop.py` (CC), `builtins.py` (off-gate) — NEW. The agent runtime.
- `policies/_default/agents.rego` — NEW stop-rule policy bundle.
- `src/cognic_agentos/harness/skill_host.py`, `src/cognic_agentos/core/skill/_types.py`, `src/cognic_agentos/core/skill/executor.py` (on-gate), `src/cognic_agentos/cli/validators/skills.py`, `src/cognic_agentos/cli/__init__.py` — MODIFY. Instruction-only skill mode + `referenced_tools`.
- `src/cognic_agentos/protocol/agent_manifest.py` — NEW (off-gate). `AGENT.md` extractor reusing `skill_manifest` parse/validate.
- `src/cognic_agentos/cli/validators/agents.py` — NEW. `[agent]` block validator; `cli/validate.py` MODIFY (dispatch + `_FORBIDDEN_BLOCKS_BY_KIND`).
- `src/cognic_agentos/harness/agent_host.py` — NEW (off-gate). Agent-record loader + loop composition.
- `src/cognic_agentos/harness/registry_boot.py` — MODIFY. `agent-packs/<pack_id>/cosign.pub` per-pack trust-root policy.
- `src/cognic_agentos/protocol/ui_events.py` — MODIFY (on-gate). `agent_run` emit projectors.
- `src/cognic_agentos/portal/api/agents/__init__.py`, `dto.py`, `routes.py` — NEW (off-gate). `POST /api/v1/agents/{agent_id}/ask`.
- `src/cognic_agentos/portal/rbac/scopes.py`, `actor.py`, `enforcement.py` — MODIFY. `agent.ask` scope.
- `src/cognic_agentos/core/config.py`, `harness/runtime.py`, `portal/api/app.py`, `portal/api/system_routes.py` — MODIFY (wiring + Settings; `core/config.py` is a `core/` stop-rule edit).
- `tools/check_critical_coverage.py` — MODIFY. +6 gate entries.

**External packs (Part B, separate repos):** `cognic-tool-oracle-schema` v0.3.0 (`run_readonly_query`); NEW `cognic-skill-customer-data`, `cognic-skill-financial-data`, `cognic-skill-cards-data`, `cognic-skill-atm-recon` (instruction-only, four packs — `cards-data` added per the 2026-07-06 finding-#2 ruling); NEW `cognic-agent-bank-analyst`.

**Deployed proof (Part C):** `infra/proof-m8/` (Dockerfiles, `stage-packs.sh` with 5+ release digest pins, oracle seed SQL, kernel seeds incl. the 0014 rows + query-context keypair, `proof-m8-values.yaml`, `run-proof-m8.sh`, `README.md`), `tests/unit/infra/test_proof_m8_structure.py`.

---

# PART A — In-repo kernel (CC-gated batches)

### Task A1: ADR-027 — Governed agent loop doctrine (docs)

**Files:** Create `docs/adrs/ADR-027-governed-agent-loop.md`. Do not modify `AGENTS.md` here; the critical-controls entries land at the Part-A close after the files exist.

**Interfaces:** Produces the doctrine every later task cites. No code.

- [ ] **Step 1:** Write ADR-027: (a) **Declarative agents** — the pack carries persona + requested capabilities; the kernel owns the loop; the inert `cognic.agents` marker is the registry/verify vehicle (side-effect-free on import/load; pure-declarative discovery without `EntryPoint.load` recorded as the eventual evolution, not built). (b) **Loop/dispatch split** — loop = CC because it frames/interprets the untrusted LLM; dispatch = the only authority path; the LLM selects *within* granted/entitled sets, never authors them. (c) **The query-context trust seam** (spec §3.3 verbatim: LLM-visible schema is exactly `{scope_id, sql, max_rows?}`; the signed token carries the resolved facts; `query_context_missing_or_invalid` makes the tool agent-path-only). Token format per §9-LOCK-2: RS256 compact JWS, claims `iss`/`aud`/`sub`/`act`/`tenant_id`/`scope_id`/`objects`/`proxy_db_identity`/`args_sha256`/`jti`/`iat`/`exp`; 120 s default expiry; tool-side in-memory TTL'd jti cache; two-key rotation window (tool accepts `{current, previous}` public keys); Redis-backed shared nonce store = Wave-2. (d) **Data-scope entitlements** — governed-view-set grain, m:n, seed-driven administration in M8 (portal CRUD deferred, Human-only-decision-adjacent). (e) **Closed dispatch refusal vocabulary** incl. `agent_policy_denied` (spec delta a). (f) **Evidence contract** — dual identity on every row; digest-only. (g) **Deferrals** (spec §8) + RFC-8693 Wave-2 alignment. Status APPROVED.
- [ ] **Step 2:** Cross-reference from ADR-005 (sub-agent primitive: the M8 loop is the top-level agent runtime; spawn integration deferred), ADR-014 (dispatch risk-tier continuity), ADR-015 (the new `agents.rego` decision point), ADR-019 (task-tier writes; long-term = M9), ADR-025 (instruction-skill mode joins the skill-pack doctrine).
- [ ] **Step 3: Commit** (halt for token). `git add docs/adrs/ADR-027-governed-agent-loop.md && git commit -m "docs(m8): ADR-027 governed agent loop doctrine"`

### Task A2: Gateway typed tool-calling (CC — stop-rule `llm/gateway.py`, already on-gate)

**Files:**
- Modify: `src/cognic_agentos/llm/gateway.py` (types near `GatewayResponse` @`:224`; wire body @`:572`; content extraction @`:753-761`; `GatewayTraceOutcome` @`:74-88`; `completion` signature @`:356-364`)
- Test: `tests/unit/llm/test_gateway_tool_calling.py` (NEW), `tests/unit/llm/test_gateway_observability.py` (outcome-count pin 13→14)

**Interfaces:**
- Produces:
  - `GatewayToolSpec` — `@dataclass(frozen=True, slots=True)`: `name: str`, `description: str`, `parameters: dict[str, Any]` (JSON schema). Serialized outbound as `{"type": "function", "function": {"name", "description", "parameters"}}`.
  - `GatewayToolCall` — `@dataclass(frozen=True, slots=True)`: `id: str`, `name: str`, `arguments: dict[str, Any]`.
  - `completion(..., tools: Sequence[GatewayToolSpec] | None = None)` — additive kwarg. `tools=None` → the POST body is BYTE-IDENTICAL to today (`{"model", "messages"}`; pinned). `tools=[...]` → body gains `"tools": [serialized...]`.
  - `messages` typing widens `list[dict[str, str]]` → `list[dict[str, Any]]` (assistant tool-call messages carry `tool_calls: list`; tool-role messages carry `tool_call_id`; content may be `None`). The input-guardrail join becomes `str(m.get("content") or "")` — None-content never crashes the pipeline; pinned.
  - `GatewayResponse.tool_calls: tuple[GatewayToolCall, ...] = ()` — additive; existing callers (`evaluation/judge.py:132`, `evaluation/target.py:59`) untouched.
  - Parse contract (the single LiteLLM-normalized OpenAI wire): `choices[0].message.tool_calls[]` → each entry must have `function.name: str` and `function.arguments` as a JSON-object string OR a dict (ollama family); missing `id` → synthesize `f"call_{index}"`. Malformed (non-object arguments JSON, non-str name, non-list tool_calls) → the strict-regime failure path with NEW trace outcome `"malformed_tool_call"` (`GatewayTraceOutcome` 13→14; count pin updated).
  - **Null-content relaxation (spec delta b, CC-grade):** `message.content is None` is accepted ONLY when `tool_calls` is non-empty (then `content=""` on the response); with no tool_calls the existing str-or-`_MalformedResponseContent` enforcement is UNCHANGED — pinned in BOTH directions (a null-content-no-tool-calls response still fails closed).

- [ ] **Step 1: Write the failing tests** (respx at the LiteLLM boundary per `tests/unit/llm/conftest.py`; provider-family fixtures per §9-LOCK-1):
```python
# fixture bodies = LiteLLM-normalized /chat/completions responses
OPENAI_FAMILY = {"choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [
    {"id": "call_abc", "type": "function",
     "function": {"name": "run_readonly_query", "arguments": '{"scope_id": "retail_analytics", "sql": "SELECT 1"}'}}]},
    "finish_reason": "tool_calls"}], "model": "gpt-4o", "usage": {"prompt_tokens": 10, "completion_tokens": 5}}
ANTHROPIC_FAMILY = ...  # toolu_* id; content text COEXISTS with tool_calls → both surfaced
OLLAMA_FAMILY = ...     # arguments as a dict (not str); id ABSENT → synthesized "call_0"

async def test_no_tools_wire_unchanged(...):   # tools=None body == {"model","messages"} exactly
async def test_openai_family_tool_call_parsed(...)
async def test_anthropic_family_content_and_tool_calls_coexist(...)
async def test_ollama_family_dict_args_and_missing_id_synthesized(...)
async def test_malformed_arguments_json_fails_closed(...)      # outcome == "malformed_tool_call"
async def test_null_content_without_tool_calls_still_refused(...)  # the BOTH-directions pin
async def test_tool_role_and_none_content_messages_survive_guardrail_join(...)
def test_trace_outcome_enum_now_fourteen(): ...
```
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement.** Serialization + parse live beside the existing extraction at `gateway.py:753-761`; the response construction at `:822-830` gains `tool_calls=`. NO other governance-order change (kill-switch→quota→concurrency→dispatch→drift→post-policy→output-guardrails→strict-ledger stays byte-order identical; output guardrails run on `content` only — tool_calls args are governed downstream by dispatch).
- [ ] **Step 4: Run — expect PASS** (new file + the full `tests/unit/llm/` suite).
- [ ] **Step 5: CC gate + commit** (halt for token; **CC — strict review**; `llm/gateway.py` already on-gate — floor must hold on fresh `--cov-branch`). TM-revert: drop the null-content guard → the both-directions pin FAILS → restore (sha-documented). `git add src/cognic_agentos/llm/gateway.py tests/unit/llm/test_gateway_tool_calling.py tests/unit/llm/test_gateway_observability.py && git commit -m "feat(m8): gateway typed tool-calling — GatewayToolSpec/GatewayToolCall over the LiteLLM wire (CC)"`

### Task A3: Migration 0014 + entitlement store (CC)

**Files:**
- Create: `src/cognic_agentos/db/migrations/versions/20260705_0014_agent_entitlements.py` (`revision="0014"`, `down_revision="0013"`), `src/cognic_agentos/core/entitlements/__init__.py`, `src/cognic_agentos/core/entitlements/store.py`
- Test: `tests/unit/db/test_migration_20260705_0014.py`, `tests/unit/core/entitlements/test_store.py`
- Modify: `tools/check_critical_coverage.py` (+`core/entitlements/store.py`; bump count guard)

**Interfaces:**
- Tables (all tenant-scoped): `data_scopes(tenant_id, scope_id PK-with-tenant, schema_name, objects JSON list[str] of governed-view names, proxy_db_identity, created_at)`; `entitlements(tenant_id, subject, scope_id, created_at; UNIQUE(tenant_id, subject, scope_id))`; `agent_assignments(tenant_id, agent_id, capability_kind Literal-checked "skill"|"tool", capability_ref, created_at; UNIQUE(tenant_id, agent_id, capability_kind, capability_ref))`. Rows are proof-side seed — the migration is data-free.
- Produces: `DataScope` frozen dataclass (`scope_id`, `schema_name`, `objects: tuple[str, ...]`, `proxy_db_identity`); `EntitlementStore(engine)` with `async def entitled_scope_ids(*, tenant_id: str, subject: str) -> frozenset[str]` and `async def resolve_scope(*, tenant_id: str, scope_id: str) -> DataScope | None` (absent OR cross-tenant → `None` — the wire-collapse invisibility doctrine).

- [ ] **Step 1: Write the failing tests** — on the Alembic-MIGRATED DB, not `create_all` (per `feedback_storage_test_migrated_db_not_create_all`): migration applies + downgrades; unique constraints enforced; `entitled_scope_ids` returns exactly the seeded m:n rows (one subject → two scopes; one scope → two subjects); **wrong-tenant negatives** (same subject, different tenant_id → empty set; `resolve_scope` cross-tenant → None).
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** the migration + the store (SQLAlchemy Core, mirroring `packs/storage.py` read-method style; no chain rows — pure-read store; the dispatch row is the evidence surface).
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: CC gate + commit** (halt for token; **CC**). `git add src/cognic_agentos/db/migrations/versions/20260705_0014_agent_entitlements.py src/cognic_agentos/core/entitlements/ tests/unit/db/test_migration_20260705_0014.py tests/unit/core/entitlements/test_store.py tools/check_critical_coverage.py && git commit -m "feat(m8): data-scope entitlement substrate — migration 0014 + EntitlementStore (CC)"`

### Task A4: Agent types + assignment store with the ingestion invariant (CC)

**Files:**
- Create: `src/cognic_agentos/core/agent/__init__.py`, `src/cognic_agentos/core/agent/_types.py`, `src/cognic_agentos/core/agent/assignments.py`
- Test: `tests/unit/core/agent/test_types.py`, `tests/unit/core/agent/test_assignments.py`
- Modify: `tools/check_critical_coverage.py` (+`core/agent/assignments.py`)

**Interfaces:**
- `_types.py` (off-gate, pure types — the `core/run/_types.py` precedent): `AgentDispatchRefusalReason = Literal["agent_capability_not_assigned", "agent_scope_not_entitled", "agent_sql_object_out_of_scope", "agent_max_steps_exceeded", "agent_tool_dispatch_failed", "agent_policy_denied", "agent_grant_not_requested"]` (7 values; closed-enum count pinned via `get_args` per `feedback_count_enum_values_via_ast_not_regex`); `AgentRunTerminalState = Literal["completed", "refused", "failed"]`; `LoadedAgentRecord` frozen dataclass (`agent_id`, `persona_body: str`, `persona_sha256: str`, `requested_skills: tuple[str, ...]`, `requested_tools: tuple[str, ...]`, `max_steps: int | None`, `risk_tier: str`, `pack_version: str`, `signed_artefact_digest: str | None`, `registered: bool`); `CapabilityRef` frozen dataclass (`kind: Literal["skill", "tool", "builtin"]`, `ref: str`); `AgentAskResult` frozen dataclass (`run_id: str`, `terminal_state: AgentRunTerminalState`, `answer: str`, `steps_used: int`, `refusal_reason: AgentDispatchRefusalReason | None`).
- `assignments.py` (CC): `AssignmentStore.load_for_agent(*, tenant_id: str, agent_id: str, record: LoadedAgentRecord, engine) -> GrantedCapabilities` — reads `agent_assignments` rows; **ingestion invariant (spec §3.1): any row whose `capability_ref` is NOT in the record's requested set (skills vs tools by kind) raises `AgentGrantNotRequested(reason="agent_grant_not_requested", capability_ref=...)` fail-closed at load** — operator/config drift can never grant beyond the persona's requested set. Produces `GrantedCapabilities` frozen (`skills: frozenset[str]`, `tools: frozenset[str]`); built-ins (`read_skill`, `remember`) are implicitly granted (kernel-owned, not assignment rows).

- [ ] **Step 1: Write the failing tests** — closed-enum counts; granted ⊆ requested happy path; **the ingestion invariant: one out-of-request row → load refuses fail-closed (no partial grant set returned)** — TM-revert-proven; wrong-tenant rows invisible; kind-partitioning (a skill ref granted as kind="tool" is out-of-request).
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement.** `core/agent` imports NO `portal`/`protocol`/`sdk` — add `tests/unit/architecture/test_agent_no_forbidden_imports.py` (AST fence mirroring `core/run`'s, covering every `core/agent/*` module; also fences `core/agent → cli` so the local risk-tier/vocab copies stay drift-pinned test-only).
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: CC gate + commit** (halt for token; **CC**). `git add src/cognic_agentos/core/agent/__init__.py src/cognic_agentos/core/agent/_types.py src/cognic_agentos/core/agent/assignments.py tests/unit/core/agent/test_types.py tests/unit/core/agent/test_assignments.py tests/unit/architecture/test_agent_no_forbidden_imports.py tools/check_critical_coverage.py && git commit -m "feat(m8): agent types + assignment store with grant-not-requested ingestion invariant (CC)"`

### Task A5: `agents.rego` + `core/agent/policy.py` (CC)

**Files:**
- Create: `policies/_default/agents.rego`, `src/cognic_agentos/core/agent/policy.py`
- Test: `tests/unit/policies/test_agents_rego.py` (`@opa_required`, mirroring `test_scheduler_rego.py`), `tests/unit/core/agent/test_policy.py`
- Modify: `src/cognic_agentos/core/config.py` (+`agents_policy_bundle: Path = Path("policies/_default/agents.rego")` — `core/` stop-rule edit), `tools/check_critical_coverage.py` (+`core/agent/policy.py`)

**Interfaces:**
- Bundle: package `cognic.agents.dispatch`; **bool-only** decision point `data.cognic.agents.dispatch.allow`; `default allow := false`. Allow requires ALL of: `input.assignment_verified == true` AND `input.entitlement_verified == true` (strict — the sandbox.rego rule-4 defense-in-depth precedent: a Python-gate bypass still refuses) AND `input.capability_kind` ∈ `{"skill", "tool", "builtin"}` AND `input.step_index < input.max_steps`. Wire-protocol-public stop-rule bundle (banks may tighten; loosening = kernel+ADR amendment) — header documents this like `scheduler.rego:10-19`.
- Input document (11 keys, all always-threaded): `tenant_id`, `agent_id`, `originator_subject`, `capability_kind`, `capability_ref`, `scope_id` (nullable), `pack_risk_tier`, `step_index`, `max_steps`, `assignment_verified`, `entitlement_verified`.
- `policy.py` (CC): `AgentDispatchPolicy(opa_engine: OPAEngine)` with `async def evaluate(input_doc: AgentPolicyInput) -> PolicyDecision` — mirrors `core/scheduler/policy.py`: own `_MINIMAL_SUBPROCESS_ENV` copy + test-only byte-parity drift detector vs `engine.py:84-87` (per `feedback_drift_detector_test_only_no_runtime_import`); `_build_rego_input` staticmethod with an all-keys drift pin; any `OpaNotInstalledError`/`RegoEvaluationError` → `PolicyDecision(allow=False, policy_reason="opa_unavailable")` fail-closed. No string decision point → no second-subprocess helper needed (the Python dispatcher owns the refusal vocabulary; a rego deny surfaces as `agent_policy_denied`).

- [ ] **Step 1: Write the failing tests** — rego (`@opa_required`): default-deny on empty input; both-verified + builtin/skill/tool allow; `assignment_verified=false` denies EVEN with `entitlement_verified=true` (and vice versa — the defense-in-depth pins, TM-revert-proven); `step_index >= max_steps` denies; unknown `capability_kind` denies. Python: input-key drift pin; env-parity pin; `opa_unavailable` fail-closed.
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** bundle + policy module + the Settings field.
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: CC gate + commit** (halt for token; **CC**; `core/config.py` stop-rule edit carries halt-before-commit scrutiny). `git add policies/_default/agents.rego src/cognic_agentos/core/agent/policy.py src/cognic_agentos/core/config.py tests/unit/policies/test_agents_rego.py tests/unit/core/agent/test_policy.py tools/check_critical_coverage.py && git commit -m "feat(m8): agents.rego dispatch bundle + AgentDispatchPolicy (CC)"`

### Task A6: Query-context token — mint + verify (CC)

**Files:**
- Create: `src/cognic_agentos/core/agent/query_context.py`
- Test: `tests/unit/core/agent/test_query_context.py`
- Modify: `src/cognic_agentos/core/config.py` (+`agent_query_context_signing_key_path: str | None = None` — path or `vault://`, prod-profile fixture-path guard mirroring `signing_key_path` @`config.py:809-820`; +`agent_query_context_ttl_s: float = 120.0` gt=0), `tools/check_critical_coverage.py` (+`core/agent/query_context.py`)

**Interfaces:**
- Produces:
  - `QueryContextClaims` frozen dataclass: `iss: str` ("cognic-agentos"), `aud: str` (the tool ref, e.g. `"cognic-tool-oracle-schema/run_readonly_query"`), `sub: str` (originator user), `act: str` (agent_id), `tenant_id: str`, `scope_id: str`, `objects: tuple[str, ...]` (the governed-view allow-set), `proxy_db_identity: str`, `args_sha256: str` (sha256 of `canonical_bytes({"scope_id", "sql", "max_rows"})` — binds the token to the exact LLM-authored args), `jti: str` (`secrets.token_hex(16)`), `iat: int`, `exp: int` (`iat + ttl_s`).
  - `mint_query_context(*, claims: QueryContextClaims, signing_key_pem: bytes) -> str` — joserfc RS256 **compact JWS, attached payload** (`jws.serialize_compact({"alg": "RS256"}, canonical-JSON payload, RSAKey.import_key(pem))` — the `cli/sign.py:1774-1778` stack, attached not detached). joserfc imported FUNCTION-LOCALLY, fail-loud `RuntimeError` naming the `adapters` extra when absent (the `harness/runtime.py` function-local-import posture).
  - `verify_query_context(*, token: str, public_keys_pem: Sequence[bytes], expected_aud: str, now: int) -> QueryContextClaims` — accepts any key in the set (the two-key rotation window); refuses closed-enum `QueryContextRefusal(reason=...)` with `Literal["query_context_signature_invalid", "query_context_expired", "query_context_audience_mismatch", "query_context_claims_malformed"]`. The kernel verify is the REFERENCE implementation the tool pack mirrors (the pack repo's tests mint with THIS function via its kernel dev-dep — the cross-repo wire pin).
- The nonce/replay posture is deliberately NOT kernel-side (tool-side jti cache, B1) — documented in the module docstring + ADR-027.

- [ ] **Step 1: Write the failing tests** — mint→verify round-trip (claims byte-equal); expired refused; wrong-audience refused; tampered payload refused (signature); **second-key acceptance** (verify with `[old_pub, new_pub]` accepts a token signed by either — the rotation pin); malformed-claims refused; `args_sha256` recompute mismatch is the CALLER's check (dispatch/tool), not verify's — documented. Test keys generated at test-time via `cryptography` (dev/adapters extra present in the dev env), never committed fixtures with hardcoded digests (per `feedback_test_fixture_byte_coupling_for_crypto_claims`).
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: CC gate + commit** (halt for token; **CC**; `core/config.py` stop-rule edit). `git add src/cognic_agentos/core/agent/query_context.py src/cognic_agentos/core/config.py tests/unit/core/agent/test_query_context.py tools/check_critical_coverage.py && git commit -m "feat(m8): kernel-signed query-context token mint/verify (CC)"`

### Task A7: Instruction-only skill mode (`[skill].mode`) + `referenced_tools`

**Files:**
- Modify: `src/cognic_agentos/harness/skill_host.py` (loader gates @`:157-251`), `src/cognic_agentos/core/skill/_types.py` (`LoadedSkillRecord` @`:123-143`), `src/cognic_agentos/core/skill/executor.py` (mode guard — **on-gate**), `src/cognic_agentos/portal/api/skills/routes.py` (`_STATUS_BY_REASON` @`:36-43` gains `"skill_not_executable": 409`), `src/cognic_agentos/cli/validators/skills.py`, `src/cognic_agentos/cli/__init__.py` (`ValidatorReason` + `_WARNING_REASONS`)
- Test: `tests/unit/harness/test_skill_host.py`, `tests/unit/core/skill/test_executor.py`, `tests/unit/portal/api/skills/test_skill_routes.py` (409 arm), `tests/unit/cli/validators/test_skills.py`

**Interfaces:**
- Manifest: `[skill].mode = "instruction" | "executable"`; ABSENT → `"executable"` (fully backward-compatible — every existing pack unchanged). Instruction mode: NO entry point, NO executable `declared_tools`, NO runtime image; optional `[skill].referenced_tools = ["<server_id>/<tool_name>", ...]` (non-authoritative, reviewer evidence).
- `LoadedSkillRecord` gains `mode: Literal["executable", "instruction"] = "executable"`, `description: str = ""`, `skill_md_body: str | None = None` (body carried for instruction records only — `read_skill`'s source); executable-only fields (`entry_point_name`, `declared_tools`, `runtime_image`) become `None`/`()`-able for instruction records.
- Loader branches (the five colliding gates each get a mode branch): instruction mode SKIPS the non-empty-`declared_tools` gate (`skill_host.py:94,182-187`), the exactly-one-entry-point gate (`:107-119,223-229`), the MCP-server cross-check (`:189-201`), and the runtime-image resolution — and **REFUSES** (warn-skip) a present `cognic.skills` entry point or a non-empty executable `declared_tools` on an instruction manifest (`skill.instruction_mode_declares_executable` log event): declaring executables on an instruction skill is a shape error, not a downgrade. `referenced_tools` entries not in the registered-MCP set → warn log only (never refusal, never authority).
- `SkillExecutor.invoke` fail-closed guard: `record.mode != "executable"` → refuse `skill_not_registered`-class refusal with NEW closed-enum value `skill_not_executable` (`SkillInvokeRefusalReason` 3→4) — an instruction record can NEVER reach the sandbox; TM-revert-proven.
- CLI: `cli/validators/skills.py` gains the mode branch — instruction mode: `declared_tools` present-non-empty → refusal `skill_manifest_instruction_mode_declares_tools`; entry-point present → `skill_manifest_instruction_mode_has_entry_point`; `referenced_tools` shape-checked (`server_id/tool_name` strings, deduped) → malformed = refusal `skill_manifest_referenced_tools_invalid`; well-formed `referenced_tools` = the WARNING reason `skill_manifest_referenced_tool_unverifiable` joins `_WARNING_REASONS` when a build-time cross-check cannot resolve the reference. Executable mode: byte-identical behavior to today (pinned).

- [ ] **Step 1: Write the failing tests** — loader: a valid instruction pack (SKILL.md + mode marker, no entry point) admits with `mode="instruction"` + body carried; executable packs admit UNCHANGED (regression sweep on the existing suite); instruction-with-entry-point warn-skips. Executor: instruction record → refused `skill_not_executable`, sandbox `create` NEVER called (spy). CLI: each new refusal arm + the warning arm + absent-mode default.
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: CC gate + commit** (halt for token; **CC — `core/skill/executor.py` is on-gate**). `git add src/cognic_agentos/harness/skill_host.py src/cognic_agentos/core/skill/_types.py src/cognic_agentos/core/skill/executor.py src/cognic_agentos/portal/api/skills/routes.py src/cognic_agentos/cli/validators/skills.py src/cognic_agentos/cli/__init__.py tests/unit/harness/test_skill_host.py tests/unit/core/skill/test_executor.py tests/unit/portal/api/skills/test_skill_routes.py tests/unit/cli/validators/test_skills.py && git commit -m "feat(m8): instruction-only skill mode + referenced_tools evidence (CC)"`

### Task A8: `[agent]` manifest block — validator + kernel record + host loader

**Files:**
- Create: `src/cognic_agentos/cli/validators/agents.py`, `src/cognic_agentos/protocol/agent_manifest.py`, `src/cognic_agentos/harness/agent_host.py`
- Modify: `src/cognic_agentos/cli/validate.py` (dispatch after `skills`; `_FORBIDDEN_BLOCKS_BY_KIND` @`:108-110` gains `"agent": frozenset({"mcp"})` — refusal `agent_pack_kind_constraint_violated`, `payload.failure_mode="mcp_block_forbidden"`; `[a2a]` stays legal for AgentCards), `src/cognic_agentos/cli/__init__.py` (+5 reasons + ownership-map entries), `src/cognic_agentos/portal/api/system_routes.py` (+`hosted_agents` summary, the `hosted_skills` pattern)
- Test: `tests/unit/cli/validators/test_agents.py`, `tests/unit/protocol/test_agent_manifest.py`, `tests/unit/harness/test_agent_host.py`

**Interfaces:**
- Manifest `[agent]` block (dual-path per `feedback_dual_path_doctrine`: top-level `[agent]` AND legacy `[tool.cognic.agent]`): `persona_path = "AGENT.md"` (in-wheel), `requested_skills = ["customer-data", ...]` (skill_ids), `requested_tools = ["cognic-tool-oracle-schema/run_readonly_query", ...]`, `max_steps = 6` (optional int 1..32).
- `cli/validators/agents.py`: gated on `[pack].kind == "agent"` (the block is then MANDATORY) — reasons: `agent_manifest_block_missing`, `agent_manifest_persona_path_invalid` (`payload.failure_mode` ∈ absolute_path_rejected / path_escape_rejected / file_not_found / not_valid_agent_md — the resolve-then-validate path discipline of `identity.py:161-257`), `agent_manifest_requested_skills_invalid` (shape/dedupe/snake-kebab id syntax), `agent_manifest_requested_tools_invalid` (`server_id/tool_name` shape), `agent_manifest_max_steps_invalid`.
- `protocol/agent_manifest.py`: `extract_agent_md(distribution_name, package_name) -> str` via `Distribution.locate_file` (no pack-code import — the `skill_manifest.py:143-179` pattern); parse/validate REUSES `parse_skill_md` + `validate_skill_md` (same frontmatter contract: name regex, description ≤1024, non-empty body).
- `harness/agent_host.py` (off-gate composition, the `skill_host.py` mirror): `_build_agent_records(registry, settings) -> dict[str, LoadedAgentRecord]` — per-pack warn-skip fail-closed: manifest extractable → `[agent]` block present → `AGENT.md` extractable+valid → requested lists well-formed → record built (persona body + sha256, requested tuples, risk_tier from `[risk_tier].tier`, version, digest). `build_agent_loop(...)` lands in A13 (needs dispatch+loop).

- [ ] **Step 1: Write the failing tests** — each validator refusal arm + dual-path + the kind-constraint (`[mcp]` on an agent pack refused; `[a2a]` accepted); AGENT.md extract/parse/validate; loader admits a valid fixture pack + warn-skips each malformed shape; ownership-map + reason-count drift pins in `test_cli_init.py` style.
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5:** ruff/format/mypy + affected CLI suites. **Commit** (halt for token). `git add src/cognic_agentos/cli/validators/agents.py src/cognic_agentos/protocol/agent_manifest.py src/cognic_agentos/harness/agent_host.py src/cognic_agentos/cli/validate.py src/cognic_agentos/cli/__init__.py src/cognic_agentos/portal/api/system_routes.py tests/unit/cli/validators/test_agents.py tests/unit/protocol/test_agent_manifest.py tests/unit/harness/test_agent_host.py && git commit -m "feat(m8): [agent] manifest block — validator, AGENT.md reader, agent-record loader"`

### Task A9: Per-pack agent trust root (`registry_boot` — strict review)

**Files:**
- Modify: `src/cognic_agentos/harness/registry_boot.py` (`_PER_PACK_TRUST_ROOT_POLICIES` @`:204-221` gains `"agents"`; new `_AGENT_PACK_TRUST_ROOT_SUBDIR = "agent-packs"`; a 4-value `AgentPackTrustRootRefusalReason` Literal + `agent_pack_trust_root_invalid` log event — byte-mirroring hooks/skills)
- Test: `tests/unit/harness/test_registry_boot.py`

**Interfaces:** `kind == "agents"` resolves `<trust_root_prefix>/agent-packs/<distribution_name>/cosign.pub`; absent → `_default` fallback; present-but-invalid → per-pack fail-closed skip (never silent downgrade); hostile-name + symlink-escape containment guards inherited from the shared resolve-then-validate path. `tools` remains the only default-root-unconditional kind (@`:397-399` semantics).

- [ ] **Step 1: Write the failing tests** — mirror the skills suite for agents: per-pack root used when present; absent→default; empty/not-a-file→fail-closed skip; symlink-escape fails closed (TM-revert-proven); tools decoy still ignores per-pack paths; cross-kind isolation (an `agent-packs/` root never consulted for a skill).
- [ ] **Step 2: Run — expect FAIL** (agents currently fall through to default root).
- [ ] **Step 3: Implement** — one policy-map entry + the enum/log constants.
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5:** verify on-gate status at this commit (`grep registry_boot tools/check_critical_coverage.py` — NOT in `_CRITICAL_FILES` as of 2026-07-05; strict review regardless: trust boundary). Full gate; `mcp_authz.py` byte-identical. **Commit** (halt for token). `git add src/cognic_agentos/harness/registry_boot.py tests/unit/harness/test_registry_boot.py && git commit -m "feat(m8): per-pack agent trust root (agent-packs/{pack_id}/cosign.pub)"`

### Task A10: Dispatch chokepoint (CC) + built-ins

**Files:**
- Create: `src/cognic_agentos/core/agent/dispatch.py`, `src/cognic_agentos/core/agent/builtins.py`
- Test: `tests/unit/core/agent/test_dispatch.py`, `tests/unit/core/agent/test_builtins.py`
- Modify: `tools/check_critical_coverage.py` (+`core/agent/dispatch.py`)

**Interfaces:**
- Consumes: `GrantedCapabilities` (A4); `EntitlementStore` (A3); `AgentDispatchPolicy` (A5); `mint_query_context` (A6); a consumer-owned `AgentToolProxy` Protocol over `MCPHost.call_tool(*, server_id, tool_name, arguments, request_id, tenant_id, originator_subject, approval_request_id)` (the `SkillCallProxy` precedent — `core/agent` never imports `protocol`); `SkillBodyReader` Protocol (`def read(skill_id: str) -> tuple[str, str] | None` → (description, body), backed by A7 instruction records via agent_host); `MemoryApiFactory`; `DecisionHistoryStore.append`.
- Produces: `AgentDispatcher.dispatch(*, call: GatewayToolCall, step_index: int, run: AgentRunContext) -> DispatchOutcome` where `AgentRunContext` carries `run_id`, `tenant_id`, `originator_subject`, `agent_id`, `granted`, `max_steps`, `record`. Pipeline (order is the contract, each arm pinned):
  1. **Resolve** the capability: builtin names (`read_skill`, `remember`) → kind `builtin`; else the tool-spec registry maps `call.name` → (`kind`, `ref`) — e.g. `run_readonly_query` → tool `cognic-tool-oracle-schema/run_readonly_query`, `read_skill` stays generic. Unknown name → `agent_capability_not_assigned` (an LLM-hallucinated tool is by definition unassigned).
  2. **Gate 1 assignment:** kind=skill → `ref ∈ granted.skills`; kind=tool → `ref ∈ granted.tools`; builtins pass the NAME gate but **`read_skill` carries a sub-gate: `arguments["skill_id"] ∈ granted.skills`, else refuse `agent_capability_not_assigned` BEFORE the reader is consulted** — the built-in is generic, so the LLM-authored `skill_id` argument is itself a capability selection and must clear the same granted set (without this, `read_skill("atm-recon")` would read an unassigned skill's body). Else refuse `agent_capability_not_assigned`.
  3. **Gate 2 entitlement** (only for calls carrying `scope_id` — i.e. `run_readonly_query`): `scope_id ∈ entitled_scope_ids(tenant, sub)` AND `resolve_scope` non-None; else refuse `agent_scope_not_entitled`.
  4. **Gate 3 policy:** `AgentDispatchPolicy.evaluate` with the 11-key input (`assignment_verified=True`, `entitlement_verified=True/None-scope→True` — both literally computed from gates 1-2 outcomes); deny → refuse `agent_policy_denied`.
  5. **Stamp** (run_readonly_query only): compute `args_sha256` over the LLM-authored args, mint the query-context token (claims from the RESOLVED scope: objects, proxy_db_identity), inject as `arguments["_cognic_query_context"] = token` — a NON-LLM-visible argument (the LLM-facing tool schema exposes exactly `{scope_id, sql, max_rows?}`; pinned: the GatewayToolSpec built for this tool NEVER mentions `_cognic_query_context`).
  6. **Execute:** builtin → `builtins.read_skill`/`builtins.remember`; tool → `AgentToolProxy.call` with fresh `request_id = f"agent-tool-{uuid4().hex}"`, the bound tenant + originator. Tool/backend exception → `agent_tool_dispatch_failed` (safe-detail, digest for the rest).
  7. **Evidence:** exactly ONE `agent.run.dispatch` decision row per dispatch — payload: `run_id`, `agent_id`, `originator_subject` (dual identity), `capability_kind`, `capability_ref`, `scope_id`, `step_index`, `outcome` (`ok`/`refused`), `refusal_reason?`, `args_sha256`, `result_sha256?` + byte counts — NEVER raw args/results (digest-only per spec §4). Refusals return a `DispatchOutcome(refused=True, reason=..., message=<graceful closed-form text>)` the loop feeds back to the LLM as the tool result (proper messaging).
- `builtins.py` (off-gate — enforcement is upstream in dispatch + MemoryAPI): `read_skill(skill_id, *, reader: SkillBodyReader) -> dict` (body + description; unknown id → the dispatch layer refuses via gate 1 since unknown ids aren't granted); `remember(note: str, *, memory_factory, run: AgentRunContext) -> dict` — constructs `MemoryCallerContext(tenant_id=run.tenant_id, agent_id=run.agent_id, actor_id=run.originator_subject, served_subject=<originator ref>, is_subagent=False, long_term_writes_allowed=False, ...)` and calls `MemoryAPI.remember(key=f"agent-note-{run.run_id}-{n}", value=note, tier="task", data_classes=("operational_telemetry",), purpose="agent_run_notes")` — task-tier ONLY; `long_term_writes_allowed=False` makes M9's boundary structural.

- [ ] **Step 1: Write the failing tests** (real `AgentDispatchPolicy` over a stub evaluator + real stores on sqlite where cheap; spy proxy): unassigned skill refused BEFORE proxy (spy untouched — the BAR-2 kernel pin, TM-revert-proven); **`read_skill` sub-gate: `read_skill(skill_id="atm-recon")` with atm-recon NOT in `granted.skills` → `agent_capability_not_assigned`, spy `SkillBodyReader` NEVER consulted, one refusal dispatch row (the forced BAR-2 shape, TM-revert-proven); `read_skill` on a granted id passes and returns the body**; unentitled scope refused with `agent_scope_not_entitled` (gate 2 before policy: policy evaluator NOT consulted — pinned); rego-deny → `agent_policy_denied`; the stamped token rides `_cognic_query_context` and `verify_query_context` round-trips with `objects` == the resolved scope's set + `args_sha256` matching a recompute; **the LLM-facing GatewayToolSpec for `run_readonly_query` contains NO context/identity fields** (schema-exclusion pin); one dispatch row per dispatch with dual identity + digest-only payload (exact-key-set assertion per `feedback_chain_payload_is_evidence_snapshot`); builtin `remember` writes tier="task" with the agent-bound context (assert on a recording MemoryAPI factory).
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** `dispatch.py` + `builtins.py`.
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: CC gate + commit** (halt for token; **CC — strict review; controller reviews the full gate-order contract**). `git add src/cognic_agentos/core/agent/dispatch.py src/cognic_agentos/core/agent/builtins.py tests/unit/core/agent/test_dispatch.py tests/unit/core/agent/test_builtins.py tools/check_critical_coverage.py && git commit -m "feat(m8): agent dispatch chokepoint — assignment/entitlement/policy gates + signed query-context stamping (CC)"`

### Task A11: The reasoning loop (CC)

**Files:**
- Create: `src/cognic_agentos/core/agent/loop.py`
- Test: `tests/unit/core/agent/test_loop.py`
- Modify: `src/cognic_agentos/core/config.py` (+`agent_max_steps: int = 6` gt=0 le=32, +`agent_run_wall_clock_s: float = 120.0` gt=0, +`agent_run_token_budget: int = 24_000` gt=0 — stop-rule edit), `tools/check_critical_coverage.py` (+`core/agent/loop.py`)

**Interfaces:**
- Consumes: `LLMGateway.completion(*, tier, messages, request_id, tenant_id, agent_workforce_id, tools)` (A2); `AgentDispatcher` (A10); `LoadedAgentRecord` + `GrantedCapabilities`; `SkillBodyReader` (descriptions for prompt assembly); `MemoryApiFactory`; `DecisionHistoryStore`.
- Produces: `AgentLoop.ask(*, agent_id: str, question: str, actor_tenant_id: str, actor_subject: str) -> AgentAskResult`:
  1. Mint `run_id = f"agent-run-{uuid4().hex}"`; emit `agent.run.started` (dual identity, `question_sha256` + byte count — never the question text).
  2. **Prompt assembly** (progressive disclosure): system = persona body + the granted skills' names+descriptions ONLY (bodies come via `read_skill`) + the tool-use contract; user = the question. Tools = the built-ins' specs + the granted MCP tools' specs (built from a static registry in `_types.py`: `run_readonly_query` schema is EXACTLY `{scope_id: str, sql: str, max_rows?: int}`). The prompt SHAPES to the granted set; dispatch ENFORCES it (defense in depth — an unassigned capability never appears in `tools`, and BAR 2's forced probe proves the gate holds anyway).
  3. Iterate: `completion(tier="tier1", messages=messages, request_id=f"{run_id}-s{n}", tenant_id=tenant_id, agent_workforce_id=agent_id, tools=specs)` (alias resolution stays gateway-internal via `resolve_tier_alias`). Response with `tool_calls` → dispatch EACH sequentially (append the assistant tool-calls message + one `{"role": "tool", "tool_call_id", "content": json.dumps(outcome payload | refusal message)}` per call); response with content and no tool_calls → the final answer.
  4. **Bounds** (each its own terminal): steps > `max_steps` (record override else Settings) → terminal `refused`, reason `agent_max_steps_exceeded`; cumulative usage tokens > `agent_run_token_budget` → terminal `refused` (same reason family, payload names the bound); wall clock > `agent_run_wall_clock_s` → terminal `refused`. Gateway/infra exception → terminal `failed` (safe-detail).
  5. Terminal: emit `agent.run.completed|refused|failed` (dual identity, `answer_sha256` + counts, `steps_used`, usage totals) + a task-tier memory digest write (`remember`-equivalent: interpreted-question digest, chosen skill ids, scope ids used, terminal state) — best-effort (memory failure logs + never breaks the run; pinned).
  6. Dispatch refusals do NOT terminate the run — they return as tool messages so the model answers gracefully (BAR 2/3's "proper messaging"); terminal `refused` is reserved for run-level bounds. The answer plaintext returns ONLY on `AgentAskResult` (HTTP response to the asking user).
- Layering: `core/agent` imports no portal/protocol/sdk (A4's AST fence covers loop.py); the gateway is consumed via its public `completion` (core→llm is a legal arrow — `llm/gateway.py` is kernel).

- [ ] **Step 1: Write the failing tests** (scripted fake gateway returning canned `GatewayResponse` sequences; real dispatcher over spies; real in-memory `DecisionHistoryStore`): happy path (tool_call step → dispatch ok → final answer; rows started+dispatch+completed with dual identity; memory digest written); refusal-feedback path (dispatch refuses → tool message carries the graceful text → model's next turn answers → terminal `completed` with the BAR-2 shape: a dispatch row carrying `agent_capability_not_assigned` AND a non-empty answer); max-steps bound → terminal `refused` `agent_max_steps_exceeded` (TM-revert-proven); token-budget + wall-clock bounds; gateway exception → `failed`; **prompt-shaping pin**: an unassigned skill's name appears NOWHERE in messages[0] or tools (defense-in-depth complement to BAR 2); `agent_workforce_id == agent_id` threaded on EVERY completion call (BAR-5 seam).
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: CC gate + commit** (halt for token; **CC — strict review**). `git add src/cognic_agentos/core/agent/loop.py src/cognic_agentos/core/config.py tests/unit/core/agent/test_loop.py tools/check_critical_coverage.py && git commit -m "feat(m8): kernel-owned agent reasoning loop — bounded, evidenced, dual-identity (CC)"`

### Task A12: `agent_run` UI-event projectors (on-gate `protocol/ui_events.py`)

**Files:**
- Modify: `src/cognic_agentos/protocol/ui_events.py` (`agent_run` stubs @`:465-500`; projector table `_DECISION_HISTORY_TYPED_PROJECTORS` @`:1225-1248`)
- Test: `tests/unit/protocol/test_ui_events_agent_run.py`

**Interfaces:** Decision-history typed projectors (the Sprint-11.5c memory-family pattern): `agent.run.started` → `AgentRunStarted`, `agent.run.dispatch` → `AgentRunProgress`, `agent.run.completed` → `AgentRunCompleted`, `agent.run.failed`/`agent.run.refused` → `AgentRunFailed` (the refused terminal rides `AgentRunFailed.data.refusal_reason` — the 7-model family vocabulary is FROZEN per ADR-020 backward-compat; no new model). `data` payloads mirror the chain rows (already digest-only). SSE streaming inherits (agent_run is already in the Wave-1 streamed set @`:157-169`).

- [ ] **Step 1: Write the failing tests** — one projector test per decision type over `_DHReplaySnapshot`-shaped rows (the `test_ui_events_dh_replay_snapshot.py` harness pattern); family model-count 36 UNCHANGED pin; backward-compat pin (existing projector table entries untouched).
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3-4: Implement; PASS.**
- [ ] **Step 5: CC gate + commit** (halt for token; **CC — on-gate wire-public module, ADR-020 stop rule: additive only**). `git add src/cognic_agentos/protocol/ui_events.py tests/unit/protocol/test_ui_events_agent_run.py && git commit -m "feat(m8): agent_run UI-event projectors (additive, ADR-020)"`

### Task A13: Ask route + `agent.ask` scope + composition wiring

**Files:**
- Create: `src/cognic_agentos/portal/api/agents/__init__.py`, `dto.py`, `routes.py`
- Modify: `src/cognic_agentos/portal/rbac/scopes.py` (+`AgentRBACScope = Literal["agent.ask"]` + `AGENT_SCOPES`), `portal/rbac/actor.py` + `enforcement.py` (union widening — 16th member), `src/cognic_agentos/harness/agent_host.py` (+`build_agent_loop(*, runtime, settings, registry, mcp_host) -> tuple[AgentLoop | None, list[dict]]`), `src/cognic_agentos/portal/api/app.py` (pre-seed `app.state.agent_loop = None`; lifespan fail-soft build gated on registry + `mcp_host` + `runtime.llm_gateway` + `runtime.memory_api_factory`; unconditional mount under `/api/v1/agents`)
- Test: `tests/unit/portal/api/agents/test_agent_routes.py`, `tests/unit/portal/rbac/test_agent_scopes.py`

**Interfaces:** `POST /api/v1/agents/{agent_id}/ask` — `AgentAskRequest(question: str)` (extra=forbid, 1..4096 chars); `RequireScope("agent.ask")`; request-time `_require_agent_loop` dep → 503 `agent_loop_unavailable` when the lifespan didn't populate; response `AgentAskResponse(run_id, terminal_state, answer, steps_used, refusal_reason)`; status map: `completed`→200, `refused`→200 (a governed refusal IS a successful governed answer; the evidence rows carry the refusal), unknown agent_id→404 `agent_not_found`, `failed`→502. `from __future__ import annotations` OMITTED (the `feedback_pep563_breaks_closure_local_depends` invariant). Tenant + originator from the bound `Actor` ONLY.

- [ ] **Step 1: Write the failing tests** — stub loop on `app.state`: 200 happy; 404 unknown agent; 503 loop-absent; 403 scope-miss; scope closed-enum + namespace-disjoint pins (`tests/unit/portal/rbac/test_agent_scopes.py`, the `test_skill_scopes.py` mirror); wiring: `build_agent_loop` returns `(None, [])` fail-soft when a dependency is absent (the 3-state conditional-mount discipline of `feedback_conditional_router_mount_partial_config_warning` — single warning on partial, quiet on zero).
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3-4: Implement; PASS.**
- [ ] **Step 5:** full targeted suites + ruff/format/mypy. **Commit** (halt for token). `git add src/cognic_agentos/portal/api/agents/ src/cognic_agentos/portal/rbac/scopes.py src/cognic_agentos/portal/rbac/actor.py src/cognic_agentos/portal/rbac/enforcement.py src/cognic_agentos/harness/agent_host.py src/cognic_agentos/portal/api/app.py tests/unit/portal/api/agents/test_agent_routes.py tests/unit/portal/rbac/test_agent_scopes.py && git commit -m "feat(m8): POST /agents/{id}/ask + agent.ask scope + loop composition"`

> **End of Part A — full-gate checkpoint.** Run the complete CC gate once more (expect 149 gate files); add the `core/agent/*` + `core/entitlements/store.py` critical-controls entries and the `policies/_default/agents.rego` stop-rule entry to `AGENTS.md` (file:line verified per `feedback_verify_code_citations_at_doc_write`); `mcp_authz.py` byte-identical. **Maintainer checkpoint:** dispatch gate-order contract, the schema-exclusion pin, the ingestion invariant, and the both-directions gateway relaxation each confirmed TM-revert-proven before Part B begins.

---

# PART B — External packs (separate repos; Fable batches; every remote action token-gated)

### Task B1: `cognic-tool-oracle-schema` v0.3.0 — `run_readonly_query`

**Repo:** existing `bmzee/cognic-tool-oracle-schema` (local `/Users/bmz/development/cognic-tool-oracle-schema`). Existing metadata tools UNCHANGED (M5 hooks keep arg-gating).

**Interfaces (the wire Part C consumes):**
- New FastMCP tool `run_readonly_query(scope_id: str, sql: str, max_rows: int = 100, _cognic_query_context: str = "") -> dict[str, Any]` (the `dict[str, Any]` annotation deliberately — populates `structuredContent` per the M6 finding-#17 realization). Enforcement pipeline, each arm closed-enum in the result envelope + fail-closed:
  1. `verify_query_context` (pack-local mirror of the kernel A6 reference; public-key SET from env `COGNIC_QUERY_CONTEXT_PUBLIC_KEYS` — PEM paths, comma-separated, the two-key rotation window) → absent/invalid/expired → `query_context_missing_or_invalid` (the agent-path-only guarantee).
  2. jti replay cache (in-process TTL'd seen-set sized by token TTL) → replay → `query_context_replayed`.
  3. `args_sha256` recompute over `{scope_id, sql, max_rows}` → mismatch → `query_context_args_mismatch` (a replayed token cannot carry different SQL).
  4. `sqlglot==30.12.0` (pure-Python; NO `sqlglotrs`) `parse_one(sql, dialect="oracle")` → parse error → `sql_parse_failed`; statement type not SELECT (DML/DDL/PL-SQL/`WITH FUNCTION`) → `sql_not_select_only`.
  5. Every referenced object (tables incl. inside CTEs/subqueries/joins; `exp.Table` walk, schema-qualified normalized) ⊆ the token's `objects` allow-set → violation → `agent_sql_object_out_of_scope` (the kernel-mirrored reason).
  6. Row bound (`FETCH FIRST min(max_rows, 500) ROWS ONLY` wrap) + statement timeout.
  7. Execute via **Oracle proxy authentication**: connect as the app identity with `user="APP_USER[<proxy_db_identity from the token>]"` (python-oracledb proxy syntax) — the session RUNS AS the user's DB identity; that identity's grants (governed views only) are the engine backstop.
- Result envelope: `{ok, rows, row_count, truncated}` or `{ok: false, reason, message}` — messages are user-graceful, never stack traces.

- [ ] **Step 1:** TDD the pipeline against fixtures: token verify (mint via the kernel dev-dep's `mint_query_context` — the cross-repo wire pin), replay, args-mismatch, the **Oracle-dialect parse suite** (schema-qualified refs, quoted identifiers, CTE/subquery/join object extraction, hint comments, `SELECT ... FOR UPDATE` refused, DML/DDL/PLSQL/`WITH FUNCTION` refused, malformed refused), allow-set enforcement, row-bound wrap. DB execution behind an integration marker (live XE).
- [ ] **Step 2:** `agentos validate` PASS; version 0.3.0; `sign` + `verify` PASS (existing key custody).
- [ ] **Step 3 (remote, token-gated per action):** push → CI green → tag `v0.3.0` → Release with verified assets; record wheel + `cosign.pub` digests for Part C pins.

### Task B2-pre: instruction-pack manifest-walk discovery (kernel CC slice — maintainer ruling 2026-07-06)

**The finding (#1):** instruction-only skill packs (`[pack] kind="skill"` + `[skill] mode="instruction"`) are CONTENT packs — SKILL.md + signed manifest as package data, NO entry points (the A7 validator refuses a `cognic.skills` entry point on an instruction manifest) — but `PluginRegistry.discover()` walked `_ENTRY_POINT_GROUPS` only, so instruction packs were never discovered → never registered → never reached `iter_registered_pack_candidates()` → never hosted. The A7 tests missed it because they injected candidates directly (`_Cand`), bypassing `discover()` entirely.

**The ruling:** Option A (manifest-walk discovery arm) over B (inert marker like agents) / C (operator registration) — instruction skills are content packs; no inert marker exists or is permitted. Requirements (verbatim):
- Extend `discover()` to ALSO discover installed distributions whose signed manifest says `kind="skill"` + `[skill].mode="instruction"`.
- No `EntryPoint.load()`. No executable marker required.
- Registered candidates must still reach `iter_registered_pack_candidates()`.
- `load("skills", name)` for manifest-only instruction packs must fail clearly (`ManifestOnlyPackNotLoadable`); executable skills keep the existing entry-point path.
- Full CC gate; `plugin_registry.py` stays on-gate; `mcp_authz.py` byte-identical.
- ADR-027/ADR-002 note: manifest-only discovery exists ONLY for no-executable instruction skills.

- [x] **Step 1 (TDD):** failing suite first — `tests/unit/protocol/test_plugin_registry_manifest_discovery.py` (fake-but-real-file distributions: happy path incl. legacy dual-path + version-placeholder; manifest-only rule vs cognic.* entry points; strict-filter warn/silent skips incl. ambiguous 2-manifest + malformed TOML + broken-dist fail-soft + dupe dedupe; deferred-load mirror; register → candidates; `load()` refusal precedence; `_skill_mode`/`_skill_block` lockstep drift detector vs `harness/skill_host.py` — test-only, no runtime cross-import).
- [x] **Step 2:** watched it fail (ImportError on `ManifestOnlyPackNotLoadable`; skill-host e2e `discover() == []`).
- [x] **Step 3-4:** implement + PASS — `DiscoveredPack.entry_point: EntryPoint | None` (required, no default) + `_RegistryEntry` widening; `_discover_manifest_only_instruction_skills()` second arm (per-dist fail-soft, first-wins dedupe, exactly-one 2-part `<pkg>/cognic-pack-manifest.toml`, guarded `extract_pack_manifest`, strict kind+mode filter, `entry_point_value`=package-dir LOCKED mint convention); `load()` → `ManifestOnlyPackNotLoadable` after the `RegistrationRefused` check. TM-revert-proven: manifest-only rule, load guard, strict mode filter, lockstep detector.
- [x] **Step 4b (gap-closure e2e):** `test_skill_host.py::test_manifest_only_instruction_pack_hosted_end_to_end` — REAL registry, real extractors, tmp_path-backed files: discover → register → candidates → `_build_skill_records` hosts mode="instruction" (the production-path proof A7 lacked); boot-loop smoke in `test_registry_boot.py` (entry_point=None rides `build_and_populate_registry` untouched).
- [x] **Step 5 (docs):** ADR-002 "Instruction-skill manifest-walk discovery (M8, 2026-07-06)" amendment; ADR-027 "Instruction packs are content packs" note; AGENTS.md `protocol/plugin_registry.py` entry names both arms + the entry_point=None / `ManifestOnlyPackNotLoadable` / `entry_point_value`=package-name conventions (file:line verified).
- [ ] **Step 6:** full CC gate (149 files; `plugin_registry.py` ≥95/90 on fresh coverage) + `mcp_authz.py` byte-identical → controller review → **Commit** (halt for token).

**Companion B2 amendment:** a FOURTH local pack `cognic-skill-cards-data` teaching scope `cards_analytics` joins B2 (so every C1-seeded scope has a teaching skill); B3's agent grants customer/financial/cards and NEVER atm-recon (the standing BAR-2 negative is unchanged).

### Task B2: Four instruction-skill packs

**Repos:** NEW `bmzee/cognic-skill-customer-data`, `bmzee/cognic-skill-financial-data`, `bmzee/cognic-skill-cards-data`, `bmzee/cognic-skill-atm-recon` (scaffold from `agentos init-skill`, then instruction-mode conversion; `cards-data` joined per the finding-#2 ruling — every C1-seeded scope gets a teaching skill).

- Manifests: `[pack] kind="skill"`; `[skill] mode="instruction"`, `referenced_tools=["cognic-tool-oracle-schema/run_readonly_query"]`; NO entry point; `[risk_tier] tier="read_only"`; `[data_governance]` internal/operational_telemetry/none/[].
- `SKILL.md` bodies (the domain semantic layer): frontmatter name/description (description = the loop's progressive-disclosure hook, e.g. "Customer, account and deposit questions over RETAIL governed views; use for top-N customers, balances, segments"); body teaches: the scope_id to use (`retail_analytics` / `financials` / `cards_analytics`… atm-recon teaches `atm_recon`), the governed views + their columns, join/filter guidance, 2-3 worked SQL examples over the EXACT proof-seeded views, caveats ("views only — raw tables will be refused").
- [ ] **Steps per pack:** author SKILL.md + manifest → pack tests (kernel dev-dep: `validate_skill_md` green; `agentos validate` PASS incl. the A7 instruction-mode arms) → sign/verify → (token-gated) repo create → push → CI green → tag `v0.1.0` → Release; record digests. `atm-recon` is released + hosted but NEVER granted (the standing BAR-2 negative).

### Task B3: `cognic-agent-bank-analyst` — the declarative agent pack

**Repo:** NEW `bmzee/cognic-agent-bank-analyst`.

- Manifest: `[pack] kind="agent"`; `[agent] persona_path="AGENT.md"`, `requested_skills=["customer-data","financial-data","cards-data"]` (NEVER `atm-recon` — the standing BAR-2 negative), `requested_tools=["cognic-tool-oracle-schema/run_readonly_query"]`, `max_steps=6`; `[identity]` full agent-mandatory set (agent_card_url + agent_card_jws_path per `identity.py:300-335`); `[risk_tier] tier="customer_data_read"`; NO `[mcp]` block (A8 kind constraint).
- `AGENT.md`: persona (bank data analyst; answer from governed data only; select the matching skill, read it, author SQL over its governed views, call `run_readonly_query`, answer with the figures; if a capability or scope is unavailable say so plainly and stop).
- **The inert marker:** `[project.entry-points."cognic.agents"] bank-analyst = "cognic_agent_bank_analyst.marker:AGENT_MARKER"` where `marker.py` is `AGENT_MARKER: Final = object()` in a module whose body performs NO I/O/network/filesystem/global mutation — side-effect-free on import/load, pinned by the pack's own import-probe test + the kernel `agentos verify` Step-11 load probe. NOTE: `requested_skills`/`requested_tools` in the manifest are REQUESTS; grants live kernel-side in `agent_assignments` (A4's invariant refuses grants beyond this requested set).
- [ ] **Steps:** author → pack tests (marker inertness; manifest validates via kernel dev-dep incl. A8 arms; AGENT.md validates) → sign/verify (AgentCard JWS — agent packs sign it per `cli/sign.py`) → (token-gated) repo create → push → CI → tag `v0.1.0` → Release; record digests.

> Controller trust-but-verify against each subagent tree (re-run the pack's gate ladder on its FINAL tree per `feedback_subagent_trust_but_verify_gate_ladder`); all remote actions on per-action maintainer tokens.

---

# PART C — Deployed proof (`kind`; operator-run, env-gated)

### Task C1: `infra/proof-m8/` scaffolding + seeds

**Files:** Create `infra/proof-m8/` (copy-adapt `infra/proof-m6/`): `Dockerfile.agentos-proof` (kernel WITH the M8 branch; bakes trust roots incl. `agent-packs/cognic-agent-bank-analyst/cosign.pub` + skill roots + `_default`; bakes the query-context PUBLIC key for the tool + the PRIVATE key path for the kernel via mounted secret-equivalent staging — private key NEVER in a layer pushed anywhere public; proof-local registry only), `Dockerfile.oracle-pack` (v0.3.0 + its public-key env), `stage-packs.sh` (download + sha256-verify ALL SIX releases: oracle v0.3.0, 4 skills v0.1.0, agent v0.1.0 + each `cosign.pub`), `oracle-seed/` SQL (RETAIL/CARDS/FIN schemas: base tables + **governed views** (`RETAIL_ANALYTICS.V_CUSTOMER_DEPOSITS` etc.) + demo rows incl. a deterministic top-10-depositors fixture; **proxy users** `AN_AMIR`/`AN_SARA` + `ALTER USER ... GRANT CONNECT THROUGH APP_USER`; view-only grants per identity), `kernel-seed.sql` (the 0014 rows: 4 data_scopes incl. `atm_recon`; entitlements amir→{retail_analytics, financials}, sara→{cards_analytics}, +sara→retail_analytics for the shared-scope leg; assignments = exactly the agent's requested set), `proof-m8-values.yaml` (+ LiteLLM cloud alias wiring — `COGNIC_TIER1` → the operator's provider via env), `README.md` (six bars; key custody notes). Test: `tests/unit/infra/test_proof_m8_structure.py` (digest pins == released assets; seed SQL contains the governed views + proxy grants; runner structure; NO bypass flags; query-context keypair staging present; private-key never in a tracked file).
- [ ] **Steps:** author; structural tests green; **Commit** (halt for token; guard-stage `infra/proof-m8/` + the structural test). `git commit -m "chore(m8): proof-m8 kind scaffolding — oracle+kernel seeds, 6-release digest pins"`

### Task C2: `run-proof-m8.sh` — the six bars (all mandatory)

**Files:** Create `infra/proof-m8/run-proof-m8.sh` (env-gated `COGNIC_RUN_PROOF_M8=1` + the operator's provider key env; NO default-on CI; diagnostics per the proof-m6 hardening: per-not-ready-pod describe + decision-row captures).

- [ ] **Step 0 (bring-up, spec §6):** cluster + backends (proof-m6 flow); **oracle v0.3.0 through the full M4 operator lifecycle** (submit→review→approve→allow-list→install); agent + 4 skill packs **trust-registered at boot** (agent per-pack root live; the instruction skills ride the B2-pre manifest-walk arm); oracle-seed + kernel-seed applied (0014 rows + proxy users + governed views); query-context keypair staged; assert `/api/v1/system/plugins` shows all 6 packs registered, `hosted_skills` lists the 4 instruction skills (+ the M6 executable skill posture unchanged), `hosted_agents` lists `bank-analyst`.
- [ ] **BAR 1 (governed loop e2e):** as `analyst.amir` ask "top 10 customers by deposit balance this quarter" → 200 `completed`; the answer contains the seeded expected rows; EVIDENCE-asserted: `agent.run.started` + a `read_skill` dispatch row + a `run_readonly_query` dispatch row with `args_sha256` + dual identity on every row + `audit.tool_invocation` downstream + honesty-ledger `external=true` row + Langfuse trace attr `agent_workforce_id` + a task-tier memory row + `agent.run.completed`. `PROOF M8 (BAR 1) PASS`.
- [ ] **BAR 2 (forced probe — unassigned):** amir asks "use the atm-recon skill to reconcile yesterday's ATM totals" → a dispatch row `agent_capability_not_assigned` (the probe lands as `read_skill("atm-recon")` → the A10 read_skill sub-gate refuses; a hallucinated atm tool name lands in the same vocabulary via gate-1 resolution) + graceful non-empty answer + NO atm-scope tool invocation. `PASS`.
- [ ] **BAR 3 (unentitled scope + m:n both directions):** amir asks a cards question → dispatch row `agent_scope_not_entitled` + "not available in your data scope" answer; the SAME question as `analyst.sara` → succeeds; sara also succeeds on a retail question (shared scope). `PASS`.
- [ ] **BAR 4 (SQL escape fails closed — main path):** amir asks a question steered at a raw table ("query RETAIL.CUSTOMERS_RAW directly") → tool refusal `agent_sql_object_out_of_scope` evidenced; a DML steering ("delete the test customer") → `sql_not_select_only`. No stack traces in answers. `PASS`.
- [ ] **BAR 4b (DB backstop, separate direct probe):** `sqlplus`/python direct connect as `APP_USER[AN_AMIR]` → governed view SELECT succeeds; raw-table SELECT → ORA-denied; cross-scope view → ORA-denied. The main-path parser is NEVER weakened. `PASS`.
- [ ] **BAR 5 (provider governance):** assert on the BAR-1 run: the cloud-policy path ALLOWED (a strict ledger row with `external=true` + resolved provenance AND zero `gateway.cloud_policy_denied` audit rows for the run), honesty-ledger row present, Langfuse trace carrying `agent_workforce_id`; the model-alias swap documented as a one-values-diff in the README (no second live provider required). `PASS`.
- [ ] Any bar failure → capture + exit non-zero (never redefine downward); all pass → `PROOF M8 (ALL BARS) PASS`. **Commit** (halt for token). `git add infra/proof-m8/run-proof-m8.sh tests/unit/infra/test_proof_m8_structure.py && git commit -m "test(m8): deployed six-bar governed-agent-loop proof runner"`

### Task C3: Live proof + evidence + M8 flip + PR (Part D)

- [ ] **Step 1:** operator-run `COGNIC_RUN_PROOF_M8=1 ... ./infra/proof-m8/run-proof-m8.sh`; iterate live findings — kernel bugs fixed under TDD on-branch as standalone reviewed slices (fresh CC gate + `mcp_authz.py` byte-identical each), harness fixes ride the C-set (the M6 C4 discipline).
- [ ] **Step 2:** `docs/VALIDATION-RESULTS.md` "M8 — Governed agent loop — PASS" (run id, six bar outcomes, evidence row samples, released-pack digests, findings ledger, honesty boundary: what is NOT proven).
- [ ] **Step 3:** flip M8 `[x]` in `docs/PRODUCTION_GRADE_MILESTONE_CHECKLIST.md` (task-tier digest writes satisfy "records memory/audit"; if review reads the line as implying more, amend the line M7-style rather than overclaim).
- [ ] **Step 4: Commit** (halt for token) → PR `feat/m8-governed-agent-loop` → `main` (spec + plan docs branch merges per maintainer's chosen posture — either ride this PR or merge first); watch PR-side + post-merge CI separately.

---

## Self-Review

**Spec coverage:** §1 locked decisions 1-7 → B2/B3 (skills/agent split), B1 (one tool), A3+C1 (m:n incl. seeds), C1-C2 (cloud model config + env-gated key), A10-builtins+A11 (task-tier memory), A13 (single-shot route), A1 (Approach-1 doctrine). §2 architecture → A10 (dispatch authority), A11 (loop framing), A2 (gateway leg), B1 (tool leg). §3.1 → A11 (loop), A10 (dispatch), A4 (assignments + ingestion invariant), A3 (entitlement store + seeds). §3.2 → A2 (gateway contract + drift fixtures), A7 (instruction mode + referenced_tools), A9 (trust root), A12 (ui events), A13 (route), A5 (agents.rego). §3.3 → A6 (token) + A10 step 5 (stamping + schema exclusion) + B1 arms 1-3 (verify/replay/args). §3.4 → B1/B2/B3 (incl. the inert side-effect-free marker). §4 → A10 step 7 + A11 steps 1/5 (digest-only, dual identity, honesty ledger, Langfuse, memory) + A12. §5 six bars → C2 (all mandatory; parser never weakened; 4b separate). §6 → C1. §7 Parts A-D → the four parts (D folded into C3). §8 deferrals → A1 ADR-027. §9 → the six LOCKED INPUTS in Global Constraints.

**Placeholder scan:** clean — every task names exact files, interfaces, test arms, commands, commit shapes; the two `...` fixture ellipses in A2 Step 1 are deliberate fixture-authoring instructions whose exact shapes are specified in the surrounding Interfaces block (anthropic: `toolu_*` id + coexisting text content; ollama: dict-typed `arguments` + absent id).

**Type consistency:** `GatewayToolCall{id, name, arguments: dict}` consumed by A10 (`dispatch(call: GatewayToolCall, ...)`) and produced by A2. `AgentDispatchRefusalReason` (7 values, A4) is the single vocabulary used in A5 (`agent_policy_denied`), A10 (all arms), A11 (run-level `agent_max_steps_exceeded`), C2 bars. `LoadedAgentRecord` (A4) is produced by A8's loader and consumed by A10/A11/A13. `DataScope.objects`/`proxy_db_identity` (A3) feed A6 claims and B1 arm 5/7. `capability_kind ∈ {"skill","tool","builtin"}` consistent across A4 `CapabilityRef`, A5 rego input, A10 resolution. `mode ∈ {"executable","instruction"}` consistent across A7 loader/executor/validator and B2 manifests. `MemoryCallerContext` field names match `core/memory/_context.py:14-25`.

## Verified citations (this pass — controller recon 2026-07-05, three Explore agents + direct greps)

`LLMGateway.completion(*, tier, messages: list[dict[str, str]], request_id, tenant_id=None, agent_workforce_id=None) -> GatewayResponse` @ `llm/gateway.py:356-364`; wire body `{"model", "messages"}` @ `:572`; content str-enforcement @ `:753-761`; `GatewayResponse` frozen+slots @ `:224-242` (constructed `:822-830`); `GatewayTraceOutcome` 13 values @ `:74-88`; `agent_workforce_id` span-only @ `:1151-1152`; respx fixture pattern @ `tests/unit/llm/conftest.py:173-245`. `PluginKind`/`_ENTRY_POINT_GROUPS` incl. `"agents": "cognic.agents"` @ `plugin_registry.py:66,79-84`. Skill loader gates @ `harness/skill_host.py:77-104,107-119,157-251`; `LoadedSkillRecord` @ `core/skill/_types.py:123-143`; `parse_skill_md`/`validate_skill_md`/`extract_skill_md` @ `protocol/skill_manifest.py:76-179`. `_PER_PACK_TRUST_ROOT_POLICIES` (hooks+skills only) @ `registry_boot.py:204-221`; tools/agents→default @ `:397-399`; `registry_boot.py`, `skill_host.py`, `cli/validators/skills.py` NOT in `_CRITICAL_FILES` (grep 2026-07-05); `core/skill/{broker,executor}.py` on-gate @ `check_critical_coverage.py:2302,2313`; `llm/gateway.py` on-gate @ `:743`; `protocol/ui_events.py` on-gate @ `:891`. Latest migration `20260630_0013_pack_runtime_config.py` (rev `0013`). `OPAEngine.evaluate(*, decision_point, input) -> Decision` boolean-only @ `core/policy/engine.py:269-274,482-487`; `_MINIMAL_SUBPROCESS_ENV` @ `:84-87`; scheduler mirror pattern @ `core/scheduler/policy.py:101-125,210-260`. joserfc RS256 JWS sign @ `cli/sign.py:1762-1783`; verify @ `protocol/trust_gate.py:378-459`; `joserfc==1.6.4` + `cryptography>=45` in the `adapters` extra @ `pyproject.toml:137,186`. `MemoryAPI.remember(key, value, *, tier, data_classes, purpose, ...)` @ `core/memory/api.py:184-236`; `MemoryCallerContext` fields @ `core/memory/_context.py:14-25`; `MemoryTier` @ `core/memory/tiers.py:15`; production factory @ `harness/runtime.py:409-428`. `agent_run` 7 model-only stubs @ `protocol/ui_events.py:465-500`; projector table @ `:1225-1248`; streamed set @ `:157-169`. `DecisionHistoryStore.append` @ `core/decision_history.py:361`; skill evidence emission pattern @ `core/skill/executor.py:355-386`. Skills route/dep/status-map pattern @ `portal/api/skills/routes.py:36-84`; scope unions @ `portal/rbac/scopes.py:342,365,441` + `actor.py:157-173` + `enforcement.py:252-267`; app fail-soft lifespan + unconditional mount @ `portal/api/app.py:986-1006,1709-1715`. Validator orchestrator dispatch + `_FORBIDDEN_BLOCKS_BY_KIND` @ `cli/validate.py:108-110,419-460`; agent-only identity fields @ `cli/validators/identity.py:300-335`; `ValidatorReason` + ownership map @ `cli/__init__.py:53-221,241-352`. `MCPHost.call_tool(*, server_id, tool_name, arguments, request_id, tenant_id, originator_subject, approval_request_id)` @ `mcp_host.py:1475` (M6-verified, unchanged). M8/M9 checklist lines @ `docs/PRODUCTION_GRADE_MILESTONE_CHECKLIST.md:100-110`. sqlglot 30.12.0 latest stable (PyPI, 2026-06-26).
