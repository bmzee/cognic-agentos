# M6 — Governed Agent Skill proof — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Implement this plan in the long-running batches named below, then return a complete report per batch for controller review. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove — live on a deployed `kind` AgentOS — that a released, cosign-signed `SKILL.md` skill pack runs its deterministic executable action **fully sandboxed**, composing only its **declared** MCP tools through a governed Unix-socket **broker** that routes to `MCPHost.call_tool`, with undeclared tool use and network egress refused, and both the instruction and execution layers audited.

**Architecture:** The public noun is **`Skill = SKILL.md package`** (agentskills.io standard); the deterministic `sdk/skill.py` composer is repositioned as the **governed executable action inside** a skill (not a competing "skill"). The action runs in the ADR-004 sandbox (`--network none`, no ambient credentials) via a generic in-repo **skill-runner** baked into an immutable runtime image; its only egress is a request/response tool-call RPC over a `0700` Unix domain socket to a kernel-side **skill-execution broker** that enforces `declared_tools` per call and forwards to `MCPHost.call_tool`. Merges checklist **M6 + M7** into one "Governed Agent Skill proof" milestone.

**Tech Stack:** Python 3.12, FastAPI, the ADR-004 sandbox (docker-sibling / kubernetes-pod), cosign/syft/grype supply chain, `MCPHost.call_tool`, Unix-domain-socket length-framed JSON transport, kind/Helm for the deployed proof.

## Global Constraints

- Source spec: `docs/superpowers/specs/2026-07-02-m6-governed-agent-skill-design.md` (main @ `afe5264`). Every task's requirements implicitly include the spec.
- **`protocol/mcp_authz.py` MUST stay byte-identical** — the standing AST/byte guard `tests/unit/architecture/test_mcp_authz_untouched.py`; verify at EVERY commit (`git diff --stat src/cognic_agentos/protocol/mcp_authz.py` empty).
- **Critical-controls discipline:** the broker + executor are new trust boundaries → on the durable per-file coverage gate (`tools/check_critical_coverage.py`, 95% line / 90% branch); each of the eleven §5.4 transport invariants is a threat-model-revert-proven load-bearing test (per `feedback_security_regression_hardening`).
- **BAR 3 (isolation) is MANDATORY.** Arbitrary bundled `scripts/` execution is OUT of M6 — only the signed `cognic.skills` Python action runs.
- **Separation:** Part A is in-repo kernel work (CC-gated, on branch `feat/m6-governed-agent-skill`). Part B is a NEW separate public repo `cognic-skill-schema-summary` (named here, NOT built in this repo; independent CI/sign/verify/release). Part C is the deployed proof consuming the RELEASED Part-B pack.
- Full CC gate at each CC commit: `uv run ruff check && uv run ruff format --check && uv run mypy src tests && uv run pytest --cov=cognic_agentos --cov-branch --cov-report=json -q && uv run python tools/check_critical_coverage.py`.
- Per-task commit-token gating: guard-stage the EXACT named files (assert `git diff --cached --name-only`), halt for the maintainer's one-word token before every commit.
- Execution mode: **Claude/Fable worker in long-running batches; controller as critical reviewer.** The worker should implement and test coherent task clusters before handing back a full report, rather than stopping after each small task. Suggested batches: A1; A2-A4; A5-A7; A8-A9; B1; C1-C3; C4. The controller still performs trust-but-verify, checks the critical-controls gate, and splits/stages commits only at security-coherent boundaries.
- This plan and its spec are docs-only on `main`. **Do NOT cut `feat/m6-governed-agent-skill` until Part-A Task A1's code phase begins.**

---

## File Structure

**In-repo kernel (Part A):**
- `docs/adrs/ADR-025-governed-agent-skills.md` — NEW. The Agent Skills hosting doctrine (vocabulary, M6/M7 merge, sandbox-broker security model, the eleven transport invariants).
- `src/cognic_agentos/sdk/skill_transport.py` — NEW (SDK-light; ships in the sandbox image). The FROZEN wire protocol: length-framed JSON codec, bounded max-frame, the request/response shapes, the closed-enum broker reasons, AND the sandbox-side `BrokerToolRegistry` / `BrokerTool` client adapters.
- `src/cognic_agentos/sdk/skill_runner.py` — NEW (SDK-light). The generic in-sandbox runner entrypoint: connect to the broker socket, load the `cognic.skills` entry-point, bind a `BrokerToolRegistry`, run `execute()`, emit the result frame.
- `src/cognic_agentos/core/skill/__init__.py`, `_types.py`, `broker.py`, `executor.py` — NEW. `_types.py` (closed enums + dataclasses, off-gate); `broker.py` (CC — the kernel-side socket server: perms, session-id auth, cleanup, timeout, `declared_tools` enforcement, `MCPHost.call_tool` routing); `executor.py` (CC — the orchestrator: sandbox session + per-invocation socket + broker + runner exec + teardown; threads tenant/actor).
- `src/cognic_agentos/portal/api/skills/__init__.py`, `dto.py`, `routes.py` — NEW (off-gate). `POST /api/v1/skills/{skill_id}/invoke`.
- `src/cognic_agentos/harness/registry_boot.py` — MODIFY. Extend `_resolve_pack_trust_root` for `skills` → `skill-packs/{pack_id}/cosign.pub`.
- `src/cognic_agentos/harness/skill_host.py` — NEW (off-gate). Composition: build the executor (wire `MCPHost`, the sandbox backend, the registry) + the skill-hosting admission (SKILL.md validation at boot).
- `src/cognic_agentos/cli/validators/skills.py` — NEW. The `[skill]` block + `SKILL.md` frontmatter + entry-point cross-check validator; `cli/templates/skill/` realignment.
- `src/cognic_agentos/portal/rbac/scopes.py` — MODIFY. Add `skill.invoke` scope.
- `src/cognic_agentos/portal/api/app.py`, `harness/runtime.py` — MODIFY (off-gate wiring).

**External pack (Part B, separate repo `cognic-skill-schema-summary`):** `SKILL.md`, `cognic-pack-manifest.toml`, `src/cognic_skill_schema_summary/skill.py`, `pyproject.toml`, `cosign.pub`, `.github/workflows/`, tests, `docs/VALIDATION-RESULTS.md`.

**Deployed proof (Part C):** `infra/proof-m6/` (Dockerfiles incl. the skill-runtime image, `stage-packs.sh`, `manifests/`, `proof-m6-values.yaml`, `run-proof-m6.sh`, `README.md`), `tests/unit/infra/test_proof_m6_structure.py`, `tests/integration/proof_m6/`.

---

# PART A — In-repo kernel (inline, CC-gated)

### Task A1: ADR-025 — Governed Agent Skills doctrine (docs)

**Files:** Create `docs/adrs/ADR-025-governed-agent-skills.md`. Do not modify `AGENTS.md` in this task; the concrete critical-controls entries land at the Part-A close after the files exist.

**Interfaces:** Produces the doctrine every later task cites. No code.

- [ ] **Step 1:** Write ADR-025 with sections: (a) **Vocabulary** — `Skill = SKILL.md package` is the public noun; the `sdk/skill.py` deterministic composer is the *governed executable action* inside a skill, not a "skill"; the 6-way pack vocab collapses "instruction skill" + "executable skill service" into one `skill` kind. (b) **M6/M7 merge** — one "Governed Agent Skill proof" milestone; AgentOS *governs* the open format, does not replace it. (c) **Security model** — full sandbox (`--network none`, `requires_credentials=()`), the broker as the sole tool-egress, `declared_tools` enforced per-call, `SKILL.md`/`references`/`assets` hosted-not-executed, `scripts/` execution explicitly deferred. (d) **The eleven transport invariants** (copy §5.4 verbatim). (e) Status APPROVED.
- [ ] **Step 2:** Add ADR-025 to `docs/adrs/`; cross-reference from ADR-001 (three-pool amendment: skill kind unified) + ADR-008 (authoring: skill scaffold realignment).
- [ ] **Step 3: Commit** (halt for token). `git add docs/adrs/ADR-025-governed-agent-skills.md && git commit -m "docs(m6): ADR-025 governed agent skills doctrine"`

### Task A2: SDK skill transport — frozen wire protocol + sandbox-side broker client

**Files:**
- Create: `src/cognic_agentos/sdk/skill_transport.py`
- Test: `tests/unit/sdk/test_skill_transport.py`

**Interfaces:**
- Produces:
  - `MAX_FRAME_BYTES: int = 1_048_576` (1 MiB bounded max).
  - `encode_frame(obj: dict) -> bytes` / `decode_frame(reader) -> dict` — 4-byte big-endian length prefix + UTF-8 JSON; `decode_frame` raises `FrameTooLarge` if the prefix exceeds `MAX_FRAME_BYTES` (BEFORE reading the body) and `MalformedFrame` on truncation/bad JSON/missing keys.
  - `SkillBrokerReason = Literal["skill_tool_not_declared", "skill_broker_malformed_frame", "skill_broker_oversized_frame", "skill_broker_unauthorized", "skill_tool_invocation_failed"]`.
  - `BrokerToolRegistry(*, sock_path: str, session_token: str)` implementing the `sdk.registry.ToolRegistry` Protocol: `list_tools()` returns the declared identities (from the runner's env), `get(tool_ref)` returns a `BrokerTool`.
  - `BrokerTool(*, tool_ref: str, sock_path: str, session_token: str)` with `async def invoke(self, **kwargs) -> dict` — connects to the socket, sends `{"session_token", "tool_ref", "arguments": kwargs}`, reads the response frame, returns `result` or raises `SkillToolRefused(reason)`.

- [ ] **Step 1: Write the failing tests** — frame round-trip; oversized-prefix refused before body read; malformed (truncated / non-JSON / missing `tool_ref`) refused; `SkillBrokerReason` closed-enum count == 5 via `get_args`.
```python
import pytest
from cognic_agentos.sdk.skill_transport import (
    MAX_FRAME_BYTES, encode_frame, decode_frame, FrameTooLarge, MalformedFrame, SkillBrokerReason,
)
from typing import get_args

def test_frame_roundtrip():
    payload = {"tool_ref": "s/t", "arguments": {"table": "EMPLOYEES"}}
    raw = encode_frame(payload)
    assert decode_frame(_BytesReader(raw)) == payload

def test_oversized_prefix_refused_before_body(monkeypatch):
    # a 4-byte prefix declaring > MAX_FRAME_BYTES must raise WITHOUT reading the body
    huge = (MAX_FRAME_BYTES + 1).to_bytes(4, "big")
    reader = _BytesReader(huge)  # body deliberately absent
    with pytest.raises(FrameTooLarge):
        decode_frame(reader)
    assert reader.bytes_read == 4  # only the prefix was consumed

def test_malformed_frame_refused():
    for bad in [b"\x00\x00\x00\x02{", b"\x00\x00\x00\x04nope", encode_frame({"no": "toolref"})]:
        with pytest.raises((MalformedFrame,)):
            decode_frame(_BytesReader(bad))

def test_reason_enum_closed_five():
    assert len(get_args(SkillBrokerReason)) == 5
```
- [ ] **Step 2: Run — expect FAIL** (module absent).
- [ ] **Step 3: Implement** `skill_transport.py` — the codec (length-prefix read with the pre-body bound check), the exceptions, the closed enum, and the `BrokerToolRegistry`/`BrokerTool` asyncio-socket clients. Keep it dependency-light (stdlib `asyncio`, `json`, `struct`) so it imports cleanly inside the sandbox image.
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5:** ruff/format/mypy on the two files. **Commit** (halt for token). `git add src/cognic_agentos/sdk/skill_transport.py tests/unit/sdk/test_skill_transport.py && git commit -m "feat(m6): skill transport wire protocol + sandbox-side broker client"`

### Task A3: Skill-execution broker (CC — the socket server + declared_tools enforcement)

**Files:**
- Create: `src/cognic_agentos/core/skill/__init__.py`, `src/cognic_agentos/core/skill/_types.py`, `src/cognic_agentos/core/skill/broker.py`
- Test: `tests/unit/core/skill/test_broker.py`
- Modify: `tools/check_critical_coverage.py` (`_CRITICAL_FILES` += `core/skill/broker.py` at 95/90; bump the count guard).

**Interfaces:**
- Consumes: `skill_transport.{encode_frame, decode_frame, MAX_FRAME_BYTES, SkillBrokerReason, FrameTooLarge, MalformedFrame}`; `MCPHost.call_tool(*, server_id, tool_name, arguments, request_id, tenant_id, originator_subject, approval_request_id)`.
- Produces:
  - `SkillCallProxy` Protocol — a narrow seam over `MCPHost.call_tool` (so the broker unit-tests without a full host): `async def call(self, *, server_id, tool_name, arguments, request_id, tenant_id, originator_subject) -> Any`.
  - `SkillBroker(*, declared_tools: frozenset[str], tenant_id: str, actor_subject: str, request_id_prefix: str, call_proxy: SkillCallProxy, timeout_s: float)`.
  - `async def serve(self) -> _BrokerHandle` — creates a per-invocation `0700` directory under `tempfile` with a **cryptographically-random** session id (`secrets.token_hex(16)`), binds an `asyncio` Unix socket at `broker_dir / "broker.sock"` (chmod `0600`), mints a `session_token = secrets.token_hex(32)`, and starts serving. Returns a handle carrying `sock_path`, `session_token`, and `close()`.
  - Per connection: read a request frame; **(a)** if `session_token` mismatches → refuse `skill_broker_unauthorized`, do not process; **(b)** decode errors → `skill_broker_malformed_frame` / `skill_broker_oversized_frame`; **(c)** if `tool_ref` (`server_id/tool_name`) ∉ `declared_tools` → refuse `skill_tool_not_declared` **without calling `call_proxy`**; **(d)** else call `call_proxy.call` with a fresh `request_id = f"{prefix}{uuid4().hex}"` per call, return `{"ok": true, "result": result_payload}` or map an exception to `{"ok": false, "error": error_payload}`.
  - `close()` — cancel the server, unlink the socket + rmdir the `0700` dir (finally-guarded); idempotent.

- [ ] **Step 1: Write the failing tests** — broker-side §5.4 invariants #1-#8 and #11, each its own test, over an in-process `SkillBroker` with a spy `SkillCallProxy` and a raw asyncio Unix-socket client. Invariants #9 (no general network) and #10 (no ambient credentials) are owned by Task A5 because they are sandbox-executor policy assertions, not broker transport behavior.
```python
# #1 socket dir 0700; #2 socket not world-accessible
async def test_socket_dir_is_0700_and_socket_not_world_accessible(broker):
    h = await broker.serve()
    assert (os.stat(os.path.dirname(h.sock_path)).st_mode & 0o777) == 0o700
    assert (os.stat(h.sock_path).st_mode & 0o077) == 0     # no group/other bits
    await h.close()

# #3 unguessable session id (path embeds 32-hex random; not sequential/pid)
async def test_session_id_is_random_hex(broker):
    h1 = await broker.serve(); h2 = await broker.serve()
    assert h1.sock_path != h2.sock_path and re.search(r"[0-9a-f]{32}", h1.sock_path)
    await h1.close(); await h2.close()

# #4 unauthorized client refused (wrong/absent session_token) → no call_proxy
async def test_unauthorized_client_refused(broker, spy_proxy):
    h = await broker.serve()
    resp = await _rpc(h.sock_path, {"session_token": "WRONG", "tool_ref": "oracle/list_tables", "arguments": {}})
    assert resp["ok"] is False and resp["reason"] == "skill_broker_unauthorized"
    assert spy_proxy.calls == []
    await h.close()

# #5 stale-socket cleanup on success AND failure
async def test_cleanup_on_success_and_failure(broker):
    h = await broker.serve(); p = h.sock_path; d = os.path.dirname(p)
    await h.close()
    assert not os.path.exists(p) and not os.path.exists(d)
    # failure path: an exception mid-serve still unlinks (finally-guarded) — see test_close_is_finally_guarded

# #6 broker closes on timeout / cancel
async def test_broker_closes_on_timeout(broker_short_timeout):
    h = await broker_short_timeout.serve()
    # a client that connects but never sends → the per-invocation deadline fires + tears down
    await _connect_and_wait_for_server_close(h.sock_path)
    assert not os.path.exists(h.sock_path)

# #7 malformed frame refused (does not reach call_proxy)
async def test_malformed_frame_refused(broker, spy_proxy):
    h = await broker.serve()
    resp = await _rpc_raw(h.sock_path, b"\x00\x00\x00\x04nope")
    assert resp["ok"] is False and resp["reason"] == "skill_broker_malformed_frame"
    assert spy_proxy.calls == []
    await h.close()

# #8 oversized payload refused before allocation
async def test_oversized_payload_refused(broker, spy_proxy):
    h = await broker.serve()
    resp = await _rpc_raw(h.sock_path, (MAX_FRAME_BYTES + 1).to_bytes(4, "big"))
    assert resp["ok"] is False and resp["reason"] == "skill_broker_oversized_frame"
    assert spy_proxy.calls == []
    await h.close()

# #11 undeclared tool refused BEFORE call_proxy (the load-bearing guard)
async def test_undeclared_tool_refused_before_call(broker, spy_proxy):
    h = await broker.serve()  # broker.declared_tools = {"oracle/list_tables","oracle/describe_table"}
    resp = await _rpc(h.sock_path, {"session_token": h.session_token,
                                    "tool_ref": "oracle/get_constraints", "arguments": {}})
    assert resp["ok"] is False and resp["reason"] == "skill_tool_not_declared"
    assert spy_proxy.calls == []   # call_proxy NEVER reached
    await h.close()

# declared tool routes through call_proxy with a fresh request_id + the bound tenant/actor
async def test_declared_tool_routes_through_proxy(broker, spy_proxy):
    h = await broker.serve()
    resp = await _rpc(h.sock_path, {"session_token": h.session_token,
                                    "tool_ref": "oracle/list_tables", "arguments": {"owner": "COGNIC"}})
    assert resp["ok"] is True
    c = spy_proxy.calls[0]
    assert c["server_id"] == "oracle" and c["tool_name"] == "list_tables"
    assert c["tenant_id"] == "tenant-1" and c["originator_subject"] == "actor-1"
    assert c["request_id"].startswith("skill-tool-")
    await h.close()
```
Invariants #9 (no general network) + #10 (no ambient credentials) are properties of the **sandbox session** the executor creates (Task A5) — pinned there. Each broker test above is threat-model-revert-proven load-bearing (a temporary weakening — e.g. skip the session-token check — must make the matching test FAIL; document in the commit).
- [ ] **Step 2: Run — expect FAIL** (module absent).
- [ ] **Step 3: Implement** `_types.py` (closed enums, the `SkillCallProxy` Protocol, `_BrokerHandle`) + `broker.py` (the `0700` tempdir, `secrets`-random session id + token, asyncio Unix server, the connection handler enforcing #4/#7/#8/#11, the per-invocation deadline, the finally-guarded `close`).
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: CC gate + commit** (halt for token; **CC — strict review**). Add `core/skill/broker.py` to `_CRITICAL_FILES` (95/90) + bump the count guard; run the full CC gate; assert `mcp_authz.py` byte-identical. `git add src/cognic_agentos/core/skill/__init__.py src/cognic_agentos/core/skill/_types.py src/cognic_agentos/core/skill/broker.py tests/unit/core/skill/test_broker.py tools/check_critical_coverage.py && git commit -m "feat(m6): skill-execution broker — 0700 socket, session-auth, declared_tools enforcement (CC)"`

### Task A4: Skill-runner — the generic in-sandbox action runner

**Files:**
- Create: `src/cognic_agentos/sdk/skill_runner.py`
- Test: `tests/unit/sdk/test_skill_runner.py`

**Interfaces:**
- Consumes: `skill_transport.{BrokerToolRegistry}`; `sdk.skill.Skill`; `importlib.metadata` entry-points (group `cognic.skills`).
- Produces: `async def run_skill(*, entry_point_name: str, sock_path: str, session_token: str, declared_tools: Sequence[str], kwargs: dict) -> dict` — loads the `cognic.skills` entry-point by name (`EntryPoint.load()` INSIDE the sandbox), constructs it with a `BrokerToolRegistry(sock_path, session_token, declared_tools)`, `await`s `skill.execute(**kwargs)`, returns the result dict. A `__main__` guard reads its parameters from argv/env (the executor passes them) and writes the result as a final frame to stdout.

- [ ] **Step 1: Write the failing test** — a fake `cognic.skills` entry-point (a `Skill` subclass whose `execute` calls `self._tools.get("oracle/list_tables").invoke(owner="COGNIC")`) + a stub broker socket → `run_skill` resolves the entry-point, the tool call round-trips over the socket, the result returns. A second test: a `mode="forbidden"` skill whose `execute` calls an undeclared tool → the `BrokerTool.invoke` raises `SkillToolRefused("skill_tool_not_declared")` and `run_skill` surfaces it.
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** `skill_runner.py`. Keep it SDK-light (no kernel imports) so it runs inside the minimal sandbox image.
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5:** ruff/format/mypy. **Commit** (halt for token). `git add src/cognic_agentos/sdk/skill_runner.py tests/unit/sdk/test_skill_runner.py && git commit -m "feat(m6): generic in-sandbox skill-runner"`

### Task A5: Skill executor (CC — orchestrator; threads tenant/actor)

**Files:**
- Create: `src/cognic_agentos/core/skill/executor.py`
- Test: `tests/unit/core/skill/test_executor.py`
- Modify: `tools/check_critical_coverage.py` (`_CRITICAL_FILES` += `core/skill/executor.py`; bump count).

**Interfaces:**
- Consumes: `SkillBroker`; the sandbox `SandboxBackend.create(*, policy, actor, tenant_id, pack_context, use_warm_pool, requires_credentials, approval_request_id) -> SandboxSession` + `exec(*, session, command, timeout_s) -> SandboxExecResult` (`stdout: bytes`, `exit_code: int`); a `SkillRecordLoader` Protocol (skill id → `{entry_point_name, declared_tools, runtime_image}`); `MCPHost` (wrapped as the broker's `SkillCallProxy`).
- Produces: `SkillExecutor.invoke(*, skill_id: str, arguments: dict, actor: Actor) -> SkillInvokeResult` — the synchronous governed run:
  1. Load + validate the trusted skill record (exists / tenant-scoped / registered); refuse `skill_not_found` / `skill_not_registered` otherwise.
  2. `create(policy=skill_runtime_policy, actor=actor, tenant_id=actor.tenant_id, pack_context=read_only_pack_context, **requires_credentials=()**)` — **no ambient credentials** (invariant #10); the policy sets `--network none` egress (invariant #9).
  3. `broker = SkillBroker(declared_tools=frozenset(record.declared_tools), tenant_id=actor.tenant_id, actor_subject=actor.subject, request_id_prefix="skill-tool-", call_proxy=mcp_host_call_proxy, timeout_s=skill_execution_timeout_s)`; `handle = await broker.serve()`.
  4. Mount the broker's `0700` socket dir into the session via the EXISTING `SandboxPolicy.writable_mounts = (WritableMount(host_path=broker_dir, container_path="/run/cognic-skill", read_only=False),)` (`sandbox/policy.py:135`) — no sandbox-backend extension needed; the runner then connects to `/run/cognic-skill/broker.sock`. `exec(command=["python", "-m", "cognic_agentos.sdk.skill_runner"], timeout_s=skill_execution_timeout_s)`, passing `COGNIC_SKILL_BROKER_SOCKET=/run/cognic-skill/broker.sock`, `COGNIC_SKILL_BROKER_SESSION_TOKEN`, `COGNIC_SKILL_ENTRY_POINT`, `COGNIC_SKILL_DECLARED_TOOLS_JSON`, and `COGNIC_SKILL_ARGUMENTS_JSON` via env. (The M6 proof uses the **docker-sibling** backend — kernel-side broker + host bind-mount per spec §5.5; the kubernetes-pod sidecar+`emptyDir` realization is the documented production variant, same invariants, out of the M6 proof scope.)
  5. Parse the runner's final result frame from `stdout`; `broker.close()` + `session.destroy()` (finally-guarded).
  6. Emit dual-layer evidence: a `skill.invoked` decision row (instruction layer: skill id + actor) — the broker's per-tool `call_tool`s already emit the M5 `mcp_call` rows (execution layer).
- Closed enums in `_types.py`: `SkillInvokeRefusalReason` (`skill_not_found`/`skill_not_registered`/`skill_runtime_error`), `SkillInvokeTerminalState`.

- [ ] **Step 1: Write the failing tests** (real `SkillBroker` + real `DecisionHistoryStore` in-memory + a stub `SandboxBackend`/`SkillRecordLoader`): happy path (runner echoes a declared tool-call result → the executor returns it + a `skill.invoked` row present); the `forbidden` path (runner requests an undeclared tool → broker refuses → the executor surfaces `skill_tool_not_declared` and NO `call_tool` reached the proxy); teardown always runs (`session.destroy` + `broker.close` called on both success and runner-exception paths); **the sandbox `create` was called with `requires_credentials=()`** (invariant #10) **and a `--network none` policy** (invariant #9) — assert on the stub's captured kwargs.
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** `executor.py`. Layering: `core/skill` imports NO `portal`; the `Actor` is TYPE_CHECKING-only (projected to the sandbox `actor` + the broker's `actor_subject`). Add `tests/unit/architecture/test_skill_executor_boundaries.py` with AST fences for no `portal` imports and no SDK imports at module import time, mirroring `core/run`.
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: CC gate + commit** (halt for token; **CC — strict review**). Add `core/skill/executor.py` to the gate; full CC gate; `mcp_authz.py` byte-identical. `git add src/cognic_agentos/core/skill/executor.py src/cognic_agentos/core/skill/_types.py tests/unit/core/skill/test_executor.py tests/unit/architecture/test_skill_executor_boundaries.py tools/check_critical_coverage.py && git commit -m "feat(m6): skill executor — sandboxed governed run, actor-scoped, dual-layer evidence (CC)"`

### Task A6: Invocation endpoint + `skill.invoke` RBAC scope (off-gate)

**Files:**
- Create: `src/cognic_agentos/portal/api/skills/__init__.py`, `dto.py`, `routes.py`
- Modify: `src/cognic_agentos/portal/rbac/scopes.py` (add `SkillRBACScope = Literal["skill.invoke"]` + `SKILL_SCOPES`; widen `Actor.scopes` + `RequireScope`), `tests`
- Test: `tests/unit/portal/api/skills/test_skill_routes.py`, `tests/unit/portal/rbac/test_skill_scopes.py`

**Interfaces:**
- Produces: `POST /api/v1/skills/{skill_id}/invoke` — `SkillInvokeRequest(arguments: dict)` (extra=forbid); binds `Actor` via the actor-binder + `RequireScope("skill.invoke")`; calls `app.state.skill_executor.invoke(skill_id=, arguments=body.arguments, actor=actor)`; maps `SkillInvokeResult` → 200, `skill_not_found`→404, `skill_tool_not_declared`→**403** (the load-bearing refusal), `skill_runtime_error`→502, `skill_executor_unavailable`→503. `from __future__ import annotations` OMITTED (the FastAPI closure-local `Depends` invariant, `feedback_pep563_breaks_closure_local_depends`).

- [ ] **Step 1: Write the failing tests** — stub executor on `app.state`: 200 happy; 403 `skill_tool_not_declared`; 404 unknown skill; 503 when executor absent; scope-miss 403; `SkillRBACScope` closed-enum pin.
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** the DTOs + route factory (`build_skill_routes`, eval-router pattern, mounted unconditionally under `/api/v1/skills`) + the RBAC scope widenings.
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5:** ruff/format/mypy + the affected RBAC suite. **Commit** (halt for token). `git add src/cognic_agentos/portal/api/skills/ src/cognic_agentos/portal/rbac/scopes.py tests/unit/portal/api/skills/test_skill_routes.py tests/unit/portal/rbac/test_skill_scopes.py && git commit -m "feat(m6): POST /skills/{id}/invoke + skill.invoke scope"`

### Task A7: Skill-pack hosting/ingestion + SKILL.md validation (kernel)

**Files:**
- Create: `src/cognic_agentos/harness/skill_host.py` (off-gate), `src/cognic_agentos/protocol/skill_manifest.py` (the `SKILL.md` frontmatter + `[skill].declared_tools` reader — small, may ride the gate if it owns a wire-public closed enum)
- Test: `tests/unit/harness/test_skill_host.py`, `tests/unit/protocol/test_skill_manifest.py`
- Modify: `src/cognic_agentos/portal/api/system_routes.py` (surface hosted skills on `/api/v1/system/plugins` — reuse the M5 discovery-status pattern), `harness/runtime.py` + `portal/api/app.py` (wire `app.state.skill_executor` + the skill-record loader)

**Interfaces:**
- Produces: `build_skill_executor(*, runtime, settings, mcp_host, sandbox_backend) -> SkillExecutor`; a `SkillRecordLoader` backed by the trusted registry (`iter_registered_pack_candidates()` filtered to `kind == "skills"`, re-extracting `SKILL.md` + `[skill].declared_tools` per pack); `validate_skill_md(frontmatter) -> None` refusing on the agentskills.io shape (name regex `^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`, description ≤ 1024, non-empty body).

- [ ] **Step 1: Write the failing tests** — a registered skill candidate whose wheel ships a valid `SKILL.md` + `[skill].declared_tools` → the loader yields a record with the entry-point + declared identities; malformed `SKILL.md` frontmatter (bad name / >1024 desc) → warn-skip (mirrors the M5 mapper); `declared_tools` referencing an unregistered MCP tool → refused at admission (`skill_declared_tool_unregistered`).
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** the manifest reader + the host builder + the loader; wire `app.state.skill_executor` on the SDK-present lifespan (the sandbox backend + `MCPHost` must be constructed — fail-soft `None` otherwise, mirroring the 13.8/14A builders).
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5:** full targeted suites + ruff/format/mypy. **Commit** (halt for token). `git add src/cognic_agentos/harness/skill_host.py src/cognic_agentos/protocol/skill_manifest.py src/cognic_agentos/portal/api/system_routes.py src/cognic_agentos/harness/runtime.py src/cognic_agentos/portal/api/app.py tests/unit/harness/test_skill_host.py tests/unit/protocol/test_skill_manifest.py && git commit -m "feat(m6): skill-pack hosting + SKILL.md validation + executor wiring"`

### Task A8: Per-pack skill trust root (CC-adjacent — `registry_boot`)

**Files:**
- Modify: `src/cognic_agentos/harness/registry_boot.py:289-320` (`_resolve_pack_trust_root`), `:87` (add `_SKILL_PACK_TRUST_ROOT_SUBDIR = "skill-packs"`)
- Test: `tests/unit/harness/test_registry_boot.py`

**Interfaces:**
- Consumes/Produces: extend `_resolve_pack_trust_root` so `kind == "skills"` resolves `trust_root_prefix / "skill-packs" / distribution_name / "cosign.pub"` with the SAME semantics as hooks — absent→`_default`, present-but-invalid→fail closed (reuse `_HookPackTrustRootInvalid` or generalise to a shared `_PerPackTrustRootInvalid`), the same resolve-then-validate name/containment guards.

- [ ] **Step 1: Write the failing tests** — mirror the M5 hook trust-root suite for skills: per-pack root used when present; absent→default fallback; tools/agents still ignore the per-pack path (decoy); empty→fail-closed-no-downgrade; **symlink-escape containment fails closed** (the load-bearing one, TM-revert-proven).
- [ ] **Step 2: Run — expect FAIL** (skills currently hit `kind != "hooks" → default_root`).
- [ ] **Step 3: Implement** — generalise the hooks branch to a `{"hooks": "hook-packs", "skills": "skill-packs"}` subdir map; the two per-pack kinds share the resolve-then-validate code; non-per-pack kinds still return `default_root`.
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: CC gate + commit** (halt for token; `registry_boot.py` is on the gate — strict review). Full CC gate; `mcp_authz.py` byte-identical. `git add src/cognic_agentos/harness/registry_boot.py tests/unit/harness/test_registry_boot.py && git commit -m "feat(m6): per-pack skill trust root (skill-packs/{pack_id}/cosign.pub)"`

### Task A9: CLI skill validator + scaffold realignment

**Files:**
- Create: `src/cognic_agentos/cli/validators/skills.py`
- Modify: `src/cognic_agentos/cli/validate.py` (register the skill validator), `src/cognic_agentos/cli/templates/skill/*` (realign: emit `SKILL.md` + the `Skill` action + `[skill].declared_tools`), `src/cognic_agentos/cli/__init__.py` (`ValidatorReason` += skill reasons)
- Test: `tests/unit/cli/validators/test_skills.py`, `tests/unit/cli/test_cli_init.py`

**Interfaces:**
- Produces: `validate_skill_manifest(manifest_path: Path, skill_md_path: Path) -> list[ValidationFinding]` refusing on: missing/blank `SKILL.md`; malformed frontmatter (name regex / description length); `[skill].declared_tools` shape (`server_id/tool_name` strings, non-empty, deduped); declaration↔entry-point cross-check (the `cognic.skills` entry-point exists). Closed-enum `skill_manifest_*` reasons. The realigned `init-skill` scaffold emits a working `SKILL.md` + a `Skill` subclass stub + the `[skill]` block.

- [ ] **Step 1: Write the failing tests** — a valid skill pack fixture validates clean; each refusal arm (no SKILL.md / bad name / bad declared_tools shape / entry-point mismatch); `init-skill` produces a tree that `validate_skill_manifest` accepts.
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** the validator + the template realignment.
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5:** targeted + affected CLI suites + ruff/format/mypy. **Commit** (halt for token). `git add src/cognic_agentos/cli/validators/skills.py src/cognic_agentos/cli/validate.py src/cognic_agentos/cli/templates/skill/ src/cognic_agentos/cli/__init__.py tests/unit/cli/validators/test_skills.py tests/unit/cli/test_cli_init.py && git commit -m "feat(m6): CLI skill validator + SKILL.md scaffold realignment"`

> **End of Part A — full-gate checkpoint.** Run the complete CC gate once more; add the `core/skill/*` critical-controls entries to `AGENTS.md` (verified at file:line per `feedback_verify_code_citations_at_doc_write`). Part A is in-repo, deployable-neutral (no skill pack installed yet). **Broker review checkpoint (maintainer):** confirm all eleven §5.4 invariants are each pinned + TM-revert-proven before proceeding to Parts B/C.

---

# PART B — External pack (NEW separate repo; subagent, Fable)

### Task B1: `cognic-skill-schema-summary` — release the first governed skill

**Files (separate public repo `bmzee/cognic-skill-schema-summary`, local `/Users/bmz/development/cognic-skill-schema-summary`):** `SKILL.md`, `cognic-pack-manifest.toml`, `src/cognic_skill_schema_summary/{__init__,skill.py}`, `pyproject.toml` (`[project.entry-points."cognic.skills"]`; kernel dev-only pin), `cosign.pub`, `.github/workflows/{ci,sign-and-publish}.yml`, `tests/`, `docs/VALIDATION-RESULTS.md`, `README.md`, `.gitignore`.

**Interfaces (the shapes Part C consumes):**
- `SKILL.md` frontmatter: `name: schema-summary`, `description:` "Summarize an Oracle schema's tables and key columns; use when a user asks for a schema overview." + an instructions body (agent-facing, M8).
- `cognic-pack-manifest.toml`: `[pack] kind="skill"`; `[skill] declared_tools = ["cognic-tool-oracle-schema/list_tables", "cognic-tool-oracle-schema/describe_table"]`; `[data_governance]` (`internal`, `operational_telemetry`, `none`, `[]`); `[risk_tier] tier="read_only"`; `[supply_chain]`.
- `skill.py`: `class SchemaSummary(Skill)` — `name`, `declared_tools` ClassVar; `execute(self, owner, mode="normal")`: `mode="normal"` → `list_tables(owner)` then bounded `describe_table(owner, table)` per table → fixed `{schema, table_count, tables:[{name, column_count, columns}]}`; `mode="forbidden"` → attempts `self._tools.get("cognic-tool-oracle-schema/get_constraints")` (outside `declared_tools`) → broker refuses; `mode="exfil"` → attempts a direct outbound HTTP call → blocked by the sandbox (BAR 3).

- [ ] **Step 1:** Scaffold from `agentos init-skill` @ the kernel tag; fill `SKILL.md` + the three-mode `execute`; declare `declared_tools`.
- [ ] **Step 2:** `uv run pytest` (the action's deterministic composition tested against a fake tool registry, mirroring the SDK Skill test fixtures; the arg-gated `forbidden`/`exfil` modes assert they *attempt* the out-of-band access, which the deployed proof then shows is *refused*).
- [ ] **Step 3:** `agentos validate .` PASS; `uv build --wheel`; `agentos sign --bundle .` (dev-grade key `~/.cognic/signing/cognic-skill-schema-summary/v0.1.0/`); `agentos verify --trust-root cosign.pub .` PASS; record digests in `docs/VALIDATION-RESULTS.md`.
- [ ] **Step 4 (remote, token-gated, per-action):** create repo → push → CI green → tag `v0.1.0` → push tag → GitHub Release with the 9 verified assets (wheel + 7 attestations + `cosign.pub`). Record the released wheel + `cosign.pub` sha256 for Part C's `stage-packs.sh` pins.

> Controller trust-but-verify against the subagent's tree; the whole external-repo release runs on the maintainer's per-action tokens (repo create / push / tag / release), mirroring the M5 pack releases.

---

# PART C — Deployed proof (`kind`)

### Task C1: Skill runtime image (bakes the released wheel + the skill-runner)

**Files:** Create `infra/proof-m6/Dockerfile.skill-runtime` — `FROM` a minimal immutable Python base; pip-install the DOWNLOADED released `cognic_skill_schema_summary-0.1.0` wheel (digest-verified, `--no-deps` where possible) + the kernel `sdk` runtime (`skill_runner` + `skill_transport`); set the entrypoint to `python -m cognic_agentos.sdk.skill_runner`. This is the immutable, cosign-verifiable sandbox runtime image the executor runs.

- [ ] **Step 1:** Author the Dockerfile; the wheel + the sdk are the only added layers.
- [ ] **Step 2:** structural test asserting the Dockerfile stages the `0.2.0`-free released skill wheel + the skill-runner entrypoint. (Part of `test_proof_m6_structure.py`.)
- [ ] **Step 3: Commit** with C2.

### Task C2: `infra/proof-m6/` scaffolding (from proof-m5)

**Files:** Create `infra/proof-m6/` (copy-adapt `infra/proof-m5/`): `Dockerfile.agentos-proof` (kernel image WITH the M6 branch), `Dockerfile.oracle-pack` (stages the released oracle `v0.2.0`), `Dockerfile.skill-runtime` (C1), `stage-packs.sh` (download + digest-verify BOTH released packs: oracle `v0.2.0` + skill `v0.1.0` + both `cosign.pub`s; arrange `_default` + `skill-packs/{pack_id}/cosign.pub` trust roots), `manifests/`, `proof-m6-values.yaml`, `migrate-job.yaml`, `seed-db.sh`, `seed-vault.sh`, `oracle-seed/`, `README.md` (the three bars + the skill-vs-tool split). NO `run-proof-m6.sh` (Task C3). Test: `tests/unit/infra/test_proof_m6_structure.py`.

- [ ] **Steps:** copy-adapt m5→m6; point oracle at `v0.2.0`; stage the skill pack + its per-pack trust root; digest pins for all 4 released assets; structural pins (dir set, no runner yet, skill trust-root staged, digests present). **Commit** (halt for token; guard-stage `infra/proof-m6/` + the structural test). `git commit -m "chore(m6): proof-m6 kind scaffolding + skill runtime image"`

### Task C3: `run-proof-m6.sh` — the three DLP bars (BAR 3 mandatory)

**Files:** Create `infra/proof-m6/run-proof-m6.sh` (model `run-proof-m5.sh`; env-gated `COGNIC_RUN_PROOF_M6=1`; NO default-on CI).

- [ ] **Step 1:** bring up the cluster (reuse M5 flow) — oracle `v0.2.0` operator-installed; the **skill pack trust-registered + hosted** (assert `/system/plugins` shows `cognic-skill-schema-summary` `kind=skills status=registered`).
- [ ] **Step 2: BAR 1 (composition works):** `POST /api/v1/skills/schema-summary/invoke {"arguments":{"owner":"COGNIC"}}` → 200 + fixed-shape summary; assert the two governed `mcp_call` rows (`list_tables`, `describe_table`) present (execution layer) + a `skill.invoked` row (instruction layer). `PROOF M6 (BAR 1) PASS`.
- [ ] **Step 3: BAR 2 (undeclared refused):** `invoke {"arguments":{"owner":"COGNIC","mode":"forbidden"}}` → **403** `skill_tool_not_declared`; assert the oracle `get_constraints` tool was NOT invoked (no new `audit.tool_invocation` row for it) — the broker refused before `call_tool`. `PROOF M6 (BAR 2) PASS`.
- [ ] **Step 4: BAR 3 (isolation — MANDATORY):** `invoke {"arguments":{"owner":"COGNIC","mode":"exfil"}}` → the direct outbound call is blocked (`--network none`), the skill fails closed, and no credential/egress leaked. `PROOF M6 (BAR 3) PASS`.
- [ ] **Step 5:** on any bar failure capture logs + reason to `docs/VALIDATION-RESULTS.md` + exit non-zero (never redefine downward). All-pass → `PROOF M6 (ALL BARS) PASS`. **Commit** (halt for token). `git add infra/proof-m6/run-proof-m6.sh && git commit -m "test(m6): deployed 3-bar governed-skill proof runner"`

### Task C4: Live proof + evidence + M6/M7 flip + PR

- [ ] **Step 1:** operator-run `COGNIC_RUN_PROOF_M6=1 ./infra/proof-m6/run-proof-m6.sh` — iterate on deploy/harness findings until `PROOF M6 (ALL BARS) PASS`; any real kernel bug fixed under TDD on-branch (re-run the CC gate; `mcp_authz.py` byte-identical).
- [ ] **Step 2:** write the `docs/VALIDATION-RESULTS.md` "M6 — Governed Agent Skill proof — PASS" section (run id, the three bar outcomes incl. mandatory BAR 3, the dual-layer evidence, the released-pack digests).
- [ ] **Step 3:** flip **BOTH M6 and M7 to `[x]`** in `docs/PRODUCTION_GRADE_MILESTONE_CHECKLIST.md` with a merged "Governed Agent Skill proof" evidence note (only after the live proof passes).
- [ ] **Step 4: Commit** (halt for token) → PR `feat/m6-governed-agent-skill` → `main` (CI is the authority for the CC/milestone work); watch PR-side + post-merge CI separately.

---

## Self-Review

**Spec coverage:** §1 motivation → A1 (ADR-025). §2 vocabulary → A1. §3 five components → A2/A4 (transport+runner), A3 (broker), A5 (executor), A6 (endpoint), A7 (hosting), evidence in A5/C3. §4 D1/D2/D3 → the sandbox in A5, no-LLM-agent scope, signed-wheel pack in B1. §5.1 execution model → A4/A5 (runner-in-sandbox, immutable image in C1). §5.2 broker + §5.4 eleven invariants → A3 (#1-#8,#11) + A5 (#9,#10). §5.3 declared_tools→MCP identity → A2/A3/A7/A9. §5.5 local-vs-k8s → A5 (mount seam) + C2 (proof realization). §6 pack shape + scripts ban → B1 + A9. §7 hosting/ADR-025 → A1/A7. §8 proof/`schema-summary`/3 bars → B1 + C3. §9 scope → honored (no LLM agent; no scripts/; no workflow). §10 risks → the per-invocation deadline (A3 #6), the actor binding (A5/A6). §11 references → A1.

**Completeness scan:** every task has concrete files, tests, commands, and finished implementation instructions.

**Type consistency:** `declared_tools` uses `server_id/tool_name` string identities throughout (A2 `BrokerToolRegistry`, A3 `SkillBroker.declared_tools: frozenset[str]`, A7 loader, A9 validator, B1 manifest, C3 bars). `SkillBrokerReason` (transport, 5 values) is distinct from `SkillInvokeRefusalReason` (executor) and the route status map (A6). `MCPHost.call_tool` kwargs match the verified signature. The sandbox `create(requires_credentials=())` + `exec(session=, command=, timeout_s=) -> SandboxExecResult(stdout: bytes, exit_code: int)` match `sandbox/protocol.py`.

## Verified citations (this pass)
`harness/registry_boot._resolve_pack_trust_root(*, trust_root_prefix, kind, distribution_name, default_root) -> Path` with the `if kind != "hooks": return default_root` branch @ `registry_boot.py:289,315` + `_HOOK_PACK_TRUST_ROOT_SUBDIR` @ `:87`; `SandboxBackend.create(*, policy, actor, tenant_id, pack_context, use_warm_pool, requires_credentials=(), approval_request_id) -> SandboxSession` + `exec(*, session, command, timeout_s) -> SandboxExecResult` + `SandboxExecResult{stdout: bytes, stderr: bytes, exit_code: int, proxy_log}` @ `sandbox/protocol.py:549,612,668`; `MCPHost.call_tool(*, server_id, tool_name, arguments, request_id, tenant_id, originator_subject="", approval_request_id=None)` @ `mcp_host.py:1475`; `cognic.skills` registrable `PluginKind` @ `plugin_registry.py:81`; `sdk/skill.py::Skill` (ToolRegistry-bound `__init__` + `declared_tools` cross-check + abstract `execute`); `_CRITICAL_FILES` tuple @ `check_critical_coverage.py:711`; the deployed oracle tool `cognic-tool-oracle-schema@v0.2.0`.
