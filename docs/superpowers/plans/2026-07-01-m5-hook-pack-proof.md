# M5 — Real Hook Pack Proof — Implementation Plan
<!-- STATUS: HISTORICAL -->
<!-- OWNER: cognic-agentos maintainers -->
<!-- LAST-VERIFIED: 2026-07-18 -->

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the dormant hook subsystem onto `MCPHost.call_tool` (boot → registry → DLPGuard → pre-invocation scan) and prove it live in `kind` with the first separately-released signed `cognic-hook-*` pack — a forbidden tool-call argument is refused *before the tool runs*, digest-only, fail-closed.

**Architecture:** In-repo work is two layers. **Kernel (CC, `protocol/mcp_host.py` on the 95/90 gate):** `MCPServerEntry` gains `dlp_pre_hooks` + `manifest_purpose`; `MCPHost` gains an optional `dlp_guard`; `call_tool` runs `DLPGuard.scan_pre` over the canonical-serialized arguments *after* the static/approval gates and *before* token/session/transport, mapping refusals to three new closed-enum reasons (`dlp_pre_refused`→403 / `dlp_pre_failed`→409 / `dlp_pre_guard_unavailable`→503). **Boot (off-gate harness + lifespan):** a new `harness/hook_registry.py` walks the already-trusted registry candidates, admits verified hook packs into a `HookRegistry`, and builds the `DLPGuard`; the lifespan threads it into `build_mcp_host`. The two pack repos (`cognic-hook-schema-guard`, `cognic-tool-oracle-schema@v0.2.0`) are separate public-repo work — this plan names their shapes (Appendix A) but does not implement them here.

**Tech Stack:** Python 3.12, `uv`, pytest (+ `pytest-asyncio`), FastAPI, the Sprint-7A2 hook kernel (`packs/hooks/*`), `core/canonical.canonical_bytes`, cosign-signed packs, `kind` + Helm for the deployed proof.

## Global Constraints

- **TDD, always.** Every production change starts with a failing test; watch it fail before implementing. (`superpowers:test-driven-development`.)
- **`protocol/mcp_host.py` is on the critical-controls coverage gate** (`tools/check_critical_coverage.py:831` → 95% line / 90% branch). Every commit that touches it runs, at commit time: `uv run ruff check` + `uv run ruff format --check` + `uv run mypy src tests` + the full suite + fresh coverage + `uv run python tools/check_critical_coverage.py`.
- **`protocol/mcp_authz.py` stays byte-identical.** M5 does not touch the authz/SSRF path (verify with `git diff --stat` before every commit).
- **`packs/hooks/*` is CONSUMED, not modified.** No new CC surface there; the DLPGuard/registry/dispatcher APIs are used as-is.
- **Digest-only evidence.** No tool-call argument plaintext ever enters an audit row, decision row, or log line — only the sha256 digest + hook metadata. Hard test invariant.
- **Canonical serialization = `core/canonical.canonical_bytes`** (already imported in `mcp_host.py:580`). The bytes passed to `scan_pre` are exactly what the dispatcher digests, so `DLPGuardOutcome.policy_input_digest` correlates with no second canonical form (resolves spec §9 risk 1).
- **Additive / back-compat.** New `MCPServerEntry` fields default to empty (`()` / `""`); the `dlp_guard` param defaults to `None`. Empty `dlp_pre_hooks` ⇒ byte-identical no-op ⇒ every existing tool pack (incl. M3/M4 oracle `v0.1.0`) is unaffected and `main` stays deployable.
- **Docs-only plan on `main`.** This plan file commits to `main`. All code lands on `feat/m5-hook-pack-proof`, cut only when Part A implementation begins (Task 1).
- **Per-action commit discipline (user-mandated).** During execution, every commit / push / PR / merge halts for the user's explicit one-word token; guard-stage exactly the named paths (assert `git diff --cached --name-only` == the task's file set) and never stage `.claude/settings.json`, the protected untracked docs, or `scratchpad/`.
- **The two pack repos are separate work.** Appendix A names their manifest + hook shapes; do NOT create pack source in this repo.

---

## Decisions this plan makes beyond the spec (surface at plan-review)

1. **BAR 3 binding (resolves spec §6 "bind/exercise" + §9 risk):** `cognic-tool-oracle-schema@v0.2.0` declares **both** hooks — `dlp_pre_hooks = ["refuse_forbidden_schema_arg", "explode_schema_guard"]` — with **both arg-gated** (each fires only on its own sentinel argument). All three bars then run against the **single deployed `v0.2.0`** via argument variation (matching BAR 2's "same pack, arg is the only variable" theme): BAR 1 normal args → both pass; BAR 2 forbidden arg → hook 1 policy-refuses; BAR 3 explode-sentinel arg → hook 1 passes, hook 2 raises. **Spec §5.2 is patched to match this binding.** *Alternative rejected:* a separate `v0.2.1` binding only the explode hook — an extra release + heavier proof for no added assurance.
2. **`dlp_hook_id_unresolved` → `dlp_pre_failed` (409).** The three new wire reasons are `dlp_pre_refused` / `dlp_pre_failed` / `dlp_pre_guard_unavailable`. A declared hook that the registry cannot resolve is "DLP could not produce a clean verdict" → fail-closed → 409, the same bucket as `dlp_dispatcher_failed`. (503 `dlp_pre_guard_unavailable` stays reserved for "the guard was never wired at all".)
3. **`build_dlp_guard` fail-soft to `None`; per-pack fail-closed in `call_tool`.** The boot loader skips a malformed hook pack per-pack (logged, mirrors the MCP mapper's warn-skip); only a hard construction failure yields `dlp_guard=None`, in which case un-hooked packs keep working and a pack with non-empty `dlp_pre_hooks` fail-closes with `dlp_pre_guard_unavailable` (the spec §4.1 absent-guard invariant).
4. **New file `harness/hook_registry.py`** owns the boot loader (single responsibility); `harness/mcp_host.py` consumes its `DLPGuard` output.

---

## File Structure

**Part A — kernel (CC), branch `feat/m5-hook-pack-proof`:**
| File | Change | Responsibility |
|---|---|---|
| `src/cognic_agentos/protocol/mcp_host.py` | Modify (`MCPServerEntry` 238-276; `ToolInvocationRefusalReason` 603-610; `MCPHost.__init__` 664-793; new `_dlp_pre_scan`; `call_tool` insert ~1476) | The DLP pre-invocation gate + closed-enum reasons |
| `src/cognic_agentos/portal/api/mcp/routes.py` | Modify (`_REFUSAL_STATUS` 37-44; refusal arm 140-144) | Map the 3 new reasons to 403/409/503 |
| `tests/unit/protocol/test_mcp_host_dlp.py` | Create | `_dlp_pre_scan` + `call_tool` × scan_pre behaviour |
| `tests/unit/protocol/test_mcp_approval_seam.py` | Modify (`:24`, `:29`) | Refusal-enum drift: six→nine |
| `tests/unit/protocol/test_mcp_high_risk_tier_refused.py` | Modify (`:556`) | Second refusal-enum drift assertion |
| `tests/unit/portal/api/mcp/test_mcp_routes.py` | Modify | 3 new reason→status rows + coverage-pin |

**Part B — boot (off-gate):**
| File | Change | Responsibility |
|---|---|---|
| `src/cognic_agentos/harness/hook_registry.py` | Create | Walk trusted candidates → `VerifiedHookPack` → `HookRegistry` → `HookDispatcher` → `DLPGuard` |
| `src/cognic_agentos/harness/mcp_host.py` | Modify (mapper 146-170; `build_mcp_host` 175-224) | Extract `dlp_pre_hooks`+`purpose`; thread `dlp_guard` into `MCPHost` |
| `src/cognic_agentos/portal/api/app.py` | Modify (lifespan 789-809) | Build the `DLPGuard` in the SDK-gated block, pass to `build_mcp_host` |
| `tests/unit/harness/test_hook_registry_builder.py` | Create | Boot loader: admits verified pack, skips malformed, resolves entry-points |
| `tests/unit/harness/test_mcp_host_builder.py` | Modify | Mapper extracts the two new fields; `dlp_guard` threads through |

**Part C — deployed proof (infra), after A+B green:**
| File | Change | Responsibility |
|---|---|---|
| `infra/proof-m5/` (tree) | Create (model `infra/proof-m4/`) | Dockerfiles, manifests, values, seed scripts, README |
| `infra/proof-m5/run-proof-m5.sh` | Create | The 3-bar deployed proof runner |
| `docs/VALIDATION-RESULTS.md` | Modify | "M5 — Real hook pack proof — PASS" evidence |
| `docs/PRODUCTION_GRADE_MILESTONE_CHECKLIST.md` | Modify | Flip M5 to `[x]` (only after the live proof passes) |

---

## PART A — Kernel wiring (CC; branch `feat/m5-hook-pack-proof`)

> **Before Task 1:** `git checkout main && git pull --ff-only && git checkout -b feat/m5-hook-pack-proof` (halt for the user's token per discipline).

### Task 1: `MCPServerEntry` gains `dlp_pre_hooks` + `manifest_purpose`

**Files:**
- Modify: `src/cognic_agentos/protocol/mcp_host.py:270-276`
- Test: `tests/unit/protocol/test_mcp_host.py`

**Interfaces:**
- Produces: `MCPServerEntry(..., data_classes=(), dlp_pre_hooks=(), manifest_purpose="")` — two new trailing keyword fields, both defaulted so every existing constructor stays green.

- [ ] **Step 1: Write the failing test**
```python
# tests/unit/protocol/test_mcp_host.py
def test_mcp_server_entry_dlp_fields_default_empty_and_settable() -> None:
    from cognic_agentos.protocol.mcp_host import MCPServerEntry
    e = MCPServerEntry(
        server_id="p", server_url="https://h/mcp", transport_kind="streamable-http",
        manifest_scopes=("s",), risk_tier="read_only", pack_signature_digest="d",
    )
    assert e.dlp_pre_hooks == ()
    assert e.manifest_purpose == ""
    e2 = MCPServerEntry(
        server_id="p", server_url="https://h/mcp", transport_kind="streamable-http",
        manifest_scopes=("s",), risk_tier="read_only", pack_signature_digest="d",
        data_classes=("internal",), dlp_pre_hooks=("refuse_forbidden_schema_arg",),
        manifest_purpose="operational_telemetry",
    )
    assert e2.dlp_pre_hooks == ("refuse_forbidden_schema_arg",)
    assert e2.manifest_purpose == "operational_telemetry"
    import pytest
    with pytest.raises((AttributeError, TypeError)):
        e2.dlp_pre_hooks = ()  # type: ignore[misc]  # frozen
```

- [ ] **Step 2: Run — expect FAIL** (`unexpected keyword argument 'dlp_pre_hooks'`)
Run: `uv run pytest tests/unit/protocol/test_mcp_host.py::test_mcp_server_entry_dlp_fields_default_empty_and_settable -v`

- [ ] **Step 3: Implement** — add two fields after `data_classes` at `mcp_host.py:276`:
```python
    data_classes: tuple[str, ...] = ()
    dlp_pre_hooks: tuple[str, ...] = ()
    """Manifest ``[data_governance].dlp_pre_hooks`` (M5, ADR-017): the
    calling tool pack's declared dlp_pre hook ids. Empty ⇒ no DLP scan
    (byte-identical no-op). Set at registration by the off-gate mapper."""
    manifest_purpose: str = ""
    """Manifest ``[data_governance].purpose`` (M5); threaded into the
    ``HookContext.manifest_purpose`` field at scan time. Empty default
    keeps pre-M5 constructors green."""
```
Extend the class docstring's field list (`mcp_host.py:264-267`) with one line each.

- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: Commit** (halt for token). `git add src/cognic_agentos/protocol/mcp_host.py tests/unit/protocol/test_mcp_host.py && git commit -m "feat(m5): MCPServerEntry carries dlp_pre_hooks + manifest_purpose"`

### Task 2: `ToolInvocationRefusalReason` gains three DLP values

**Files:**
- Modify: `src/cognic_agentos/protocol/mcp_host.py:596-610`
- Test: `tests/unit/protocol/test_mcp_approval_seam.py:24-38`, `tests/unit/protocol/test_mcp_high_risk_tier_refused.py:556`

**Interfaces:**
- Produces: `ToolInvocationRefusalReason` = the 6 existing values **+** `"dlp_pre_refused"`, `"dlp_pre_failed"`, `"dlp_pre_guard_unavailable"` (nine total).

- [ ] **Step 1: Update the drift test to the target (it will fail first).** In `test_mcp_approval_seam.py`, rename `test_tool_invocation_refusal_reason_has_exactly_six_values` → `..._has_exactly_nine_values` and set the expected set:
```python
def test_tool_invocation_refusal_reason_has_exactly_nine_values() -> None:
    import typing
    from cognic_agentos.protocol.mcp_host import ToolInvocationRefusalReason
    assert set(typing.get_args(ToolInvocationRefusalReason)) == {
        "tool_approval_engine_not_available", "tool_approval_pending",
        "tool_approval_denied", "tool_approval_expired",
        "tool_approval_binding_mismatch", "tool_approval_request_not_found",
        "dlp_pre_refused", "dlp_pre_failed", "dlp_pre_guard_unavailable",
    }
```

- [ ] **Step 2: Run — expect FAIL** (set mismatch — 6 ≠ 9).
Run: `uv run pytest tests/unit/protocol/test_mcp_approval_seam.py::test_tool_invocation_refusal_reason_has_exactly_nine_values -v`

- [ ] **Step 3: Implement** — extend the Literal at `mcp_host.py:603-610` (append the three values) and update the `#:` doc comment (596-602) to say "M5 extended it with the three DLP pre-invocation reasons → nine values; drift-pinned in `test_mcp_approval_seam.py` + `test_mcp_high_risk_tier_refused.py`."

- [ ] **Step 4: Fix the sibling drift assertion.** `test_mcp_high_risk_tier_refused.py:556` asserts `frozenset(get_args(host_module.ToolInvocationRefusalReason))` against a hard-coded set — read that assertion and add the three new values to its expected set (grep the surrounding `assert` to see the exact literal).

- [ ] **Step 5: Run both — expect PASS.**
Run: `uv run pytest tests/unit/protocol/test_mcp_approval_seam.py tests/unit/protocol/test_mcp_high_risk_tier_refused.py -v`

- [ ] **Step 6: Commit** (halt for token). `git add src/cognic_agentos/protocol/mcp_host.py tests/unit/protocol/test_mcp_approval_seam.py tests/unit/protocol/test_mcp_high_risk_tier_refused.py && git commit -m "feat(m5): three DLP pre-invocation refusal reasons"`

### Task 3: `MCPHost.__init__` accepts an optional `dlp_guard`

**Files:**
- Modify: `src/cognic_agentos/protocol/mcp_host.py:664-793` (+ a `TYPE_CHECKING` import)
- Test: `tests/unit/protocol/test_mcp_host_dlp.py` (Create)

**Interfaces:**
- Consumes: `DLPGuard` from `cognic_agentos.packs.hooks.dlp_integration` (SDK-free import).
- Produces: `MCPHost(..., dlp_guard: DLPGuard | None = None)` → `self._dlp_guard`.

- [ ] **Step 1: Write the failing test** (a small host builder to reuse across Part A tests):
```python
# tests/unit/protocol/test_mcp_host_dlp.py
import pytest
from cognic_agentos.protocol.mcp_host import MCPHost, MCPServerEntry

def _entry(**kw) -> MCPServerEntry:
    base = dict(server_id="oracle", server_url="https://h/mcp",
                transport_kind="streamable-http", manifest_scopes=("s",),
                risk_tier="read_only", pack_signature_digest="d")
    base.update(kw)
    return MCPServerEntry(**base)  # type: ignore[arg-type]

def _host(*, entry, dlp_guard, transports, authz, audit_store, dh_store, settings):
    return MCPHost(servers={entry.server_id: entry}, transports=transports,
                   authz=authz, audit_store=audit_store,
                   decision_history_store=dh_store, settings=settings,
                   dlp_guard=dlp_guard)

def test_host_accepts_dlp_guard_and_defaults_none(mcp_test_deps) -> None:
    # mcp_test_deps: an existing conftest fixture giving (transport, authz, audit, dh, settings)
    d = mcp_test_deps
    h = MCPHost(servers={}, transports=d.transports, authz=d.authz,
                audit_store=d.audit_store, decision_history_store=d.dh_store,
                settings=d.settings)
    assert h._dlp_guard is None
    guard = object()  # placeholder; real DLPGuard in later tasks
    h2 = MCPHost(servers={}, transports=d.transports, authz=d.authz,
                 audit_store=d.audit_store, decision_history_store=d.dh_store,
                 settings=d.settings, dlp_guard=guard)  # type: ignore[arg-type]
    assert h2._dlp_guard is guard
```
> First read `tests/unit/protocol/test_mcp_host.py` for the existing MCP-deps fixture (transport/authz/audit/dh/settings) and reuse it; name the conftest fixture accordingly rather than inventing `mcp_test_deps`.

- [ ] **Step 2: Run — expect FAIL** (`unexpected keyword argument 'dlp_guard'`).
- [ ] **Step 3: Implement.** Add to `__init__` signature after `override_store` (675): `dlp_guard: "DLPGuard | None" = None,`. Add under TYPE_CHECKING imports: `from cognic_agentos.packs.hooks.dlp_integration import DLPGuard`. Store after `self._override_store` (783): `self._dlp_guard = dlp_guard` with a comment mirroring the `override_store` note (None ⇒ no DLP; wired ⇒ `call_tool` scans packs that declare `dlp_pre_hooks`).
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: Commit** (halt for token). `git add src/cognic_agentos/protocol/mcp_host.py tests/unit/protocol/test_mcp_host_dlp.py && git commit -m "feat(m5): MCPHost accepts optional dlp_guard"`

### Task 4: `_dlp_pre_scan` + `call_tool` insertion (the core gate)

**Files:**
- Modify: `src/cognic_agentos/protocol/mcp_host.py` (new `_dlp_pre_scan`; `call_tool` insert after the approval gate at ~1476)
- Test: `tests/unit/protocol/test_mcp_host_dlp.py`

**Interfaces:**
- Consumes: `DLPGuard.scan_pre(*, payload: bytes, declared_hook_ids: Sequence[str], context_template: HookContext) -> DLPGuardOutcome`; `HookContext` (`sdk/hook.py:112`, 9 fields); `DLPGuardOutcome.{outcome, refusal_reason, underlying_policy_reason, failed_hook_id, failed_pack_distribution_name, policy_input_digest}`; `canonical_bytes` (`mcp_host.py:580`).
- Produces: a private `async _dlp_pre_scan(*, entry, arguments, request_id, tenant_id, declared_risk_tier, tool_name) -> None` that returns on pass and raises `MCPToolInvocationRefused` (evidence already emitted) on refusal.

**Reason mapping (implement exactly):** `dlp_dispatcher_refused → dlp_pre_refused`; `dlp_dispatcher_failed → dlp_pre_failed`; `dlp_hook_id_unresolved → dlp_pre_failed`; guard-absent + non-empty hooks → `dlp_pre_guard_unavailable`.

- [ ] **Step 1: Write the failing tests** (one file, several cases). Build a real `DLPGuard` via the hook kernel (mirror `tests/unit/packs/hooks/test_dlp_hook_integration.py:160-210` `_seed_registry_with` + `_build_guard`). Seed two arg-gated `Hook` subclasses in-test: `_RefuseHook` (returns `HookResult(decision="refuse", policy_reason="forbidden_schema_arg")` when the payload contains the forbidden sentinel) and `_ExplodeHook` (raises on its sentinel).
```python
@pytest.mark.asyncio
async def test_empty_dlp_pre_hooks_is_noop_scan_not_called(mcp_test_deps, monkeypatch) -> None:
    d = mcp_test_deps
    called = False
    class _Spy:
        async def scan_pre(self, **kw):  # would flip `called`
            nonlocal called; called = True
            raise AssertionError("scan_pre must not run for empty hooks")
    entry = _entry(dlp_pre_hooks=())  # empty
    host = _host(entry=entry, dlp_guard=_Spy(), transports=d.transports, authz=d.authz,
                 audit_store=d.audit_store, dh_store=d.dh_store, settings=d.settings)
    await host._dlp_pre_scan(entry=entry, arguments={"table": "EMPLOYEES"},
                             request_id="r", tenant_id="t",
                             declared_risk_tier="read_only", tool_name="describe_table")
    assert called is False

@pytest.mark.asyncio
async def test_non_empty_hooks_absent_guard_fails_closed(mcp_test_deps) -> None:
    d = mcp_test_deps
    entry = _entry(dlp_pre_hooks=("refuse_forbidden_schema_arg",))
    host = _host(entry=entry, dlp_guard=None, transports=d.transports, authz=d.authz,
                 audit_store=d.audit_store, dh_store=d.dh_store, settings=d.settings)
    with pytest.raises(MCPToolInvocationRefused) as ei:
        await host._dlp_pre_scan(entry=entry, arguments={"table": "EMPLOYEES"},
                                 request_id="r", tenant_id="t",
                                 declared_risk_tier="read_only", tool_name="describe_table")
    assert ei.value.reason == "dlp_pre_guard_unavailable"

@pytest.mark.asyncio
async def test_policy_refuse_maps_to_dlp_pre_refused_digest_only(mcp_test_deps) -> None:
    d = mcp_test_deps
    registry = _seed_registry_with([(_RefuseHook, "dlp_pre", "input_validation")])
    guard = _build_guard(registry)
    entry = _entry(
        data_classes=("internal",),
        dlp_pre_hooks=("refuse_forbidden_schema_arg",),
        manifest_purpose="operational_telemetry",
    )
    host = _host(entry=entry, dlp_guard=guard, transports=d.transports, authz=d.authz,
                 audit_store=d.audit_store, dh_store=d.dh_store, settings=d.settings)
    with pytest.raises(MCPToolInvocationRefused) as ei:
        await host._dlp_pre_scan(
            entry=entry, arguments={"table": "__FORBIDDEN__"},
            request_id="r", tenant_id="t", declared_risk_tier="read_only",
            tool_name="describe_table")
    exc = ei.value
    assert exc.reason == "dlp_pre_refused"
    assert exc.payload.get("policy_reason") == "forbidden_schema_arg"
    # digest-only: the raw argument value never appears in the audit payload
    row = d.audit_store.append.await_args_list[-1].args[0]
    assert "__FORBIDDEN__" not in repr(row)
    assert row.payload["refusal_reason"] == "dlp_pre_refused"
    assert "dlp_policy_input_digest" in row.payload

@pytest.mark.asyncio
async def test_hook_exception_maps_to_dlp_pre_failed(mcp_test_deps) -> None:
    d = mcp_test_deps
    registry = _seed_registry_with([(_ExplodeHook, "dlp_pre", "input_validation")])
    guard = _build_guard(registry)
    entry = _entry(
        dlp_pre_hooks=("explode_schema_guard",),
        manifest_purpose="operational_telemetry",
    )
    host = _host(entry=entry, dlp_guard=guard, transports=d.transports, authz=d.authz,
                 audit_store=d.audit_store, dh_store=d.dh_store, settings=d.settings)
    with pytest.raises(MCPToolInvocationRefused) as ei:
        await host._dlp_pre_scan(
            entry=entry, arguments={"table": "__EXPLODE__"},
            request_id="r", tenant_id="t", declared_risk_tier="read_only",
            tool_name="describe_table")
    assert ei.value.reason == "dlp_pre_failed"

@pytest.mark.asyncio
async def test_passed_scan_returns_and_call_tool_reaches_transport(mcp_test_deps) -> None:
    # permitted arg → scan_pre passes → _dlp_pre_scan returns None → call_tool proceeds
    d = mcp_test_deps
    registry = _seed_registry_with([(_RefuseHook, "dlp_pre", "input_validation")])
    guard = _build_guard(registry)
    entry = _entry(
        dlp_pre_hooks=("refuse_forbidden_schema_arg",),
        manifest_purpose="operational_telemetry",
    )
    host = _host(entry=entry, dlp_guard=guard, transports=d.transports, authz=d.authz,
                 audit_store=d.audit_store, dh_store=d.dh_store, settings=d.settings)
    await host._dlp_pre_scan(
        entry=entry, arguments={"table": "EMPLOYEES"},
        request_id="r", tenant_id="t", declared_risk_tier="read_only",
        tool_name="describe_table")
```
Add a `call_tool`-level test: with a real refusing guard + spy authz + spy transport, assert `authz.acquire_token`, `transport.open_session`, and `transport.send` are **never awaited** on the refusal path (proves "no token/session/transport work reaches the tool").

- [ ] **Step 2: Run — expect FAIL** (`_dlp_pre_scan` undefined).
- [ ] **Step 3: Implement `_dlp_pre_scan`** (place near `_approval_gate`, ~`mcp_host.py:1300`):
```python
    #: DLP reason → wire refusal reason. dlp_hook_id_unresolved folds into
    #: dlp_pre_failed (DLP could not produce a clean verdict → fail closed).
    _DLP_REASON_TO_WIRE = {
        "dlp_dispatcher_refused": "dlp_pre_refused",
        "dlp_dispatcher_failed": "dlp_pre_failed",
        "dlp_hook_id_unresolved": "dlp_pre_failed",
    }

    async def _dlp_pre_scan(
        self, *, entry: MCPServerEntry, arguments: Mapping[str, Any],
        request_id: str, tenant_id: str, declared_risk_tier: str, tool_name: str,
    ) -> None:
        """M5 (ADR-017): run the calling pack's dlp_pre hooks over the
        canonical-serialized arguments BEFORE token/session/transport.
        Returns on pass; emits digest-only refusal evidence then raises
        MCPToolInvocationRefused on refusal. Empty dlp_pre_hooks ⇒ no-op."""
        if not entry.dlp_pre_hooks:
            return  # byte-identical no-op — no serialization, no guard call
        payload_bytes = canonical_bytes(dict(arguments))
        payload_digest = hashlib.sha256(payload_bytes).hexdigest()
        if self._dlp_guard is None:
            await self._emit_call_evidence(
                event_type="audit.tool_invocation_refused", decision="refused",
                decision_reason="dlp_pre_guard_unavailable", entry=entry,
                tool_name=tool_name, request_id=request_id, tenant_id=tenant_id,
                declared_risk_tier=declared_risk_tier,
                extra_audit_payload={"refusal_reason": "dlp_pre_guard_unavailable",
                                     "dlp_policy_input_digest": payload_digest,
                                     "declared_dlp_pre_hooks": list(entry.dlp_pre_hooks)},
                extra_decision_payload={"dlp_refusal": True})
            raise MCPToolInvocationRefused(
                "dlp_pre_guard_unavailable",
                f"tool {_sanitize_string_for_operator_surface(tool_name)!r} on "
                f"server {_sanitize_string_for_operator_surface(entry.server_id)!r} "
                f"declares dlp_pre_hooks but no DLP guard is wired; failing closed.")
        from cognic_agentos.sdk.hook import HookContext  # SDK-free
        template = HookContext(
            hook_id="", phase="dlp_pre", pack_id=entry.server_id, tenant_id=tenant_id,
            request_id=request_id, trace_id=None, parent_trace_id=None,
            manifest_data_classes=entry.data_classes,
            manifest_purpose=entry.manifest_purpose)
        outcome = await self._dlp_guard.scan_pre(
            payload=payload_bytes, declared_hook_ids=entry.dlp_pre_hooks,
            context_template=template)
        if outcome.refusal_reason is None:
            return  # passed — proceed with the ORIGINAL arguments (redaction deferred)
        wire = self._DLP_REASON_TO_WIRE[outcome.refusal_reason]
        await self._emit_call_evidence(
            event_type="audit.tool_invocation_refused", decision="refused",
            decision_reason=wire, entry=entry, tool_name=tool_name,
            request_id=request_id, tenant_id=tenant_id, declared_risk_tier=declared_risk_tier,
            extra_audit_payload={"refusal_reason": wire,
                                 "dlp_policy_input_digest": outcome.policy_input_digest,
                                 "dlp_failed_hook_id": outcome.failed_hook_id,
                                 "dlp_failed_pack_distribution_name": outcome.failed_pack_distribution_name},
            extra_decision_payload={"dlp_refusal": True})
        raise MCPToolInvocationRefused(
            wire,  # type: ignore[arg-type]  # ∈ ToolInvocationRefusalReason (Task 2)
            f"dlp_pre hook refused tool "
            f"{_sanitize_string_for_operator_surface(tool_name)!r} on server "
            f"{_sanitize_string_for_operator_surface(entry.server_id)!r}",
            policy_reason=outcome.underlying_policy_reason)
```
> Note the `dlp_pre_refused` payload carries `policy_reason=outcome.underlying_policy_reason` (the hook's closed-enum reason) — never the arguments.

- [ ] **Step 4: Insert the call in `call_tool`.** After the `_approval_gate` block (`mcp_host.py:1466-1475`) and before `_call_tool_inner` (1476), inside the same evidence-emitting `try`:
```python
            await self._dlp_pre_scan(
                entry=entry, arguments=arguments, request_id=request_id,
                tenant_id=tenant_id, declared_risk_tier=declared_risk_tier,
                tool_name=tool_name)
```
The existing `except MCPToolInvocationRefused: raise` (1484) already prevents the generic-Exception arm from double-emitting (evidence was emitted at the `_dlp_pre_scan` refusal site — same pattern as `_approval_gate`).

- [ ] **Step 5: Run the Task-4 tests — expect PASS.**
Run: `uv run pytest tests/unit/protocol/test_mcp_host_dlp.py -v`

- [ ] **Step 6: CC gate + commit** (halt for token). Run the full gate:
```bash
uv run ruff check && uv run ruff format --check && uv run mypy src tests
uv run pytest --cov=cognic_agentos --cov-branch --cov-report=json -q
uv run python tools/check_critical_coverage.py   # mcp_host.py must hold 95/90
git diff --stat src/cognic_agentos/protocol/mcp_authz.py   # MUST be empty
git add src/cognic_agentos/protocol/mcp_host.py tests/unit/protocol/test_mcp_host_dlp.py
git commit -m "feat(m5): call_tool runs dlp_pre scan before token/session/transport"
```
If `check_critical_coverage.py` flags `mcp_host.py` below floor, add negative-path tests (guard-absent, each reason arm, the no-op early-return branch) in the SAME commit.

### Task 5: Portal route maps the three reasons; pin coverage

**Files:**
- Modify: `src/cognic_agentos/portal/api/mcp/routes.py:37-44, 140-144`
- Test: `tests/unit/portal/api/mcp/test_mcp_routes.py`

**Interfaces:**
- Consumes: `MCPToolInvocationRefused.reason` (now nine values) + `.payload["policy_reason"]`.

- [ ] **Step 1: Write the failing tests** — three reason→status rows + a coverage-pin + `policy_reason` surfacing:
```python
def test_refusal_status_covers_every_reason() -> None:
    import typing
    from cognic_agentos.portal.api.mcp.routes import _REFUSAL_STATUS
    from cognic_agentos.protocol.mcp_host import ToolInvocationRefusalReason
    assert set(_REFUSAL_STATUS) == set(typing.get_args(ToolInvocationRefusalReason))

@pytest.mark.parametrize("reason,status", [
    ("dlp_pre_refused", 403), ("dlp_pre_failed", 409), ("dlp_pre_guard_unavailable", 503)])
def test_dlp_refusals_map_to_status(
    memory_settings: Any, memory_registry: Any, tmp_path: Any, reason: str, status: int
) -> None:
    # host stub raises MCPToolInvocationRefused(reason, policy_reason="forbidden_schema_arg")
    resp = _call(
        memory_settings,
        memory_registry,
        tmp_path,
        host=_StubHost(
            raises=MCPToolInvocationRefused(reason, policy_reason="forbidden_schema_arg")
        ),
        json={"tool_name": "describe_table", "arguments": {"table": "EMPLOYEES"}},
    )
    assert resp.status_code == status
    assert resp.json()["detail"]["reason"] == reason
    if reason == "dlp_pre_refused":
        assert resp.json()["detail"]["policy_reason"] == "forbidden_schema_arg"
```
> Reuse the existing route test harness in `test_mcp_routes.py` (a stub `MCPHost` on `app.state.mcp_host`); model the raise on the existing refusal-arm tests there.

- [ ] **Step 2: Run — expect FAIL** (`_REFUSAL_STATUS` missing 3 keys ⇒ KeyError/coverage-pin fail).
- [ ] **Step 3: Implement.** Add rows to `_REFUSAL_STATUS` (37-44): `"dlp_pre_refused": 403, "dlp_pre_failed": 409, "dlp_pre_guard_unavailable": 503`; update the `#:` comment (33-36) from "6-value" to "9-value". In the `except MCPToolInvocationRefused` arm (140-144), surface `policy_reason` when present:
```python
        except MCPToolInvocationRefused as exc:
            detail: dict[str, Any] = {"reason": exc.reason}
            if exc.reason == "tool_approval_pending":
                detail["approval_request_id"] = exc.payload.get("approval_request_id")
            if exc.reason == "dlp_pre_refused" and exc.payload.get("policy_reason"):
                detail["policy_reason"] = exc.payload["policy_reason"]
            raise HTTPException(status_code=_REFUSAL_STATUS[exc.reason], detail=detail) from None
```
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: Commit** (halt for token). `git add src/cognic_agentos/portal/api/mcp/routes.py tests/unit/portal/api/mcp/test_mcp_routes.py && git commit -m "feat(m5): route maps dlp_pre refusals to 403/409/503"`

---

## PART B — Boot wiring (off-gate harness + lifespan)

### Task 6: Mapper extracts `dlp_pre_hooks` + `purpose`

**Files:**
- Modify: `src/cognic_agentos/harness/mcp_host.py:146-170`
- Test: `tests/unit/harness/test_mcp_host_builder.py`

**Interfaces:**
- Produces: `MCPServerEntry` populated with `dlp_pre_hooks` + `manifest_purpose` from `[data_governance]`.

- [ ] **Step 1: Write the failing test** — a candidate whose manifest has `[data_governance]` with `dlp_pre_hooks=["refuse_forbidden_schema_arg"]` + `purpose="operational_telemetry"` ⇒ the mapped entry carries both; a candidate without them ⇒ `()` / `""`; a malformed `dlp_pre_hooks` (non-list / blank entry) ⇒ warn-skip (mirror the `data_classes` warn-skip already in the mapper).
> Model the fixture on the existing `test_mcp_host_builder.py` mapper tests (a stub registry + a fake `extract_pack_manifest`).

- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** — in `_map_registered_packs_to_servers`, after the `data_classes` block (`harness/mcp_host.py:146-161`) and before constructing the entry (162), read `dlp_pre_hooks` + `purpose` off the same `dg` dict:
```python
        dlp_pre_hooks: tuple[str, ...] = ()
        if isinstance(dg, dict) and "dlp_pre_hooks" in dg:
            raw_h = dg["dlp_pre_hooks"]
            if not isinstance(raw_h, list) or not all(
                isinstance(h, str) and h.strip() for h in raw_h):
                logger.warning("mcp.pack_mcp_block_malformed",
                    extra={"distribution_name": cand.distribution_name,
                           "reason": "malformed dlp_pre_hooks"})
                continue
            dlp_pre_hooks = tuple(raw_h)
        manifest_purpose = ""
        if isinstance(dg, dict):
            p = dg.get("purpose")
            if isinstance(p, str):
                manifest_purpose = p
```
Add `dlp_pre_hooks=dlp_pre_hooks, manifest_purpose=manifest_purpose,` to the `MCPServerEntry(...)` call (170).

- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: Commit** (halt for token). `git add src/cognic_agentos/harness/mcp_host.py tests/unit/harness/test_mcp_host_builder.py && git commit -m "feat(m5): mapper extracts dlp_pre_hooks + purpose onto MCPServerEntry"`

### Task 7: Hook-registry boot loader (`harness/hook_registry.py`)

**Files:**
- Create: `src/cognic_agentos/harness/hook_registry.py`
- Test: `tests/unit/harness/test_hook_registry_builder.py`

**Interfaces:**
- Consumes: `PluginRegistry.iter_registered_pack_candidates()` (→ `RegisteredPackCandidate{distribution_name, package_name, signature_digest}`); `extract_pack_manifest`; `HookRegistry(*, max_timeout_seconds)`; `HookDeclaration(...)`; `VerifiedHookPack(...)`; `HookDispatcher(*, registry, max_payload_bytes, max_timeout_seconds_runtime, audit_emitter=None)`; `DLPGuard(*, dispatcher, audit_emitter=None)`; `importlib.metadata` entry-points (group `cognic.hooks`); `Settings.hook_max_timeout_s`.
- Produces: `build_dlp_guard(*, registry, settings) -> DLPGuard` (raises only on hard construction failure; skips malformed hook packs per-pack).

- [ ] **Step 1: Write the failing tests:**
```python
# a stub registry yields one candidate whose distribution ships a real
# cognic.hooks entry-point + a [hooks] block with one declaration.
@pytest.mark.asyncio
async def test_build_dlp_guard_admits_verified_hook_pack(
    monkeypatch: pytest.MonkeyPatch, settings: Settings
) -> None:
    guard = build_dlp_guard(registry=stub, settings=settings)
    # scan_pre against the declared hook resolves (not dlp_hook_id_unresolved)
    outcome = await guard.scan_pre(
        payload=canonical_bytes({"table": "EMPLOYEES"}),
        declared_hook_ids=("refuse_forbidden_schema_arg",),
        context_template=_ctx_template(pack_id="cognic-tool-oracle-schema"),
    )
    assert outcome.outcome == "passed"

def test_malformed_hook_pack_is_skipped_not_fatal(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    # candidate with a [hooks] declaration whose hook_id has no matching
    # entry-point → that pack is skipped (logged); guard still builds.
def test_pack_without_hooks_block_is_ignored(
    monkeypatch: pytest.MonkeyPatch, settings: Settings
) -> None:
    # non-hook packs (no [hooks]) contribute nothing; guard builds empty-registry.
def test_missing_signature_digest_refuses_pack(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    # register_pack fail-closed on empty digest → pack skipped (logged).
```

- [ ] **Step 2: Run — expect FAIL** (module absent).
- [ ] **Step 3: Implement** `harness/hook_registry.py` (`from __future__ import annotations` is fine — no closure-local FastAPI Depends here; mirror `harness/mcp_host.py`'s header):
```python
"""Hook-registry production construction (M5, ADR-008 + ADR-017).

Walks the ALREADY-TRUSTED registry candidates (trust is upstream), admits each
verified hook pack's [hooks] declarations into a HookRegistry (digest-pinned via
register_pack), and assembles the DLPGuard the MCP host consumes. SDK-free; the
hook kernel imports cleanly. Per-pack fail-closed: a malformed hook pack is
skipped + logged (mirrors the MCP mapper); the guard still builds."""
from __future__ import annotations
import importlib.metadata as md
import logging
from typing import TYPE_CHECKING, Any, Protocol

from cognic_agentos.packs.hooks.dispatcher import HookDispatcher
from cognic_agentos.packs.hooks.dlp_integration import DLPGuard
from cognic_agentos.packs.hooks.registry import (
    HookDeclaration, HookRegistry, HookRegistryRefusal, VerifiedHookPack)
from cognic_agentos.protocol.mcp_manifest import (
    PackManifestMalformedError, PackManifestNotFoundError, extract_pack_manifest)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from cognic_agentos.core.config import Settings
    from cognic_agentos.protocol.plugin_registry import RegisteredPackCandidate

logger = logging.getLogger(__name__)

#: Payload budget fed to HookDispatcher.max_payload_bytes. There is NO
#: Settings field for this today (only Settings.hook_max_timeout_s exists);
#: a module constant is the YAGNI choice for M5. Promote to a Setting if an
#: operator ever needs to tune it (follow-up).
_HOOK_MAX_PAYLOAD_BYTES = 1_000_000

class _RegistryCandidates(Protocol):
    def iter_registered_pack_candidates(self) -> "Iterator[RegisteredPackCandidate]": ...

def _hooks_block(manifest: dict[str, Any]) -> list[dict[str, Any]] | None:
    """[hooks].declarations (canonical) with the legacy [tool.cognic.hooks]
    fallback; None when absent (non-hook pack)."""
    for path in (("hooks",), ("tool", "cognic", "hooks")):
        cur: Any = manifest
        for seg in path:
            cur = cur.get(seg) if isinstance(cur, dict) else None
        if isinstance(cur, dict) and isinstance(cur.get("declarations"), list):
            return [d for d in cur["declarations"] if isinstance(d, dict)]
    return None

def _entry_points_and_version(distribution_name: str) -> tuple[dict[str, md.EntryPoint], str | None]:
    try:
        dist = md.distribution(distribution_name)
    except md.PackageNotFoundError:
        return {}, None
    return ({ep.name: ep for ep in dist.entry_points if ep.group == "cognic.hooks"}, dist.version)

def _verified_pack(cand: "RegisteredPackCandidate", manifest: dict[str, Any],
                   decls_raw: list[dict[str, Any]]) -> VerifiedHookPack | None:
    eps, dist_version = _entry_points_and_version(cand.distribution_name)
    if dist_version is None:
        logger.warning("hook.distribution_not_found",
            extra={"distribution_name": cand.distribution_name})
        return None
    decls: list[HookDeclaration] = []
    for d in decls_raw:
        hook_id = d.get("hook_id")
        ep = eps.get(hook_id) if isinstance(hook_id, str) else None
        if ep is None:
            logger.warning("hook.declaration_no_entry_point",
                extra={"distribution_name": cand.distribution_name, "hook_id": hook_id})
            return None  # per-pack fail-closed: a declared hook must have an entry-point
        try:
            decls.append(HookDeclaration(
                hook_id=hook_id, phase=d["phase"], ordering_class=d["ordering_class"],
                timeout_seconds=float(d["timeout_seconds"]), fail_policy=d["fail_policy"],
                fail_open_exception=d.get("fail_open_exception"),
                callable_loader=ep.load))  # deferred load; NOT invoked here
        except (KeyError, ValueError, TypeError) as exc:
            logger.warning("hook.declaration_malformed",
                extra={"distribution_name": cand.distribution_name, "error": str(exc)})
            return None
    try:
        return VerifiedHookPack(distribution_name=cand.distribution_name,
            distribution_version=dist_version,
            signature_digest=cand.signature_digest or "",
            declarations=tuple(decls))
    except ValueError as exc:  # duplicate (phase, hook_id) etc.
        logger.warning("hook.pack_malformed",
            extra={"distribution_name": cand.distribution_name, "error": str(exc)})
        return None

def build_dlp_guard(*, registry: _RegistryCandidates, settings: "Settings") -> DLPGuard:
    hook_registry = HookRegistry(max_timeout_seconds=float(settings.hook_max_timeout_s))
    for cand in registry.iter_registered_pack_candidates():
        try:
            manifest = extract_pack_manifest(
                distribution_name=cand.distribution_name, package_name=cand.package_name)
        except PackManifestNotFoundError:
            continue
        except PackManifestMalformedError:
            logger.warning("hook.pack_manifest_malformed",
                extra={"distribution_name": cand.distribution_name})
            continue
        decls_raw = _hooks_block(manifest)
        if not decls_raw:
            continue  # non-hook pack
        pack = _verified_pack(cand, manifest, decls_raw)
        if pack is None:
            continue
        try:
            hook_registry.register_pack(pack)
        except HookRegistryRefusal as exc:
            logger.warning("hook.registry_refused",
                extra={"distribution_name": cand.distribution_name, "reason": exc.reason})
    dispatcher = HookDispatcher(
        registry=hook_registry,
        max_payload_bytes=_HOOK_MAX_PAYLOAD_BYTES,
        max_timeout_seconds_runtime=float(settings.hook_max_timeout_s))
    return DLPGuard(dispatcher=dispatcher)
```
> Verified: `Settings.hook_max_timeout_s` exists (`core/config.py:878`, default 30.0). There is NO Settings field for the payload budget — the dispatcher's `max_payload_bytes` is only ever passed literally in tests today — so the boot loader uses the `_HOOK_MAX_PAYLOAD_BYTES` module constant above (keeps M5 off the `core/config.py` stop-rule surface).

- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: Commit** (halt for token). `git add src/cognic_agentos/harness/hook_registry.py tests/unit/harness/test_hook_registry_builder.py && git commit -m "feat(m5): hook-registry boot loader builds the DLPGuard"`

### Task 8: Thread `dlp_guard` through `build_mcp_host` + the lifespan

**Files:**
- Modify: `src/cognic_agentos/harness/mcp_host.py:175-224`; `src/cognic_agentos/portal/api/app.py:789-809`
- Test: `tests/unit/harness/test_mcp_host_builder.py`; an app-lifespan test (find the existing one via `grep -rln "app.state.mcp_host" tests/`)

**Interfaces:**
- Produces: `build_mcp_host(..., dlp_guard: DLPGuard | None = None)` → `MCPHost(..., dlp_guard=dlp_guard)`.

- [ ] **Step 1: Write the failing test** — `build_mcp_host(..., dlp_guard=g)` yields a host whose `_dlp_guard is g`; default `None` keeps `_dlp_guard is None`.
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement.** In `build_mcp_host` add `dlp_guard: "DLPGuard | None" = None` (import under TYPE_CHECKING) and pass `dlp_guard=dlp_guard` to `MCPHost(...)` (210-224). In `app.py`, inside the `if registry is not None and is_mcp_available():` block (789), before `build_mcp_host` (797), fail-soft-build the guard and thread it:
```python
                    from cognic_agentos.harness.hook_registry import build_dlp_guard
                    from cognic_agentos.harness.mcp_host import build_mcp_host
                    mcp_http_client = httpx.AsyncClient()
                    try:
                        try:
                            dlp_guard = build_dlp_guard(registry=registry, settings=settings)
                        except Exception:
                            logger.error("mcp.dlp_guard_construction_failed", exc_info=True)
                            dlp_guard = None  # per-pack fail-closed handles hooked packs
                        app.state.dlp_guard = dlp_guard
                        app.state.mcp_host = build_mcp_host(
                            registry=registry, runtime=runtime, settings=settings,
                            http_client=mcp_http_client, vault_client=adapters.secret,
                            discovery_status_recorder=discovery_status_recorder,
                            dlp_guard=dlp_guard)
                    except Exception:
                        logger.error("mcp.host_construction_failed", exc_info=True)
                        await mcp_http_client.aclose()
                        mcp_http_client = None
                        app.state.mcp_host = None
```
Predeclare `app.state.dlp_guard = None` alongside `app.state.mcp_host = None` (near `app.py:1176`).
- [ ] **Step 4: Run — expect PASS** (builder + lifespan tests).
- [ ] **Step 5: Commit** (halt for token). `git add src/cognic_agentos/harness/mcp_host.py src/cognic_agentos/portal/api/app.py tests/unit/harness/test_mcp_host_builder.py tests/<lifespan test> && git commit -m "feat(m5): lifespan builds + wires DLPGuard into the MCP host"`

> **End of Part A+B: run the full gate once more** (`ruff` + `mypy src tests` + full suite + fresh coverage + `check_critical_coverage.py`) before Part C. `main`/branch stays deployable — every existing pack has empty `dlp_pre_hooks` (no-op).

---

## PART C — Deployed proof (`kind`), after A+B green

> Model everything on `infra/proof-m4/` (Dockerfiles, `manifests/`, `proof-m4-values.yaml`, `seed-db.sh`, `seed-vault.sh`, `run-proof-m4.sh`, `README.md`). The proof consumes the two **externally-built, signed** packs (Appendix A) — stage their wheels/images the way proof-m4 stages the released oracle pack; do NOT build pack source in this repo.

### Task 9: `infra/proof-m5/` scaffolding

**Files:** Create `infra/proof-m5/` (copy-and-adapt proof-m4): `Dockerfile.agentos-proof` (rebuild the kernel image WITH the M5 branch so the DLP wiring is baked in — reuse the M4 site-packages-chmod fix), `Dockerfile.as`, `Dockerfile.oracle-pack` (now stages `v0.2.0`), a hook-pack staging step, `manifests/`, `proof-m5-values.yaml`, `migrate-job.yaml`, `seed-db.sh`, `seed-vault.sh`, `README.md`.

- [ ] **Step 1:** Copy `infra/proof-m4/` → `infra/proof-m5/`; update names/labels; point the oracle image at `v0.2.0`; add the hook-pack wheel into the kernel image so `iter_registered_pack_candidates()` sees it (trust-register the hook pack — the tool is operator-installed via the M4 flow, the hook is trust-register + registry-admit only, per spec §6).
- [ ] **Step 2:** Extend `README.md` to state the three DLP bars + the trust-register-vs-operator-install split.
- [ ] **Step 3: Commit** (halt for token). `git add infra/proof-m5/ && git commit -m "chore(m5): proof-m5 kind scaffolding (from proof-m4)"` (exclude `run-proof-m5.sh` — Task 10).

### Task 10: `run-proof-m5.sh` — the three DLP bars

**Files:** Create `infra/proof-m5/run-proof-m5.sh` (model `run-proof-m4.sh`; env-gated `COGNIC_RUN_PROOF_M5=1`; NO default-on CI job).

- [ ] **Step 1:** Bring up the cluster (reuse the M4 flow through `install` for oracle `v0.2.0`); confirm the hook pack is registry-admitted (assert a boot log / a `HookRegistry`-admitted probe).
- [ ] **Step 2: BAR 1 (happy):** `call_tool(describe_table, owner=COGNIC, table=EMPLOYEES)` → 200, `FULL_NAME` present (hook ran + clean call passed). Print `PROOF M5 (BAR 1) PASS`.
- [ ] **Step 3: BAR 2 (closer):** `call_tool(..., table=__FORBIDDEN__)` → **403** `dlp_pre_refused` (+ `policy_reason`); assert the Oracle tool was **not** invoked (no new tool audit row / no query) and the audit row is **digest-only** (grep the row for the forbidden literal → absent). Print `PROOF M5 (BAR 2) PASS`.
- [ ] **Step 4: BAR 3 (fail-closed):** `call_tool(..., table=__EXPLODE__)` → **409** `dlp_pre_failed`. Print `PROOF M5 (BAR 3) PASS`.
- [ ] **Step 5:** On any bar failure, capture logs + status + reason to `docs/VALIDATION-RESULTS.md` and exit non-zero (never redefine the proof downward). On success, `RUNNER_EXIT=0` + `PROOF M5 (ALL BARS) PASS`.
- [ ] **Step 6: Commit** (halt for token). `git add infra/proof-m5/run-proof-m5.sh && git commit -m "test(m5): deployed 3-bar DLP hook proof runner"`

### Task 11: Live proof + evidence + milestone flip

- [ ] **Step 1:** Run the live proof (operator-run): `COGNIC_RUN_PROOF_M5=1 ./infra/proof-m5/run-proof-m5.sh` — iterate on harness/deploy findings (expect several, per M3/M4) until `PROOF M5 (ALL BARS) PASS`. Any genuine kernel bug the live path surfaces is fixed under TDD on the branch (re-run the CC gate).
- [ ] **Step 2:** Write the `docs/VALIDATION-RESULTS.md` "M5 — Real hook pack proof — PASS" section (the run id, the three bar outcomes, the digest-only assertion).
- [ ] **Step 3:** Flip M5 to `[x]` in `docs/PRODUCTION_GRADE_MILESTONE_CHECKLIST.md` — **only after** the live proof passes.
- [ ] **Step 4: Commit** (halt for token) → then PR `feat/m5-hook-pack-proof` → `main` (CI is the authority for the milestone/CC work), per the per-action discipline.

---

## Appendix A — Separate-repo pack shapes (NAMED, not built here)

### A.1 `cognic-hook-schema-guard` (new signed hook pack)
`pyproject.toml`:
```toml
[project.entry-points."cognic.hooks"]
refuse_forbidden_schema_arg = "cognic_hook_schema_guard.hooks:RefuseForbiddenSchemaArg"
explode_schema_guard        = "cognic_hook_schema_guard.hooks:ExplodeSchemaGuard"

[[hooks.declarations]]
hook_id = "refuse_forbidden_schema_arg"
phase = "dlp_pre"
ordering_class = "input_redaction"   # a dlp_pre-phase class (HOOK_ORDERING_CLASS_PHASE)
timeout_seconds = 1.0
fail_policy = "fail_closed"

[[hooks.declarations]]
hook_id = "explode_schema_guard"
phase = "dlp_pre"
ordering_class = "input_redaction"
timeout_seconds = 1.0
fail_policy = "fail_closed"
```
Two `Hook` subclasses (subclass `cognic_agentos.sdk.hook.Hook` and implement the abstract `async def _invoke(self, context: HookContext, payload: bytes) -> HookResult` — the `(context, payload)` arg order per `sdk/hook.py:373`; `Hook.invoke` at `:347` is the public wrapper that enforces the result contract). Deterministic, no-LLM:
- `RefuseForbiddenSchemaArg._invoke(self, context, payload)` — decode the canonical `payload` bytes; if the arguments contain the forbidden sentinel (e.g. `table == "__FORBIDDEN__"`, documented), return `HookResult(decision="refuse", redacted_payload=None, policy_reason="forbidden_schema_arg")`; else `HookResult(decision="pass", redacted_payload=None, policy_reason=None)`.
- `ExplodeSchemaGuard._invoke(self, context, payload)` — if the arguments contain the explode sentinel (`table == "__EXPLODE__"`), `raise RuntimeError("schema guard exploded")`; else `HookResult(decision="pass", redacted_payload=None, policy_reason=None)`.
Release shape identical to M3: wheel + 7 attestations + `cosign.pub` + independent CI. Read the real `Hook` / `HookResult` API in `sdk/hook.py` (incl. the `decision`↔`redacted_payload`/`policy_reason` field invariants) before implementing.

### A.2 `cognic-tool-oracle-schema@v0.2.0` (re-release)
Add (cross-checked against `[risk_tier].tier = "read_only"`):
```toml
[data_governance]
data_classes     = ["internal"]
purpose          = "operational_telemetry"
retention_policy = "none"
dlp_pre_hooks    = ["refuse_forbidden_schema_arg", "explode_schema_guard"]  # BAR-3 delta
```
`v0.1.0` stays the M3/M4 evidence artifact; `v0.2.0` is the M5 DLP-governed release. Both coexist.

---

## Self-Review

**Spec coverage:** §2 dormant-wiring → T3/T4/T7/T8. §3 decisions → all tasks. §4 five pieces → T7 (HookRegistry) / T7 (DLPGuard) / T6 (mapper) / T4 (scan_pre before transport) / T5 (status map). §4.1 six invariants → T4 (canonical-bytes, digest-only, no-op, absent-guard fail-closed, HookContext completeness) + T7 (trusted-pack-only admission). §4.2 CC posture → T4/T5 gate steps. §5 packs → Appendix A. §6 three bars → T9-T11. §7 tests → each task's tests. §8 out-of-scope → honored (scan_post/redaction untouched; passed path proceeds with original args). §9 open risks → resolved: canonical form (global constraints), insertion point (T4 after approval / before inner), forbidden-arg definition (Appendix A sentinels).

**Placeholder scan:** no omitted test bodies or implementation placeholders remain. The remaining ellipses are Python variadic type notation (`tuple[str, ...]`), Protocol stubs (`...` as the method body), or prose shorthand for existing constructor/path context; no `TODO`/`TBD`.

**Type consistency:** `dlp_pre_hooks: tuple[str,...]`, `manifest_purpose: str`, `dlp_guard: DLPGuard | None`, the `_DLP_REASON_TO_WIRE` values ⊆ the Task-2 Literal, `_REFUSAL_STATUS` keys == the nine-value enum (T5 pin), `HookContext` 9 fields all set (T4) — consistent across tasks.

**Citations verified this pass:** `mcp_host.py` symbols (MCPServerEntry:270-276, refusal enum:603-610, `__init__`:664, `_emit_call_evidence`:2049, `call_tool` approval-gate:1466 / inner:1476), `_REFUSAL_STATUS` (routes.py:37-44), `DLPGuard`/`DLPGuardOutcome`/`scan_pre` (dlp_integration.py), `HookRegistry`/`VerifiedHookPack`/`HookDeclaration`/`register_pack` (registry.py), `HookDispatcher.__init__` (dispatcher.py:237), `Hook._invoke` order (sdk/hook.py:373), `Settings.hook_max_timeout_s` (config.py:878, no payload-bytes field → module constant), both refusal-enum drift tests (test_mcp_approval_seam.py:24 + test_mcp_high_risk_tier_refused.py:556), CC gate (check_critical_coverage.py:831), `input_redaction`→`dlp_pre` (_governance_vocab.py:299). **One watch-item for the implementer** (inline, non-blocking): reuse — not reinvent — the existing MCP-deps + route-client conftest fixtures (T3/T4/T5 notes).
