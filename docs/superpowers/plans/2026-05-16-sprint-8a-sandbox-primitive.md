# Sprint 8A — Sandbox primitive (core + Docker-sibling backend + canonical image catalog) — Implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Each T-task that touches a CC module ends with an explicit halt-before-commit gate per AGENTS.md "Critical-controls rule".

**Goal:** ship Sprint 8A — the first of two Wave-1 sandbox backends — per the [T1 design spec](../specs/2026-05-16-sprint-8a-sandbox-primitive-design.md) (committed at `287fb90`) + the 3 ADR amendments (committed at `624a469`). Lands the `SandboxBackend` Protocol + `DockerSiblingSandboxBackend` + 4-image canonical catalog + dual-container internal-network egress topology + warm-pool + audit + admission pipeline + Rego bundle. Sprint 8B (Kubernetes/OpenShift backend) is the sibling sprint and consumes the same Protocol + conformance suite.

**Architecture:** layered subpackage `sandbox/` under `src/cognic_agentos/` matching the established `core/memory/` / `core/scheduler/` / `core/approval/` pattern. Audit event emission lands at T4 BEFORE any module that emits (admission / catalog / proxy / warm-pool / backend depend on it). Backend selection at process-wide env var (`COGNIC_SANDBOX_BACKEND=docker_sibling`). Forward-compatible with Sprint 10.5 scheduler wrap (no breaking change at 10.5 landing).

**Tech Stack:** Python 3.13 + asyncio + Pydantic v2 + docker-py (async) + pytest + pytest-asyncio + cosign subprocess + syft subprocess + grype subprocess + OPA Rego subprocess. Real Docker daemon required for env-gated DockerSibling integration tests (`COGNIC_RUN_DOCKER_SANDBOX=1`).

**Sprint sizing:** ~3.5 wu floor (core 3 wu + warm-pool minimum 0.5 wu); ceiling ~4.5 wu per the BUILD_PLAN §1142 schedule-risk row.

**Total tasks:** 11 implementation tasks (T3-T13) on top of T1 (spec, DONE) + T2 (this plan, COMMITTING). Per-T halt-before-commit on every CC module.

---

## Post-T5 implementation notes (added 2026-05-17 after T5 commit `4967ce8` + R2)

This plan was authored at T2 with the assumption that T5 could import
from yet-unlanded T6 + T8 modules. Three drifts surfaced at T5
implementation time and were resolved with user authorization; T6
and T8 implementors MUST read these notes before consuming the T5
code blocks below verbatim.

1. **Protocols + sentinel live in `sandbox/admission.py`, NOT in T6/T8 files.**
   The T5 plan-block code (lines ~1015-1016 + ~1376-1380) imports
   `CanonicalImageCatalog` from `sandbox.catalog` and
   `CredentialAdapter` + `KernelDefaultCredentialAdapter` from
   `sandbox.credentials`. The committed T5 implementation
   ([4967ce8](#)) declares **`CatalogProtocol` + `CredentialAdapter`
   Protocol + `KernelDefaultCredentialAdapter` concrete sentinel
   class** in `sandbox/admission.py` so T5 is independently
   compilable. T6 ships the concrete `CanonicalImageCatalog`
   structurally conforming to `CatalogProtocol`; T8 may either
   re-export the sentinel from `sandbox/credentials` for symmetry
   OR move its canonical home there (rewriting T5's import).
   Per the "consumer-owned Protocol when downstream not landed"
   resolution rule. (T5 R0 P3 doctrine decision.)

2. **Settings fields are `sandbox_per_tenant_max_*` (prefixed), NOT bare `per_tenant_max_*`.**
   The T5 plan-block mocks (e.g. line ~1086-1088) use unprefixed
   `MagicMock(per_tenant_max_cpu=4.0, ...)`. The committed T5
   implementation extends `core/config.py:Settings` with three
   sandbox-prefixed fields (`sandbox_per_tenant_max_cpu` /
   `sandbox_per_tenant_max_memory` /
   `sandbox_per_tenant_max_walltime`) per the in-repo
   sectioning convention (`ui_event_stream_*`, `adapters_*`).
   `admit_policy` + tests use the prefixed names.

3. **Rego decision-point is `data.cognic.sandbox.admit.allow` (the boolean expression), NOT bare `data.cognic.sandbox.admit` (the package); `OPAEngine.evaluate` is kw-only.**
   The T5 plan-block code (line ~1497-1521) calls
   `rego_engine.evaluate("data.cognic.sandbox.admit", input={...})`
   positionally and reads `.allowed` / `.deny_reason`. Three
   fixups in the committed implementation:
   * Real `OPAEngine.evaluate` signature at
     `core/policy/engine.py:269` is kw-only `evaluate(*,
     decision_point: str, input: dict)`.
   * Decision-point points at the `.allow` boolean expression
     INSIDE the package (spec §6.1 step 9 + §816 + §920) — NOT
     the bare package, which would return a dict and trip
     `RegoEvaluationError` once T11's real bundle lands per
     `core/policy/engine.py:296-298`. (T5 R1 P1 BLOCKING fix.)
   * `Decision` shape uses `.allow` (not `.allowed`) +
     `.reasoning` (not `.deny_reason`) per
     `core/policy/engine.py:133`.

   T9 (sandbox.rego bundle) authors MUST declare the `allow`
   rule INSIDE the `data.cognic.sandbox.admit` package per this
   wire-contract.

**Affected downstream tasks:**
* **T6 (this task next)** — the catalog implementation must
  structurally conform to `CatalogProtocol` declared in
  `sandbox/admission.py` (4 methods: 2 sync `is_canonical` /
  `is_tenant_allow_listed` + 2 async `verify_cosign_or_refuse` /
  `verify_sbom_policy_or_refuse`). Adding `CanonicalImageCatalog`
  as a Protocol subclass is OPTIONAL — structural conformance is
  what `admit_policy` needs.
* **T8** — `sandbox/credentials.py` becomes one of: (a) a
  re-export shim that does `from cognic_agentos.sandbox.admission
  import CredentialAdapter, KernelDefaultCredentialAdapter`
  (cheapest), (b) the new canonical home with `admission.py`
  importing back from it (cyclic-resolve via TYPE_CHECKING),
  or (c) a full move that updates `admission.py` to import from
  `credentials`. Decision is T8's; the user's preference at T5
  R0 was option (a) re-export shim.
* **T9 (sandbox.rego)** — bundle MUST declare
  `package cognic.sandbox.admit` with a top-level `allow := false`
  default + explicit allow rules per the `.allow`-suffix
  wire-contract.

---

## Post-T9 implementation notes (added 2026-05-17 before T10 execution)

T10 is the first integration-heavy task in Sprint 8A — every earlier
seam (protocol, policy, admission, catalog, audit, proxy, credentials,
warm_pool) lands together inside `DockerSiblingSandboxBackend`. Per
user direction (2026-05-17), T10 is **split deliberately** into
T10a / T10b / T10c with a halt-before-commit per sub-task. This is
NOT a one-shot "land all then halt" pattern.

**Sub-task scope (locked at T10 pre-flight):**

* **T10a** — lifecycle + dual-container topology. `create()` / `destroy()` /
  `health()` implementing `SandboxBackend` Protocol; per-session internal
  Docker network with `Internal=true` + proxy sidecar on internal+egress
  networks; sandbox `HTTP_PROXY` / `HTTPS_PROXY` env wiring. Also lands the
  `sandbox_session` `@asynccontextmanager` helper in `sandbox/__init__.py`
  per spec §288-334 (warm-pool-aware exit routing).
* **T10b** — resource caps + cgroup integration. `--memory` + `--memory-swap`
  for OOM kill; AgentOS-side `asyncio.wait_for` walltime; cgroup
  `cpuacct.usage_us` reader + kill for `cpu_time_budget_s`; image-pin
  validation. Spec §7 round-3 P2 invariant: `--cpus` throttling under
  cap is NOT a violation; only `cpu_time_budget_exceeded` fires (and
  only when set).
* **T10c** — egress integration + conformance harness. Proxy sidecar
  lifecycle (build `ALLOW_LIST` + `SESSION_ID` env from
  `EgressProxyConfig.to_env()`; read proxy_log JSON on exec exit;
  materialise via `proxy_log_to_chain_payload` onto
  `sandbox.lifecycle.exec_completed` chain row); shared conformance
  suite at `tests/conformance/sandbox/` parametrised on backend
  (Sprint 8B extends with `kubernetes_pod`).

**Pre-flight gap closures:**

1. **`aiodocker` was missing from `pyproject.toml`.** Plan recipe
   imports `aiodocker.Docker()`; without the dep, `pip install -e .`
   would leave the DockerSibling backend module unable to import.
   Resolution: added as `[project.optional-dependencies].sandbox-docker`
   extra (NOT base) so KubernetesPod-only deployments (Sprint 8B, the
   production target per AGENTS.md) do not pull a docker-py-stack
   dependency they don't use. Re-export from `sandbox/__init__.py`
   wrapped behind a try/except ImportError that surfaces a structured
   `NotImplementedError` pointing at the extra when missing. Per
   `feedback_verify_dep_availability_at_implementation`.

2. **`sandbox_session` helper context manager has no implementation
   yet.** Spec §288-334 declares the contract; T10a lands the
   implementation as part of the lifecycle wire-up. NOT a separate
   task — it composes the backend + warm_pool seams that T10a is
   already integrating.

3. **`cognic/sandbox-egress-proxy` canonical image — REAL artifact,
   NOT placeholder.** User-locked doctrine 2026-05-17: the canonical
   proxy image IS the security enforcement point; treating it as
   placeholder-only would make T10's "secure Docker sibling backend"
   green while the main egress control is absent. OSS components
   (tinyproxy / mitmproxy / envoy) ARE allowed only INSIDE the
   canonical cosign-signed image, OR as clearly-named local fixtures
   behind an explicit `COGNIC_USE_LOCAL_FIXTURE_PROXY=1` env flag
   (refused in production profile). Missing canonical artifact at
   T10c env-gated test time → `pytest.skip(f"canonical artifact
   {ref} not pullable; ...")` with structured message naming the
   missing ref, NEVER silent OSS substitution. Per
   `feedback_canonical_artifact_not_oss_substitute`. T10c carries
   this as an explicit pre-flight blocker contract.

**Halt cadence:** each of T10a/T10b/T10c ends with a CC
halt-before-commit gate + per-action authorization token before
its commit. No "land all then halt" pattern.

---

## Post-T8 implementation notes (added 2026-05-17 after T8 patch decision)

T8's original plan body (pre-patch) wrote a richer
`CredentialLease + mint_lease/revoke_lease` API for both the Protocol +
the sentinel that did NOT match the T5-committed reality. T5 landed a
single-method `fetch_secret` API inline in `sandbox/admission.py`. The
divergence was a stale plan-body — the plan was authored at T2 before
T5's R0 CC-ADJ resolution chose the consumer-owned-Protocol pattern.

**Resolution (2026-05-17):** patched T8 body to:

1. Drop the `CredentialLease` dataclass + `mint_lease/revoke_lease`
   method-pair declarations. Those belong to Sprint 10's
   `VaultCredentialAdapter` concrete design, not the Wave-1 Protocol.
2. Make `sandbox/credentials.py` a thin re-export shim importing
   `CredentialAdapter` + `KernelDefaultCredentialAdapter` from
   `sandbox.admission` — per `feedback_consumer_owned_protocol_for_unlanded_dep`
   resolution preference (a) + the user's T5 R0 stated preference.
3. Rewrite the test recipe to pin object-identity re-export
   equivalence (`AdmissionCA is CredentialsCA`) + Protocol membership
   + the actual T5-committed `fetch_secret` stub error contract
   (cites Sprint 10 + ADR-009 + `VaultCredentialAdapter` + "fail-loud
   sentinel") + the admit_policy short-circuit invariant.

No CC-ADJ to `admission.py` — the sentinel's error message is
unchanged. The T8 test recipe expects the message that already ships at
`admission.py:136-143`.

Companion doctrine: `feedback_patch_plan_against_doctrine` (halt + patch
plan before executing) + `feedback_verify_code_citations_at_doc_write`
(the patched test recipe quotes the actual T5 message verbatim, not
cite-from-memory).

---

## Source-doctrine references

| Doc | Commit | Scope |
|---|---|---|
| T1 design spec | `287fb90` | `docs/superpowers/specs/2026-05-16-sprint-8a-sandbox-primitive-design.md` (1012 lines, 24 reviewer findings across 5 rounds) |
| ADR-004 amendment | `624a469` | DockerSibling naming + dual-backend Wave-1 + immutable image doctrine + 4-image catalog + dual-container egress topology + CPU semantics + 8A/8B/8.5/9/10/10.5/13.5/W2 phase table |
| ADR-016 amendment | `624a469` | "AgentOS-published runtime artifacts" subsection: 4-image catalog joins cosign+SBOM+vuln+licence+Sigstore-bundle pipeline; no trust shortcut for AgentOS-published |
| ADR-006 amendment | `624a469` | A.6.2.5 row extended: 8 sandbox lifecycle events + 2 closed-enum vocabularies |
| BUILD_PLAN §694-715 | merged via PR #26 | Sprint 8A deliverables + ≤500ms P95 exit + resource caps prove-out + egress allow-list blocks |
| AGENTS.md "Stop rules" | live | Sandbox tree is stop-rule isolation boundary; every edit requires `core-controls-engineer` + `/critical-module-mode` |

---

## File Structure

| Module | T-task | CC gate at landing | Test files | Lines (est.) |
|---|---|---|---|---|
| `sandbox/__init__.py` | T3 | NO (public re-exports only) | — | ~80 |
| `sandbox/protocol.py` | T3 | **YES** (Protocol contract) | `test_protocol_shape.py` (covered via T3) | ~150 |
| `sandbox/policy.py` | T3 | **YES** (pure validation + admission contract) | `test_policy_shape.py` | ~200 |
| `sandbox/audit.py` | T4 | NO (thin chain-row converter; upstream gates cover CC risk) | `test_audit_event_taxonomy.py` | ~250 |
| `sandbox/admission.py` | T5 | **YES** (Stage-2 admission pipeline) | `test_admission_pipeline.py` | ~350 |
| `sandbox/catalog.py` | T6 | **YES** (image-catalog enforcement point) | `test_image_catalog.py` | ~280 |
| `sandbox/proxy.py` | T7 | **YES** (egress enforcement point) | `test_egress_proxy_config.py` | ~220 |
| `sandbox/credentials.py` | T8 | NO (fail-loud stub; replaced by Sprint 10) | `test_credential_adapter_stub.py` | ~80 |
| `sandbox/warm_pool.py` | T9 | **YES** (bounded queue + drain semantics) | `test_warm_pool.py` | ~400 |
| `sandbox/backends/docker_sibling.py` | T10 | **YES** (backend-specific enforcement surface) | `test_docker_sibling_{lifecycle,egress,resource_caps,image_pin}.py` | ~600 |
| `policies/_default/sandbox.rego` | T11 | YES (stop-rule policy bundle) | `test_sandbox_rego.py` (in `tests/unit/policies/`) | ~100 |
| `tests/conformance/sandbox/test_backend_conformance.py` | T10 | — (conformance harness; Docker arm green at 8A; K8s arm parameterized in 8B) | — | ~300 |

**Module total**: ~10 production modules + 1 Rego bundle; **gate uplift 63 → 70** (7 modules promoted: protocol + policy + admission + catalog + proxy + warm_pool + backends/docker_sibling).

---

## Cross-task invariants (apply to EVERY T-task)

1. **CC halt-before-commit on every CC module** — per AGENTS.md "Critical-controls rule" + `feedback_strict_review_off_gate`. Each CC task ends with explicit halt + user-typed `commit` (or `commit without pytest`) token before commit fires.
2. **TDD red-then-green** — every new function gets a failing test FIRST, then minimal impl, then verify green. Per `superpowers:test-driven-development`.
3. **Gate ladder per task** — at halt-before-commit: `ruff check src tests` + `ruff format --check src tests` + `mypy src tests` (full-tree) + per-file pytest narrow. Full pytest suite runs at COMMIT TIME only per `feedback_gate_ladder_per_microfix`.
4. **Closed-enum drift detectors** — each closed-enum Literal (SandboxRefusalReason 15-value / SandboxPolicyViolationReason 5-value / SandboxLifecycleEvent 8-value) gets a partition-invariant test at module load.
5. **No mocks in production paths** — per AGENTS.md production-grade rule. Test mocks live ONLY under `tests/` paths. Fail-loud stubs (`KernelDefaultCredentialAdapter`) are explicit scaffolding pointing at the future sprint that replaces them.
6. **No runtime cross-module imports for shared constants** — per `feedback_drift_detector_test_only_no_runtime_import`. If two production modules share a constant, each declares its own local copy + a test asserts equality.
7. **Real `git diff --check`** — for untracked files use `git diff --no-index --check /dev/null <path>` per `feedback_git_diff_check_untracked`.
8. **Per-T commit message template** — `feat(sprint-8a): T<N> — <module> (<scope-tag>)`. CC modules tag `(CRITICAL CONTROLS)`. Co-Authored-By trailer mandatory.
9. **No push without explicit user authorization** per AGENTS.md + `feedback_explicit_authorization_per_action`.

---

## Task T3 — Protocol + Policy + PackAdmissionContext + closed-enum vocabularies

**Scope:** the foundation — every other T-task depends on these contracts. No backend logic; no I/O. Pure types + Protocols + pure validation.

**Files:**
- Create: `src/cognic_agentos/sandbox/__init__.py`
- Create: `src/cognic_agentos/sandbox/protocol.py`
- Create: `src/cognic_agentos/sandbox/policy.py`
- Create: `tests/unit/sandbox/__init__.py`
- Create: `tests/unit/sandbox/test_policy_shape.py`
- Modify: none

**Doctrine refs:** spec §4 (closed-enum vocabularies) + §5 (Protocol signatures) + §6 (SandboxPolicy schema + Stage-1 pure validation) + ADR-004 §Decision (per amendment).

### T3 steps

- [ ] **Step 1: Write failing test — closed-enum partition invariants**

```python
# tests/unit/sandbox/test_policy_shape.py
"""Sprint 8A T3 — pure Stage-1 shape validation + closed-enum vocab pins.

NO I/O. Stage-2 admission (catalog + cosign + SBOM + Rego) lives in
T5 (sandbox/admission.py); these tests cover ONLY the pure validation
surface per spec §6.1.
"""
from __future__ import annotations

import typing

import pytest

from cognic_agentos.sandbox import (
    SandboxRefusalReason,
    SandboxPolicyViolationReason,
    SandboxLifecycleEvent,
    PackAdmissionContext,
    SandboxPolicy,
    validate_policy_shape,
    SandboxLifecycleRefused,
)


class TestClosedEnumPartitionInvariants:
    """Pin the wire-protocol-public closed-enum values + counts."""

    def test_sandbox_refusal_reason_has_exactly_15_values(self) -> None:
        values = typing.get_args(SandboxRefusalReason)
        assert len(values) == 15, (
            f"SandboxRefusalReason must have 15 values per spec §4.1; "
            f"found {len(values)}: {values}"
        )

    def test_sandbox_policy_violation_reason_has_exactly_5_values(self) -> None:
        values = typing.get_args(SandboxPolicyViolationReason)
        assert len(values) == 5, (
            f"SandboxPolicyViolationReason must have 5 values per spec §4.2; "
            f"found {len(values)}: {values}"
        )

    def test_sandbox_lifecycle_event_has_exactly_8_values(self) -> None:
        values = typing.get_args(SandboxLifecycleEvent)
        assert len(values) == 8, (
            f"SandboxLifecycleEvent must have 8 values per spec §4.3; "
            f"found {len(values)}: {values}"
        )

    def test_sandbox_refusal_reason_includes_high_risk_pre_13_5(self) -> None:
        assert "sandbox_high_risk_tier_refused_pre_13_5" in typing.get_args(SandboxRefusalReason)

    def test_sandbox_policy_violation_reason_does_not_include_cpu_cap_exceeded(self) -> None:
        # Round-3 P2 fix: --cpus throttling under cap is NOT a violation
        assert "cpu_cap_exceeded" not in typing.get_args(SandboxPolicyViolationReason)
        assert "cpu_time_budget_exceeded" in typing.get_args(SandboxPolicyViolationReason)


class TestRiskTierDriftDetectorTestOnly:
    """Pin the sandbox-local RiskTier Literal against cli/_governance_vocab.RiskTier
    at test time WITHOUT a runtime cross-module import.

    Per feedback_drift_detector_test_only_no_runtime_import +
    AGENTS.md "Plugin discipline" (runtime sandbox code must not import
    build-time CLI vocab). Each module declares its own local Literal;
    this test imports from BOTH and asserts equality so drift fails CI.
    """

    def test_sandbox_local_risk_tier_matches_cli_governance_vocab(self) -> None:
        from cognic_agentos.cli._governance_vocab import RiskTier as CLIRiskTier
        from cognic_agentos.sandbox.policy import RiskTier as SandboxRiskTier

        cli_values = frozenset(typing.get_args(CLIRiskTier))
        sandbox_values = frozenset(typing.get_args(SandboxRiskTier))
        assert sandbox_values == cli_values, (
            f"sandbox/policy.py:RiskTier must mirror "
            f"cli/_governance_vocab.py:RiskTier verbatim. "
            f"sandbox-only: {sandbox_values - cli_values}; "
            f"cli-only: {cli_values - sandbox_values}"
        )

    def test_sandbox_module_does_not_runtime_import_cli_vocab(self) -> None:
        """AST-walk sandbox/policy.py source; assert no `from cognic_agentos.cli`
        import statement. Runtime sandbox must not depend on build-time CLI vocab."""
        import ast
        import inspect
        from cognic_agentos.sandbox import policy

        source = inspect.getsource(policy)
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert not node.module.startswith("cognic_agentos.cli"), (
                    f"sandbox/policy.py must not import from cognic_agentos.cli "
                    f"(found `from {node.module} import ...`); per AGENTS.md "
                    "Plugin discipline + feedback_drift_detector_test_only_no_runtime_import"
                )
```

- [ ] **Step 2: Run to verify fail**

```bash
uv run pytest tests/unit/sandbox/test_policy_shape.py -v
```

Expected: `ImportError: cannot import name 'SandboxRefusalReason' from 'cognic_agentos.sandbox'`.

- [ ] **Step 3: Implement closed-enums + PackAdmissionContext + SandboxPolicy + Protocol**

```python
# src/cognic_agentos/sandbox/protocol.py
"""Sprint 8A T3 — SandboxBackend + SandboxSession Protocols.

Wire-protocol-public per spec §5. Critical-controls module per AGENTS.md.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal, Protocol, runtime_checkable

# 15-value SandboxRefusalReason — wire-protocol-public per spec §4.1
SandboxRefusalReason = Literal[
    "sandbox_credential_adapter_not_configured",
    "sandbox_runtime_deps_unsupported_in_production",
    "sandbox_high_risk_tier_refused_pre_13_5",
    "sandbox_image_digest_not_in_canonical_catalog",
    "sandbox_image_cosign_verification_failed",
    "sandbox_image_sbom_check_failed",
    "sandbox_image_digest_format_invalid",
    "sandbox_policy_exceeds_tenant_max_cpu",
    "sandbox_policy_exceeds_tenant_max_memory",
    "sandbox_policy_exceeds_tenant_max_walltime",
    "sandbox_policy_egress_host_invalid",
    "sandbox_policy_egress_protocol_not_http",
    "sandbox_policy_rego_denied",
    "sandbox_backend_unavailable",
    "sandbox_warm_pool_drained",
]

# 5-value SandboxPolicyViolationReason — wire-protocol-public per spec §4.2
SandboxPolicyViolationReason = Literal[
    "cpu_time_budget_exceeded",
    "memory_cap_exceeded",
    "walltime_cap_exceeded",
    "egress_host_not_allow_listed",
    "egress_protocol_not_http",
]

# 8-value SandboxLifecycleEvent — wire-protocol-public per spec §4.3
SandboxLifecycleEvent = Literal[
    "sandbox.lifecycle.created",
    "sandbox.lifecycle.exec_completed",
    "sandbox.lifecycle.destroyed",
    "sandbox.lifecycle.refused",
    "sandbox.policy.violated",
    "sandbox.warm_pool.precreated",
    "sandbox.warm_pool.checked_out",
    "sandbox.warm_pool.drained",
]


class SandboxLifecycleRefused(Exception):
    """Raised at any admission stage on refusal. Carries the closed-enum reason."""

    def __init__(self, reason: SandboxRefusalReason, *, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


class SandboxPolicyViolated(Exception):
    """Raised at exec() when a runtime policy cap is exceeded."""

    def __init__(self, reason: SandboxPolicyViolationReason, *, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class SandboxExecResult:
    """Per spec §5 — result of SandboxSession.exec()."""
    stdout: bytes
    stderr: bytes
    exit_code: int
    proxy_log: tuple["ProxyAccessRecord", ...] = ()  # forward ref; lands at T7


SandboxBackendHealthStatus = Literal["ok", "degraded", "unavailable"]


@dataclass(frozen=True)
class SandboxBackendHealth:
    status: SandboxBackendHealthStatus
    detail: str = ""


# Forward refs for types defined in T-task downstream modules — used
# only inside Protocol signatures so the runtime import dance is safe.
# MUST use TYPE_CHECKING (not `if False`) so mypy resolves the
# annotations and `uv run mypy src tests` at the T3 halt gate passes.
from typing import TYPE_CHECKING  # noqa: E402 — module-level imports moved up at impl-time
if TYPE_CHECKING:
    from cognic_agentos.portal.rbac.actor import Actor
    from cognic_agentos.sandbox.policy import (
        PackAdmissionContext,
        SandboxPolicy,
    )


@runtime_checkable
class SandboxSession(Protocol):
    """A live sandbox. Identity persists across exec() calls.

    Per spec §5 — 6 fields. `pack_context` carries the admission context
    under which this session was admitted (round-3 follow-on P1 fix)
    so warm_pool.release_or_destroy(session) can derive the correct
    pool key for cold-created sessions; also load-bearing for Sprint
    8.5 wake-time re-admission against the same context.
    """

    session_id: str               # uuid4 hex; persists into Sprint 8.5 checkpoint store
    policy: "SandboxPolicy"
    tenant_id: str
    pack_context: "PackAdmissionContext"
    created_at: datetime
    warm_pool_hit: bool

    async def exec(
        self,
        command: list[str],
        *,
        timeout_s: float | None = None,
    ) -> SandboxExecResult: ...

    async def destroy(self) -> None: ...


@runtime_checkable
class SandboxBackend(Protocol):
    """Backend-abstracted sandbox lifecycle.

    Wave-1 implementations: DockerSiblingSandboxBackend (T10 of Sprint 8A),
    KubernetesPodSandboxBackend (Sprint 8B). Wave-2: gVisor, Firecracker,
    Kata, rootless Docker. All implementations MUST honor the same
    lifecycle contract and the shared conformance test suite at
    tests/conformance/sandbox/test_backend_conformance.py.
    """

    async def create(
        self,
        policy: "SandboxPolicy",
        *,
        actor: "Actor",
        tenant_id: str,
        pack_context: "PackAdmissionContext",
        use_warm_pool: bool = True,
    ) -> SandboxSession:
        """Admit + create a sandbox session.

        Raises SandboxLifecycleRefused carrying a SandboxRefusalReason
        closed-enum value on any admission failure (per spec §5 + §6.1).

        use_warm_pool=True: attempt warm-pool checkout first (only if
        policy.warm_pool_key is set AND a matching member exists);
        cold-create on miss; audit-emits warm_pool.checked_out +
        lifecycle.created (warm_pool_hit=True) OR lifecycle.created
        (warm_pool_hit=False) accordingly.

        use_warm_pool=False: forces cold-create path (the replenishment
        contract — SandboxWarmPool.precreate calls this so it never
        consumes an existing pool member; round-1 P1 reviewer fix).
        """

    async def exec(
        self,
        session: SandboxSession,
        command: list[str],
        *,
        timeout_s: float | None = None,
    ) -> SandboxExecResult:
        """Execute a command in the session.

        Raises SandboxPolicyViolated carrying a SandboxPolicyViolationReason
        on runtime policy-cap exceeded (memory OOM, walltime exceeded,
        cpu_time_budget exceeded when set, or proxy-observed egress
        violation). Throttling under --cpus cap is NOT a violation by
        itself (round-2 P2 fix).
        """

    async def destroy(self, session: SandboxSession) -> None:
        """Tear down the session. Idempotent.

        For warm-pool members, the public seam is
        SandboxWarmPool.release_or_destroy() (which routes back to the
        pool when policy + context match an existing key). destroy() is
        the unconditional teardown.
        """

    async def health(self) -> SandboxBackendHealth:
        """Backend readiness check. Used by /readyz and at startup."""
```

```python
# src/cognic_agentos/sandbox/policy.py
"""Sprint 8A T3 — SandboxPolicy + PackAdmissionContext + Stage-1 pure shape validation.

NO I/O. Critical-controls module per AGENTS.md. Stage-2 async admission
(catalog + cosign + SBOM + Rego + credential-adapter + high-risk-tier)
lives in T5 sandbox/admission.py per spec §6.1.

RiskTier is declared LOCALLY here, NOT imported from
`cognic_agentos.cli._governance_vocab` — runtime sandbox code must not
import build-time CLI vocab per AGENTS.md "Plugin discipline" + the
plan's invariant #6 (no runtime cross-module imports for shared
constants per feedback_drift_detector_test_only_no_runtime_import).
A test-only drift detector at tests/unit/sandbox/test_policy_shape.py
pins this local Literal against cli/_governance_vocab.RiskTier — if
either side drifts, the test fails at CI time without coupling
runtime modules.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

# Local 8-value RiskTier Literal — matches ADR-014 canonical set verbatim.
# Drift against cli/_governance_vocab.RiskTier pinned at test layer only.
RiskTier = Literal[
    "read_only",
    "internal_write",
    "customer_data_read",
    "customer_data_write",
    "payment_action",
    "regulator_communication",
    "cross_tenant",
    "high_risk_custom",
]

_SHA256_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
# RFC 1123 hostname per the wire-protocol public spec §6.1 Step 2:
# total length 1-253; per-label length 1-63; LDH-only labels.
_RFC1123_HOST_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)


@dataclass(frozen=True)
class PackAdmissionContext:
    """Pack-level context for sandbox admission. Built by the harness
    from the pack manifest when a tool call requires a sandbox; threaded
    through to admit_policy() so admission has manifest-level fields it
    needs to make decisions that aren't on per-call SandboxPolicy.

    6 fields per spec §6.1 (round-3-third-follow-on amendment):
    pack_id + pack_version + pack_artifact_digest + risk_tier +
    declares_dynamic_install + profile.
    """
    pack_id: str
    pack_version: str
    pack_artifact_digest: str  # cosign-verified sha256 per ADR-016
    risk_tier: RiskTier
    declares_dynamic_install: bool
    profile: Literal["production", "development"]


@dataclass(frozen=True)
class WritableMount:
    """Per spec §6 SandboxPolicy.writable_mounts."""
    host_path: str
    container_path: str
    read_only: bool = False


@dataclass(frozen=True)
class SandboxPolicy:
    cpu_cores: float
    cpu_time_budget_s: float | None  # None = no CPU-seconds kill condition
    memory_mb: int
    walltime_s: float
    runtime_image: str  # OCI ref + @sha256:<64-hex>
    egress_allow_list: tuple[str, ...]
    vault_path: str | None
    read_only_root: bool = True
    writable_mounts: tuple[WritableMount, ...] = ()
    warm_pool_key: str | None = None


def validate_policy_shape(policy: SandboxPolicy) -> None:
    """PURE Stage-1 shape validation per spec §6.1 step 1+2.

    Raises SandboxLifecycleRefused on first failure. No I/O.
    """
    # cpu_cores > 0
    if policy.cpu_cores <= 0:
        raise SandboxLifecycleRefused(
            "sandbox_policy_exceeds_tenant_max_cpu",
            detail=f"cpu_cores must be > 0; got {policy.cpu_cores}",
        )
    # memory_mb > 0
    if policy.memory_mb <= 0:
        raise SandboxLifecycleRefused(
            "sandbox_policy_exceeds_tenant_max_memory",
            detail=f"memory_mb must be > 0; got {policy.memory_mb}",
        )
    # walltime_s > 0
    if policy.walltime_s <= 0:
        raise SandboxLifecycleRefused(
            "sandbox_policy_exceeds_tenant_max_walltime",
            detail=f"walltime_s must be > 0; got {policy.walltime_s}",
        )
    # cpu_time_budget_s is None or > 0
    if policy.cpu_time_budget_s is not None and policy.cpu_time_budget_s <= 0:
        raise SandboxLifecycleRefused(
            "sandbox_policy_exceeds_tenant_max_cpu",
            detail=f"cpu_time_budget_s must be > 0 when set; got {policy.cpu_time_budget_s}",
        )
    # Image-reference validation — defer to OCI parser per spec §6.1 step 1
    _validate_image_ref(policy.runtime_image)
    # Egress allow-list shape — RFC 1123 + scheme refusal
    for host in policy.egress_allow_list:
        _validate_egress_host(host)


def _validate_image_ref(ref: str) -> None:
    """Validate OCI image ref + @sha256:<64-hex> digest suffix per spec §6.1 step 1.

    Validation steps (all Stage-1 pure — NO subprocess; NO network):
    (a) ref contains the `@sha256:` separator → format-invalid if missing
    (b) digest portion matches `^sha256:[0-9a-f]{64}$`
    (c) ref portion (before `@`) parses as a valid OCI image reference

    For (c) we use docker-py's `docker.utils.parse_repository_tag` which
    is import-time-cheap + side-effect-free + accepts the realistic shape
    `[registry[:port]/]repository[:tag]` (rejected by the round-2 inline
    regex). Round-2 reviewer correction: refs like
    `registry.example.com:5000/foo:bar@sha256:...` and the spec's own
    `cognic/sandbox-runtime-python:v1.2@sha256:...` now validate green.
    """
    from docker.utils import parse_repository_tag  # local import — keeps module import cheap

    if "@" not in ref:
        raise SandboxLifecycleRefused(
            "sandbox_image_digest_format_invalid",
            detail=f"image ref missing @sha256: suffix: {ref}",
        )
    repo_tag, digest = ref.rsplit("@", 1)
    if not _SHA256_DIGEST_RE.fullmatch(digest):
        raise SandboxLifecycleRefused(
            "sandbox_image_digest_format_invalid",
            detail=f"digest must be sha256:<64-hex>; got {digest}",
        )
    try:
        repo, tag = parse_repository_tag(repo_tag)
        # parse_repository_tag returns (repo, tag_or_None) and raises ValueError on
        # malformed refs (empty repo, illegal characters in registry).
        if not repo:
            raise ValueError("empty repository portion")
    except (ValueError, AttributeError) as exc:
        raise SandboxLifecycleRefused(
            "sandbox_image_digest_format_invalid",
            detail=f"image ref does not parse as OCI reference: {repo_tag!r} ({exc})",
        ) from exc


def _validate_egress_host(entry: str) -> None:
    """Validate egress allow-list entry per spec §6.1 step 2.

    Stage-1 pure validation. Two checks:
    (a) If the entry carries a scheme, it MUST be http or https. Wave-1
        only allows HTTP/HTTPS outbound per the §2.1 doctrinal lock.
    (b) The hostname portion MUST match RFC 1123 (1-253 chars total;
        1-63 chars per label; LDH characters only; no leading/trailing
        hyphen on any label).

    Examples that pass: `api.example.com`, `https://api.example.com`,
    `localhost`, `a.b.c`. Examples that refuse:
    `ftp://files.example.com` (scheme), `-bad.example.com` (leading
    hyphen), `` (empty), `a..b.c` (empty label).
    """
    if "://" in entry:
        scheme, host = entry.split("://", 1)
        if scheme not in ("http", "https"):
            raise SandboxLifecycleRefused(
                "sandbox_policy_egress_protocol_not_http",
                detail=f"Wave-1 allows http/https only; got {scheme}://",
            )
    else:
        host = entry

    # Strip path/query if present (the allow-list is hostname-only)
    host = host.split("/", 1)[0]
    if not host:
        raise SandboxLifecycleRefused(
            "sandbox_policy_egress_host_invalid",
            detail=f"empty hostname in egress entry: {entry!r}",
        )
    if not _RFC1123_HOST_RE.fullmatch(host):
        raise SandboxLifecycleRefused(
            "sandbox_policy_egress_host_invalid",
            detail=f"hostname does not match RFC 1123: {host!r}",
        )
```

```python
# src/cognic_agentos/sandbox/__init__.py
"""Sprint 8A sandbox primitive — public API surface."""
from __future__ import annotations

from cognic_agentos.sandbox.policy import (
    PackAdmissionContext,
    SandboxPolicy,
    WritableMount,
    validate_policy_shape,
)
from cognic_agentos.sandbox.protocol import (
    SandboxBackend,  # T-future
    SandboxSession,  # T-future
    SandboxLifecycleEvent,
    SandboxLifecycleRefused,
    SandboxPolicyViolated,
    SandboxPolicyViolationReason,
    SandboxRefusalReason,
)

__all__ = [
    "PackAdmissionContext",
    "SandboxBackend",
    "SandboxLifecycleEvent",
    "SandboxLifecycleRefused",
    "SandboxPolicy",
    "SandboxPolicyViolated",
    "SandboxPolicyViolationReason",
    "SandboxRefusalReason",
    "SandboxSession",
    "WritableMount",
    "validate_policy_shape",
]
```

- [ ] **Step 4: Run to verify pass**

```bash
uv run pytest tests/unit/sandbox/test_policy_shape.py -v
```

Expected: PASS.

- [ ] **Step 5: Add Stage-1 shape-arm tests covering each refusal reason**

For each of these refusal arms reachable from Stage-1, add a test:
- `cpu_cores <= 0` → `sandbox_policy_exceeds_tenant_max_cpu`
- `memory_mb <= 0` → `sandbox_policy_exceeds_tenant_max_memory`
- `walltime_s <= 0` → `sandbox_policy_exceeds_tenant_max_walltime`
- `cpu_time_budget_s = 0` → `sandbox_policy_exceeds_tenant_max_cpu`
- `runtime_image without @sha256:` → `sandbox_image_digest_format_invalid`
- `runtime_image with malformed digest` → `sandbox_image_digest_format_invalid`
- `egress_allow_list with ftp:// scheme` → `sandbox_policy_egress_protocol_not_http`

Each test mirrors the partition-invariant pattern: minimal valid policy + one field tweak + assert specific `SandboxLifecycleRefused.reason`.

- [ ] **Step 6: Halt-before-commit (CC modules: protocol.py + policy.py)**

Per AGENTS.md + `feedback_strict_review_off_gate`. CC-gate halt required before commit fires. Run:
- `uv run ruff check src tests` — must be clean
- `uv run ruff format --check src tests` — must be clean
- `uv run mypy src tests` — must be clean
- `uv run pytest tests/unit/sandbox/ -q` — must be green
- `git diff --check` (or `--no-index --check /dev/null <file>` for untracked) — clean

Produce halt-before-commit summary; pause for user `commit` token.

- [ ] **Step 7: Commit**

```
feat(sprint-8a): T3 — protocol + policy + closed-enum vocab + PackAdmissionContext (CRITICAL CONTROLS)

Lands sandbox/protocol.py + sandbox/policy.py + sandbox/__init__.py per
Sprint 8A T1 spec §4 (closed-enums) + §5 (Protocols) + §6 (SandboxPolicy
+ pure shape validation).

* SandboxRefusalReason 15-value Literal
* SandboxPolicyViolationReason 5-value Literal
* SandboxLifecycleEvent 8-value Literal
* PackAdmissionContext 6-field frozen dataclass
* SandboxPolicy frozen dataclass with cpu_time_budget_s opt-in
* validate_policy_shape() pure Stage-1 validator (no I/O)
* SandboxLifecycleRefused + SandboxPolicyViolated exception types
* Partition-invariant pins (15/5/8) at module load

Stage-2 async admission (catalog + cosign + SBOM + Rego) lands in T5.
No backend logic; no I/O. Critical-controls modules: protocol.py +
policy.py join the durable coverage gate at T12 (gate uplift 63 → 70).

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
```

---

## Task T4 — Audit event builders + chain-row emitters

**Scope:** the audit emission substrate. Lives BEFORE admission/catalog/proxy/warm-pool/backend so each subsequent task can emit chain rows without needing a temporary direct chain helper. Adopted user direction (2026-05-16): moved up from prior-draft T10.

**Files:**
- Create: `src/cognic_agentos/sandbox/audit.py`
- Create: `tests/unit/sandbox/test_audit_event_taxonomy.py`
- Modify: `src/cognic_agentos/sandbox/__init__.py` (export `emit_sandbox_event` + payload types)

**Doctrine refs:** spec §4.3 (8-event taxonomy) + §12 (audit emission section) + ADR-006 amendment (A.6.2.5 control mapping).

### T4 steps

- [ ] **Step 1: Write failing test — 8-event taxonomy emits correctly-shaped chain rows**

The real `DecisionRecord` dataclass at `core/decision_history.py:207` is `frozen=True, slots=True` with **exactly 10 constructor fields**: 3 required (`decision_type`, `request_id`, `payload`) + 7 optional defaulting to None or `()` (`actor_id`, `tenant_id`, `trace_id`, `span_id`, `langfuse_trace_id`, `provider_label`, `iso_controls`). NO `actor_subject` / `session_id` / `previous_hash` constructor field — session-scoped values go on `payload` per the established `escalation.py:560` pattern. The fields `record_id` / `chain_id` / `sequence` / `new_hash` / `created_at` live on a SEPARATE dataclass — `AppendedDecisionSnapshot` at `core/decision_history.py:252` — which is the post-commit snapshot the store passes to hooks AFTER successful chain-write; those are NOT fields the implementor passes to the DecisionRecord constructor.

The real `append_with_precondition` signature at `core/decision_history.py:409`:
```python
async def append_with_precondition[T](
    self,
    *,
    record_builder: Callable[[T], DecisionRecord],
    precondition: Callable[[AsyncConnection, int, bytes], Awaitable[T]],
) -> tuple[uuid.UUID, bytes]:
```
The precondition is `async (conn, prev_sequence, prev_hash) → T`; record_builder is `sync (captured: T) → DecisionRecord`.

```python
# tests/unit/sandbox/test_audit_event_taxonomy.py
"""Sprint 8A T4 — sandbox lifecycle event taxonomy + chain-row shape pins.

Verified against real core/decision_history.py API at session compose
time per feedback_verify_code_citations_at_doc_write.
"""
from __future__ import annotations

import typing
import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.core.decision_history import DecisionRecord
from cognic_agentos.sandbox import SandboxLifecycleEvent
from cognic_agentos.sandbox.audit import emit_sandbox_event


class TestEventTaxonomyAndChainRowShape:
    @pytest.mark.asyncio
    async def test_lifecycle_created_emits_chain_row_with_a6_2_5_iso_tag(self) -> None:
        """Audit emission for sandbox.lifecycle.created builds a
        DecisionRecord with iso_controls=('A.6.2.5',) per ADR-006
        amendment + session_id on payload (NOT a top-level field)."""
        store = AsyncMock()
        store.append_with_precondition.return_value = (uuid.uuid4(), b"\x00" * 32)

        await emit_sandbox_event(
            store,
            event="sandbox.lifecycle.created",
            tenant_id="t-1",
            actor_id="s-1",
            trace_id="trace-1",
            session_id="sess-1",
            payload={"warm_pool_hit": False},
        )

        store.append_with_precondition.assert_awaited_once()
        call_kwargs = store.append_with_precondition.call_args.kwargs

        # Drive the precondition closure to get the captured value;
        # then drive record_builder to inspect the produced record.
        prev_hash = b"\x00" * 32
        prev_sequence = 0
        conn = AsyncMock()
        captured = await call_kwargs["precondition"](conn, prev_sequence, prev_hash)
        built = call_kwargs["record_builder"](captured)

        assert isinstance(built, DecisionRecord)
        assert built.decision_type == "sandbox.lifecycle.created"
        assert built.iso_controls == ("A.6.2.5",)
        assert built.tenant_id == "t-1"
        assert built.actor_id == "s-1"
        assert built.trace_id == "trace-1"
        # session_id lives on payload, NOT as a top-level field
        assert built.payload["session_id"] == "sess-1"
        assert built.payload["warm_pool_hit"] is False
        # request_id auto-minted with sandbox-evt prefix
        assert built.request_id.startswith("sandbox-evt-")

    @pytest.mark.asyncio
    async def test_refused_event_carries_closed_enum_reason_on_payload(self) -> None:
        store = AsyncMock()
        store.append_with_precondition.return_value = (uuid.uuid4(), b"\x00" * 32)

        await emit_sandbox_event(
            store,
            event="sandbox.lifecycle.refused",
            tenant_id="t-1",
            actor_id="s-1",
            trace_id="trace-1",
            session_id="sess-1",
            payload={"reason": "sandbox_credential_adapter_not_configured"},
        )

        call_kwargs = store.append_with_precondition.call_args.kwargs
        captured = await call_kwargs["precondition"](AsyncMock(), 0, b"\x00" * 32)
        built = call_kwargs["record_builder"](captured)
        assert built.payload["reason"] == "sandbox_credential_adapter_not_configured"
        assert built.payload["session_id"] == "sess-1"

    @pytest.mark.asyncio
    async def test_emit_rejects_unknown_event_at_module_boundary(self) -> None:
        with pytest.raises(ValueError, match="not a valid SandboxLifecycleEvent"):
            await emit_sandbox_event(
                AsyncMock(),
                event="sandbox.lifecycle.bogus",  # type: ignore[arg-type]
                tenant_id="t-1", actor_id="s-1",
                trace_id="trace-1", session_id="sess-1",
                payload={},
            )


class TestAllEightEventsReachable:
    """Pin that all 8 events have working emit paths."""

    @pytest.mark.parametrize("event", list(typing.get_args(SandboxLifecycleEvent)))
    @pytest.mark.asyncio
    async def test_each_event_emits_chain_row_without_error(self, event: str) -> None:
        store = AsyncMock()
        store.append_with_precondition.return_value = (uuid.uuid4(), b"\x00" * 32)
        await emit_sandbox_event(
            store,
            event=event,  # type: ignore[arg-type]
            tenant_id="t-1", actor_id="s-1",
            trace_id="trace-1", session_id="sess-1",
            payload={},
        )
        store.append_with_precondition.assert_awaited_once()
```

- [ ] **Step 2: Verify fail**

```bash
uv run pytest tests/unit/sandbox/test_audit_event_taxonomy.py -v
```

Expected: `ImportError: cannot import name 'emit_sandbox_event'`.

- [ ] **Step 3: Implement `sandbox/audit.py`**

```python
# src/cognic_agentos/sandbox/audit.py
"""Sprint 8A T4 — sandbox lifecycle event emitters.

NOT on the durable critical-controls coverage gate (thin chain-row
converter; the substantive audit-chain invariants are enforced upstream
by the on-gate core/audit.py + core/decision_history.py + core/canonical.py).
Per spec §17 critical-controls-scope rationale.

Verified against core/decision_history.py:207 DecisionRecord shape +
:409 append_with_precondition signature at session compose time per
feedback_verify_code_citations_at_doc_write. session_id lives on
payload (per the established escalation.py:560 pattern), NOT as a
top-level DecisionRecord field. The precondition is async and runs
INSIDE the chain-head FOR UPDATE lock; for audit-only events with no
state precondition, the closure is a no-op that returns None.
"""
from __future__ import annotations

import typing
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncConnection

from cognic_agentos.core.decision_history import (
    DecisionHistoryStore,
    DecisionRecord,
)
from cognic_agentos.sandbox.protocol import SandboxLifecycleEvent

_VALID_EVENTS: frozenset[str] = frozenset(typing.get_args(SandboxLifecycleEvent))


# Per-event payload shape contracts (informational; the emit signature
# accepts any dict and the runtime callers MUST match these per spec §4.3):
#   sandbox.lifecycle.created       → {"warm_pool_hit": bool, "session_id": str}
#   sandbox.lifecycle.exec_completed → {"exit_code": int, "proxy_log": list[dict],
#                                       "session_id": str}
#   sandbox.lifecycle.destroyed     → {"duration_s": float, "session_id": str}
#   sandbox.lifecycle.refused       → {"reason": SandboxRefusalReason,
#                                       "session_id": str}
#   sandbox.policy.violated         → {"reason": SandboxPolicyViolationReason,
#                                       "session_id": str}
#   sandbox.warm_pool.precreated    → {"pool_key": str, "pool_size_after": int}
#   sandbox.warm_pool.checked_out   → {"pool_key": str, "pool_size_after": int,
#                                       "session_id": str}
#   sandbox.warm_pool.drained       → {"pool_key": str, "drained_count": int}


async def emit_sandbox_event(
    decision_history_store: DecisionHistoryStore,
    *,
    event: SandboxLifecycleEvent,
    tenant_id: str,
    actor_id: str,           # the Actor.subject (matches DecisionRecord.actor_id field)
    trace_id: str,
    session_id: str,         # threaded into payload — NOT a top-level DR field
    payload: dict[str, Any],
) -> tuple[uuid.UUID, bytes]:
    """Emit one sandbox lifecycle event into the chain.

    Tagged with ISO 42001 A.6.2.5 per ADR-006 amendment.

    Returns the (record_id, new_hash) tuple from
    DecisionHistoryStore.append_with_precondition per core/decision_history.py:414.

    Audit-only events have no transactional precondition (no state
    machine; nothing to read+lock before insert), so the precondition
    closure is a no-op returning None. The record_builder receives the
    captured value (None) and builds the DecisionRecord.
    """
    if event not in _VALID_EVENTS:
        raise ValueError(
            f"{event!r} is not a valid SandboxLifecycleEvent; "
            f"expected one of {sorted(_VALID_EVENTS)}"
        )

    # Merge session_id into payload — NOT a top-level DR field per
    # the verified core/decision_history.py:207 shape.
    full_payload = {**payload, "session_id": session_id}
    request_id = f"sandbox-evt-{uuid.uuid4().hex}"

    async def _precondition(
        _conn: AsyncConnection, _prev_sequence: int, _prev_hash: bytes
    ) -> None:
        # Audit-only — no state to project; no validator to run inside
        # the chain-head lock; returns None which flows into _build_record.
        return None

    def _build_record(_captured: None) -> DecisionRecord:
        # Constructs the 10-field DecisionRecord per core/decision_history.py:207.
        # record_id / chain_id / sequence / new_hash / created_at live on the
        # SEPARATE AppendedDecisionSnapshot (post-commit, hook-only) — NOT on
        # DecisionRecord; the store assigns the snapshot fields after commit.
        return DecisionRecord(
            decision_type=event,
            request_id=request_id,
            payload=full_payload,
            actor_id=actor_id,
            tenant_id=tenant_id,
            trace_id=trace_id,
            iso_controls=("A.6.2.5",),
        )

    return await decision_history_store.append_with_precondition(
        record_builder=_build_record,
        precondition=_precondition,
    )
```

**Verification reminder per `feedback_verify_code_citations_at_doc_write`:** before T4 implementation begins, re-verify `DecisionRecord` field list at `core/decision_history.py:207` AND `append_with_precondition` signature at `:409` are still as described above. If either has drifted, the test code + impl code in this T-task need re-syncing FIRST. The 2026-05-16 verification (this commit) confirmed: `DecisionRecord` is `frozen=True, slots=True` with **exactly 10 constructor fields** — 3 required (`decision_type`, `request_id`, `payload`) + 7 optional (`actor_id`, `tenant_id`, `trace_id`, `span_id`, `langfuse_trace_id`, `provider_label`, `iso_controls`). `AppendedDecisionSnapshot` at `:252` is a SEPARATE dataclass carrying `record_id` / `chain_id` / `sequence` / `new_hash` / `created_at` + all 10 DecisionRecord fields — the store passes this snapshot to hooks AFTER successful chain-write; the implementor does NOT pass those snapshot fields to the DecisionRecord constructor. The `append_with_precondition` signature: precondition is `async (conn, prev_sequence, prev_hash) → T`; record_builder is `sync (captured: T) → DecisionRecord`.

- [ ] **Step 4: Verify green + add per-event payload-shape assertion tests**

For each of the 8 events, add a test asserting the payload-shape contract matches §4.3 table. This is the per-T closure pin.

- [ ] **Step 5: Halt-before-commit** (sandbox/audit.py is OFF the durable gate; still runs standard pre-commit gate ladder).

- [ ] **Step 6: Commit**

```
feat(sprint-8a): T4 — sandbox/audit.py + 8-event taxonomy emitters

Per spec §4.3 + §12 + ADR-006 amendment. Lands the chain-row substrate
that every subsequent T-task (admission/catalog/proxy/warm-pool/backend)
emits into. Per user direction (2026-05-16): moved up from prior-draft
T10 so the chain event substrate exists BEFORE any module that emits.

* emit_sandbox_event() async — validates event against 8-value Literal
  at module boundary; builds DecisionRecord with iso_controls=("A.6.2.5",)
  per ADR-006 amendment; threads through decision_history_store.
  append_with_precondition for chain integrity.
* All 8 events parametrized-tested for reachability.
* Module stays OFF the durable coverage gate per spec §17 R32-doctrine
  carve-out (thin chain-row converter; substantive audit-chain
  invariants live in upstream core/audit.py + core/decision_history.py).

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
```

---

## Task T5 — Admission pipeline (Stage-2)

> **DONE (committed at `4967ce8`). Plan-vs-reality fixups applied — see "Post-T5 implementation notes" at top of file before re-reading the code blocks below verbatim.** The committed implementation declares Protocols in `sandbox/admission.py`, uses `sandbox_per_tenant_max_*` Settings prefix, and points the Rego decision-point at `data.cognic.sandbox.admit.allow` (kw-only `OPAEngine.evaluate`).

**Scope:** the async admission seam shared across all backends. Calls Stage-1 pure validator + then runs catalog + cosign + SBOM + Rego + credential-adapter + high-risk-tier checks in order, refusing fail-closed on the first failure.

**Files:**
- Create: `src/cognic_agentos/sandbox/admission.py`
- Create: `tests/unit/sandbox/test_admission_pipeline.py`
- Modify: `src/cognic_agentos/sandbox/__init__.py` (export `admit_policy`)

**Doctrine refs:** spec §6.1 (two-stage validation; admit_policy signature) + ADR-014 risk-tier reference (high-risk-tier transitional refusal).

### T5 steps

- [ ] **Step 1: Write failing test — admit_policy refuses on each closed-enum arm in order**

Tests cover steps 3 (credential-adapter), 3a (dynamic-install), 4 (high-risk-tier), 5 (tenant-max), 6 (catalog), 7 (cosign), 8 (SBOM), 9 (Rego). Each test injects mocked deps (`AsyncMock`) and asserts the matching `SandboxLifecycleRefused.reason`.

```python
# tests/unit/sandbox/test_admission_pipeline.py
"""Sprint 8A T5 — Stage-2 admission pipeline.

PURE TDD: each Stage-2 step gets a dedicated failure-arm test.
All deps mocked; integration with real catalog/cosign/SBOM/Rego lives in T6+.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock

from cognic_agentos.sandbox import (
    PackAdmissionContext,
    SandboxPolicy,
    SandboxLifecycleRefused,
)
from cognic_agentos.sandbox.admission import admit_policy
from cognic_agentos.sandbox.credentials import KernelDefaultCredentialAdapter

# Shared minimal valid fixtures
_VALID_POLICY = SandboxPolicy(
    cpu_cores=1.0, cpu_time_budget_s=None, memory_mb=256, walltime_s=30.0,
    runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
    egress_allow_list=("api.example.com",),
    vault_path=None,
)
_VALID_PACK_CONTEXT = PackAdmissionContext(
    pack_id="cognic.test_pack",
    pack_version="v1.0.0",
    pack_artifact_digest="sha256:" + "b" * 64,
    risk_tier="internal_write",
    declares_dynamic_install=False,
    profile="production",
)


class TestAdmissionRefusalArms:
    @pytest.mark.asyncio
    async def test_credential_adapter_default_stub_refuses_when_vault_path_set(self) -> None:
        policy = SandboxPolicy(**{**_VALID_POLICY.__dict__, "vault_path": "secret/test"})
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                policy,
                tenant_id="t-1", actor=MagicMock(),
                pack_context=_VALID_PACK_CONTEXT,
                catalog=AsyncMock(), credential_adapter=KernelDefaultCredentialAdapter(),
                rego_engine=AsyncMock(), settings=MagicMock(),
            )
        assert exc.value.reason == "sandbox_credential_adapter_not_configured"

    @pytest.mark.asyncio
    async def test_dynamic_install_refused_in_production(self) -> None:
        ctx = PackAdmissionContext(**{**_VALID_PACK_CONTEXT.__dict__,
                                       "declares_dynamic_install": True, "profile": "production"})
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _VALID_POLICY,
                tenant_id="t-1", actor=MagicMock(), pack_context=ctx,
                catalog=AsyncMock(), credential_adapter=AsyncMock(spec=[]),  # not the default stub
                rego_engine=AsyncMock(), settings=MagicMock(),
            )
        assert exc.value.reason == "sandbox_runtime_deps_unsupported_in_production"

    @pytest.mark.asyncio
    async def test_dynamic_install_permitted_in_dev_profile(self) -> None:
        ctx = PackAdmissionContext(**{**_VALID_PACK_CONTEXT.__dict__,
                                       "declares_dynamic_install": True, "profile": "development"})
        # Mock downstream steps to succeed
        # Round-6 R6 P1 #1 fix: MagicMock (not AsyncMock) so that
        # is_canonical() / is_tenant_allow_listed() return real bools
        # synchronously per the admit_policy code path. Only the async
        # verify_* methods get explicit AsyncMock assignment below.
        catalog = MagicMock()
        catalog.is_canonical.return_value = True
        # Round-7 R7 P1 #1 fix: admit_policy awaits the *_or_refuse
        # variants per spec §6.1 steps 7+8; mocking the bare
        # verify_cosign / verify_sbom_policy methods would leave the
        # awaited methods as plain MagicMock attributes and break the
        # green-path test.
        catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
        catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
        rego = AsyncMock()
        rego.evaluate = AsyncMock(return_value=MagicMock(allowed=True))
        await admit_policy(
            _VALID_POLICY,
            tenant_id="t-1", actor=MagicMock(), pack_context=ctx,
            catalog=catalog, credential_adapter=AsyncMock(spec=[]),
            rego_engine=rego, settings=MagicMock(per_tenant_max_cpu=4.0,
                                                  per_tenant_max_memory=1024,
                                                  per_tenant_max_walltime=300.0),
        )
        # No exception raised → dev profile bypassed the dynamic-install refusal

    @pytest.mark.parametrize("tier", [
        "customer_data_read", "customer_data_write", "payment_action",
        "regulator_communication", "cross_tenant", "high_risk_custom",
    ])
    @pytest.mark.asyncio
    async def test_high_risk_tier_refused_pre_13_5(self, tier: str) -> None:
        ctx = PackAdmissionContext(**{**_VALID_PACK_CONTEXT.__dict__, "risk_tier": tier})
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _VALID_POLICY,
                tenant_id="t-1", actor=MagicMock(), pack_context=ctx,
                catalog=AsyncMock(), credential_adapter=AsyncMock(spec=[]),
                rego_engine=AsyncMock(), settings=MagicMock(),
            )
        assert exc.value.reason == "sandbox_high_risk_tier_refused_pre_13_5"
```

```python
class TestAdmissionRefusalArms_Continued:
    @pytest.mark.asyncio
    async def test_tenant_max_cpu_exceeded(self) -> None:
        policy = SandboxPolicy(**{**_VALID_POLICY.__dict__, "cpu_cores": 16.0})
        settings = MagicMock(per_tenant_max_cpu=4.0,
                             per_tenant_max_memory=1024,
                             per_tenant_max_walltime=300.0)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                policy, tenant_id="t-1", actor=MagicMock(),
                pack_context=_VALID_PACK_CONTEXT,
                catalog=AsyncMock(), credential_adapter=AsyncMock(spec=[]),
                rego_engine=AsyncMock(), settings=settings,
            )
        assert exc.value.reason == "sandbox_policy_exceeds_tenant_max_cpu"

    @pytest.mark.asyncio
    async def test_tenant_max_memory_exceeded(self) -> None:
        policy = SandboxPolicy(**{**_VALID_POLICY.__dict__, "memory_mb": 8192})
        settings = MagicMock(per_tenant_max_cpu=4.0,
                             per_tenant_max_memory=1024,
                             per_tenant_max_walltime=300.0)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                policy, tenant_id="t-1", actor=MagicMock(),
                pack_context=_VALID_PACK_CONTEXT,
                catalog=AsyncMock(), credential_adapter=AsyncMock(spec=[]),
                rego_engine=AsyncMock(), settings=settings,
            )
        assert exc.value.reason == "sandbox_policy_exceeds_tenant_max_memory"

    @pytest.mark.asyncio
    async def test_tenant_max_walltime_exceeded(self) -> None:
        policy = SandboxPolicy(**{**_VALID_POLICY.__dict__, "walltime_s": 3600.0})
        settings = MagicMock(per_tenant_max_cpu=4.0,
                             per_tenant_max_memory=1024,
                             per_tenant_max_walltime=300.0)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                policy, tenant_id="t-1", actor=MagicMock(),
                pack_context=_VALID_PACK_CONTEXT,
                catalog=AsyncMock(), credential_adapter=AsyncMock(spec=[]),
                rego_engine=AsyncMock(), settings=settings,
            )
        assert exc.value.reason == "sandbox_policy_exceeds_tenant_max_walltime"

    @pytest.mark.asyncio
    async def test_image_not_in_canonical_catalog_or_tenant_allow_list(self) -> None:
        # Round-6 R6 P1 #1 fix: MagicMock (not AsyncMock) so that
        # is_canonical() / is_tenant_allow_listed() return real bools
        # synchronously per the admit_policy code path. Only the async
        # verify_* methods get explicit AsyncMock assignment below.
        catalog = MagicMock()
        catalog.is_canonical.return_value = False
        catalog.is_tenant_allow_listed.return_value = False
        settings = MagicMock(per_tenant_max_cpu=4.0,
                             per_tenant_max_memory=1024,
                             per_tenant_max_walltime=300.0)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _VALID_POLICY, tenant_id="t-1", actor=MagicMock(),
                pack_context=_VALID_PACK_CONTEXT,
                catalog=catalog, credential_adapter=AsyncMock(spec=[]),
                rego_engine=AsyncMock(), settings=settings,
            )
        assert exc.value.reason == "sandbox_image_digest_not_in_canonical_catalog"

    @pytest.mark.asyncio
    async def test_cosign_verification_fail(self) -> None:
        # Round-6 R6 P1 #1 fix: MagicMock (not AsyncMock) so that
        # is_canonical() / is_tenant_allow_listed() return real bools
        # synchronously per the admit_policy code path. Only the async
        # verify_* methods get explicit AsyncMock assignment below.
        catalog = MagicMock()
        catalog.is_canonical.return_value = True
        catalog.verify_cosign_or_refuse = AsyncMock(
            side_effect=SandboxLifecycleRefused(
                "sandbox_image_cosign_verification_failed",
                detail="signature mismatch",
            )
        )
        settings = MagicMock(per_tenant_max_cpu=4.0,
                             per_tenant_max_memory=1024,
                             per_tenant_max_walltime=300.0)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _VALID_POLICY, tenant_id="t-1", actor=MagicMock(),
                pack_context=_VALID_PACK_CONTEXT,
                catalog=catalog, credential_adapter=AsyncMock(spec=[]),
                rego_engine=AsyncMock(), settings=settings,
            )
        assert exc.value.reason == "sandbox_image_cosign_verification_failed"

    @pytest.mark.asyncio
    async def test_sbom_check_fail(self) -> None:
        # Round-6 R6 P1 #1 fix: MagicMock (not AsyncMock) so that
        # is_canonical() / is_tenant_allow_listed() return real bools
        # synchronously per the admit_policy code path. Only the async
        # verify_* methods get explicit AsyncMock assignment below.
        catalog = MagicMock()
        catalog.is_canonical.return_value = True
        catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)  # passes
        catalog.verify_sbom_policy_or_refuse = AsyncMock(
            side_effect=SandboxLifecycleRefused(
                "sandbox_image_sbom_check_failed",
                detail="GPL-3.0 detected",
            )
        )
        settings = MagicMock(per_tenant_max_cpu=4.0,
                             per_tenant_max_memory=1024,
                             per_tenant_max_walltime=300.0)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _VALID_POLICY, tenant_id="t-1", actor=MagicMock(),
                pack_context=_VALID_PACK_CONTEXT,
                catalog=catalog, credential_adapter=AsyncMock(spec=[]),
                rego_engine=AsyncMock(), settings=settings,
            )
        assert exc.value.reason == "sandbox_image_sbom_check_failed"

    @pytest.mark.asyncio
    async def test_rego_denied(self) -> None:
        # Round-6 R6 P1 #1 fix: MagicMock (not AsyncMock) so that
        # is_canonical() / is_tenant_allow_listed() return real bools
        # synchronously per the admit_policy code path. Only the async
        # verify_* methods get explicit AsyncMock assignment below.
        catalog = MagicMock()
        catalog.is_canonical.return_value = True
        catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
        catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
        rego = AsyncMock()
        rego.evaluate = AsyncMock(return_value=MagicMock(
            allowed=False, deny_reason="bank-overlay-policy-tightened",
        ))
        settings = MagicMock(per_tenant_max_cpu=4.0,
                             per_tenant_max_memory=1024,
                             per_tenant_max_walltime=300.0)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _VALID_POLICY, tenant_id="t-1", actor=MagicMock(),
                pack_context=_VALID_PACK_CONTEXT,
                catalog=catalog, credential_adapter=AsyncMock(spec=[]),
                rego_engine=rego, settings=settings,
            )
        assert exc.value.reason == "sandbox_policy_rego_denied"


class TestAdmissionPipelineOrderingInvariants:
    @pytest.mark.asyncio
    async def test_credential_check_runs_before_high_risk_tier_check(self) -> None:
        """Step ordering: §6.1 step 3 (credential) BEFORE step 4 (high-risk).
        A high-risk-tier pack with vault_path + default credential adapter
        MUST refuse with credential_adapter_not_configured (step 3 fires
        first), NOT high_risk_tier_refused_pre_13_5 (step 4)."""
        ctx = PackAdmissionContext(**{**_VALID_PACK_CONTEXT.__dict__,
                                       "risk_tier": "payment_action"})
        policy = SandboxPolicy(**{**_VALID_POLICY.__dict__, "vault_path": "secret/p"})
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                policy, tenant_id="t-1", actor=MagicMock(), pack_context=ctx,
                catalog=AsyncMock(), credential_adapter=KernelDefaultCredentialAdapter(),
                rego_engine=AsyncMock(), settings=MagicMock(),
            )
        assert exc.value.reason == "sandbox_credential_adapter_not_configured"


class TestStage1RunsBeforeStage2:
    """Round-4 R4 P1 #4 pin: admit_policy is the single admission seam;
    calls validate_policy_shape() (Stage 1) BEFORE any async I/O step.
    Without this, backends could drift by calling Stage-1 separately
    (or forgetting to)."""

    @pytest.mark.asyncio
    async def test_malformed_image_digest_refuses_before_catalog_call(self) -> None:
        """Stage-1 rejects `image_digest_format_invalid` (no @sha256:
        suffix) WITHOUT calling catalog.is_canonical() or any other
        async dep. Pin: catalog mocks see ZERO calls."""
        policy = SandboxPolicy(**{**_VALID_POLICY.__dict__,
                                   "runtime_image": "cognic/sandbox-runtime-python:v1"})  # no @sha256:
        # Round-6 R6 P1 #1 fix: MagicMock (not AsyncMock) so that
        # is_canonical() / is_tenant_allow_listed() return real bools
        # synchronously per the admit_policy code path. Only the async
        # verify_* methods get explicit AsyncMock assignment below.
        catalog = MagicMock()
        rego = AsyncMock()
        cred = AsyncMock(spec=[])

        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                policy, tenant_id="t-1", actor=MagicMock(),
                pack_context=_VALID_PACK_CONTEXT,
                catalog=catalog, credential_adapter=cred,
                rego_engine=rego, settings=MagicMock(),
            )
        assert exc.value.reason == "sandbox_image_digest_format_invalid"
        # Stage-1 short-circuited; no Stage-2 dep was called
        catalog.is_canonical.assert_not_called()
        catalog.verify_cosign_or_refuse.assert_not_called()
        catalog.verify_sbom_policy_or_refuse.assert_not_called()
        rego.evaluate.assert_not_called()

    @pytest.mark.asyncio
    async def test_malformed_egress_host_refuses_before_catalog_call(self) -> None:
        """Stage-1 rejects `egress_host_invalid` (`-bad.example.com` —
        leading hyphen RFC 1123 violation) WITHOUT any async I/O."""
        policy = SandboxPolicy(**{**_VALID_POLICY.__dict__,
                                   "egress_allow_list": ("-bad.example.com",)})
        # Round-6 R6 P1 #1 fix: MagicMock (not AsyncMock) so that
        # is_canonical() / is_tenant_allow_listed() return real bools
        # synchronously per the admit_policy code path. Only the async
        # verify_* methods get explicit AsyncMock assignment below.
        catalog = MagicMock()
        rego = AsyncMock()
        cred = AsyncMock(spec=[])

        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                policy, tenant_id="t-1", actor=MagicMock(),
                pack_context=_VALID_PACK_CONTEXT,
                catalog=catalog, credential_adapter=cred,
                rego_engine=rego, settings=MagicMock(),
            )
        assert exc.value.reason == "sandbox_policy_egress_host_invalid"
        catalog.is_canonical.assert_not_called()
        rego.evaluate.assert_not_called()

    @pytest.mark.asyncio
    async def test_ftp_scheme_in_egress_refuses_at_stage_1(self) -> None:
        """Stage-1 rejects `ftp://` scheme per spec §6.1 step 2
        (Wave-1 allows http/https only) WITHOUT any async I/O."""
        policy = SandboxPolicy(**{**_VALID_POLICY.__dict__,
                                   "egress_allow_list": ("ftp://files.example.com",)})
        # Round-6 R6 P1 #1 fix: MagicMock (not AsyncMock) so that
        # is_canonical() / is_tenant_allow_listed() return real bools
        # synchronously per the admit_policy code path. Only the async
        # verify_* methods get explicit AsyncMock assignment below.
        catalog = MagicMock()
        rego = AsyncMock()

        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                policy, tenant_id="t-1", actor=MagicMock(),
                pack_context=_VALID_PACK_CONTEXT,
                catalog=catalog, credential_adapter=AsyncMock(spec=[]),
                rego_engine=rego, settings=MagicMock(),
            )
        assert exc.value.reason == "sandbox_policy_egress_protocol_not_http"
        catalog.is_canonical.assert_not_called()
        rego.evaluate.assert_not_called()
```

- [ ] **Step 2: Verify fail** — `uv run pytest tests/unit/sandbox/test_admission_pipeline.py -v` → `ImportError: cannot import name 'admit_policy'`.

- [ ] **Step 3: Implement `sandbox/admission.py`**

```python
# src/cognic_agentos/sandbox/admission.py
"""Sprint 8A T5 — Stage-2 async admission pipeline.

Critical-controls module per AGENTS.md + spec §17. Shared by all
backends (DockerSibling T10 + KubernetesPod 8B + Wave-2 backends).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from cognic_agentos.sandbox.catalog import CanonicalImageCatalog
from cognic_agentos.sandbox.credentials import (
    CredentialAdapter,
    KernelDefaultCredentialAdapter,
)
from cognic_agentos.sandbox.policy import (
    PackAdmissionContext,
    SandboxPolicy,
    validate_policy_shape,
)
from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

if TYPE_CHECKING:
    from cognic_agentos.core.config import Settings
    from cognic_agentos.core.policy.engine import OPAEngine
    from cognic_agentos.portal.rbac.actor import Actor

_HIGH_RISK_TIERS_PRE_13_5: frozenset[str] = frozenset({
    "customer_data_read",
    "customer_data_write",
    "payment_action",
    "regulator_communication",
    "cross_tenant",
    "high_risk_custom",
})


async def admit_policy(
    policy: SandboxPolicy,
    *,
    tenant_id: str,
    actor: "Actor",
    pack_context: PackAdmissionContext,
    catalog: CanonicalImageCatalog,
    credential_adapter: CredentialAdapter,
    rego_engine: "OPAEngine",
    settings: "Settings",
) -> None:
    """Admission pipeline per spec §6.1 — single seam for both stages.

    Round-4 R4 P1 #4 fix: admit_policy() is now the ONLY admission seam
    a backend calls. It internally runs Stage-1 (`validate_policy_shape`,
    pure, synchronous) before Stage-2 (async I/O steps). Backends MUST
    NOT call validate_policy_shape() separately — that creates two
    independent admission seams that can drift.

    Raises SandboxLifecycleRefused on the first failure in either stage.
    """
    # Stage 1 — synchronous pure shape validation per spec §6.1 step 1+2.
    # Raises SandboxLifecycleRefused with the specific shape-arm reason
    # (sandbox_image_digest_format_invalid / sandbox_policy_egress_host_invalid
    # / etc.) before any async I/O happens.
    validate_policy_shape(policy)

    # Stage 2 — async admission below (steps 3 through 9 per spec §6.1).

    # Step 3 — credential-adapter check
    if policy.vault_path is not None and isinstance(
        credential_adapter, KernelDefaultCredentialAdapter
    ):
        raise SandboxLifecycleRefused(
            "sandbox_credential_adapter_not_configured",
            detail=f"policy.vault_path={policy.vault_path!r} requires a real CredentialAdapter; Sprint 10 ships VaultCredentialAdapter",
        )

    # Step 3a — dynamic-install refusal (production profile only)
    if pack_context.declares_dynamic_install and pack_context.profile == "production":
        raise SandboxLifecycleRefused(
            "sandbox_runtime_deps_unsupported_in_production",
            detail=f"pack {pack_context.pack_id} declares dynamic install + profile=production",
        )

    # Step 4 — high-risk-tier transitional refusal (pre-13.5)
    if pack_context.risk_tier in _HIGH_RISK_TIERS_PRE_13_5:
        raise SandboxLifecycleRefused(
            "sandbox_high_risk_tier_refused_pre_13_5",
            detail=f"tier={pack_context.risk_tier!r} requires core/approval engine (Sprint 13.5)",
        )

    # Step 5 — tenant-max check
    if policy.cpu_cores > settings.per_tenant_max_cpu:
        raise SandboxLifecycleRefused(
            "sandbox_policy_exceeds_tenant_max_cpu",
            detail=f"cpu_cores={policy.cpu_cores} > tenant max {settings.per_tenant_max_cpu}",
        )
    if policy.memory_mb > settings.per_tenant_max_memory:
        raise SandboxLifecycleRefused(
            "sandbox_policy_exceeds_tenant_max_memory",
            detail=f"memory_mb={policy.memory_mb} > tenant max {settings.per_tenant_max_memory}",
        )
    if policy.walltime_s > settings.per_tenant_max_walltime:
        raise SandboxLifecycleRefused(
            "sandbox_policy_exceeds_tenant_max_walltime",
            detail=f"walltime_s={policy.walltime_s} > tenant max {settings.per_tenant_max_walltime}",
        )

    # Step 6 — image catalog check (canonical OR per-tenant allow-list)
    # Round-4 R4 P1 #3 fix: extract the digest for fast O(1) catalog
    # lookup BUT keep the full `policy.runtime_image` ref for cosign +
    # syft subprocess calls (those need the full OCI ref to look up the
    # image in the registry; `docker.io/sha256:...` is not a valid ref).
    # The catalog stores both via `_digest_to_ref` reverse-map.
    _, image_digest = policy.runtime_image.rsplit("@", 1)
    if not (catalog.is_canonical(image_digest)
            or catalog.is_tenant_allow_listed(image_digest, tenant_id)):
        raise SandboxLifecycleRefused(
            "sandbox_image_digest_not_in_canonical_catalog",
            detail=f"digest {image_digest} not in catalog and not allow-listed for {tenant_id} "
                   f"(full ref was {policy.runtime_image})",
        )

    # Step 7 — cosign verification
    # Catalog's verify_cosign_or_refuse() resolves the full OCI ref via
    # its internal `_digest_to_ref` reverse-map; cosign shells out with
    # the real ref, not `docker.io/sha256:...`.
    await catalog.verify_cosign_or_refuse(image_digest, tenant_id=tenant_id)

    # Step 8 — SBOM policy check (same full-ref-resolution pattern)
    await catalog.verify_sbom_policy_or_refuse(image_digest, tenant_id=tenant_id)

    # Step 9 — Rego admission
    decision = await rego_engine.evaluate(
        "data.cognic.sandbox.admit",
        input={
            "policy": {
                "cpu_cores": policy.cpu_cores,
                "memory_mb": policy.memory_mb,
                "walltime_s": policy.walltime_s,
                "egress_allow_list": list(policy.egress_allow_list),
                "vault_path": policy.vault_path,
            },
            "pack_context": {
                "risk_tier": pack_context.risk_tier,
                "declares_dynamic_install": pack_context.declares_dynamic_install,
                "profile": pack_context.profile,
            },
            "tenant_max": {
                "cpu_cores": settings.per_tenant_max_cpu,
                "memory_mb": settings.per_tenant_max_memory,
                "walltime_s": settings.per_tenant_max_walltime,
            },
            "credential_adapter_wired": not isinstance(
                credential_adapter, KernelDefaultCredentialAdapter
            ),
        },
    )
    if not decision.allowed:
        raise SandboxLifecycleRefused(
            "sandbox_policy_rego_denied",
            detail=getattr(decision, "deny_reason", "rego policy denied"),
        )
```

- [ ] **Step 4: Verify green** — all admission tests pass (red + ordering + happy-path).

- [ ] **Step 5: CC halt-before-commit per AGENTS.md.** Gate ladder + halt summary; pause for user `commit` token.

- [ ] **Step 6: Commit**

```
feat(sprint-8a): T5 — admission.py Stage-2 pipeline (CRITICAL CONTROLS)

Per spec §6.1. Async admit_policy() runs the 9-step pipeline:
credential-adapter check → dynamic-install refusal (production only) →
high-risk-tier transitional refusal (6-value canonical set) → tenant-
max (cpu/memory/walltime) → catalog membership (canonical OR per-tenant
allow-list) → cosign verification → SBOM policy → Rego admission.
Shared across DockerSibling (T10) + KubernetesPod (8B sprint).

All 9 refusal arms reachable in unit tests + ordering invariant pinned
(credential check fires BEFORE high-risk-tier check so a high-risk
pack with vault_path + default credential adapter refuses with
credential_adapter_not_configured not high_risk_tier_refused_pre_13_5).

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
```

---

## Task T6 — Canonical image catalog + cosign + SBOM verification (CC)

**Scope:** `sandbox/catalog.py` — the 4-image canonical catalog + per-pack-image escape hatch + cosign subprocess + SBOM check. Emits `sandbox.lifecycle.refused` via T4's `emit_sandbox_event` on each refusal arm.

**Files:**
- Create: `src/cognic_agentos/sandbox/catalog.py`
- Create: `tests/unit/sandbox/test_image_catalog.py`
- Modify: `src/cognic_agentos/sandbox/__init__.py` (export `CanonicalImageCatalog`)
- Modify: `src/cognic_agentos/core/config.py` (catalog-config Settings group: 4 image digests + per-tenant cosign-trust-root path + per-tenant allow-list path)

**Doctrine refs:** spec §9 (catalog table) + ADR-016 amendment (AgentOS-published runtime artifacts subsection) + Sprint-4 trust-gate cosign pattern at `protocol/trust_gate.py`.

### T6 steps

- [ ] **Step 1: Write failing tests — catalog membership + cosign + SBOM refusal arms**

```python
# tests/unit/sandbox/test_image_catalog.py
"""Sprint 8A T6 — CanonicalImageCatalog membership + cosign + SBOM.

cosign + syft subprocesses are MOCKED at the subprocess boundary
(monkeypatch.setattr on the `_run_cosign_verify` / `_run_syft_inspect`
seam). Real cosign integration runs in the env-gated DockerSibling
backend tests at T10.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from cognic_agentos.sandbox import SandboxLifecycleRefused
from cognic_agentos.sandbox.catalog import (
    CanonicalImageCatalog,
    CosignVerifyResult,
    SBOMVerifyResult,
)


@pytest.fixture
def trust_root(tmp_path: Path) -> Path:
    """Test fixture cosign trust root (mocked subprocess never reads it)."""
    p = tmp_path / "cognic-cosign.pub"
    p.write_text("# fixture cosign pubkey (mocked subprocess does not read)\n")
    return p


@pytest.fixture
def catalog(trust_root: Path) -> CanonicalImageCatalog:
    return CanonicalImageCatalog(
        canonical_refs=frozenset({
            "cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
            "cognic/sandbox-runtime-shell:v1@sha256:" + "b" * 64,
            "cognic/sandbox-runtime-data:v1@sha256:" + "c" * 64,
            "cognic/sandbox-egress-proxy:v1@sha256:" + "d" * 64,
        }),
        tenant_trust_roots={"t-1": trust_root},
        tenant_allow_lists={"t-1": frozenset({
            "bank/custom-pack-sandbox:v1@sha256:" + "e" * 64,  # one per-pack image
        })},
    )


class TestCatalogMembership:
    def test_canonical_image_passes_membership(self, catalog: CanonicalImageCatalog) -> None:
        assert catalog.is_canonical("sha256:" + "a" * 64)
        assert not catalog.is_canonical("sha256:" + "z" * 64)

    def test_tenant_allow_listed_image_passes(self, catalog: CanonicalImageCatalog) -> None:
        assert catalog.is_tenant_allow_listed("sha256:" + "e" * 64, "t-1")
        assert not catalog.is_tenant_allow_listed("sha256:" + "e" * 64, "t-other")

    def test_unknown_image_fails_both(self, catalog: CanonicalImageCatalog) -> None:
        assert not catalog.is_canonical("sha256:" + "z" * 64)
        assert not catalog.is_tenant_allow_listed("sha256:" + "z" * 64, "t-1")


class TestCosignVerification:
    @pytest.mark.asyncio
    async def test_cosign_verify_passes_for_signed_canonical_image(
        self, catalog: CanonicalImageCatalog
    ) -> None:
        with patch.object(
            catalog, "_run_cosign_verify",
            new=AsyncMock(return_value=CosignVerifyResult(passed=True, detail="ok"))
        ):
            result = await catalog.verify_cosign("sha256:" + "a" * 64, tenant_id="t-1")
            assert result.passed is True

    @pytest.mark.asyncio
    async def test_cosign_verify_fail_raises_refusal(
        self, catalog: CanonicalImageCatalog
    ) -> None:
        with patch.object(
            catalog, "_run_cosign_verify",
            new=AsyncMock(return_value=CosignVerifyResult(
                passed=False, detail="signature does not match trust root"
            ))
        ):
            with pytest.raises(SandboxLifecycleRefused) as exc:
                await catalog.verify_cosign_or_refuse("sha256:" + "a" * 64, tenant_id="t-1")
            assert exc.value.reason == "sandbox_image_cosign_verification_failed"

    @pytest.mark.asyncio
    async def test_cosign_binary_missing_is_fail_closed_refusal(
        self, catalog: CanonicalImageCatalog
    ) -> None:
        """No cosign on PATH → refuse fail-closed; do NOT skip the check."""
        with patch.object(
            catalog, "_run_cosign_verify",
            new=AsyncMock(side_effect=FileNotFoundError("cosign not on PATH"))
        ):
            with pytest.raises(SandboxLifecycleRefused) as exc:
                await catalog.verify_cosign_or_refuse("sha256:" + "a" * 64, tenant_id="t-1")
            assert exc.value.reason == "sandbox_image_cosign_verification_failed"


class TestSBOMVerification:
    @pytest.mark.asyncio
    async def test_sbom_blocked_license_raises_refusal(
        self, catalog: CanonicalImageCatalog
    ) -> None:
        with patch.object(
            catalog, "_run_syft_inspect",
            new=AsyncMock(return_value=SBOMVerifyResult(
                passed=False, detail="GPL-3.0 detected in transitive deps"
            ))
        ):
            with pytest.raises(SandboxLifecycleRefused) as exc:
                await catalog.verify_sbom_policy_or_refuse(
                    "sha256:" + "a" * 64, tenant_id="t-1"
                )
            assert exc.value.reason == "sandbox_image_sbom_check_failed"


class TestRealSubprocessVerification:
    """Round-6 R6 P1 #2 fix: patch `asyncio.create_subprocess_exec` at
    the subprocess boundary so the real _run_cosign_verify +
    _run_syft_inspect code runs (JSON parsing, default-deny license
    policy, reverse-map lookup, subprocess failure handling). Without
    these tests, the prior whole-method monkeypatch in
    TestCosignVerification + TestSBOMVerification left the actual
    subprocess + parsing logic uncovered.
    """

    def _make_fake_subprocess(self, *, returncode: int, stdout: bytes = b"", stderr: bytes = b""):
        """Returns an AsyncMock suitable for patching
        asyncio.create_subprocess_exec. The mock's .communicate()
        coroutine yields the configured (stdout, stderr); .returncode
        reads as the configured value."""
        from unittest.mock import AsyncMock as _AsyncMock
        proc = _AsyncMock()
        proc.communicate = _AsyncMock(return_value=(stdout, stderr))
        proc.returncode = returncode
        return _AsyncMock(return_value=proc)

    @pytest.mark.asyncio
    async def test_run_cosign_verify_returns_passed_on_subprocess_exit_zero(
        self, catalog: CanonicalImageCatalog, monkeypatch
    ) -> None:
        import asyncio
        fake = self._make_fake_subprocess(returncode=0, stdout=b"Verified OK")
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_cosign_verify("sha256:" + "a" * 64, tenant_id="t-1")
        assert result.passed is True
        assert "Verified OK" in result.detail

    @pytest.mark.asyncio
    async def test_run_cosign_verify_returns_fail_on_subprocess_exit_nonzero(
        self, catalog: CanonicalImageCatalog, monkeypatch
    ) -> None:
        import asyncio
        fake = self._make_fake_subprocess(returncode=1, stderr=b"signature mismatch")
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_cosign_verify("sha256:" + "a" * 64, tenant_id="t-1")
        assert result.passed is False
        assert "signature mismatch" in result.detail

    @pytest.mark.asyncio
    async def test_run_cosign_verify_returns_fail_when_digest_not_in_reverse_map(
        self, catalog: CanonicalImageCatalog, monkeypatch
    ) -> None:
        """Bug-class guard per spec §10 — admission step 6 should
        catch this first, but the catalog's _run_cosign_verify MUST
        also refuse if the digest isn't in `_digest_to_ref`."""
        result = await catalog._run_cosign_verify("sha256:" + "z" * 64, tenant_id="t-1")
        assert result.passed is False
        assert "not in catalog reverse-map" in result.detail

    @pytest.mark.asyncio
    async def test_run_syft_inspect_passes_on_clean_sbom(
        self, catalog: CanonicalImageCatalog, monkeypatch
    ) -> None:
        """A canonical image's SBOM with only MIT + Apache-2.0
        artifacts passes the default-deny policy."""
        import asyncio
        import json
        clean_sbom = {
            "artifacts": [
                {"name": "requests", "version": "2.31", "licenses": [{"value": "Apache-2.0"}]},
                {"name": "click", "version": "8.1", "licenses": [{"value": "MIT"}]},
            ]
        }
        fake = self._make_fake_subprocess(returncode=0, stdout=json.dumps(clean_sbom).encode())
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect("sha256:" + "a" * 64, tenant_id="t-1")
        assert result.passed is True
        assert "2 artifacts" in result.detail

    @pytest.mark.asyncio
    async def test_run_syft_inspect_fails_on_gpl3_detected(
        self, catalog: CanonicalImageCatalog, monkeypatch
    ) -> None:
        import asyncio
        import json
        bad_sbom = {
            "artifacts": [
                {"name": "readline", "version": "8.0", "licenses": [{"value": "GPL-3.0"}]},
            ]
        }
        fake = self._make_fake_subprocess(returncode=0, stdout=json.dumps(bad_sbom).encode())
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect("sha256:" + "a" * 64, tenant_id="t-1")
        assert result.passed is False
        assert "GPL-3.0" in result.detail
        assert "denied" in result.detail

    @pytest.mark.asyncio
    async def test_run_syft_inspect_default_deny_for_unknown_license(
        self, catalog: CanonicalImageCatalog, monkeypatch
    ) -> None:
        """License neither in allowed nor in denied → refuse
        (default-deny per the policy doctrine in spec §9 + ADR-016
        amendment)."""
        import asyncio
        import json
        unknown_sbom = {
            "artifacts": [
                {"name": "exotic-lib", "version": "1.0",
                 "licenses": [{"value": "BUSL-1.1"}]},  # Business Source — not in default policy
            ]
        }
        fake = self._make_fake_subprocess(returncode=0, stdout=json.dumps(unknown_sbom).encode())
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect("sha256:" + "a" * 64, tenant_id="t-1")
        assert result.passed is False
        assert "BUSL-1.1" in result.detail
        assert "not in allow-list" in result.detail

    @pytest.mark.asyncio
    async def test_run_syft_inspect_returns_fail_on_subprocess_nonzero(
        self, catalog: CanonicalImageCatalog, monkeypatch
    ) -> None:
        import asyncio
        fake = self._make_fake_subprocess(returncode=2, stderr=b"syft: unable to inspect image")
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect("sha256:" + "a" * 64, tenant_id="t-1")
        assert result.passed is False
        assert "syft exited 2" in result.detail
```

- [ ] **Step 2: Verify fail** — `uv run pytest tests/unit/sandbox/test_image_catalog.py -v` → all tests `ImportError: cannot import name 'CanonicalImageCatalog'`.

- [ ] **Step 3: Implement `sandbox/catalog.py`**

```python
# src/cognic_agentos/sandbox/catalog.py
"""Sprint 8A T6 — canonical image catalog + cosign + SBOM verification.

Critical-controls module per AGENTS.md + spec §17. Substantive
enforcement point — a bug here lets untrusted images run.
"""
from __future__ import annotations

import asyncio
import json  # for SBOM JSON parsing
from dataclasses import dataclass
from pathlib import Path

from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused


@dataclass(frozen=True)
class CosignVerifyResult:
    passed: bool
    detail: str = ""


@dataclass(frozen=True)
class SBOMVerifyResult:
    passed: bool
    detail: str = ""


# Default Wave-1 license policy — banks override per-tenant by passing
# tenant_license_policies to the constructor.
_DEFAULT_LICENSE_POLICY = {
    "denied": frozenset({"GPL-1.0", "GPL-2.0", "GPL-3.0", "AGPL-1.0", "AGPL-3.0"}),
    "allowed": frozenset({
        "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Python-2.0",
    }),
}


class CanonicalImageCatalog:
    """4-image AgentOS canonical catalog + per-tenant allow-list +
    cosign + SBOM verification per spec §9 + ADR-016 amendment.

    Round-3 R4 P1 #3 fix: catalog stores FULL image refs (incl tag +
    digest, e.g. `cognic/sandbox-runtime-python:v1@sha256:...`), NOT
    bare digests. cosign + syft need the full ref to look up the image
    in the registry; `docker.io/sha256:...` is not a valid OCI ref.
    """

    def __init__(
        self,
        *,
        canonical_refs: frozenset[str],            # full image refs incl @sha256:<digest>
        tenant_trust_roots: dict[str, Path],
        tenant_allow_lists: dict[str, frozenset[str]],  # per-tenant full image refs
        tenant_license_policies: dict[str, dict[str, frozenset[str]]] | None = None,
    ) -> None:
        self._canonical_refs = canonical_refs
        # Derived digest set for fast O(1) lookup; built from the refs at construction
        self._canonical_digests: frozenset[str] = frozenset(
            ref.rsplit("@", 1)[1] for ref in canonical_refs if "@" in ref
        )
        self._tenant_trust_roots = tenant_trust_roots
        self._tenant_allow_lists = tenant_allow_lists
        # Derived per-tenant digest sets
        self._tenant_allow_listed_digests: dict[str, frozenset[str]] = {
            tid: frozenset(ref.rsplit("@", 1)[1] for ref in refs if "@" in ref)
            for tid, refs in tenant_allow_lists.items()
        }
        # Reverse-map digest → full ref so cosign + syft can look up the
        # full OCI ref from just the digest at admission time.
        self._digest_to_ref: dict[str, str] = {}
        for ref in canonical_refs:
            if "@" in ref:
                self._digest_to_ref[ref.rsplit("@", 1)[1]] = ref
        for refs in tenant_allow_lists.values():
            for ref in refs:
                if "@" in ref:
                    self._digest_to_ref[ref.rsplit("@", 1)[1]] = ref
        self._tenant_license_policies = tenant_license_policies or {}

    def is_canonical(self, image_digest: str) -> bool:
        return image_digest in self._canonical_digests

    def is_tenant_allow_listed(self, image_digest: str, tenant_id: str) -> bool:
        # Round-5 R5 P1 #2 fix: query the DERIVED digest set
        # (_tenant_allow_listed_digests) NOT the raw full-ref set
        # (_tenant_allow_lists). The raw set stores full OCI refs like
        # `bank/custom-pack-sandbox:v1@sha256:...`; admission passes
        # the bare digest extracted from policy.runtime_image; lookup
        # must compare on the digest axis.
        return image_digest in self._tenant_allow_listed_digests.get(tenant_id, frozenset())

    async def verify_cosign(self, image_digest: str, *, tenant_id: str) -> CosignVerifyResult:
        """Pure-result variant — caller decides refuse vs continue."""
        return await self._run_cosign_verify(image_digest, tenant_id=tenant_id)

    async def verify_cosign_or_refuse(self, image_digest: str, *, tenant_id: str) -> None:
        """Convenience: raises SandboxLifecycleRefused on fail."""
        try:
            result = await self._run_cosign_verify(image_digest, tenant_id=tenant_id)
        except FileNotFoundError as exc:
            raise SandboxLifecycleRefused(
                "sandbox_image_cosign_verification_failed",
                detail=f"cosign binary missing: {exc}",
            ) from exc
        if not result.passed:
            raise SandboxLifecycleRefused(
                "sandbox_image_cosign_verification_failed",
                detail=result.detail,
            )

    async def verify_sbom_policy(self, image_digest: str, *, tenant_id: str) -> SBOMVerifyResult:
        return await self._run_syft_inspect(image_digest, tenant_id=tenant_id)

    async def verify_sbom_policy_or_refuse(
        self, image_digest: str, *, tenant_id: str
    ) -> None:
        result = await self._run_syft_inspect(image_digest, tenant_id=tenant_id)
        if not result.passed:
            raise SandboxLifecycleRefused(
                "sandbox_image_sbom_check_failed",
                detail=result.detail,
            )

    async def _run_cosign_verify(
        self, image_digest: str, *, tenant_id: str
    ) -> CosignVerifyResult:
        """Subprocess seam — mocked at test time. Real impl shells out to
        `cosign verify` against tenant trust root.

        Round-3 R4 P1 #3 fix: resolves the full OCI image ref (incl
        registry + repo + tag + digest) from the catalog's reverse-map
        before shelling out. `docker.io/sha256:...` is NOT a valid OCI
        ref; cosign needs the full `cognic/sandbox-runtime-python:v1
        @sha256:...` form (or whatever registry-namespaced ref the
        catalog has registered).
        """
        trust_root = self._tenant_trust_roots.get(tenant_id)
        if trust_root is None:
            return CosignVerifyResult(passed=False, detail=f"no trust root for {tenant_id}")
        full_ref = self._digest_to_ref.get(image_digest)
        if full_ref is None:
            # Bug-class guard: cosign was asked about a digest that
            # isn't in the catalog's reverse-map. Should be unreachable
            # if admission step 6 (catalog-membership) passed first.
            return CosignVerifyResult(
                passed=False,
                detail=f"digest {image_digest} not in catalog reverse-map (admission step 6 should have caught this)",
            )
        proc = await asyncio.create_subprocess_exec(
            "cosign", "verify",
            "--key", str(trust_root),
            "--certificate-identity-regexp", ".*",
            full_ref,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode == 0:
            return CosignVerifyResult(passed=True, detail=stdout.decode())
        return CosignVerifyResult(passed=False, detail=stderr.decode())

    async def _run_syft_inspect(
        self, image_digest: str, *, tenant_id: str
    ) -> SBOMVerifyResult:
        """Subprocess seam — mocked at test time. Real impl shells out
        to `syft <image_ref> -o json` + applies tenant license-policy
        loaded from `self._tenant_license_policies[tenant_id]`.

        Per-tenant license policy file shape (Wave-1 default):
        ```yaml
        # policies/tenants/<tenant_id>/sandbox_licenses.yaml
        version: 1
        denied:
          - GPL-1.0
          - GPL-2.0
          - GPL-3.0
          - AGPL-1.0
          - AGPL-3.0
        allowed:
          - MIT
          - Apache-2.0
          - BSD-2-Clause
          - BSD-3-Clause
          - ISC
          - Python-2.0
        # Licenses neither in allowed nor denied → refuse (default-deny).
        ```
        """
        full_ref = self._digest_to_ref.get(image_digest)
        if full_ref is None:
            return SBOMVerifyResult(
                passed=False,
                detail=f"digest {image_digest} not in catalog reverse-map (admission step 6 should have caught this)",
            )
        proc = await asyncio.create_subprocess_exec(
            "syft", full_ref, "-o", "json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            return SBOMVerifyResult(
                passed=False, detail=f"syft exited {proc.returncode}: {stderr.decode()}",
            )
        sbom = json.loads(stdout)
        # Apply tenant license policy: every license in the SBOM's artifacts
        # MUST be in the tenant's `allowed` set AND none in the `denied` set.
        policy = self._tenant_license_policies.get(tenant_id, _DEFAULT_LICENSE_POLICY)
        violations: list[str] = []
        for artifact in sbom.get("artifacts", []):
            for lic in artifact.get("licenses", []):
                lic_id = lic.get("value", "")
                if lic_id in policy["denied"]:
                    violations.append(
                        f"{artifact['name']}@{artifact.get('version', '?')}: {lic_id} (denied)"
                    )
                elif lic_id not in policy["allowed"]:
                    violations.append(
                        f"{artifact['name']}@{artifact.get('version', '?')}: {lic_id} (not in allow-list; default-deny)"
                    )
        if violations:
            return SBOMVerifyResult(
                passed=False,
                detail=f"license policy violations ({len(violations)} entries): "
                       + "; ".join(violations[:5])
                       + (f"; +{len(violations) - 5} more" if len(violations) > 5 else ""),
            )
        return SBOMVerifyResult(passed=True, detail=f"sbom passed; {len(sbom.get('artifacts', []))} artifacts")
```

(The `_DEFAULT_LICENSE_POLICY` constant + `json` / `asyncio` imports are already at module top per the round-4 R4 P1 #2 fix. The `__init__` signature was simultaneously updated to accept `canonical_refs` (full OCI refs incl `@sha256:` digest) instead of bare `canonical_digests` per the round-4 R4 P1 #3 fix; the reverse-map `_digest_to_ref` is built at construction so cosign + syft can shell out against the real image ref. The T6 fixture above already uses the round-5-corrected `canonical_refs=` constructor signature — no migration step needed at implementation time.)

- [ ] **Step 4: Verify green** — all catalog tests pass with mocked subprocess.

- [ ] **Step 5: CC halt-before-commit per AGENTS.md**

Run the gate ladder: `uv run ruff check src tests` + `ruff format --check` + `mypy src tests` (full-tree) + `pytest tests/unit/sandbox/test_image_catalog.py -v`. Produce halt summary; pause for user `commit` token.

- [ ] **Step 6: Commit**

```
feat(sprint-8a): T6 — catalog.py canonical image catalog + cosign + real syft SBOM verification (CRITICAL CONTROLS)

Per spec §9 + ADR-016 amendment "AgentOS-published runtime artifacts".
Lands CanonicalImageCatalog with:

* 4-image canonical catalog stored as full OCI refs (runtime-python +
  runtime-shell + runtime-data + egress-proxy sidecar) with derived
  digest sets + _digest_to_ref reverse-map for fast O(1) admission
  lookup AND full-ref resolution at cosign/syft subprocess time
* Per-tenant allow-list (full OCI refs) for per-pack image escape
  hatch; admission's is_tenant_allow_listed() queries the derived
  per-tenant digest set
* cosign subprocess seam (_run_cosign_verify shells out to `cosign
  verify --key <trust-root> <full-ref>`); mocked at unit-test layer,
  real cosign in T10 env-gated integration tests
* Real syft SBOM verification (_run_syft_inspect shells out to `syft
  <full-ref> -o json`, parses artifacts, applies per-tenant license
  policy from tenant_license_policies kwarg with _DEFAULT_LICENSE_POLICY
  fallback: denied GPL-1.0/2.0/3.0 + AGPL; allowed MIT/Apache-2.0/
  BSD-2/BSD-3/ISC/Python-2.0; default-deny otherwise)
* Bug-class guard: cosign/syft return SandboxLifecycleRefused if
  asked about a digest not in the reverse-map (admission step 6
  should have caught it; this is defence-in-depth)

Critical-controls module per spec §17 (round-2 P1 promotion — a bug
here lets untrusted images run or runs unverified-license code; not
"thin wiring"). 95/90 line/branch coverage targeted at T12 gate-uplift.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
```

---

## Task T7 — Egress proxy config rendering (CC)

**Scope:** `sandbox/proxy.py` — render `SandboxPolicy.egress_allow_list` into proxy-bundle config (env vars passed to the proxy sidecar at start); per-request `ProxyAccessRecord` shape; proxy_log → chain row materialisation helper.

**Files:**
- Create: `src/cognic_agentos/sandbox/proxy.py`
- Create: `tests/unit/sandbox/test_egress_proxy_config.py`
- Modify: `src/cognic_agentos/sandbox/__init__.py` (export `EgressProxyConfig` + `ProxyAccessRecord` + `render_proxy_config`)

**Doctrine refs:** spec §10.2 (proxy implementation) + §10.3 (audit emission) + §10.4 (proxy-observed vs network-blocked).

### T7 steps

- [ ] **Step 1: Write failing tests — allow-list rendering + ProxyAccessRecord shape**

```python
# tests/unit/sandbox/test_egress_proxy_config.py
"""Sprint 8A T7 — egress proxy config rendering + ProxyAccessRecord shape."""
from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from cognic_agentos.sandbox import SandboxLifecycleRefused
from cognic_agentos.sandbox.proxy import (
    EgressProxyConfig,
    ProxyAccessRecord,
    proxy_log_to_chain_payload,
    render_proxy_config,
)


class TestRenderProxyConfig:
    def test_renders_allow_list_to_env_vars_for_sidecar(self) -> None:
        config = render_proxy_config(
            egress_allow_list=("api.example.com", "data.example.com"),
            session_id="sess-1",
        )
        assert isinstance(config, EgressProxyConfig)
        env = config.to_env()
        # ALLOW_LIST is a JSON array — the sidecar parses on start
        assert json.loads(env["ALLOW_LIST"]) == ["api.example.com", "data.example.com"]
        assert env["SESSION_ID"] == "sess-1"

    def test_empty_allow_list_renders_no_external_egress_allowed(self) -> None:
        config = render_proxy_config(egress_allow_list=(), session_id="sess-2")
        assert json.loads(config.to_env()["ALLOW_LIST"]) == []

    def test_https_scheme_stripped_to_hostname_only(self) -> None:
        """Allow-list entries may carry https:// scheme; sidecar config
        wants hostnames only (the sidecar enforces https-CONNECT itself)."""
        config = render_proxy_config(
            egress_allow_list=("https://api.example.com",), session_id="s",
        )
        assert json.loads(config.to_env()["ALLOW_LIST"]) == ["api.example.com"]

    def test_ftp_scheme_refused_via_egress_protocol_not_http(self) -> None:
        """Defence-in-depth — Stage-1 validate_policy_shape already
        catches ftp:// in egress_allow_list, but render_proxy_config
        must ALSO refuse so it cannot be called from an unvalidated
        path."""
        with pytest.raises(SandboxLifecycleRefused) as exc:
            render_proxy_config(egress_allow_list=("ftp://files.example.com",), session_id="s")
        assert exc.value.reason == "sandbox_policy_egress_protocol_not_http"


class TestProxyAccessRecord:
    def test_record_shape_carries_required_fields(self) -> None:
        rec = ProxyAccessRecord(
            host="api.example.com",
            method="GET",
            timestamp=datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC),
            policy_id="pol-1",
            outcome="allowed",
            refusal_reason=None,
        )
        assert rec.host == "api.example.com"
        assert rec.outcome == "allowed"
        assert rec.refusal_reason is None

    def test_refusal_record_carries_closed_enum_reason(self) -> None:
        rec = ProxyAccessRecord(
            host="evil.example.com",
            method="GET",
            timestamp=datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC),
            policy_id="pol-1",
            outcome="refused",
            refusal_reason="not_in_allow_list",
        )
        assert rec.outcome == "refused"
        assert rec.refusal_reason == "not_in_allow_list"


class TestProxyLogToChainPayload:
    def test_renders_list_of_records_to_canonical_json_friendly_dicts(self) -> None:
        records = (
            ProxyAccessRecord(
                host="api.example.com", method="GET",
                timestamp=datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC),
                policy_id="pol-1", outcome="allowed", refusal_reason=None,
            ),
        )
        payload = proxy_log_to_chain_payload(records)
        assert payload == [{
            "host": "api.example.com",
            "method": "GET",
            "timestamp": "2026-05-16T12:00:00+00:00",
            "policy_id": "pol-1",
            "outcome": "allowed",
            "refusal_reason": None,
        }]
```

- [ ] **Step 2: Verify fail.** **Step 3: Implement** with `EgressProxyConfig` dataclass + `render_proxy_config` (validates each entry, strips scheme, returns env-dict via `to_env()`) + `ProxyAccessRecord` frozen dataclass + `proxy_log_to_chain_payload(records)` returning the list-of-dicts for the chain row's `payload.proxy_log` per spec §10.3. **Step 4: Verify green. Step 5: CC halt-before-commit. Step 6: Commit.**

```
feat(sprint-8a): T7 — proxy.py egress allow-list rendering + ProxyAccessRecord (CRITICAL CONTROLS)

Per spec §10.2 + §10.3 + §10.4. Lands EgressProxyConfig (allow-list →
sidecar env vars) + ProxyAccessRecord (per-request audit shape) +
proxy_log_to_chain_payload (list[record] → list[dict] for chain row).
Defence-in-depth scheme refusal: ftp:// in egress_allow_list refuses
even if Stage-1 was bypassed.

Critical-controls module per spec §17 (round-2 P1 promotion — single
egress enforcement point; a bug here lets forbidden traffic through).

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
```

---

## Task T8 — CredentialAdapter re-export shim (NOT-CC; replaced in Sprint 10)

> **PATCHED 2026-05-17 — see "Post-T8 implementation notes" at top of file. The original T8 body (pre-patch) declared a richer `CredentialLease + mint_lease/revoke_lease` API that DIVERGED from the T5-committed reality (T5 at `4967ce8` landed a single-method `fetch_secret` CredentialAdapter + the matching KernelDefaultCredentialAdapter sentinel inline in `sandbox/admission.py`). This T8 body is the patched recipe — a thin re-export shim per the consumer-owned-Protocol resolution rule. Re-declaring the Protocol + sentinel as standalone would create two source-of-truth modules that drift.**

**Scope:** `sandbox/credentials.py` — a thin re-export shim that imports `CredentialAdapter` + `KernelDefaultCredentialAdapter` from `sandbox.admission` (the canonical home as of T5). The downstream import path `from cognic_agentos.sandbox.credentials import ...` becomes a stable alias point so Sprint 10's `VaultCredentialAdapter` can replace the stub without rewriting consumers. OFF the durable critical-controls gate (re-export shim with zero new logic; the real `VaultCredentialAdapter` at Sprint 10 lands on the gate).

**Files:**
- Create: `src/cognic_agentos/sandbox/credentials.py` (~30 LoC re-export shim + docstring)
- Create: `tests/unit/sandbox/test_credential_adapter_stub.py` (pins re-export equivalence + the actual stub error contract)
- Modify: `src/cognic_agentos/sandbox/__init__.py` — already re-exports `CredentialAdapter` + `KernelDefaultCredentialAdapter` from `sandbox.admission`; T8 leaves the public surface unchanged but adds explicit re-export from `sandbox.credentials` so both import paths resolve to the same objects.

**Doctrine refs:** spec §8 (CredentialAdapter Protocol + Sprint-10 stub) + ADR-004 amendment §"Credential-scoped" + AGENTS.md production-grade rule ("stub modules that raise `NotImplementedError` pointing at an ADR are acceptable scaffolding; silent in-process fallbacks that pretend to work are not") + `feedback_consumer_owned_protocol_for_unlanded_dep` resolution rule (preference (a): re-export shim).

### T8 steps

- [ ] **Step 1: Write failing tests — re-export equivalence + Protocol membership + the actual fetch_secret stub error contract + admit_policy short-circuit invariant**

```python
# tests/unit/sandbox/test_credential_adapter_stub.py
"""Sprint 8A T8 — credentials.py re-export shim.

Pins that:
* `sandbox.credentials` re-exports the SAME OBJECTS as `sandbox.admission`
  for `CredentialAdapter` + `KernelDefaultCredentialAdapter` (re-export
  equivalence; NOT structural duplication — duplicates would drift).
* `sandbox.__init__` exposes both import paths and they resolve to the
  same objects.
* `KernelDefaultCredentialAdapter` satisfies the @runtime_checkable
  `CredentialAdapter` Protocol.
* `fetch_secret` raises `NotImplementedError` with the actual T5-committed
  stub message (cites Sprint 10 + ADR-009 — ADR-009 is the canonical
  pluggable-adapter ADR; ADR-004's credential-scope is the architectural
  intent, ADR-009 is the implementation home).
* Defence-in-depth: when `policy.vault_path is None`, admit_policy NEVER
  calls `fetch_secret` on the wired adapter, regardless of which adapter
  is wired (covered separately at T10a lifecycle level; this is the
  unit-level pin).
"""
from __future__ import annotations

import pytest

from cognic_agentos.sandbox import (
    CredentialAdapter,
    KernelDefaultCredentialAdapter,
)


class TestReExportEquivalence:
    """The shim MUST re-export the SAME object (not a duplicate
    declaration). Object identity catches drift-by-duplicate before
    runtime."""

    def test_credential_adapter_is_same_object_via_both_paths(self) -> None:
        from cognic_agentos.sandbox.admission import CredentialAdapter as AdmissionCA
        from cognic_agentos.sandbox.credentials import CredentialAdapter as CredentialsCA

        assert AdmissionCA is CredentialsCA, (
            "credentials.py must re-export the SAME CredentialAdapter "
            "Protocol from sandbox.admission, not redeclare it. "
            "Object-identity check catches a duplicate declaration "
            "that would otherwise pass `isinstance` checks but drift "
            "in signature."
        )

    def test_kernel_default_is_same_object_via_both_paths(self) -> None:
        from cognic_agentos.sandbox.admission import (
            KernelDefaultCredentialAdapter as AdmissionKDCA,
        )
        from cognic_agentos.sandbox.credentials import (
            KernelDefaultCredentialAdapter as CredentialsKDCA,
        )

        assert AdmissionKDCA is CredentialsKDCA

    def test_sandbox_package_exposes_same_object_as_credentials_module(self) -> None:
        """`from cognic_agentos.sandbox import X` and `from
        cognic_agentos.sandbox.credentials import X` MUST resolve to
        the same object so consumers can use either path."""
        from cognic_agentos.sandbox import (
            CredentialAdapter as PkgCA,
            KernelDefaultCredentialAdapter as PkgKDCA,
        )
        from cognic_agentos.sandbox.credentials import (
            CredentialAdapter as CredentialsCA,
            KernelDefaultCredentialAdapter as CredentialsKDCA,
        )

        assert PkgCA is CredentialsCA
        assert PkgKDCA is CredentialsKDCA


class TestProtocolShape:
    def test_kernel_default_satisfies_credential_adapter_protocol(self) -> None:
        """The stub MUST satisfy the @runtime_checkable Protocol so
        admission's isinstance check works AND the type system accepts
        the stub wherever a real CredentialAdapter is expected."""
        adapter = KernelDefaultCredentialAdapter()
        assert isinstance(adapter, CredentialAdapter)

    def test_credential_adapter_declares_fetch_secret_only(self) -> None:
        """T5 landed the single-method `fetch_secret` API. The richer
        mint_lease/revoke_lease lease API belongs to Sprint 10's
        concrete VaultCredentialAdapter design — adding it to the
        Wave-1 Protocol would be scope creep. This pin catches an
        accidental re-introduction of the lease API onto the Protocol."""
        # The Protocol is structural; assert the only method the
        # admission seam contracts on is fetch_secret.
        method_names = {
            name for name in dir(CredentialAdapter)
            if not name.startswith("_") and callable(getattr(CredentialAdapter, name, None))
        }
        # `fetch_secret` is the contract; everything else is Protocol
        # machinery from `typing`.
        assert "fetch_secret" in method_names


class TestStubFailsLoudWithSprintTenPointer:
    @pytest.mark.asyncio
    async def test_fetch_secret_raises_not_implemented_with_sprint_10_pointer(self) -> None:
        adapter = KernelDefaultCredentialAdapter()
        with pytest.raises(NotImplementedError) as exc:
            await adapter.fetch_secret("secret/test")
        # Per AGENTS.md production-grade rule: stub error message MUST
        # cite the sprint that replaces it AND the ADR that owns the
        # contract. The T5-committed message cites Sprint 10 + ADR-009
        # (ADR-009 is the pluggable-adapter home; ADR-004 is the
        # sandbox-primitive ADR that lifts the architectural intent
        # into a sandbox-level concept).
        msg = str(exc.value)
        assert "Sprint 10" in msg
        assert "ADR-009" in msg
        assert "VaultCredentialAdapter" in msg
        assert "fail-loud sentinel" in msg


class TestSandboxesWithoutCredentialsUnaffected:
    """Sandboxes whose policy has vault_path=None never call the
    credential adapter; the fail-loud stub is invisible to them. This
    is the load-bearing invariant from spec §2.2 ("Sandboxes that do
    not request credentials are unaffected"). The actual sandbox-
    without-creds happy path lands in T10a's lifecycle test; this
    is the unit-level pin that fetch_secret is NEVER called when
    policy.vault_path is None."""

    @pytest.mark.asyncio
    async def test_admit_policy_does_not_call_fetch_secret_when_vault_path_none(
        self,
    ) -> None:
        from unittest.mock import AsyncMock, MagicMock

        from cognic_agentos.sandbox import PackAdmissionContext, SandboxPolicy
        from cognic_agentos.sandbox.admission import admit_policy

        # Wrap the stub so we can assert fetch_secret was never called
        stub = KernelDefaultCredentialAdapter()
        original_fetch_secret = stub.fetch_secret
        stub.fetch_secret = AsyncMock(side_effect=original_fetch_secret)  # type: ignore[method-assign]

        # MagicMock (not AsyncMock) so sync membership checks return
        # real bools; the verify_* async methods get explicit AsyncMock.
        catalog = MagicMock()
        catalog.is_canonical.return_value = True
        catalog.is_tenant_allow_listed.return_value = False
        catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
        catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
        rego = MagicMock()
        rego_decision = MagicMock()
        rego_decision.allow = True
        rego_decision.reasoning = ""
        rego.evaluate = AsyncMock(return_value=rego_decision)
        settings = MagicMock(
            sandbox_per_tenant_max_cpu=4.0,
            sandbox_per_tenant_max_memory=1024,
            sandbox_per_tenant_max_walltime=300.0,
        )

        policy = SandboxPolicy(
            cpu_cores=0.5,
            cpu_time_budget_s=None,
            memory_mb=256,
            walltime_s=30.0,
            runtime_image=(
                "cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64
            ),
            egress_allow_list=(),
            vault_path=None,  # ← KEY: no creds requested
        )
        ctx = PackAdmissionContext(
            pack_id="p",
            pack_version="v1",
            pack_artifact_digest="sha256:" + "1" * 64,
            risk_tier="internal_write",
            declares_dynamic_install=False,
            profile="production",
        )

        await admit_policy(
            policy,
            tenant_id="t-1",
            actor=MagicMock(),
            pack_context=ctx,
            catalog=catalog,
            credential_adapter=stub,
            rego_engine=rego,
            settings=settings,
        )

        stub.fetch_secret.assert_not_called()
```

- [ ] **Step 2: Verify fail** — `uv run pytest tests/unit/sandbox/test_credential_adapter_stub.py -v` → `ModuleNotFoundError: No module named 'cognic_agentos.sandbox.credentials'`.

- [ ] **Step 3: Implement `sandbox/credentials.py` re-export shim**

```python
# src/cognic_agentos/sandbox/credentials.py
"""Sprint 8A T8 — credentials.py re-export shim.

The canonical home of ``CredentialAdapter`` Protocol +
``KernelDefaultCredentialAdapter`` sentinel is
:mod:`cognic_agentos.sandbox.admission` (T5 commit ``4967ce8`` per
``feedback_consumer_owned_protocol_for_unlanded_dep`` — T5 declared the
dependency Protocols + sentinel inline in admission.py so the CC module
could ship independently runnable; T8 was scheduled to own the canonical
home but the user-preferred resolution (T5 R0) was a re-export shim, NOT
a canonical-home shift).

This module is a thin re-export shim that exposes the same names at the
``cognic_agentos.sandbox.credentials`` import path. Sprint 10's
``VaultCredentialAdapter`` will replace ``KernelDefaultCredentialAdapter``
in this module without rewriting any consumer that imports from
``sandbox.credentials``.

NOT on the durable critical-controls coverage gate — re-export shim with
zero new logic. The CC risk is covered by ``sandbox/admission.py``
already being on the gate. Sprint 10's real ``VaultCredentialAdapter``
goes on the gate when it lands.

Per spec §8 + ADR-004 §"Credential-scoped" + ADR-009 (pluggable adapter
layer where the real Vault implementation lives).
"""

from __future__ import annotations

from cognic_agentos.sandbox.admission import (
    CredentialAdapter,
    KernelDefaultCredentialAdapter,
)

__all__ = [
    "CredentialAdapter",
    "KernelDefaultCredentialAdapter",
]
```

- [ ] **Step 4: Verify green** — `uv run pytest tests/unit/sandbox/test_credential_adapter_stub.py -v` passes.

- [ ] **Step 5: Standard pre-commit gate ladder** (NOT-CC module; no extended halt beyond the gate). `ruff check . + ruff format --check . + mypy src tests + uv run pytest tests/unit/sandbox -q`.

- [ ] **Step 6: Commit (await per-action authorization token)**

```
feat(sprint-8a): T8 — credentials.py re-export shim for CredentialAdapter + KernelDefaultCredentialAdapter (Sprint 10 placeholder)

Per spec §8 + ADR-004 §"Credential-scoped" + ADR-009 (pluggable adapter
layer). T8 lands the canonical `cognic_agentos.sandbox.credentials`
import path as a thin re-export shim that aliases the
`CredentialAdapter` Protocol + `KernelDefaultCredentialAdapter` sentinel
from `sandbox.admission` (where T5 declared them inline per the
consumer-owned-Protocol resolution rule when downstream modules are not
yet landed).

Sprint 10's VaultCredentialAdapter replaces KernelDefaultCredentialAdapter
in this module without rewriting any consumer.

NOT on the durable critical-controls coverage gate — re-export shim with
zero new logic. CC risk covered by `sandbox/admission.py` already on the
gate.

Tests pin: (1) object-identity re-export equivalence (caches drift-by-
duplicate); (2) Protocol membership; (3) the actual fetch_secret stub
error contract (cites Sprint 10 + ADR-009 + VaultCredentialAdapter +
fail-loud sentinel); (4) admit_policy short-circuit invariant
(fetch_secret never called when vault_path is None).

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
```

---

## Task T9 — Warm-pool (CC)

**Scope:** `sandbox/warm_pool.py` — `SandboxWarmPool` with `register / precreate / checkout / release_or_destroy / drain`; pool-key derives from `canonical_bytes(policy)` + 5 PackAdmissionContext fields (`pack_id` + `pack_artifact_digest` + `risk_tier` + `declares_dynamic_install` + `profile`); replenisher iterates registered pairs + calls `backend.create(..., use_warm_pool=False, pack_context=...)`.

**Files:**
- Create: `src/cognic_agentos/sandbox/warm_pool.py`
- Create: `tests/unit/sandbox/test_warm_pool.py`
- Modify: `src/cognic_agentos/sandbox/__init__.py` (export `SandboxWarmPool`)

**Doctrine refs:** spec §11 (warm-pool design + pool-key derivation + load-bearing test pins).

### T9 steps

- [ ] **Step 1: Write failing tests — the 3 spec-locked load-bearing pinning tests + per-method coverage**

```python
# tests/unit/sandbox/test_warm_pool.py
"""Sprint 8A T9 — SandboxWarmPool with the 3 load-bearing pinning tests
from spec §11 (replenisher uses use_warm_pool=False; checkout with
mismatched pack_context is pool miss; cold-created session releases to
correct pool key)."""
from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, call

import pytest

from cognic_agentos.sandbox import (
    PackAdmissionContext,
    SandboxPolicy,
    SandboxLifecycleRefused,
)
from cognic_agentos.sandbox.warm_pool import SandboxWarmPool

# Shared fixtures
_POLICY = SandboxPolicy(
    cpu_cores=1.0, cpu_time_budget_s=None, memory_mb=256, walltime_s=30.0,
    runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
    egress_allow_list=("api.example.com",),
    vault_path=None, warm_pool_key="python-interactive",
)
_PACK_CTX_A = PackAdmissionContext(
    pack_id="pack.a", pack_version="v1",
    pack_artifact_digest="sha256:" + "1" * 64,
    risk_tier="internal_write",
    declares_dynamic_install=False, profile="production",
)
_PACK_CTX_B = PackAdmissionContext(  # different pack_id + different artifact
    pack_id="pack.b", pack_version="v1",
    pack_artifact_digest="sha256:" + "2" * 64,
    risk_tier="internal_write",
    declares_dynamic_install=False, profile="production",
)


def _make_session(session_id: str, pack_ctx: PackAdmissionContext) -> MagicMock:
    """Mock SandboxSession that carries policy + pack_context per spec §5."""
    s = MagicMock()
    s.session_id = session_id
    s.policy = _POLICY
    s.tenant_id = "t-1"
    s.pack_context = pack_ctx
    s.created_at = datetime.now(UTC)
    s.warm_pool_hit = False
    return s


class TestReplenisherBypassesPool:
    """Spec §11 load-bearing pinning test #1 — replenisher MUST call
    backend.create(..., use_warm_pool=False); without this kwarg the
    replenisher would re-enter the pool-check fast-path and either
    consume an existing member (decrementing while incrementing) OR
    loop indefinitely."""

    @pytest.mark.asyncio
    async def test_precreate_calls_backend_create_with_use_warm_pool_false(self) -> None:
        backend = AsyncMock()
        new_session = _make_session("warmed", _PACK_CTX_A)
        backend.create.return_value = new_session
        pool = SandboxWarmPool(
            backend=backend, max_pool_size_per_key=4, idle_ttl_s=300.0,
            audit_store=MagicMock(), decision_history_store=MagicMock(),
        )

        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)

        # Critical: backend.create was called with use_warm_pool=False
        backend.create.assert_awaited_once()
        kwargs = backend.create.await_args.kwargs
        assert kwargs["use_warm_pool"] is False, (
            "Replenisher MUST bypass warm-pool fast-path or it will "
            "either consume existing members or loop. Spec §11."
        )
        assert kwargs["pack_context"] == _PACK_CTX_A
        assert kwargs["tenant_id"] == "t-1"

    @pytest.mark.asyncio
    async def test_pool_size_monotonically_increases_under_replenishment(self) -> None:
        backend = AsyncMock()
        backend.create.side_effect = [
            _make_session(f"warmed-{i}", _PACK_CTX_A) for i in range(3)
        ]
        pool = SandboxWarmPool(
            backend=backend, max_pool_size_per_key=4, idle_ttl_s=300.0,
            audit_store=MagicMock(), decision_history_store=MagicMock(),
        )
        for _ in range(3):
            await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        assert pool.current_size(_POLICY, pack_context=_PACK_CTX_A) == 3


class TestCheckoutWithPackContextMismatchIsPoolMiss:
    """Spec §11 load-bearing pinning test #2 — a session admitted for
    pack A (pack_artifact_digest X) MUST NOT be handed to pack B
    (pack_artifact_digest Y) even if policy is identical."""

    @pytest.mark.asyncio
    async def test_checkout_with_different_pack_context_returns_none(self) -> None:
        backend = AsyncMock()
        backend.create.return_value = _make_session("warmed-A", _PACK_CTX_A)
        pool = SandboxWarmPool(
            backend=backend, max_pool_size_per_key=4, idle_ttl_s=300.0,
            audit_store=MagicMock(), decision_history_store=MagicMock(),
        )
        # Pool has a member admitted for pack A
        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        assert pool.current_size(_POLICY, pack_context=_PACK_CTX_A) == 1

        # Checkout for pack B (different pack_id + artifact_digest) → pool miss
        result = await pool.checkout(
            policy=_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_B,
        )
        assert result is None, (
            "Pack B checkout MUST NOT consume pack A warm member; "
            "spec §11 pool-key uses 5 PackAdmissionContext fields"
        )
        # Pack A's warm member is still in the pool
        assert pool.current_size(_POLICY, pack_context=_PACK_CTX_A) == 1


class TestColdCreatedSessionReleasesToCorrectPoolKey:
    """Spec §11 load-bearing pinning test #3 — when sandbox_session()
    cold-creates after a pool miss and calls release_or_destroy(session)
    on context exit, the pool must derive the correct key from the
    session's pack_context field (which is on SandboxSession per the
    round-3 follow-on Protocol amendment)."""

    @pytest.mark.asyncio
    async def test_cold_release_then_matching_checkout_returns_session(self) -> None:
        backend = AsyncMock()
        pool = SandboxWarmPool(
            backend=backend, max_pool_size_per_key=4, idle_ttl_s=300.0,
            audit_store=MagicMock(), decision_history_store=MagicMock(),
        )
        # Caller cold-creates (no precreate); release_or_destroy deposits
        cold_session = _make_session("cold-1", _PACK_CTX_A)
        await pool.release_or_destroy(cold_session)
        assert pool.current_size(_POLICY, pack_context=_PACK_CTX_A) == 1
        # Subsequent matching checkout returns the deposited session
        result = await pool.checkout(
            policy=_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A,
        )
        assert result is cold_session


class TestDrainSemantics:
    @pytest.mark.asyncio
    async def test_drain_destroys_all_warm_members_and_refuses_subsequent_checkout(
        self,
    ) -> None:
        backend = AsyncMock()
        backend.create.return_value = _make_session("warmed", _PACK_CTX_A)
        pool = SandboxWarmPool(
            backend=backend, max_pool_size_per_key=4, idle_ttl_s=300.0,
            audit_store=MagicMock(), decision_history_store=MagicMock(),
        )
        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)

        await pool.drain()

        # Checkout from drained pool → SandboxLifecycleRefused
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await pool.checkout(policy=_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        assert exc.value.reason == "sandbox_warm_pool_drained"
```

- [ ] **Step 2: Verify fail.** **Step 3: Implement** `SandboxWarmPool` with internal `dict[bytes, deque[SandboxSession]]` keyed by `_derive_pool_key(policy, pack_context)`; per-key `asyncio.Lock` so checkouts + releases are serialised; `_drained: bool` flag flipped by `drain()`; background replenisher launched by `start_replenisher()` (called by the harness; not in unit tests). **Step 4: Verify green. Step 5: CC halt-before-commit. Step 6: Commit.**

```
feat(sprint-8a): T9 — warm_pool.py SandboxWarmPool + 3 load-bearing pinning tests (CRITICAL CONTROLS)

Per spec §11. Lands SandboxWarmPool with register/precreate/checkout/
release_or_destroy/drain API. Pool-key from canonical_bytes(policy) +
5 PackAdmissionContext fields (pack_id + pack_artifact_digest +
risk_tier + declares_dynamic_install + profile per round-3-third-
follow-on amendment).

Three load-bearing pinning tests catch the regression classes the
spec rounds discovered:
* test_precreate_calls_backend_create_with_use_warm_pool_false
  (round-1 P1 — replenisher bypass; without it consume-while-increment
  or infinite loop)
* test_checkout_with_different_pack_context_returns_none (round-3-FU2
  P1 — pack A's warm session cannot serve pack B even if policy matches)
* test_cold_release_then_matching_checkout_returns_session (round-3-FU
  P1 — sandbox_session() cold-create followed by release_or_destroy
  deposits to correct key derived from session.pack_context)

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
```

---

## Task T10 — DockerSiblingSandboxBackend (CC; LARGEST SINGLE TASK — sub-divisible)

**Scope:** `sandbox/backends/docker_sibling.py` — dual-container topology + cgroup integration + create/exec/destroy/health implementing the SandboxBackend Protocol. Largest single T-task; ~600 LoC + 4 dedicated test files + shared conformance suite parameterized for Docker arm. **Likely sub-divisible at execution time** into T10a (lifecycle + topology) + T10b (resource caps + cgroup integration) + T10c (egress integration + conformance harness) if single-task reviewer attention budget is overrun; the per-sub-task halt-before-commit pattern stays identical.

**Files:**
- Create: `src/cognic_agentos/sandbox/backends/__init__.py` (empty package marker)
- Create: `src/cognic_agentos/sandbox/backends/docker_sibling.py` (~600 LoC)
- Create: `tests/unit/sandbox/backends/__init__.py`
- Create: `tests/unit/sandbox/backends/test_docker_sibling_lifecycle.py` (env-gated `COGNIC_RUN_DOCKER_SANDBOX=1`; needs real Docker daemon)
- Create: `tests/unit/sandbox/backends/test_docker_sibling_egress.py` (env-gated; needs real Docker + the proxy sidecar image)
- Create: `tests/unit/sandbox/backends/test_docker_sibling_resource_caps.py` (env-gated; needs real cgroups)
- Create: `tests/unit/sandbox/backends/test_docker_sibling_image_pin.py` (unit; mocks `CanonicalImageCatalog`)
- Create: `tests/conformance/sandbox/__init__.py`
- Create: `tests/conformance/sandbox/conftest.py` (backend-parameterized fixture; in 8A only Docker arm exists; 8B adds K8sPod arm)
- Create: `tests/conformance/sandbox/test_backend_conformance.py` (parametrized over backend impls)
- Modify: `src/cognic_agentos/sandbox/__init__.py` (export `DockerSiblingSandboxBackend`)

**Doctrine refs:** spec §7 (DockerSibling impl) + §10.1 (dual-container topology with ASCII diagram) + ADR-004 amendment §Backend choice.

### T10 sub-task breakdown (recommend separate halt-before-commit per sub-task)

#### T10a — Lifecycle + dual-container topology

- [ ] **Step 1: Write failing test — lifecycle on real Docker (env-gated)**

```python
# tests/unit/sandbox/backends/test_docker_sibling_lifecycle.py
"""Sprint 8A T10a — DockerSiblingSandboxBackend lifecycle on real Docker.

env-gated: COGNIC_RUN_DOCKER_SANDBOX=1 + Docker daemon reachable.
Tests skipped in standard CI; runs locally + in the Sprint-8A
sandbox-integration CI lane.
"""
import os
import uuid
from datetime import UTC, datetime

import pytest

from cognic_agentos.sandbox import PackAdmissionContext, SandboxPolicy
from cognic_agentos.sandbox.backends.docker_sibling import DockerSiblingSandboxBackend

pytestmark = pytest.mark.skipif(
    os.environ.get("COGNIC_RUN_DOCKER_SANDBOX") != "1",
    reason="Docker daemon required — set COGNIC_RUN_DOCKER_SANDBOX=1 to run",
)


@pytest.fixture
async def docker_client():
    """Real Docker AsyncClient against host daemon."""
    import aiodocker
    client = aiodocker.Docker()
    yield client
    await client.close()


@pytest.fixture
async def catalog(tmp_path):
    """In-memory catalog preloaded with the 4 canonical Sprint-8A images.

    The image digests below are placeholders the T10-implementor fills
    in from the actual cognic/sandbox-runtime-{python,shell,data} + the
    egress-proxy sidecar images that the Sprint-4 supply-chain pipeline
    publishes for Sprint 8A. Tests assume the host docker daemon has
    them pre-pulled (CI lane runs `docker pull` against the canonical
    digests in a fixture setup step).
    """
    from cognic_agentos.sandbox.catalog import CanonicalImageCatalog
    trust_root = tmp_path / "cognic-cosign.pub"
    trust_root.write_text("# fixture trust root for env-gated DockerSibling test")
    return CanonicalImageCatalog(
        canonical_refs=frozenset({
            "cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
            "cognic/sandbox-runtime-shell:v1@sha256:" + "b" * 64,
            "cognic/sandbox-runtime-data:v1@sha256:" + "c" * 64,
            "cognic/sandbox-egress-proxy:v1@sha256:" + "d" * 64,
        }),
        tenant_trust_roots={"t-1": trust_root},
        tenant_allow_lists={"t-1": frozenset()},  # no per-pack overrides
    )


@pytest.fixture
async def backend(docker_client, catalog):
    """Real DockerSiblingSandboxBackend wired against the host Docker
    daemon + the fixture catalog + in-memory audit + decision-history
    stores. Tests assume cosign + syft are mocked at the catalog seam
    via monkeypatch.setattr in each test method (so the env-gated
    tests don't actually shell out to cosign + syft binaries)."""
    from cognic_agentos.core.audit import AuditStore
    from cognic_agentos.core.decision_history import DecisionHistoryStore
    from cognic_agentos.sandbox.backends.docker_sibling import DockerSiblingSandboxBackend
    from cognic_agentos.sandbox.credentials import KernelDefaultCredentialAdapter
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    audit = AuditStore(engine=engine)
    dh = DecisionHistoryStore(engine=engine)
    # Mock the OPA engine to always allow (Rego rules tested at T11)
    from unittest.mock import AsyncMock, MagicMock
    rego = AsyncMock()
    rego.evaluate = AsyncMock(return_value=MagicMock(allowed=True))
    return DockerSiblingSandboxBackend(
        docker_client=docker_client,
        image_catalog=catalog,
        credential_adapter=KernelDefaultCredentialAdapter(),
        rego_engine=rego,
        audit_store=audit,
        decision_history_store=dh,
        warm_pool=None,
    )


_INTERNAL_WRITE_POLICY = SandboxPolicy(
    cpu_cores=0.5, cpu_time_budget_s=None, memory_mb=256, walltime_s=30.0,
    runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
    egress_allow_list=("httpbin.org",), vault_path=None,
)
_TEST_PACK_CTX = PackAdmissionContext(
    pack_id="cognic.test_pack", pack_version="v1.0.0",
    pack_artifact_digest="sha256:" + "1" * 64,
    risk_tier="internal_write",
    declares_dynamic_install=False, profile="production",
)


class TestLifecycle:
    @pytest.mark.asyncio
    async def test_create_starts_sandbox_and_proxy_containers_on_internal_network(
        self, backend, monkeypatch
    ) -> None:
        """Per spec §7 + §10.1: create() spawns TWO containers (sandbox +
        proxy sidecar) on a per-session internal Docker network with no
        external gateway; sandbox HTTP_PROXY env points at the proxy."""
        from cognic_agentos.sandbox import sandbox_session
        from unittest.mock import MagicMock

        # Bypass cosign + SBOM at the catalog seam (T6 owns real impl tests)
        from cognic_agentos.sandbox.catalog import CosignVerifyResult, SBOMVerifyResult
        monkeypatch.setattr(
            backend._catalog, "_run_cosign_verify",
            AsyncMock(return_value=CosignVerifyResult(passed=True)),
        )
        monkeypatch.setattr(
            backend._catalog, "_run_syft_inspect",
            AsyncMock(return_value=SBOMVerifyResult(passed=True)),
        )

        actor = MagicMock(); actor.subject = "test-subject"
        async with sandbox_session(
            backend, _INTERNAL_WRITE_POLICY,
            actor=actor, tenant_id="t-1", pack_context=_TEST_PACK_CTX,
            use_warm_pool=False,
        ) as session:
            # Sandbox container is on exactly ONE network (the internal bridge)
            sandbox_info = await backend._docker.containers.get(session.session_id)
            attrs = await sandbox_info.show()
            assert attrs["State"]["Running"] is True
            networks = attrs["NetworkSettings"]["Networks"]
            assert len(networks) == 1
            internal_net_name = next(iter(networks))
            assert internal_net_name.startswith(f"cognic-sb-internal-{session.session_id[:8]}")

            # Internal network has Internal=true (no external gateway)
            internal_net = await backend._docker.networks.get(internal_net_name)
            net_attrs = await internal_net.show()
            assert net_attrs["Internal"] is True

            # Proxy sidecar container is on BOTH internal + egress networks
            proxy_info = await backend._docker.containers.get(f"{session.session_id}-proxy")
            proxy_attrs = await proxy_info.show()
            assert len(proxy_attrs["NetworkSettings"]["Networks"]) == 2

            # Sandbox HTTP_PROXY env vars point at proxy on internal-net DNS
            env_pairs = attrs["Config"]["Env"]
            env_dict = dict(p.split("=", 1) for p in env_pairs)
            assert env_dict["HTTP_PROXY"].startswith("http://egress-proxy:")
            assert env_dict["HTTPS_PROXY"].startswith("http://egress-proxy:")

        # On context exit: both containers + both networks gone (cleanup)
        from aiodocker.exceptions import DockerError
        with pytest.raises(DockerError):
            await backend._docker.containers.get(session.session_id)
        with pytest.raises(DockerError):
            await backend._docker.networks.get(internal_net_name)

    @pytest.mark.asyncio
    async def test_destroy_is_idempotent(self, backend, monkeypatch) -> None:
        """destroy() called twice does NOT raise per spec §5 SandboxBackend.destroy
        docstring ("Tear down the session. Idempotent.")."""
        from cognic_agentos.sandbox.catalog import CosignVerifyResult, SBOMVerifyResult
        monkeypatch.setattr(backend._catalog, "_run_cosign_verify",
            AsyncMock(return_value=CosignVerifyResult(passed=True)))
        monkeypatch.setattr(backend._catalog, "_run_syft_inspect",
            AsyncMock(return_value=SBOMVerifyResult(passed=True)))

        from unittest.mock import MagicMock
        actor = MagicMock(); actor.subject = "test-subject"
        session = await backend.create(
            _INTERNAL_WRITE_POLICY,
            actor=actor, tenant_id="t-1", pack_context=_TEST_PACK_CTX,
            use_warm_pool=False,
        )
        await backend.destroy(session)
        # Second destroy() must not raise
        await backend.destroy(session)


class TestHealth:
    @pytest.mark.asyncio
    async def test_health_returns_ok_when_docker_daemon_reachable(self, backend) -> None:
        from cognic_agentos.sandbox.protocol import SandboxBackendHealth
        result = await backend.health()
        assert isinstance(result, SandboxBackendHealth)
        assert result.status == "ok"
```

- [ ] **Step 2-6: implement + verify + halt + commit** for T10a (lifecycle + topology only).

#### T10b — Resource caps + cgroup integration

- [ ] **Step 1: Write failing tests — memory OOM, walltime, cpu_time_budget per spec §7**

```python
# tests/unit/sandbox/backends/test_docker_sibling_resource_caps.py
"""Sprint 8A T10b — resource cap enforcement per spec §7.

Per round-3 P2 fix: --cpus throttling under cap is NOT a violation;
only cpu_time_budget_exceeded fires (and only when budget set).
"""
import os
import pytest

from cognic_agentos.sandbox import SandboxPolicyViolated

pytestmark = pytest.mark.skipif(
    os.environ.get("COGNIC_RUN_DOCKER_SANDBOX") != "1",
    reason="Docker daemon + cgroups required",
)


class TestResourceCapsFireOrDontFire:
    """Re-uses the `backend` + `monkeypatch` + `_TEST_PACK_CTX` fixtures
    from test_docker_sibling_lifecycle.py's conftest (declare once;
    import here via the conftest auto-discovery)."""

    @pytest.mark.asyncio
    async def test_memory_oom_emits_memory_cap_exceeded(
        self, backend, monkeypatch
    ) -> None:
        """Per spec §7 + §4.2: 1 GiB malloc in a 64 MiB-capped sandbox
        kills via OOM-killer (exit code 137 + oom_killed in container
        attrs); backend raises SandboxPolicyViolated(memory_cap_exceeded)."""
        from cognic_agentos.sandbox import SandboxPolicy, SandboxPolicyViolated, sandbox_session
        from cognic_agentos.sandbox.catalog import CosignVerifyResult, SBOMVerifyResult
        from unittest.mock import AsyncMock, MagicMock

        monkeypatch.setattr(backend._catalog, "_run_cosign_verify",
            AsyncMock(return_value=CosignVerifyResult(passed=True)))
        monkeypatch.setattr(backend._catalog, "_run_syft_inspect",
            AsyncMock(return_value=SBOMVerifyResult(passed=True)))

        policy = SandboxPolicy(
            cpu_cores=0.5, cpu_time_budget_s=None, memory_mb=64, walltime_s=10.0,
            runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
            egress_allow_list=(), vault_path=None,
        )
        actor = MagicMock(); actor.subject = "test-subject"
        with pytest.raises(SandboxPolicyViolated) as exc:
            async with sandbox_session(
                backend, policy,
                actor=actor, tenant_id="t-1", pack_context=_TEST_PACK_CTX,
                use_warm_pool=False,
            ) as s:
                await s.exec(["python", "-c", "x = bytearray(1024 * 1024 * 1024)"])
        assert exc.value.reason == "memory_cap_exceeded"

    @pytest.mark.asyncio
    async def test_walltime_cap_fires_via_agentos_side_timer(
        self, backend, monkeypatch
    ) -> None:
        """Per spec §7 item 2: `sleep 60` in a 2s-walltime sandbox
        raises walltime_cap_exceeded via AgentOS-side asyncio.wait_for."""
        from cognic_agentos.sandbox import SandboxPolicy, SandboxPolicyViolated, sandbox_session
        from cognic_agentos.sandbox.catalog import CosignVerifyResult, SBOMVerifyResult
        from unittest.mock import AsyncMock, MagicMock

        monkeypatch.setattr(backend._catalog, "_run_cosign_verify",
            AsyncMock(return_value=CosignVerifyResult(passed=True)))
        monkeypatch.setattr(backend._catalog, "_run_syft_inspect",
            AsyncMock(return_value=SBOMVerifyResult(passed=True)))

        policy = SandboxPolicy(
            cpu_cores=0.5, cpu_time_budget_s=None, memory_mb=256, walltime_s=2.0,
            runtime_image="cognic/sandbox-runtime-shell:v1@sha256:" + "b" * 64,
            egress_allow_list=(), vault_path=None,
        )
        actor = MagicMock(); actor.subject = "test-subject"
        with pytest.raises(SandboxPolicyViolated) as exc:
            async with sandbox_session(
                backend, policy,
                actor=actor, tenant_id="t-1", pack_context=_TEST_PACK_CTX,
                use_warm_pool=False,
            ) as s:
                await s.exec(["sleep", "60"])
        assert exc.value.reason == "walltime_cap_exceeded"

    @pytest.mark.asyncio
    async def test_cpu_time_budget_exceeded_fires_when_budget_set(
        self, backend, monkeypatch
    ) -> None:
        """Per spec §7 item 4: cgroup cpuacct.usage_us polled at ≥1Hz;
        kills when accumulated CPU-seconds exceeds the 1s budget."""
        from cognic_agentos.sandbox import SandboxPolicy, SandboxPolicyViolated, sandbox_session
        from cognic_agentos.sandbox.catalog import CosignVerifyResult, SBOMVerifyResult
        from unittest.mock import AsyncMock, MagicMock

        monkeypatch.setattr(backend._catalog, "_run_cosign_verify",
            AsyncMock(return_value=CosignVerifyResult(passed=True)))
        monkeypatch.setattr(backend._catalog, "_run_syft_inspect",
            AsyncMock(return_value=SBOMVerifyResult(passed=True)))

        policy = SandboxPolicy(
            cpu_cores=2.0,                # generous --cpus cap (NOT the kill condition)
            cpu_time_budget_s=1.0,        # 1 CPU-second budget — IS the kill condition
            memory_mb=256, walltime_s=30.0,
            runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
            egress_allow_list=(), vault_path=None,
        )
        actor = MagicMock(); actor.subject = "test-subject"
        with pytest.raises(SandboxPolicyViolated) as exc:
            async with sandbox_session(
                backend, policy,
                actor=actor, tenant_id="t-1", pack_context=_TEST_PACK_CTX,
                use_warm_pool=False,
            ) as s:
                await s.exec(["python", "-c", "while True: pass"])
        assert exc.value.reason == "cpu_time_budget_exceeded"

    @pytest.mark.asyncio
    async def test_cpus_throttle_alone_does_NOT_fire_violation(
        self, backend, monkeypatch
    ) -> None:
        """Per round-3 P2 reviewer fix: --cpus throttling under cap is
        NOT a violation. A CPU-bound workload with cpu_cores=0.5 + NO
        cpu_time_budget_s + a short walltime should complete with
        exit_code=0 + NO SandboxPolicyViolated raised."""
        from cognic_agentos.sandbox import SandboxPolicy, SandboxPolicyViolated, sandbox_session
        from cognic_agentos.sandbox.catalog import CosignVerifyResult, SBOMVerifyResult
        from unittest.mock import AsyncMock, MagicMock

        monkeypatch.setattr(backend._catalog, "_run_cosign_verify",
            AsyncMock(return_value=CosignVerifyResult(passed=True)))
        monkeypatch.setattr(backend._catalog, "_run_syft_inspect",
            AsyncMock(return_value=SBOMVerifyResult(passed=True)))

        policy = SandboxPolicy(
            cpu_cores=0.5,            # tight throttle — expected to throttle workload
            cpu_time_budget_s=None,   # NO CPU-seconds budget → throttling alone is OK
            memory_mb=256, walltime_s=10.0,
            runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
            egress_allow_list=(), vault_path=None,
        )
        actor = MagicMock(); actor.subject = "test-subject"
        async with sandbox_session(
            backend, policy,
            actor=actor, tenant_id="t-1", pack_context=_TEST_PACK_CTX,
            use_warm_pool=False,
        ) as s:
            result = await s.exec(["python", "-c", "x = sum(range(10**5))"])
        # Tight CPU loop expected to complete within walltime; throttled but NOT killed
        assert result.exit_code == 0
        # And NO SandboxPolicyViolated was raised (test would have caught it via pytest.raises)
```

- [ ] **Step 2-6.** Halt-before-commit.

#### T10c — Egress integration + conformance harness

- [ ] **Step 1: Write failing tests — allow-listed succeeds, non-allow refused, proxy_log on chain row**

```python
# tests/unit/sandbox/backends/test_docker_sibling_egress.py
"""Sprint 8A T10c — egress allow-list enforced via proxy sidecar."""
import os
import pytest


pytestmark = pytest.mark.skipif(
    os.environ.get("COGNIC_RUN_DOCKER_SANDBOX") != "1",
    reason="Docker daemon + cognic/sandbox-egress-proxy image required",
)


class TestEgressEnforcement:
    """Re-uses backend + monkeypatch fixtures from T10a conftest."""

    @pytest.mark.asyncio
    async def test_allow_listed_host_returns_2xx(
        self, backend, monkeypatch
    ) -> None:
        """allow_list=('httpbin.org',) → curl httpbin.org/status/200 in the
        runtime-shell image returns exit code 0; proxy_log on the
        exec_completed chain row carries an `allowed` record."""
        from cognic_agentos.sandbox import SandboxPolicy, sandbox_session
        from cognic_agentos.sandbox.catalog import CosignVerifyResult, SBOMVerifyResult
        from unittest.mock import AsyncMock, MagicMock

        monkeypatch.setattr(backend._catalog, "_run_cosign_verify",
            AsyncMock(return_value=CosignVerifyResult(passed=True)))
        monkeypatch.setattr(backend._catalog, "_run_syft_inspect",
            AsyncMock(return_value=SBOMVerifyResult(passed=True)))

        policy = SandboxPolicy(
            cpu_cores=0.5, cpu_time_budget_s=None, memory_mb=128, walltime_s=15.0,
            runtime_image="cognic/sandbox-runtime-shell:v1@sha256:" + "b" * 64,
            egress_allow_list=("httpbin.org",), vault_path=None,
        )
        actor = MagicMock(); actor.subject = "test-subject"
        async with sandbox_session(
            backend, policy,
            actor=actor, tenant_id="t-1", pack_context=_TEST_PACK_CTX,
            use_warm_pool=False,
        ) as s:
            result = await s.exec(["curl", "-s", "-o", "/dev/null",
                                   "-w", "%{http_code}", "https://httpbin.org/status/200"])
        assert result.exit_code == 0
        assert b"200" in result.stdout
        # proxy_log carries the allow record
        assert any(rec.host == "httpbin.org" and rec.outcome == "allowed"
                   for rec in result.proxy_log)

    @pytest.mark.asyncio
    async def test_non_allow_listed_host_refused_via_proxy(
        self, backend, monkeypatch
    ) -> None:
        """allow_list=('only-this.example',) → curl evil.example.com → proxy
        refuses with 403; curl exits non-zero; proxy_log carries a
        refusal record with reason='not_in_allow_list'."""
        from cognic_agentos.sandbox import SandboxPolicy, sandbox_session
        from cognic_agentos.sandbox.catalog import CosignVerifyResult, SBOMVerifyResult
        from unittest.mock import AsyncMock, MagicMock

        monkeypatch.setattr(backend._catalog, "_run_cosign_verify",
            AsyncMock(return_value=CosignVerifyResult(passed=True)))
        monkeypatch.setattr(backend._catalog, "_run_syft_inspect",
            AsyncMock(return_value=SBOMVerifyResult(passed=True)))

        policy = SandboxPolicy(
            cpu_cores=0.5, cpu_time_budget_s=None, memory_mb=128, walltime_s=15.0,
            runtime_image="cognic/sandbox-runtime-shell:v1@sha256:" + "b" * 64,
            egress_allow_list=("only-this.example",), vault_path=None,
        )
        actor = MagicMock(); actor.subject = "test-subject"
        async with sandbox_session(
            backend, policy,
            actor=actor, tenant_id="t-1", pack_context=_TEST_PACK_CTX,
            use_warm_pool=False,
        ) as s:
            result = await s.exec(["curl", "-sS",
                                   "https://evil.example.com/get"])
        # curl exits non-zero on the 403 from the proxy
        assert result.exit_code != 0
        # proxy_log carries the refusal record
        refusal_records = [r for r in result.proxy_log
                           if r.host == "evil.example.com" and r.outcome == "refused"]
        assert len(refusal_records) >= 1
        assert refusal_records[0].refusal_reason == "not_in_allow_list"

    @pytest.mark.asyncio
    async def test_raw_tcp_blocked_at_network_layer_no_proxy_log(
        self, backend, monkeypatch
    ) -> None:
        """Per round-3 P2 fix + spec §10.4: raw TCP attempts (NOT through
        the HTTP proxy) get ENETUNREACH from the kernel because the
        internal network has no gateway. The proxy never sees the
        attempt → NO proxy_log entry, NO sandbox.policy.violated event
        in Wave-1 (Wave-2 may add network-level telemetry per spec §10.4)."""
        from cognic_agentos.sandbox import SandboxPolicy, sandbox_session
        from cognic_agentos.sandbox.catalog import CosignVerifyResult, SBOMVerifyResult
        from unittest.mock import AsyncMock, MagicMock

        monkeypatch.setattr(backend._catalog, "_run_cosign_verify",
            AsyncMock(return_value=CosignVerifyResult(passed=True)))
        monkeypatch.setattr(backend._catalog, "_run_syft_inspect",
            AsyncMock(return_value=SBOMVerifyResult(passed=True)))

        policy = SandboxPolicy(
            cpu_cores=0.5, cpu_time_budget_s=None, memory_mb=128, walltime_s=10.0,
            runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
            egress_allow_list=("httpbin.org",), vault_path=None,
        )
        actor = MagicMock(); actor.subject = "test-subject"
        async with sandbox_session(
            backend, policy,
            actor=actor, tenant_id="t-1", pack_context=_TEST_PACK_CTX,
            use_warm_pool=False,
        ) as s:
            # Try raw TCP socket to port 6379 (Redis) — bypasses HTTP proxy
            result = await s.exec(["python", "-c",
                "import socket; "
                "s = socket.socket(); "
                "s.settimeout(3); "
                "import sys; "
                "try: s.connect(('8.8.8.8', 6379)); print('CONNECTED')\n"
                "except OSError as e: print(f'BLOCKED: {e.errno}'); sys.exit(1)"
            ])
        # Connection refused at network layer (ENETUNREACH or similar)
        assert result.exit_code == 1
        assert b"BLOCKED" in result.stdout
        # No proxy_log entry for this attempt (proxy never saw it)
        assert not any("8.8.8.8" in r.host for r in result.proxy_log)
```

```python
# tests/conformance/sandbox/test_backend_conformance.py
"""Sprint 8A T10c — shared backend conformance suite per spec §15.3.

Parametrized over backend implementations. In Sprint 8A only the
Docker arm is parametrized; Sprint 8B adds KubernetesPod via the same
conftest.py.
"""
import pytest

from cognic_agentos.sandbox import SandboxRefusalReason


@pytest.fixture(params=["docker_sibling"])
async def backend(request, tmp_path):
    """Backend-parameterized fixture. Sprint 8B adds 'kubernetes_pod'
    to the params list (same test bodies; different fixture wiring)."""
    if request.param == "docker_sibling":
        # Reuse the T10a fixture pattern — concrete real-Docker setup
        from cognic_agentos.sandbox.backends.docker_sibling import (
            DockerSiblingSandboxBackend,
        )
        from cognic_agentos.sandbox.catalog import CanonicalImageCatalog
        from cognic_agentos.sandbox.credentials import KernelDefaultCredentialAdapter
        from cognic_agentos.core.audit import AuditStore
        from cognic_agentos.core.decision_history import DecisionHistoryStore
        from sqlalchemy.ext.asyncio import create_async_engine
        from unittest.mock import AsyncMock, MagicMock
        import aiodocker

        trust_root = tmp_path / "cognic-cosign.pub"
        trust_root.write_text("# fixture trust root for conformance suite")
        catalog = CanonicalImageCatalog(
            canonical_refs=frozenset({
                "cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
                "cognic/sandbox-runtime-shell:v1@sha256:" + "b" * 64,
                "cognic/sandbox-runtime-data:v1@sha256:" + "c" * 64,
                "cognic/sandbox-egress-proxy:v1@sha256:" + "d" * 64,
            }),
            tenant_trust_roots={"t-conformance": trust_root},
            tenant_allow_lists={"t-conformance": frozenset()},
        )
        docker = aiodocker.Docker()
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        rego = AsyncMock()
        rego.evaluate = AsyncMock(return_value=MagicMock(allowed=True))
        yield DockerSiblingSandboxBackend(
            docker_client=docker,
            image_catalog=catalog,
            credential_adapter=KernelDefaultCredentialAdapter(),
            rego_engine=rego,
            audit_store=AuditStore(engine=engine),
            decision_history_store=DecisionHistoryStore(engine=engine),
            warm_pool=None,
        )
        await docker.close()
    elif request.param == "kubernetes_pod":  # Sprint 8B
        from cognic_agentos.sandbox.backends.kubernetes_pod import (
            KubernetesPodSandboxBackend,
        )
        # ... 8B implementor wires the equivalent K8s fixture
        raise NotImplementedError("KubernetesPodSandboxBackend ships in Sprint 8B")


class TestConformanceSurface:
    """Per spec §15.3 conformance suite — runs against every Protocol-
    conforming backend impl via the parametrized `backend` fixture above."""

    @pytest.mark.asyncio
    async def test_health_returns_ok(self, backend) -> None:
        from cognic_agentos.sandbox.protocol import SandboxBackendHealth
        result = await backend.health()
        assert isinstance(result, SandboxBackendHealth)
        assert result.status == "ok"

    @pytest.mark.asyncio
    async def test_minimum_valid_policy_lifecycle(self, backend, monkeypatch) -> None:
        """Every backend MUST support the minimum valid SandboxPolicy
        lifecycle: create → exec(['echo', 'ok']) → destroy without raising."""
        from cognic_agentos.sandbox import (
            PackAdmissionContext, SandboxPolicy, sandbox_session,
        )
        from cognic_agentos.sandbox.catalog import CosignVerifyResult, SBOMVerifyResult
        from unittest.mock import AsyncMock, MagicMock

        monkeypatch.setattr(backend._catalog, "_run_cosign_verify",
            AsyncMock(return_value=CosignVerifyResult(passed=True)))
        monkeypatch.setattr(backend._catalog, "_run_syft_inspect",
            AsyncMock(return_value=SBOMVerifyResult(passed=True)))

        policy = SandboxPolicy(
            cpu_cores=0.5, cpu_time_budget_s=None, memory_mb=128, walltime_s=10.0,
            runtime_image="cognic/sandbox-runtime-shell:v1@sha256:" + "b" * 64,
            egress_allow_list=(), vault_path=None,
        )
        ctx = PackAdmissionContext(
            pack_id="conformance.test", pack_version="v1",
            pack_artifact_digest="sha256:" + "f" * 64,
            risk_tier="internal_write",
            declares_dynamic_install=False, profile="production",
        )
        actor = MagicMock(); actor.subject = "conformance-runner"
        async with sandbox_session(
            backend, policy,
            actor=actor, tenant_id="t-conformance", pack_context=ctx,
            use_warm_pool=False,
        ) as s:
            result = await s.exec(["echo", "ok"])
        assert result.exit_code == 0
        assert b"ok" in result.stdout

    @pytest.mark.parametrize("refusal_reason", [
        "sandbox_credential_adapter_not_configured",
        "sandbox_runtime_deps_unsupported_in_production",
        "sandbox_high_risk_tier_refused_pre_13_5",
        "sandbox_image_digest_not_in_canonical_catalog",
        "sandbox_image_cosign_verification_failed",
        "sandbox_image_sbom_check_failed",
        "sandbox_image_digest_format_invalid",
        "sandbox_policy_exceeds_tenant_max_cpu",
        "sandbox_policy_exceeds_tenant_max_memory",
        "sandbox_policy_exceeds_tenant_max_walltime",
        "sandbox_policy_egress_host_invalid",
        "sandbox_policy_egress_protocol_not_http",
        "sandbox_policy_rego_denied",
        "sandbox_backend_unavailable",
        "sandbox_warm_pool_drained",
    ])
    @pytest.mark.asyncio
    async def test_every_refusal_reason_is_reachable_on_backend(
        self, backend, monkeypatch, refusal_reason: str,
    ) -> None:
        """Per spec §15.3: every SandboxRefusalReason value MUST be
        reachable on every Protocol-conforming backend.

        Each `refusal_reason` parametrize value corresponds to a
        specific (policy, pack_context, catalog/rego mock setup) tuple
        that triggers exactly that closed-enum refusal. The mapping
        from reason → trigger lives in the `TRIGGERS_BY_REASON` dict
        in the conformance conftest (full 15-entry mapping below);
        `_trigger_for_reason(reason, backend, monkeypatch)` dispatches
        into it and returns `{"session_manager": <async-cm>}` whose
        `__aenter__` triggers admission's target refusal arm.
        """
        from cognic_agentos.sandbox import SandboxLifecycleRefused
        trigger = _trigger_for_reason(refusal_reason, backend, monkeypatch)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            async with trigger["session_manager"]:
                pass  # admission failure raises inside __aenter__
        assert exc.value.reason == refusal_reason
```

The `_trigger_for_reason(reason, backend)` helper lives in the conformance conftest and returns a dict `{"session_manager": <async-context-manager>, "setup": <fn>}` that the parametrized test enters; admission failure inside `__aenter__` raises the target `SandboxLifecycleRefused`. The complete 15-entry mapping (round-4 R4 P1 #5 fix — no more "follows analogously" hand-waving):

```python
# tests/conformance/sandbox/conftest.py (continued)
import dataclasses
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from typing import TypeAlias
from unittest.mock import AsyncMock, MagicMock

from cognic_agentos.sandbox import (
    PackAdmissionContext, SandboxPolicy, SandboxSession, sandbox_session,
)
from cognic_agentos.sandbox.catalog import CosignVerifyResult, SBOMVerifyResult
from cognic_agentos.sandbox.credentials import KernelDefaultCredentialAdapter


# Round-7 R7 P2 fix: `dict[str, callable]` is INVALID as a type
# annotation (callable is the built-in function, not a type).
# Round-8 R8 P1 fix: AsyncContextManager is NOT in collections.abc on
# Python 3.12 (only typing.AsyncContextManager — deprecated — or
# contextlib.AbstractAsyncContextManager — modern). Use the contextlib
# form so the T10 mypy gate AND the conftest module-load both pass.
TriggerFactory: TypeAlias = Callable[
    [object, object],  # (backend, monkeypatch); object so any backend type works
    AbstractAsyncContextManager[SandboxSession],
]


# Base fixtures — every trigger mutates one field on these.
_BASE_POLICY = SandboxPolicy(
    cpu_cores=0.5, cpu_time_budget_s=None, memory_mb=256, walltime_s=30.0,
    runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
    egress_allow_list=("httpbin.org",),
    vault_path=None,
)
_BASE_PACK_CTX = PackAdmissionContext(
    pack_id="conformance.pack", pack_version="v1",
    pack_artifact_digest="sha256:" + "1" * 64,
    risk_tier="internal_write",
    declares_dynamic_install=False, profile="production",
)
_BASE_ACTOR = MagicMock(); _BASE_ACTOR.subject = "conformance-runner"


def _make_session_manager(
    backend, policy=None, pack_context=None,
    catalog_patches=None, credential_adapter=None,
    settings_overrides=None, rego_allowed=True, rego_deny_reason=None,
    monkeypatch=None,
):
    """Construct a sandbox_session(...) async context manager with the
    backend pre-patched so admission fails on the target arm."""
    if catalog_patches is None:
        catalog_patches = {}  # default: pass all catalog checks
    catalog_patches.setdefault("_run_cosign_verify",
        AsyncMock(return_value=CosignVerifyResult(passed=True)))
    catalog_patches.setdefault("_run_syft_inspect",
        AsyncMock(return_value=SBOMVerifyResult(passed=True)))
    for attr, value in catalog_patches.items():
        monkeypatch.setattr(backend._catalog, attr, value)
    if rego_allowed:
        backend._rego.evaluate = AsyncMock(return_value=MagicMock(allowed=True))
    else:
        backend._rego.evaluate = AsyncMock(return_value=MagicMock(
            allowed=False, deny_reason=rego_deny_reason or "deny",
        ))
    if settings_overrides:
        for k, v in settings_overrides.items():
            setattr(backend._settings, k, v)
    if credential_adapter is not None:
        backend._credential_adapter = credential_adapter
    return sandbox_session(
        backend,
        policy or _BASE_POLICY,
        actor=_BASE_ACTOR,
        tenant_id="t-conformance",
        pack_context=pack_context or _BASE_PACK_CTX,
        use_warm_pool=False,
    )


# 15-entry mapping — one entry per closed-enum SandboxRefusalReason value.
# Each entry is a callable taking (backend, monkeypatch) → context-manager
# that admission refuses on the target arm at __aenter__.
TRIGGERS_BY_REASON: dict[str, TriggerFactory] = {
    "sandbox_credential_adapter_not_configured":
        lambda backend, monkeypatch: _make_session_manager(
            backend,
            policy=dataclasses.replace(_BASE_POLICY, vault_path="secret/test"),
            credential_adapter=KernelDefaultCredentialAdapter(),
            monkeypatch=monkeypatch,
        ),
    "sandbox_runtime_deps_unsupported_in_production":
        lambda backend, monkeypatch: _make_session_manager(
            backend,
            pack_context=dataclasses.replace(
                _BASE_PACK_CTX, declares_dynamic_install=True, profile="production",
            ),
            monkeypatch=monkeypatch,
        ),
    "sandbox_high_risk_tier_refused_pre_13_5":
        lambda backend, monkeypatch: _make_session_manager(
            backend,
            pack_context=dataclasses.replace(_BASE_PACK_CTX, risk_tier="payment_action"),
            monkeypatch=monkeypatch,
        ),
    "sandbox_image_digest_not_in_canonical_catalog":
        lambda backend, monkeypatch: _make_session_manager(
            backend,
            policy=dataclasses.replace(
                _BASE_POLICY,
                runtime_image="not-in-catalog/x:v1@sha256:" + "0" * 64,
            ),
            monkeypatch=monkeypatch,
        ),
    "sandbox_image_cosign_verification_failed":
        lambda backend, monkeypatch: _make_session_manager(
            backend,
            catalog_patches={"_run_cosign_verify": AsyncMock(
                return_value=CosignVerifyResult(passed=False, detail="signature mismatch"),
            )},
            monkeypatch=monkeypatch,
        ),
    "sandbox_image_sbom_check_failed":
        lambda backend, monkeypatch: _make_session_manager(
            backend,
            catalog_patches={"_run_syft_inspect": AsyncMock(
                return_value=SBOMVerifyResult(passed=False, detail="GPL-3.0 detected"),
            )},
            monkeypatch=monkeypatch,
        ),
    "sandbox_image_digest_format_invalid":
        lambda backend, monkeypatch: _make_session_manager(
            backend,
            policy=dataclasses.replace(
                _BASE_POLICY,
                runtime_image="cognic/sandbox-runtime-python:v1",  # NO @sha256:
            ),
            monkeypatch=monkeypatch,
        ),
    "sandbox_policy_exceeds_tenant_max_cpu":
        lambda backend, monkeypatch: _make_session_manager(
            backend,
            policy=dataclasses.replace(_BASE_POLICY, cpu_cores=16.0),
            settings_overrides={"per_tenant_max_cpu": 4.0},
            monkeypatch=monkeypatch,
        ),
    "sandbox_policy_exceeds_tenant_max_memory":
        lambda backend, monkeypatch: _make_session_manager(
            backend,
            policy=dataclasses.replace(_BASE_POLICY, memory_mb=8192),
            settings_overrides={"per_tenant_max_memory": 1024},
            monkeypatch=monkeypatch,
        ),
    "sandbox_policy_exceeds_tenant_max_walltime":
        lambda backend, monkeypatch: _make_session_manager(
            backend,
            policy=dataclasses.replace(_BASE_POLICY, walltime_s=3600.0),
            settings_overrides={"per_tenant_max_walltime": 300.0},
            monkeypatch=monkeypatch,
        ),
    "sandbox_policy_egress_host_invalid":
        lambda backend, monkeypatch: _make_session_manager(
            backend,
            policy=dataclasses.replace(
                _BASE_POLICY, egress_allow_list=("-bad.example.com",),
            ),
            monkeypatch=monkeypatch,
        ),
    "sandbox_policy_egress_protocol_not_http":
        lambda backend, monkeypatch: _make_session_manager(
            backend,
            policy=dataclasses.replace(
                _BASE_POLICY, egress_allow_list=("ftp://files.example.com",),
            ),
            monkeypatch=monkeypatch,
        ),
    "sandbox_policy_rego_denied":
        lambda backend, monkeypatch: _make_session_manager(
            backend,
            rego_allowed=False, rego_deny_reason="bank-overlay-tightened-policy",
            monkeypatch=monkeypatch,
        ),
    "sandbox_backend_unavailable":
        lambda backend, monkeypatch: _trigger_backend_unavailable(backend, monkeypatch),
    "sandbox_warm_pool_drained":
        lambda backend, monkeypatch: _trigger_warm_pool_drained(backend, monkeypatch),
}


def _trigger_backend_unavailable(backend, monkeypatch):
    """Trigger for sandbox_backend_unavailable. Simulate Docker daemon
    unreachable by patching the docker client's containers.create to
    raise DockerError(503). The backend's create() MUST catch the
    daemon-side error and translate to SandboxLifecycleRefused with
    closed-enum sandbox_backend_unavailable.

    Backend-specific implementation detail — the docker_sibling backend
    catches aiodocker.exceptions.DockerError; the K8sPod backend (8B)
    catches kubernetes.client.rest.ApiException; the conformance test
    here works against either via the shared SandboxBackend contract.
    For Docker, we patch the daemon client; for K8s the trigger
    would patch the API client similarly.
    """
    import aiodocker
    from unittest.mock import AsyncMock
    if hasattr(backend, "_docker"):
        # Docker backend — patch the daemon's container-create
        monkeypatch.setattr(
            backend._docker.containers, "create",
            AsyncMock(side_effect=aiodocker.exceptions.DockerError(
                503, {"message": "daemon unreachable (simulated)"},
            )),
        )
    elif hasattr(backend, "_k8s_api"):  # Sprint 8B KubernetesPod path
        from kubernetes.client.exceptions import ApiException
        monkeypatch.setattr(
            backend._k8s_api, "create_namespaced_pod",
            AsyncMock(side_effect=ApiException(status=503, reason="API server unreachable (simulated)")),
        )
    else:
        raise AssertionError(
            f"Unknown backend type {type(backend).__name__}; "
            "extend _trigger_backend_unavailable for the new backend"
        )
    return _make_session_manager(backend, monkeypatch=monkeypatch)


def _trigger_warm_pool_drained(backend, monkeypatch):
    """Trigger for sandbox_warm_pool_drained. Wire a fixture warm-pool
    on the backend + call await pool.drain() inside the session-manager
    factory; the subsequent backend.create(use_warm_pool=True) call
    refuses with sandbox_warm_pool_drained per spec §11.

    Per spec §11 the drained-pool refusal fires at checkout, NOT at
    create. So the context manager below sets use_warm_pool=True so
    backend.create() routes through the (already-drained) pool and
    surfaces the SandboxLifecycleRefused at __aenter__.
    """
    from contextlib import asynccontextmanager
    from cognic_agentos.sandbox.warm_pool import SandboxWarmPool
    from unittest.mock import MagicMock

    pool_policy = _BASE_POLICY
    pool_ctx = _BASE_PACK_CTX
    pool = SandboxWarmPool(
        backend=backend,
        max_pool_size_per_key=2, idle_ttl_s=300.0,
        audit_store=MagicMock(), decision_history_store=MagicMock(),
    )
    backend._warm_pool = pool

    @asynccontextmanager
    async def _drained_pool_session_manager():
        # Drain the pool BEFORE the test enters the context manager;
        # the subsequent checkout refuses with sandbox_warm_pool_drained.
        await pool.drain()
        async with sandbox_session(
            backend, dataclasses.replace(pool_policy, warm_pool_key="conformance-warmed"),
            actor=_BASE_ACTOR, tenant_id="t-conformance", pack_context=pool_ctx,
            use_warm_pool=True,
        ) as session:
            yield session

    # Round-6 R6 P1 #3 fix: return the BARE context manager, NOT a
    # {"session_manager": cm} dict. The wrapping happens once in
    # `_trigger_for_reason` below — double-wrapping made the test do
    # `async with {"session_manager": cm}:` which is a TypeError.
    return _drained_pool_session_manager()


def _trigger_for_reason(reason: str, backend, monkeypatch):
    """Dispatch into the 15-entry TRIGGERS_BY_REASON mapping; returns
    {"session_manager": <async-cm>} per the test contract above."""
    factory = TRIGGERS_BY_REASON.get(reason)
    if factory is None:
        raise AssertionError(
            f"No trigger registered for {reason!r}; the mapping must cover "
            f"every value in typing.get_args(SandboxRefusalReason). Did Sprint "
            f"8A add a new refusal reason without updating this mapping?"
        )
    return {"session_manager": factory(backend, monkeypatch)}
```

**Coverage-guarantee drift detector** (catches future drift where Sprint 8A or later adds a 16th `SandboxRefusalReason` value but forgets to register a trigger):

```python
def test_triggers_cover_every_refusal_reason_value() -> None:
    """Pin that TRIGGERS_BY_REASON covers every SandboxRefusalReason
    Literal value. If anyone adds a 16th value without registering a
    trigger, this fails before the conformance suite even runs."""
    import typing
    from cognic_agentos.sandbox import SandboxRefusalReason
    declared = frozenset(typing.get_args(SandboxRefusalReason))
    registered = frozenset(TRIGGERS_BY_REASON.keys())
    missing = declared - registered
    extra = registered - declared
    assert not missing, f"TRIGGERS_BY_REASON missing entries for: {sorted(missing)}"
    assert not extra, f"TRIGGERS_BY_REASON has unknown reasons: {sorted(extra)}"
```

- [ ] **Step 2-6:** implement + verify + halt + commit (per sub-task; 3 separate halts + commits for T10a + T10b + T10c).

**Commit message templates (per sub-task):**

```
feat(sprint-8a): T10a — docker_sibling.py lifecycle + dual-container internal-network topology (CRITICAL CONTROLS)
```

```
feat(sprint-8a): T10b — docker_sibling.py resource cap enforcement (cgroup integration; --cpus throttle NOT a violation per round-3 P2) (CRITICAL CONTROLS)
```

```
feat(sprint-8a): T10c — docker_sibling.py egress proxy integration + shared conformance suite (Docker arm) (CRITICAL CONTROLS)
```

---

## Task T11 — sandbox.rego policy bundle

**Scope:** `policies/_default/sandbox.rego` at `data.cognic.sandbox.admit.allow` + corresponding env-gated smoke test. Default-deny; Wave-1 rules per spec §13 (6-tier high-risk unconditionally-refused pre-13.5; no escalation-token bypass).

**Files:**
- Create: `policies/_default/sandbox.rego`
- Create: `tests/unit/policies/test_sandbox_rego.py`

**Doctrine refs:** spec §13 (sandbox.rego policy bundle) + ADR-015 policy-as-code precedent (sampling.rego / elicitation.rego / supply_chain.rego shapes).

OPA env-gated test (`shutil.which('opa') is not None`) — matches the existing `tests/unit/policies/test_elicitation_rego.py` pattern. Known gap noted in [[project_state_2026_05_16]]: lint+test CI lane doesn't currently carry OPA, so these tests will SKIP in CI; a follow-up task adds OPA to the `ci:` job. Doesn't block Sprint 8A — same posture as elicitation.rego since 7B.4.

### T11 steps

- [ ] **Step 1: Write failing tests — 5 decision-matrix arms**

```python
# tests/unit/policies/test_sandbox_rego.py
"""Sprint 8A T11 — sandbox.rego decision matrix smoke tests.

env-gated on opa binary on PATH (mirrors test_elicitation_rego.py).
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

REGO_PATH = Path(__file__).resolve().parents[3] / "policies" / "_default" / "sandbox.rego"

opa_required = pytest.mark.skipif(
    shutil.which("opa") is None,
    reason="opa binary not installed — skip; AsyncMock(OPAEngine) covers the gate dispatch matrix at tests/unit/sandbox/test_admission_pipeline.py",
)


def _eval(input_dict: dict) -> dict:
    """Shell out to `opa eval` against the rego bundle; return decision dict."""
    result = subprocess.run(
        ["opa", "eval", "--data", str(REGO_PATH),
         "--input", "-", "--format", "json",
         "data.cognic.sandbox.admit"],
        input=json.dumps(input_dict).encode(),
        capture_output=True, check=True,
    )
    return json.loads(result.stdout)


@opa_required
class TestSandboxRegoDecisionMatrix:
    def test_default_deny_baseline(self) -> None:
        """data.cognic.sandbox.admit.allow defaults to false."""
        decision = _eval({})
        assert decision["result"][0]["expressions"][0]["value"]["allow"] is False

    def test_internal_write_with_http_allow_list_passes(self) -> None:
        """Per spec §13: tier ∈ {read_only, internal_write} + within
        tenant max + http-only egress → allow."""
        decision = _eval({
            "pack_context": {"risk_tier": "internal_write",
                              "declares_dynamic_install": False,
                              "profile": "production"},
            "policy": {"cpu_cores": 0.5, "memory_mb": 256, "walltime_s": 30,
                       "egress_allow_list": ["api.example.com"],
                       "vault_path": None},
            "tenant_max": {"cpu_cores": 4.0, "memory_mb": 1024, "walltime_s": 300},
        })
        assert decision["result"][0]["expressions"][0]["value"]["allow"] is True

    @pytest.mark.parametrize("tier", [
        "customer_data_read", "customer_data_write", "payment_action",
        "regulator_communication", "cross_tenant", "high_risk_custom",
    ])
    def test_high_risk_tier_refused_unconditionally_pre_13_5(self, tier: str) -> None:
        """Per spec §13: all 6 high-risk tiers refused fail-closed
        pre-13.5; NO escalation-token bypass (round-1 P2 fix)."""
        decision = _eval({
            "pack_context": {"risk_tier": tier,
                              "declares_dynamic_install": False,
                              "profile": "production"},
            "policy": {"cpu_cores": 0.5, "memory_mb": 256, "walltime_s": 30,
                       "egress_allow_list": [], "vault_path": None},
        })
        assert decision["result"][0]["expressions"][0]["value"]["allow"] is False

    def test_vault_path_with_default_credential_adapter_refused(self) -> None:
        """Defence-in-depth with §6.1 step 3 admission check."""
        decision = _eval({
            "pack_context": {"risk_tier": "internal_write",
                              "declares_dynamic_install": False,
                              "profile": "production"},
            "policy": {"cpu_cores": 0.5, "memory_mb": 256, "walltime_s": 30,
                       "egress_allow_list": [], "vault_path": "secret/x"},
            "credential_adapter_wired": False,
        })
        assert decision["result"][0]["expressions"][0]["value"]["allow"] is False

    def test_policy_exceeds_tenant_max_refused(self) -> None:
        decision = _eval({
            "pack_context": {"risk_tier": "internal_write",
                              "declares_dynamic_install": False,
                              "profile": "production"},
            "policy": {"cpu_cores": 8.0, "memory_mb": 256, "walltime_s": 30,
                       "egress_allow_list": [], "vault_path": None},
            "tenant_max": {"cpu_cores": 4.0, "memory_mb": 1024, "walltime_s": 300},
        })
        assert decision["result"][0]["expressions"][0]["value"]["allow"] is False
```

- [ ] **Step 2: Verify fail** — `opa eval ...` returns "module not found".

- [ ] **Step 3: Implement `policies/_default/sandbox.rego`**

```rego
# policies/_default/sandbox.rego
# Sprint 8A T11 — Wave-1 sandbox admission policy bundle per spec §13.
# Wire-protocol-public per AGENTS.md stop-rule list. Bank overlays may
# tighten; loosening kernel defaults requires kernel + ADR amendment.
package cognic.sandbox.admit

default allow := false

# 6-value canonical high-risk tier set per spec §4.1 + §6.1 + §13
high_risk_tiers := {
    "customer_data_read",
    "customer_data_write",
    "payment_action",
    "regulator_communication",
    "cross_tenant",
    "high_risk_custom",
}

# Allow if: tier is read_only or internal_write
#       AND policy within tenant max (when tenant_max provided)
#       AND credential-adapter precondition satisfied
#       AND tier NOT in high_risk set (pre-13.5 transitional)
allow if {
    input.pack_context.risk_tier in {"read_only", "internal_write"}
    not input.pack_context.risk_tier in high_risk_tiers
    _within_tenant_max
    _credential_precondition_satisfied
}

_within_tenant_max if {
    not input.tenant_max  # if no tenant_max provided, skip cap check
}
_within_tenant_max if {
    input.tenant_max
    input.policy.cpu_cores <= input.tenant_max.cpu_cores
    input.policy.memory_mb <= input.tenant_max.memory_mb
    input.policy.walltime_s <= input.tenant_max.walltime_s
}

_credential_precondition_satisfied if {
    not input.policy.vault_path  # no creds requested → satisfied
}
_credential_precondition_satisfied if {
    input.policy.vault_path
    input.credential_adapter_wired == true
}
```

- [ ] **Step 4: Verify green** (locally with opa installed). **Step 5: standard pre-commit gate ladder** (non-CC module; no extra halt beyond the gate). **Step 6: Commit.**

```
feat(sprint-8a): T11 — sandbox.rego Wave-1 default-deny admission bundle + OPA smoke test (stop-rule policy bundle)

Per spec §13 + ADR-015 policy-as-code precedent. Lands the
`data.cognic.sandbox.admit.allow` decision point + the 5-test decision
matrix mirroring the pattern from sampling.rego / elicitation.rego /
supply_chain.rego.

Wave-1 rules:
* default-deny baseline
* allow if tier ∈ {read_only, internal_write} AND within tenant_max
  AND credential precondition satisfied
* refuse all 6 high-risk tiers unconditionally pre-13.5 (no escalation-
  token bypass per round-1 P2 fix)
* refuse if vault_path set AND credential_adapter_wired == false

env-gated tests SKIP without OPA on PATH (matches the elicitation.rego
pattern from 7B.4; a separate task adds OPA to the lint+test CI lane).
AsyncMock(OPAEngine) covers the gate dispatch matrix at T5
test_admission_pipeline.py for non-OPA CI lanes.

Adds 1 entry to AGENTS.md "Stop rules" list at T12.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
```

### T11 implementation notes (2026-05-17)

**Plan-vs-spec drift identified at execution time + patched per `feedback_patch_plan_against_doctrine`:**

The T11 plan stub above covers **3 of the 4** Wave-1 default rules from spec §13. Rule 4 — `Refuse if policy.runtime_image not in catalog AND not in tenant allow-list (defence-in-depth with §6.1 step 6)` — is missing from the stub's allow-rule and from its 5-arm test matrix.

**Resolution: implement per spec, not per stub.** Spec §13 is the source of truth. The implemented bundle adds:

- Extended input contract: `input.runtime_image_in_canonical_set: bool` + `input.runtime_image_in_tenant_allow_list: bool` (precomputed by the Python admission caller before OPA eval; mirrors the sampling.rego pattern of passing precomputed bools rather than re-implementing set membership in Rego)
- New rule `_runtime_image_authorised` (true when either bool is true) added to the allow-rule's required conditions
- New decision-matrix test arm `test_runtime_image_not_in_catalog_nor_tenant_allow_list_refused`

The reference test pattern follows `tests/unit/policies/test_elicitation_rego.py` (real `OPAEngine` over an in-memory SQLite chain head pair) rather than the plan stub's bare `subprocess.run(["opa", "eval", ...])` form — the engine-based pattern is the canonical Sprint-7B.4 precedent and exercises the audit-emission seam end-to-end. Both forms are env-gated on `shutil.which("opa") is not None`.

**Gate-floor count UNCHANGED.** The rego bundle is a stop-rule entry (covered by `_runtime_image_authorised` joining the AGENTS.md additions at T12), not a Python module on the durable per-file coverage gate; T12's 63 → 70 arithmetic is unaffected.

**Scope:** Update AGENTS.md "Stop rules" + "Critical-controls rule" to add the **7 newly-on-gate sandbox modules** (protocol + policy + admission + catalog + proxy + warm_pool + backends/docker_sibling per spec §17) + 1 new stop-rule entry for `policies/_default/sandbox.rego`. Update `tools/check_critical_coverage.py` and its self-test for the gate uplift **63 → 70**.

**Files:**
- Modify: `AGENTS.md` (Stop rules + Critical-controls subsections — add the new 7 modules + 1 Rego bundle)
- Modify: `tools/check_critical_coverage.py` (`_CRITICAL_FILES` 63 → 70)
- Modify: `tests/unit/tools/test_check_critical_coverage.py` (`_EXPECTED_ENTRY_COUNT` + add `_SPRINT_8A_GATE_MODULES` + `_SPRINT_8A_OFF_GATE_MODULES` partition checks)

**Doctrine refs:** spec §17 (critical-controls scope) + AGENTS.md "Critical-controls rule" + "Stop rules" + Sprint 7B.4 T13 precedent at `tools/check_critical_coverage.py` for the gate-uplift pattern.

### T12 steps

- [ ] **Step 1: Write failing test — count guard + module-set partition**

```python
# tests/unit/tools/test_check_critical_coverage.py (extend existing)
"""Sprint 8A T12 — extend the existing critical-controls coverage tool
self-test with the +7 Sprint 8A modules.

Pattern mirrors the Sprint 7B.4 T13 extension at the same file (see
TestSprint7B4GateModules / _SPRINT_7B4_GATE_MODULES at lines around
the existing _EXPECTED_ENTRY_COUNT pin).
"""

# Add to the existing imports + module-level constants:
_SPRINT_8A_GATE_MODULES = frozenset({
    "src/cognic_agentos/sandbox/protocol.py",
    "src/cognic_agentos/sandbox/policy.py",
    "src/cognic_agentos/sandbox/admission.py",
    "src/cognic_agentos/sandbox/catalog.py",
    "src/cognic_agentos/sandbox/proxy.py",
    "src/cognic_agentos/sandbox/warm_pool.py",
    "src/cognic_agentos/sandbox/backends/docker_sibling.py",
})
_SPRINT_8A_OFF_GATE_MODULES = frozenset({
    # Stay OFF the gate per spec §17 R32-doctrine carve-out:
    "src/cognic_agentos/sandbox/audit.py",         # thin chain-row converter
    "src/cognic_agentos/sandbox/credentials.py",   # fail-loud stub; replaced Sprint 10
    "src/cognic_agentos/sandbox/__init__.py",      # public re-exports only
    "src/cognic_agentos/sandbox/backends/__init__.py",
})


# Update the existing _EXPECTED_ENTRY_COUNT from 63 to 70:
def test_expected_entry_count_post_sprint_8a_is_70(self) -> None:
    """Sprint 8A adds 7 modules to the gate: protocol + policy + admission
    + catalog + proxy + warm_pool + backends/docker_sibling per spec §17.
    Floor uplift 63 → 70 (Sprint 10.5 later adds 4 more → 74).
    """
    from tools.check_critical_coverage import _CRITICAL_FILES
    assert len(_CRITICAL_FILES) == 70, (
        f"Sprint 8A T12 expected gate floor at 70 (was 63 + 7 sandbox); "
        f"found {len(_CRITICAL_FILES)}. Did T12 forget one of the 7 promoted modules?"
    )


def test_all_sprint_8a_gate_modules_present_in_critical_files(self) -> None:
    from tools.check_critical_coverage import _CRITICAL_FILES
    critical_set = frozenset(_CRITICAL_FILES)
    missing = _SPRINT_8A_GATE_MODULES - critical_set
    assert not missing, f"Sprint 8A modules missing from _CRITICAL_FILES: {sorted(missing)}"


def test_sprint_8a_off_gate_modules_intentionally_absent(self) -> None:
    """Per spec §17: sandbox/audit.py + sandbox/credentials.py + __init__.py
    files MUST NOT be on the durable gate (R32 doctrine carve-out)."""
    from tools.check_critical_coverage import _CRITICAL_FILES
    critical_set = frozenset(_CRITICAL_FILES)
    accidentally_promoted = _SPRINT_8A_OFF_GATE_MODULES & critical_set
    assert not accidentally_promoted, (
        f"Sprint 8A off-gate modules accidentally promoted: "
        f"{sorted(accidentally_promoted)}. Per spec §17 R32-doctrine."
    )
```

- [ ] **Step 2: Verify fail** — `pytest tests/unit/tools/test_check_critical_coverage.py -v` reports `assert 63 == 70` (count not yet updated).

- [ ] **Step 3: Update `tools/check_critical_coverage.py`** — add the 7 new entries to `_CRITICAL_FILES` (matches the test's `_SPRINT_8A_GATE_MODULES`); bump docstring to note Sprint 8A.

```python
# tools/check_critical_coverage.py (extend existing _CRITICAL_FILES)

_CRITICAL_FILES: Final[tuple[str, ...]] = (
    # ... existing 63 entries ...

    # ============================================================
    # Sprint 8A (2026-05-16) — Sandbox primitive +7 modules
    # ============================================================
    # Per ADR-004 amendment + spec §17 critical-controls scope.
    # Floor uplift 63 → 70 (Sprint 10.5 will add 4 more → 74).
    "src/cognic_agentos/sandbox/protocol.py",
    "src/cognic_agentos/sandbox/policy.py",
    "src/cognic_agentos/sandbox/admission.py",
    "src/cognic_agentos/sandbox/catalog.py",
    "src/cognic_agentos/sandbox/proxy.py",
    "src/cognic_agentos/sandbox/warm_pool.py",
    "src/cognic_agentos/sandbox/backends/docker_sibling.py",
)
```

- [ ] **Step 4: Update `AGENTS.md`** — two surgical edits:

(a) **Stop rules** section: add the entire `sandbox/` tree as a stop-rule isolation boundary entry (mirrors the existing `subagent/` + `core/memory/` patterns):

```diff
+- The entire `sandbox/` tree per ADR-004 — isolation boundary; `core-controls-engineer` + `/critical-module-mode` required on every edit
+- Policy bundle: `policies/_default/sandbox.rego` (per ADR-015 + Sprint 8A T11 — sandbox admission decision-point bundle invoked by `sandbox/admission.py`; default-deny posture; bank overlays may tighten but loosening kernel defaults requires kernel + ADR amendment; mirrors `elicitation.rego` precedent)
```

(b) **Critical-controls rule** section: add a new "Sandbox primitive (Sprint 8A)" subsection naming the 7 promoted modules (mirrors the existing per-sprint subsections):

```markdown
*Sandbox primitive (Sprint 8A):*
- `sandbox/protocol.py` (per ADR-004 — SandboxBackend + SandboxSession Protocols; admission contract)
- `sandbox/policy.py` (per ADR-004 — SandboxPolicy + PURE validate_policy_shape; Stage-1 admission glue + local RiskTier Literal with test-only drift detector against cli/_governance_vocab)
- `sandbox/admission.py` (per ADR-004 — ASYNC admit_policy 9-step pipeline: credential adapter + dynamic-install + high-risk-tier + tenant-max + catalog + cosign + SBOM + Rego; shared by all backends)
- `sandbox/catalog.py` (per ADR-016 amendment — CanonicalImageCatalog: 4 cosign-signed image refs + per-tenant allow-list + cosign + SBOM verification; egress-proxy sidecar image included in the catalog)
- `sandbox/proxy.py` (per ADR-004 + spec §10 — single egress enforcement point; allow-list rendering + ProxyAccessRecord per-request audit shape + proxy_log → chain row materialisation)
- `sandbox/warm_pool.py` (per ADR-004 — bounded queue + drain semantics + audit emission + use_warm_pool=False replenishment contract + 5-field pool key derivation; 3 load-bearing pinning tests)
- `sandbox/backends/docker_sibling.py` (per ADR-004 amendment — DockerSiblingSandboxBackend; dual-container internal-network egress topology; sibling-on-host-socket via host docker.sock NOT pure DinD; trust boundary: compromised AgentOS = root-equivalent on host's Docker daemon; acceptable for Wave-1 reference deployment, not the final bank-grade isolation story per ADR-004 §Backend choice)
```

- [ ] **Step 5: Verify green** — `pytest tests/unit/tools/test_check_critical_coverage.py -v` passes; `grep -c "sandbox/" AGENTS.md` shows ≥8 mentions.

- [ ] **Step 6: CC halt-before-commit per AGENTS.md doctrine** — AGENTS.md edits are doctrine; halt required even though the tool-change is mechanical. Produce halt summary listing the 7 promoted modules + 1 Rego bundle entry + AGENTS.md grep counts.

- [ ] **Step 7: Commit**

```
feat(sprint-8a): T12 — AGENTS.md Sprint 8A stop-rule + critical-controls gate 63→70 (CRITICAL CONTROLS)

Per spec §17 + ADR-004 amendment. Lands:

* AGENTS.md "Stop rules" — entire sandbox/ tree as isolation boundary +
  policies/_default/sandbox.rego as stop-rule policy bundle
* AGENTS.md "Critical-controls rule" — new "Sandbox primitive (Sprint
  8A)" subsection naming the 7 promoted modules with their doctrine
  refs
* tools/check_critical_coverage.py — _CRITICAL_FILES grows from 63 to
  70 entries (added the 7 sandbox modules per spec §17); docstring
  updated to note Sprint 8A
* tests/unit/tools/test_check_critical_coverage.py — _EXPECTED_ENTRY_
  COUNT bumped 63 → 70 + _SPRINT_8A_GATE_MODULES + _SPRINT_8A_OFF_GATE_
  MODULES partition checks (sandbox/audit.py + credentials.py + __init__
  files stay OFF the gate per spec §17 R32-doctrine carve-out)

Sprint 10.5 (scheduler) will further uplift 70 → 74 when its 4
core/scheduler/ modules land.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
```

---

## Task T13 — Sprint 8A closeout

**Scope:** Per the established Sprint 7B.4 closeout pattern at `docs/closeouts/2026-05-16-sprint-7b4-ui-event-stream-endpoints.md`. ~370 LoC. 13 sections covering: scope, files, doctrine adherence, threat model, coverage gate evolution (63 → 70), 1 new stop-rule policy bundle (sandbox.rego), 8A-specific doctrines, hand-off to Sprint 8B.

Also flip `BUILD_PLAN.md §694-715` from "Sprint 8 — Sandbox primitive (3 wu)" to "Sprint 8A CLOSED / 8B PLANNED" rows per the established status-flip convention.

**Files:**
- Create: `docs/closeouts/<date>-sprint-8a-sandbox-primitive.md`
- Modify: `docs/BUILD_PLAN.md` (§694-715 sprint table row + §1142 schedule-risk row + Phase 3 totals)

Commit message: `docs(sprint-8a): T13 — Sprint 8A closeout + BUILD_PLAN status flip`.

---

## Self-Review

**Round 8 (this revision) addressed 1 reviewer finding (1 P1) on top of round 7's 2 + round 6's 4 + round 5's 5 + round 4's 5 + round 3's 5 + round 2's 6:**

- **R8 P1 — AsyncContextManager imported from wrong module** → R7's fix incorrectly imported `AsyncContextManager` from `collections.abc`; on Python 3.12 that name lives in `typing` (deprecated alias) or `contextlib.AbstractAsyncContextManager` (modern). Switched to `from contextlib import AbstractAsyncContextManager` + updated the `TriggerFactory` TypeAlias to reference it. The conftest now imports cleanly at module-load AND mypy resolves the annotation.

**Round 7 addressed 2 reviewer findings (1 P1 + 1 P2) on top of round 6's 4 + round 5's 5 + round 4's 5 + round 3's 5 + round 2's 6:**

- **R7 P1 #1 — Dev-profile admission test mocked wrong method names** → fixed the green-path test at T5 (`test_dynamic_install_permitted_in_dev_profile`) to assign `verify_cosign_or_refuse` + `verify_sbom_policy_or_refuse` (the `*_or_refuse` variants admit_policy actually awaits per spec §6.1 steps 7+8). The bare `verify_cosign` / `verify_sbom_policy` mocks were leaving the awaited methods as plain MagicMock attributes — the test would have failed at the await site OR passed for the wrong reason.
- **R7 P2 — Built-in `callable` as type annotation** → replaced `dict[str, callable]` (invalid; `callable` is the built-in function, not a type) with `dict[str, TriggerFactory]` where `TriggerFactory: TypeAlias = Callable[[object, object], AsyncContextManager[SandboxSession]]`. Added `from collections.abc import AsyncContextManager, Callable` + `from typing import TypeAlias` imports. mypy gate at T10 will now accept the conftest as written.

Plan grew from 4113 lines (round 6) to ~4131 lines (round 7) — small typed-annotation + 2 explicit-method-name corrections.

**Round 6 addressed 4 reviewer findings (3 P1 + 1 P2) on top of round 5's 5 + round 4's 5 + round 3's 5 + round 2's 6:**

- **R6 P1 #1 — Admission tests mocked sync catalog methods with AsyncMock** → All 9 occurrences of `catalog = AsyncMock()` in T5 (admission) + T9 (warm-pool) + conformance helpers replaced with `catalog = MagicMock()` so `is_canonical()` + `is_tenant_allow_listed()` return real bools per the admit_policy code path. Async-only methods (`verify_cosign_or_refuse`, `verify_sbom_policy_or_refuse`) keep their explicit `AsyncMock(...)` assignments. Catalog-miss refusal arm is now load-bearing.
- **R6 P1 #2 — Real subprocess code untested** → new `TestRealSubprocessVerification` class in T6 with 7 tests that patch `asyncio.create_subprocess_exec` at the subprocess boundary (not the whole method): cosign exit-0/exit-nonzero + reverse-map miss + syft clean SBOM / GPL-3 violation / unknown-license default-deny / subprocess-failure. JSON parsing + default-deny license policy + reverse-map lookup + subprocess-failure handling all now have load-bearing coverage.
- **R6 P1 #3 — Warm-pool trigger double-wrapped session manager** → `_trigger_warm_pool_drained` now returns the bare `_drained_pool_session_manager()` context manager (not `{"session_manager": ...}` dict); `_trigger_for_reason` does the wrapping once. Without this fix, `async with trigger["session_manager"]:` would receive a dict and raise TypeError instead of testing the drained-pool refusal arm.
- **R6 P2 — Stale fixture-migration note** → removed (the T6 fixture already uses `canonical_refs=` per round 5; the note was instructing a now-unneeded migration).

Plan grew from 3940 lines (round 5) to ~4080 lines (round 6) — primarily from the new `TestRealSubprocessVerification` class.

**Round 5 addressed 5 reviewer findings (4 P1 + 1 P2) on top of round 4's 5 + round 3's 5 + round 2's 6:**

- **R5 P1 #1 — Catalog fixtures still used removed `canonical_digests` API** → T6 + T10a + T10c conformance fixtures all updated to `canonical_refs=frozenset({"cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64, ...})` matching the round-4 constructor signature.
- **R5 P1 #2 — `is_tenant_allow_listed` queried wrong set** → method body fixed to query `self._tenant_allow_listed_digests.get(tenant_id, frozenset())` (the derived digest set built at construction); the bug-class previously made every per-tenant escape-hatch lookup miss.
- **R5 P1 #3 — Conformance test signature mismatch** → main `test_every_refusal_reason_is_reachable_on_backend` signature updated to `(self, backend, monkeypatch, refusal_reason: str)` matching the helper contract; duplicate "Test invocation now passes the fixture-injected monkeypatch" snippet removed (was a leftover from R4).
- **R5 P1 #4 — Two trigger entries remained placeholders** → `_trigger_backend_unavailable` (patches `backend._docker.containers.create` with `AsyncMock(side_effect=aiodocker.exceptions.DockerError(503, ...))` for Docker backend; analogous K8s branch for Sprint 8B) and `_trigger_warm_pool_drained` (wires `SandboxWarmPool` fixture on `backend._warm_pool`, calls `await pool.drain()` inside an `@asynccontextmanager` factory so admission's checkout from the drained pool refuses) both written as concrete dispatch functions; the closed-enum conformance matrix is genuinely complete.
- **R5 P2 — T6 commit message still documented rejected SBOM stub** → updated to describe the real syft impl (subprocess + JSON parse + per-tenant license policy with default-deny fallback + bug-class digest-reverse-map guard).

Plan grew from 3861 lines (round 4) to ~3930 lines (round 5) — primarily the concrete trigger functions + the corrected fixture instantiations.

**Round 4 addressed 5 P1 reviewer findings on top of round 3's 5 + round 2's 6:**

- **R4 P1 #1 — T8 was still a scope summary** → T8 expanded with full TDD: 4 concrete test classes (TestStubFailsLoudWithSpringTenPointer + TestProtocolShape + TestSandboxesWithoutCredentialsUnaffected) covering NotImplementedError shape + Sprint-10 + ADR-004 pointer pinning + Protocol satisfaction + defence-in-depth-no-stub-call-when-vault-path-None; full `sandbox/credentials.py` impl with module docstring + frozen `CredentialLease` + `@runtime_checkable` `CredentialAdapter` Protocol + `KernelDefaultCredentialAdapter` raising NotImplementedError with explicit "Sprint 10" + "ADR-004 §'Credential-scoped'" in the message.
- **R4 P1 #2 — T6 SBOM impl used undefined state** → added `import json` at module-top + 4-field constructor extension (`tenant_license_policies: dict[str, dict[str, frozenset[str]]] | None = None`) + `self._tenant_license_policies` assignment; `_DEFAULT_LICENSE_POLICY` constant moved to module-top (no duplicate); test-fixture migration note added telling implementor to update from `canonical_digests=` to `canonical_refs=`.
- **R4 P1 #3 — Catalog verification lost the OCI image ref** → catalog now stores `canonical_refs: frozenset[str]` (full OCI refs incl `cognic/...@sha256:...` form) NOT bare `canonical_digests`. Builds derived `_canonical_digests` + `_tenant_allow_listed_digests` for fast O(1) lookup + `_digest_to_ref` reverse-map. `_run_cosign_verify` + `_run_syft_inspect` resolve full ref via reverse-map; bug-class guard returns refusal if digest not in reverse-map (admission step 6 should have caught it).
- **R4 P1 #4 — Stage-2 admission omitted Stage-1 validation** → `admit_policy` now calls `validate_policy_shape(policy)` as its first step internally (single admission seam; backend MUST NOT call validate_policy_shape separately). 3 new pinning tests (TestStage1RunsBeforeStage2): malformed image digest + malformed egress host + ftp:// scheme each refuse with the right Stage-1 reason AND assert ZERO calls to catalog/rego async deps (proves Stage-2 was short-circuited).
- **R4 P1 #5 — `_trigger_for_reason` was placeholder-shaped** → Full 15-entry `TRIGGERS_BY_REASON` mapping written out (one factory lambda per closed-enum value); `_make_session_manager` shared helper with kwargs for policy/pack_context/catalog_patches/credential_adapter/settings/rego mocks; `test_triggers_cover_every_refusal_reason_value` drift detector that fails if a 16th `SandboxRefusalReason` ever lands without a corresponding trigger.

Plan grew from 3208 lines (round 3) to ~3700 lines (round 4) — primarily from the T8 expansion + the conformance trigger mapping.

**Round 3 addressed 5 P1 reviewer findings on top of round 2's 6 P1/P2:**

- **R3 P1 #1 — TYPE_CHECKING (not `if False`)** → §5 Protocol forward-refs now use `from typing import TYPE_CHECKING` + `if TYPE_CHECKING:` so mypy resolves annotations at the T3 halt gate.
- **R3 P1 #2 — DecisionRecord vs AppendedDecisionSnapshot field-list confusion** → T4 verified-contract prose corrected: `DecisionRecord` at `core/decision_history.py:207` is `frozen=True, slots=True` with **exactly 10 constructor fields** (3 required + 7 optional); the snapshot fields (`record_id` / `chain_id` / `sequence` / `new_hash` / `created_at`) live on the SEPARATE `AppendedDecisionSnapshot` dataclass at `:252` (post-commit, hook-only). T4 code block removed the unnecessary `# type: ignore[call-arg]` since the 10-field constructor signature is now correct.
- **R3 P1 #3 — T5 placeholder tests + collapsed execution steps** → T5 expanded with 2 new test classes `TestAdmissionRefusalArms_Continued` (6 concrete tests for tenant-max-cpu/memory/walltime + catalog-miss + cosign-fail + sbom-fail + rego-deny) + `TestAdmissionPipelineOrderingInvariants` (ordering pin: credential check fires BEFORE high-risk-tier check); full per-step execution (Step 2-6) restored with concrete code.
- **R3 P1 #4 — T6 production NotImplementedError on `_run_syft_inspect`** → real `_run_syft_inspect` impl shelling out to `syft <ref> -o json` + applying tenant license policy from `self._tenant_license_policies[tenant_id]` with `_DEFAULT_LICENSE_POLICY` fallback (denied: GPL-1.0/2.0/3.0 + AGPL; allowed: MIT/Apache-2.0/BSD-2/BSD-3/ISC/Python-2.0; default-deny otherwise). Constructor extension noted for the `tenant_license_policies` kwarg.
- **R3 P1 #5 — T10 placeholder fixture/test bodies** → T10a + T10b + T10c all expanded with concrete fixtures (`docker_client`, `catalog`, `backend`), concrete shared policies (`_INTERNAL_WRITE_POLICY`, `_TEST_PACK_CTX`), concrete test bodies inspecting Docker container/network state, concrete exec commands triggering each violation, concrete assertions on `result.proxy_log` records. Conformance suite parametrized over all 15 SandboxRefusalReason values with explicit `_trigger_for_reason` helper contract documented (15-entry mapping the T10c implementor writes).

Plan grew from 2442 lines (round 2) to 3208 lines (round 3) — primarily from the T5 + T10 expansions + the T6 syft impl. All "scope-summary" patterns from round 2 are now concrete code.

**Spec coverage:** every spec §1-§19 surface is covered by a T-task:
- §1 scope → T3 + T10 + T11 cover the in-scope; out-of-scope items map to Sprint 8B / 8.5 / 10
- §2 doctrinal locks → enforced by tests in T3 (closed-enums + shape) + T5 (admission) + T9 (warm-pool contract) + T10 (Docker topology) + T11 (Rego)
- §3 module layout → T3-T11 each create one module
- §4 closed-enums → T3 + T4 partition-invariant pins
- §5 Protocol → T3
- §6 SandboxPolicy + 2-stage validation → T3 (Stage-1) + T5 (Stage-2)
- §7 DockerSibling impl → T10
- §8 CredentialAdapter stub → T8
- §9 catalog → T6
- §10 egress proxy → T7
- §11 warm-pool → T9
- §12 audit taxonomy → T4
- §13 sandbox.rego → T11
- §14 cross-ADR amendments → DONE at commit `624a469`
- §15 test taxonomy → spread across T3-T11 per spec
- §16 exit criteria → verified incrementally; final aggregate at T13 closeout
- §17 critical-controls scope → T12 gate uplift
- §18 "what this is NOT" → covered by test files + closeout doc

**Placeholder scan:** no "TBD" / "TODO" / vague requirements. Each T-task has concrete file paths + concrete code + concrete commit message template.

**Type consistency:** field names (`pack_context`, `pack_artifact_digest`, `cpu_time_budget_s`, `use_warm_pool`, `warm_pool_key`) match the spec verbatim. Closed-enum names (`SandboxRefusalReason`, `SandboxPolicyViolationReason`, `SandboxLifecycleEvent`) match the spec verbatim.

**Audit-early ordering** per user direction (2026-05-16): T4 audit lands before T5 admission + T6 catalog + T7 proxy + T8 credentials + T9 warm-pool + T10 docker_sibling. No T-task needs a "temporary direct chain helper" because the emit substrate exists from T4 onward.

**CC halt-before-commit gates** explicitly called out on every CC task (T3 / T5 / T6 / T7 / T9 / T10 / T12). Non-CC tasks (T4 / T8 / T11 / T13) follow the standard pre-commit gate ladder per `feedback_gate_ladder_per_microfix`.

---

## Execution Handoff

**Plan committed.** Two execution options per `superpowers:writing-plans` skill:

1. **Subagent-Driven (recommended)** — dispatch a fresh subagent per T-task; review between tasks; fast iteration. Each T's halt-before-commit summary returns to the orchestrator (this session) for user-token-gated commits.

2. **Inline Execution** — execute T-tasks in this session using `superpowers:executing-plans`; batch execution with checkpoints at each halt-before-commit.

**Recommend Subagent-Driven** — Sprint 8A has 11 implementation T-tasks; subagent-per-T keeps each task's context focused + lets reviewer rounds compose cleanly. T10 (DockerSiblingSandboxBackend, ~600 LoC) is the strongest candidate for being its own dispatched subagent because its surface area is large.

After this plan commits at T2: T3 starts. Per the established sequence, T3 spawns a fresh review cycle before commit.
