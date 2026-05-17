# Sprint 8B — KubernetesPodSandboxBackend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `KubernetesPodSandboxBackend` as the second Wave-1 `SandboxBackend` per ADR-004 amendment + `project_openshift_deployment_target`, so banks can run AgentOS sandboxes on OpenShift/Kubernetes with the same admission pipeline, audit taxonomy, canonical image catalog, warm pool, egress posture, and ADR-014/015 policy gates as the Sprint 8A `DockerSiblingSandboxBackend`.

**Architecture:** Backend-agnostic primitives (Stage-2 `admit_policy`, `CanonicalImageCatalog`, `SandboxWarmPool`, `sandbox.rego`, 8-event audit taxonomy, 15-value `SandboxRefusalReason`) ship in 8A and are reused unchanged. 8B adds (a) a `kubernetes-asyncio`-backed backend that emits the same closed-enum refusals + lifecycle events as DockerSibling but materialises sandboxes as Pods (two-container Pod sharing localhost; proxy sidecar; NetworkPolicy egress; OpenShift-compatible SecurityContext); (b) a cross-backend `_trigger_for_reason` conformance fixture parametrising the existing 2-test harness across all 15 refusal arms (deferred from Sprint 8A T2 plan §T10c); (c) a `core/config.py` Settings field + `sandbox/backend_factory.py` selecting backend per `COGNIC_SANDBOX_BACKEND=docker_sibling | kubernetes_pod`.

**Tech Stack:** Python 3.12 + `kubernetes-asyncio` (default — DEP/API verification is the FIRST step of T8B-b; do NOT lock code shape until the actual library API is verified) + existing 8A primitives (`SandboxBackend` / `SandboxSession` Protocols at `src/cognic_agentos/sandbox/protocol.py:254` + `:226`; `admit_policy` at `src/cognic_agentos/sandbox/admission.py:177`; `CanonicalImageCatalog` at `src/cognic_agentos/sandbox/catalog.py:206`; `SandboxWarmPool` at `src/cognic_agentos/sandbox/warm_pool.py:235`; `emit_sandbox_event` at `src/cognic_agentos/sandbox/audit.py:65`; OPA Rego bundle at `policies/_default/sandbox.rego`).

---

## Source-doctrine references

The plan is grounded against the following authoritative sources. Every claim in the body about an existing primitive MUST cite the file:line; reviewers are expected to verify each citation per `feedback_verify_code_citations_at_doc_write`.

| Doctrine | Source | Sprint-8B relevance |
|---|---|---|
| ADR-004 amendment | `docs/adrs/ADR-004-sandbox-primitive.md` §29-30, §65 | Adds K8s/OpenShift Pod backend as co-Wave-1 (NOT deferred to Wave-2). OpenShift-compatible pod SecurityContext (no `--privileged`; restricted-by-default SCC). NetworkPolicy egress to proxy only. ServiceAccount + minimal RBAC. Backend selection via `COGNIC_SANDBOX_BACKEND=docker_sibling | kubernetes_pod` env var (§32). |
| ADR-006 | `docs/adrs/ADR-006-iso-42001-control-mapping.md` | 8 `sandbox.lifecycle.*` + `sandbox.policy.violated` + `sandbox.warm_pool.*` audit events; `proxy_log` materialisation on `sandbox.lifecycle.exec_completed` AND `sandbox.policy.violated`. K8s backend MUST emit the SAME 8-event taxonomy via the same `emit_sandbox_event` seam (`src/cognic_agentos/sandbox/audit.py:65`). |
| ADR-014 | `docs/adrs/ADR-014-runtime-tool-approval.md` | 6 high-risk tiers refuse fail-closed via `sandbox_high_risk_tier_refused_pre_13_5` until Sprint 13.5 wires `core/approval/engine.py`. K8s backend reuses 8A's `admit_policy` Stage-2 enforcement — no backend-specific changes. |
| ADR-015 | `docs/adrs/ADR-015-policy-as-code.md` | `sandbox.rego` bundle at `data.cognic.sandbox.admit.allow` is the Stage-2 step-9 decision point. K8s backend reuses the same bundle; T8B-pre (commit `4aa6c7b` on main) ensures OPA-on-CI exercises bundle every PR. |
| ADR-016 | `docs/adrs/ADR-016-supply-chain.md` | Canonical image catalog + cosign + syft SBOM. K8s backend reuses 8A's `CanonicalImageCatalog` (no new images; same 4-image catalog). |
| `project_openshift_deployment_target` | `/Users/bmz/.claude/projects/-Users-bmz-development-cognic-agentos/memory/project_openshift_deployment_target.md` | OpenShift/Kubernetes is Wave-1 bank-production target; same `SandboxBackend` Protocol; egress posture identical (proxy-mediated HTTP/HTTPS). |
| AGENTS.md stop rules | `AGENTS.md` "Stop rules" + "Critical-controls rule" | New backend file (`sandbox/backends/kubernetes_pod.py`) is critical-controls; promoted at T8B-d with the explicit fresh-coverage gate-run per the user-locked tightening edit #2. |
| `feedback_verify_promotion_meets_floor_at_promotion_time` | `/Users/bmz/.claude/projects/-Users-bmz-development-cognic-agentos/memory/feedback_verify_promotion_meets_floor_at_promotion_time.md` | T8B-d checklist item: run `tools/check_critical_coverage.py` against fresh coverage BEFORE the commit — NOT just `_EXPECTED_ENTRY_COUNT` bump. Concrete loss case: Sprint 8A T12 verification incident. |
| `feedback_verify_dep_availability_at_implementation` | `/Users/bmz/.claude/projects/-Users-bmz-development-cognic-agentos/memory/feedback_verify_dep_availability_at_implementation.md` | T8B-b step 1: verify `kubernetes-asyncio` in `pyproject.toml` BEFORE locking any code shape; verify the actual pod-create + pods/exec API surface before naming functions. |
| `feedback_canonical_artifact_not_oss_substitute` | `/Users/bmz/.claude/projects/-Users-bmz-development-cognic-agentos/memory/feedback_canonical_artifact_not_oss_substitute.md` | Canonical images (`cognic/sandbox-runtime-*` + `cognic/sandbox-egress-proxy`) MUST be real shippable artifacts in K8s as well; missing image → env-gated test skip with structured message; NEVER silent OSS substitution. |
| `feedback_immutable_runtime_images_no_dynamic_install` | `/Users/bmz/.claude/projects/-Users-bmz-development-cognic-agentos/memory/feedback_immutable_runtime_images_no_dynamic_install.md` | K8s backend MUST refuse dynamic apt-get/pip at create time in production profile, surfacing `sandbox_runtime_deps_unsupported_in_production` (reuses 8A's enforcement at `admission.py:269-277`). |
| `feedback_sandbox_network_isolation_precision` | `/Users/bmz/.claude/projects/-Users-bmz-development-cognic-agentos/memory/feedback_sandbox_network_isolation_precision.md` | K8s egress posture: deny-all NetworkPolicy egress except `cognic-egress-proxy` Service (or sidecar via shared Pod localhost); proxy enforces per-call hostname allow-list. Sandbox container has NO direct external network route. |
| `feedback_evidence_boundary_runtime_validation` | `/Users/bmz/.claude/projects/-Users-bmz-development-cognic-agentos/memory/feedback_evidence_boundary_runtime_validation.md` | K8s backend's audit-emission helpers MUST validate runtime semantics (tz-aware timestamps; joint invariants on payload keys; unknown Literal values fail-loud) at the same evidence-boundary as 8A's proxy.py + warm_pool.py. |
| `feedback_consumer_owned_protocol_for_unlanded_dep` | `/Users/bmz/.claude/projects/-Users-bmz-development-cognic-agentos/memory/feedback_consumer_owned_protocol_for_unlanded_dep.md` | Sprint 8A admission.py declares `CatalogProtocol` + `CredentialAdapter` Protocols inline because catalog/credentials hadn't landed yet. 8B's K8s backend has NO unlanded downstream — reuses the SHARED Protocols at `admission.py`; should NOT redeclare them. |

---

## Decisions locked at preflight (2026-05-17)

User-approved before any code work. These are NOT to be re-litigated mid-task.

1. **OPA-on-CI lane** — **DONE** (PR #28 / squash commit `4aa6c7b` on main, 2026-05-17). Pinned OPA v1.16.1 installs in the `lint + test` job runner; both `sandbox.rego` (16 tests) and `elicitation.rego` (22 tests) direct-OPA smoke tests run on every PR going forward. NO 8B task re-does this work.

2. **K8s client dep** — Default `kubernetes-asyncio` (most mature async option). **Hard constraint: T8B-b step 1 verifies dep availability + the actual pod-create + pods/exec API surface BEFORE any code shape is locked.** No guessed stream/exec API contracts. If `kubernetes-asyncio` proves unsuitable (deprecated, missing API, security CVE), plan-amendment commit re-evaluates against `kr8s` or `pykube-ng` per `feedback_consumer_owned_protocol_for_unlanded_dep` doctrine. The plan body uses `kubernetes-asyncio` API names as PLACEHOLDERS subject to T8B-b step 1 verification.

3. **Live cluster strategy** — **NO live OpenShift/K8s cluster assumed for CI.** Unit tests use mocked `kubernetes-asyncio` client; integration tests env-gated on `COGNIC_RUN_K8S_SANDBOX=1` with structured `pytest.skip` message (mirrors Sprint 8A's `COGNIC_RUN_DOCKER_SANDBOX=1` pattern). **`kind` (Kubernetes-in-Docker) is NOT added to CI** unless we deliberately accept the runtime/flakiness cost in a follow-up.

4. **Backend selection** — Settings field + `sandbox/backend_factory.py` in 8B. `core/config.py` adds `sandbox_backend: Literal["docker_sibling", "kubernetes_pod"]` Setting (default `"docker_sibling"` to preserve Sprint 8A behavior on existing deployments). Bank-overlay launchers CAN override via env var (`COGNIC_SANDBOX_BACKEND`) — AgentOS owns the default selection seam.

5. **CI surface** — OPA goes into `lint + test` (already landed). K8s integration tests stay INLINE in `lint + test` and SKIP env-gated; NO new `kubernetes-integration` job in `python.yml` until there's a real cluster decision.

### Two tightening edits locked from preflight discussion

- **Edit A (T8B-a naming):** Task T8B-a is named **"Cross-backend refusal-taxonomy + conformance harness expansion"** — NOT "backend proves all 15 behavior arms." Reason: Sprint 8A T13 R2 reviewer round burned us on the EXACT overclaim ("admission_pipeline.py + docker_sibling_*.py cover all 15 arms" — actually 13/15 behaviour + 1 backend-specific + 1 reserved-Literal). T8B-a delivers WHAT it can deliver — a fixture-keyed `_trigger_for_reason` dispatch parametrised over the 15 values plus structural coverage where the value has a behaviour path. Closed-enum membership pinning + per-value behaviour coverage are NOT the same axis; the plan keeps these distinct.

- **Edit B (T8B-d gate verification):** T8B-d MUST include an explicit checklist item — `uv run pytest --cov=cognic_agentos --cov-branch --cov-report=json -m "not postgres and not oracle"` THEN `uv run python tools/check_critical_coverage.py` against the freshly-regenerated `coverage.json`, BEFORE the commit. NOT just the count-guard self-test bump (which only proves "the module is on the list"; it does NOT prove "the module ACTUALLY meets the floor"). Concrete loss case: Sprint 8A T12 committed only the count-guard, missed the actual-floor check, and post-T13 the gate found 2 of 7 promoted modules below floor (`warm_pool.py` 91.58%/81.82%; `docker_sibling.py` 90.31%/82.86%). Doctrine memory: `feedback_verify_promotion_meets_floor_at_promotion_time.md`.

---

## Stack base + branch

- **Stack base:** `main` at `4aa6c7b` (post Sprint 8A merge `4751ee8` + OPA-on-CI merge `4aa6c7b`). Verified at plan-write time: `git log --oneline -2` shows the expected ancestry.
- **Sprint branch:** `feat/sprint-8b-kubernetes-pod-backend` created from `main`. Single feature branch per sprint per `feedback_uv_and_sprint_checkpoints`. All T8B-* tasks commit to this branch.
- **PR strategy:** ONE PR for the whole sprint, mirrors Sprint 8A PR #27 + 7B.4 PR #25 single-PR pattern. Squash merge at land (matches established precedent).

---

## File Structure

### New files (created by 8B)

| Path | Owner task | Purpose |
|---|---|---|
| `src/cognic_agentos/sandbox/backends/kubernetes_pod.py` | T8B-b/c | `KubernetesPodSandboxBackend` implementing `SandboxBackend` Protocol via `kubernetes-asyncio` |
| `src/cognic_agentos/sandbox/backend_factory.py` | T8B-c | Selects `DockerSiblingSandboxBackend` or `KubernetesPodSandboxBackend` per `Settings.sandbox_backend`; AgentOS-owned default seam |
| `tests/conformance/sandbox/conftest.py` (extension) | T8B-a | Adds `_trigger_for_reason` fixture-keyed dispatch + parametrised refusal-arm tests; reuses existing `backend` fixture (Docker) + adds `k8s_backend` fixture (mocked or env-gated) |
| `tests/conformance/sandbox/test_refusal_taxonomy.py` | T8B-a | NEW test file — parametrises over `SandboxRefusalReason` values via `_trigger_for_reason`; verifies the closed-enum vocabulary is COVERED by trigger dispatch (membership pin), NOT that every backend behaviorally raises every value (per tightening edit A) |
| `tests/unit/sandbox/backends/test_kubernetes_pod_pure_helpers.py` | T8B-b | Non-env-gated unit tests for pure-helper functions (pod spec builder, NetworkPolicy spec builder, SecurityContext derivation) — mirrors `test_docker_sibling_pure_helpers.py` pattern |
| `tests/unit/sandbox/backends/test_kubernetes_pod_lifecycle.py` | T8B-b | Env-gated integration tests on real K8s cluster (`COGNIC_RUN_K8S_SANDBOX=1`); mirrors `test_docker_sibling_lifecycle.py` pattern with `pytest.importorskip("kubernetes_asyncio")` |
| `tests/unit/sandbox/backends/test_kubernetes_pod_admission_integration.py` | T8B-b | Non-env-gated unit tests for backend's admission seam (verifies `admit_policy` is called with the right kwargs; reuses 8A admission tests' mock pattern) |
| `tests/unit/sandbox/backends/test_kubernetes_pod_exec_classification.py` | T8B-c | Non-env-gated unit tests for K8s-specific cap violation classification (OOMKilled detection via `ContainerStatus.lastState.terminated.reason`; walltime; cpu-budget) |
| `tests/unit/sandbox/backends/test_kubernetes_pod_coverage_branches.py` | T8B-d | Focused regressions for any missing-line/branch surface uncovered after T8B-b + T8B-c land (mirrors Sprint 8A T12-coverage-repair pattern) |
| `tests/unit/sandbox/test_backend_factory.py` | T8B-c | Unit tests for `backend_factory.get_backend(settings)`; covers both arms + invalid-value refusal |

### Modified files (extended by 8B)

| Path | Owner task | Change |
|---|---|---|
| `pyproject.toml` | T8B-b | Add `sandbox-k8s = ["kubernetes-asyncio>=X.Y"]` extra (X.Y locked at step 1 of T8B-b after dep verification); mirrors `sandbox-docker` pattern at lines 176-190 |
| `uv.lock` | T8B-b | Lockfile regeneration after `pyproject.toml` extra addition |
| `src/cognic_agentos/core/config.py` | T8B-c | Add `sandbox_backend: Literal["docker_sibling", "kubernetes_pod"]` Setting field (default `"docker_sibling"`) |
| `src/cognic_agentos/sandbox/__init__.py` | T8B-b | Conditional re-export of `KubernetesPodSandboxBackend` under `try/except ImportError` (same pattern as `DockerSiblingSandboxBackend` re-export per `__init__.py` existing import block); fail-loud `NotImplementedError` referencing `sandbox-k8s` extra when missing |
| `tools/check_critical_coverage.py` | T8B-d | Add `("src/cognic_agentos/sandbox/backends/kubernetes_pod.py", 0.95, 0.90)` to `_CRITICAL_FILES`; new Sprint-8B docstring section block |
| `tests/unit/tools/test_check_critical_coverage.py` | T8B-d | Bump `_EXPECTED_ENTRY_COUNT` from 70 to 71; add `_SPRINT_8B_GATE_MODULES = ("src/cognic_agentos/sandbox/backends/kubernetes_pod.py",)` parametrize set |
| `AGENTS.md` | T8B-d | Add `sandbox/backends/kubernetes_pod.py` to the `*Sandbox primitive (Sprint 8A):*` subsection (rename to `*Sandbox primitive (Sprints 8A + 8B):*` OR add a `*Sandbox primitive (Sprint 8B):*` companion subsection — final structure picked at T8B-d implementation time) |
| `docs/BUILD_PLAN.md` | T8B-e | §698 — flip Sprint 8B PLANNED → CLOSED with merge commit ref; §1142 schedule-risk row update if needed |
| `docs/closeouts/2026-05-??-sprint-8b-kubernetes-pod-backend.md` | T8B-e | NEW — closeout note mirroring 8A T13 closeout structure |

### Reused unchanged (NO modifications expected; pin via citation only)

| Path | Sprint owner | Why reused |
|---|---|---|
| `src/cognic_agentos/sandbox/protocol.py` | 8A T3 | `SandboxBackend` + `SandboxSession` Protocols + 15-value `SandboxRefusalReason` + 6-value `SandboxPolicyViolationReason` + 8-value `SandboxLifecycleEvent` + `SandboxBackendHealth` + `SandboxBackendHealthStatus` (`protocol.py:201`). Backend-agnostic. |
| `src/cognic_agentos/sandbox/policy.py` | 8A T3 | `SandboxPolicy` frozen dataclass + Stage-1 `validate_policy_shape()`. Backend-agnostic. |
| `src/cognic_agentos/sandbox/admission.py` | 8A T5 | `admit_policy()` 9-step Stage-2 pipeline. Called from EVERY backend's `create()` BEFORE backend-specific pod/container materialisation. Backend-agnostic. |
| `src/cognic_agentos/sandbox/catalog.py` | 8A T6 | `CanonicalImageCatalog` + cosign + syft SBOM verification. Backend-agnostic. |
| `src/cognic_agentos/sandbox/proxy.py` | 8A T7 | `EgressProxyConfig` + `render_proxy_config` + `ProxyAccessRecord` + `proxy_log_to_chain_payload`. Backend-agnostic. |
| `src/cognic_agentos/sandbox/warm_pool.py` | 8A T9 | `SandboxWarmPool` takes any `SandboxBackend` Protocol implementation via constructor's `backend` arg (`warm_pool.py:235`). K8s backend instantiates the same `SandboxWarmPool` with itself as the backend arg — zero changes to warm-pool code. |
| `src/cognic_agentos/sandbox/audit.py` | 8A T4 | `emit_sandbox_event(decision_history_store, *, event, tenant_id, actor_id, trace_id, session_id, payload)` (`audit.py:65-74`). Same 8 event values; same ISO 42001 A.6.2.5 tagging. Backend-agnostic. |
| `src/cognic_agentos/sandbox/credentials.py` | 8A T8 | `CredentialAdapter` Protocol + `KernelDefaultCredentialAdapter` fail-loud stub. Backend-agnostic. K8s backend invokes the same adapter via `admit_policy` Stage-2 step 3. |
| `policies/_default/sandbox.rego` | 8A T11 | Wave-1 admission bundle at `data.cognic.sandbox.admit.allow`. Backend-agnostic — both backends pass the same Rego input shape. |
| `tests/conformance/sandbox/test_backend_conformance.py` | 8A T10c | 2 existing Protocol-surface tests (`test_health_returns_ok_status` + `test_destroy_is_idempotent`). T8B-a EXTENDS the conftest to parametrise these across both backends — does NOT modify the test bodies. |

---

## Cross-task invariants (apply to EVERY T-task)

These doctrines apply on every commit. NOT repeated per-task to keep tasks focused.

1. **Halt-before-commit on every CC task.** T8B-b, T8B-c, T8B-d are CC. T8B-a is CC-ADJ (touches conformance test surface; refusal-vocabulary wire-protocol-public contract). T8B-e is docs-only. Per `feedback_strict_review_off_gate`: "off-gate" plan markings do NOT downgrade reviewer strictness on any CC commit. Halt summary MUST: (a) restate scope; (b) list files touched + LoC delta; (c) report gate ladder results explicitly; (d) map every user-stated watchpoint to ≥1 pinning regression; (e) end with explicit `await full-word commit token`.

2. **Gate ladder per `feedback_full_gate_pre_commit` + `feedback_gate_ladder_per_microfix`:**
   - At halt-pre-commit: `uv run ruff check .` + `uv run ruff format --check .` (BOTH full-tree, NOT narrow-scope) + `uv run mypy src tests` (full-tree) + narrow pytest of touched test files + `git diff --check` (with `git add -N` workaround for untracked files per `feedback_git_diff_check_untracked`).
   - At commit-token: optionally `uv run pytest --cov=cognic_agentos --cov-branch -m "not postgres and not oracle"` full coverage suite. Skipped only when user authorises `commit without pytest` (test-only or docs-only commits).
   - T8B-d MUST run the full coverage suite + `tools/check_critical_coverage.py` against fresh `coverage.json` — NOT optional — per tightening edit B.

3. **Cite-from-source at doc-write time per `feedback_verify_code_citations_at_doc_write`.** EVERY claim in plan body / commit body / closeout / AGENTS.md entry that references existing code (signatures, class names, file:line, test names, closed-enum values) MUST be backed by `Read` or `grep` at the cited location in the SAME compose pass. NOT acceptable: paraphrasing from memory or from this plan-of-record document. The plan-of-record is itself a derived doc — implementors MUST re-verify at the actual source files at task-execution time.

4. **Test-only drift detectors per `feedback_drift_detector_test_only_no_runtime_import`.** When two production modules must share a constant (e.g., `_VALID_OUTCOMES` in `proxy.py` mirroring `ProxyAccessOutcome` in `protocol.py`), the test-only drift detector pattern is the canonical resolution — each module has its own local copy + a test imports from BOTH and asserts equality. T8B-a / T8B-b code MUST follow this if a similar shared-constant arises (e.g., K8s container-status-reason values mirrored from `SandboxPolicyViolationReason`).

5. **Evidence-boundary runtime validation per `feedback_evidence_boundary_runtime_validation`.** K8s backend's audit emission helpers + any chain-row materialiser MUST validate runtime semantics (tz-aware timestamps via BOTH `tzinfo is not None` AND `utcoffset() is not None`; joint invariants across closed-enum + payload key set; unknown Literal values fail-loud at the materialiser boundary; NO `# type: ignore` smuggling). 12 reviewer findings closed at Sprint 8A T7 + T9 across 8 distinct gaps — same gaps exist on the K8s side and MUST be defended against by construction.

6. **Plan-amendment-via-implementation-notes-commit per `feedback_consumer_owned_protocol_for_unlanded_dep`.** If T8B-b step 1 dep/API verification reveals that `kubernetes-asyncio` does NOT support the exact pod-create + pods/exec stream surface the plan assumes, the implementor commits a `chore(sprint-8b): T8B-b implementation notes — kubernetes_asyncio API drift correction` plan-amendment BEFORE proceeding. Pattern matches Sprint 8A T8 (`41a7e2a`) + T11 (`903b0fa`) + T2 implementation notes (`225f509`).

7. **Branch hygiene:** ONE feature branch `feat/sprint-8b-kubernetes-pod-backend` for the whole sprint. Commits land sequentially. NO pushes / NO PR creation until ALL T-tasks land AND the user explicitly authorises with a full-word token (`push it` / `open pr`).

8. **Canonical artifact doctrine per `feedback_canonical_artifact_not_oss_substitute`.** K8s integration tests MUST refuse silent substitution of canonical images. Missing canonical image at env-gated test time → `pytest.skip` with structured message naming the missing ref. NEVER substitute an OSS image masquerading as a canonical name.

9. **Immutable runtime image doctrine per `feedback_immutable_runtime_images_no_dynamic_install`.** K8s backend MUST refuse pod specs that declare dynamic install in production profile. Reuses 8A's `admit_policy` Stage-2 step 3a enforcement at `admission.py:269-277` — no new code path needed.

---

## Task T8B-a — Cross-backend refusal-taxonomy + conformance harness expansion (CC-ADJ)

**Scope:** Land the deferred 15-arm `_trigger_for_reason` conformance parametrize from Sprint 8A T2 plan §T10c. Pure test-fixture work — NO production code changes. Sets up the harness BEFORE T8B-b lands the K8s backend so 8B's K8s implementation has an immediate cross-backend test target.

**Why CC-ADJ:** The 15-value `SandboxRefusalReason` Literal is wire-protocol-public per AGENTS.md "Critical-controls rule" `*Sandbox primitive*` subsection. The `_trigger_for_reason` dispatch IS the cross-backend pin against refusal-vocabulary drift. Drift between this dispatch + the production `SandboxRefusalReason` values would mean a backend could silently ship without emitting a known refusal value AND CI would not catch it.

**Naming discipline (tightening edit A):** This task delivers "refusal-taxonomy + conformance harness expansion" — NOT "every backend proves all 15 behaviour arms." Concrete: 13/15 arms have backend-agnostic behaviour paths (admission-pipeline reasons fire identically in DockerSibling + KubernetesPod because both backends call `admit_policy` with the same inputs); 2/15 arms (`sandbox_backend_unavailable` + `sandbox_warm_pool_drained`) are backend-specific behaviour. T8B-a's pinning regression asserts closed-enum *membership* + dispatch *registration* for all 15 values, NOT behavioural equivalence — that's a separate axis.

**Files:**
- Modify: `tests/conformance/sandbox/conftest.py`
- Create: `tests/conformance/sandbox/test_refusal_taxonomy.py`

- [ ] **Step 1: Verify current state at source**

Run:
```bash
grep -n "_trigger_for_reason\|backend\|catalog\|docker_client" tests/conformance/sandbox/conftest.py
grep -n "^from\|^import\|_VALID_EVENTS\|def __init__\|class _" tests/unit/sandbox/test_policy_shape.py | head -20
```
Expected: `_trigger_for_reason` returns ZERO hits (helper does NOT exist; that's the gap T8B-a closes). The existing conftest has `docker_client` + `catalog` + `backend` fixtures.

- [ ] **Step 2: Write the failing regression — `_trigger_for_reason` registry covers ALL 15 values**

Create `tests/conformance/sandbox/test_refusal_taxonomy.py`:

```python
"""Sprint 8B T8B-a — cross-backend refusal-taxonomy conformance.

Pins that the ``_trigger_for_reason`` dispatch at
``tests/conformance/sandbox/conftest.py`` REGISTERS a trigger function
for EVERY value in the wire-public ``SandboxRefusalReason`` Literal at
``src/cognic_agentos/sandbox/protocol.py:34-50``.

This is the closed-enum membership pin per the user-locked tightening
edit A (T8B-a, 2026-05-17 preflight): T8B-a delivers REGISTRATION
coverage, NOT BEHAVIORAL coverage. Per-value behavior coverage lives in:

* ``tests/unit/sandbox/test_admission_pipeline.py`` — 13/15 admission-
  pipeline arms (backend-agnostic; both backends invoke admit_policy)
* ``tests/unit/sandbox/test_warm_pool.py`` — sandbox_warm_pool_drained
  (1/15; SandboxWarmPool primitive; backend-agnostic)
* per-backend conformance tests (Docker today; K8s when T8B-b lands)
  for sandbox_backend_unavailable (1/15; backend-specific health()
  probe). Drift detector + value count below; behavior fan-out is the
  caller's responsibility — NOT this file's claim.
"""

from __future__ import annotations

from typing import get_args

import pytest

from cognic_agentos.sandbox.protocol import SandboxRefusalReason


# This import will FAIL until step 3 lands the registry — that's the
# failing-test signal step 2 produces.
from tests.conformance.sandbox.conftest import TRIGGERS_BY_REASON


class TestRefusalTaxonomyRegistrationCoverage:
    """Pin the dispatch-registration completeness invariant."""

    def test_triggers_cover_every_refusal_reason_value(self) -> None:
        """Every ``SandboxRefusalReason`` value MUST have a trigger
        registered in ``TRIGGERS_BY_REASON``. Drift detector — fails
        when a 16th value lands in the Literal without adding a trigger
        OR when a trigger is removed without removing the value.
        """
        reasons = set(get_args(SandboxRefusalReason))
        registered = set(TRIGGERS_BY_REASON.keys())
        missing = reasons - registered
        extra = registered - reasons
        assert not missing, (
            f"SandboxRefusalReason values without a trigger: {sorted(missing)}; "
            f"add a trigger function to TRIGGERS_BY_REASON in conftest.py"
        )
        assert not extra, (
            f"TRIGGERS_BY_REASON keys not in SandboxRefusalReason: {sorted(extra)}; "
            f"remove the orphan triggers or add the values to the Literal"
        )

    def test_refusal_reason_count_locked_at_fifteen(self) -> None:
        """Crisp value-count guard — separate from the membership
        assertion so drift in size shows clean diagnostic.
        """
        assert len(get_args(SandboxRefusalReason)) == 15
```

- [ ] **Step 3: Run test to verify it fails for the right reason**

Run: `uv run pytest tests/conformance/sandbox/test_refusal_taxonomy.py -v`
Expected: **FAIL** with `ImportError: cannot import name 'TRIGGERS_BY_REASON' from 'tests.conformance.sandbox.conftest'`. This proves the test would catch the gap; if it passed accidentally (e.g., a duplicate symbol elsewhere) we'd know step 4 is operating on a false-green baseline.

- [ ] **Step 4: Land `TRIGGERS_BY_REASON` registry in conftest.py**

Extend `tests/conformance/sandbox/conftest.py` with the dispatch table. Each value maps to a `_trigger_<name>` factory function (sync def returning an async context manager that, when entered, sets up the backend state such that the next `backend.create(...)` raises `SandboxLifecycleRefused(<value>)`):

```python
# ... existing imports ...
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any, Callable, TypeAlias

# Sprint 8B T8B-a — cross-backend refusal-taxonomy conformance dispatch.
# Each trigger function returns an async context manager which, when
# entered, prepares the backend such that a subsequent backend.create(...)
# raises SandboxLifecycleRefused carrying the named SandboxRefusalReason
# value. Closed-enum membership pin lives at
# tests/conformance/sandbox/test_refusal_taxonomy.py — DO NOT add a
# trigger here without a corresponding SandboxRefusalReason value, and
# vice versa.

TriggerFactory: TypeAlias = Callable[
    [Any, Any], AbstractAsyncContextManager[None]
]


# Per tightening edit A (T8B-a, 2026-05-17 preflight): this dispatch
# pins REGISTRATION coverage, NOT BEHAVIORAL equivalence between
# backends. Trigger bodies for admission-pipeline arms (13 of 15)
# are backend-agnostic — both DockerSibling + KubernetesPod call
# admit_policy with the same inputs, so the same trigger works for
# both. Trigger bodies for the 2 backend-specific arms
# (sandbox_backend_unavailable + sandbox_warm_pool_drained) are
# defined per-backend in the backend's own conformance test module
# (T8B-b for K8s; existing test_docker_sibling_*.py for Docker today).

@asynccontextmanager
async def _trigger_sandbox_credential_adapter_not_configured(
    backend, ctx
):  # type: ignore[no-untyped-def]
    """Trigger the admission step-3 credential-adapter refusal."""
    # admission.py:256-267 — raises when policy.vault_path is set AND
    # backend._credential_adapter is the KernelDefaultCredentialAdapter
    # sentinel. The trigger expects the backend fixture to already wire
    # KernelDefaultCredentialAdapter; the policy passed to create() must
    # carry a non-None vault_path. Caller orchestrates policy + ctx;
    # this manager is a no-op envelope so backend-specific arms can
    # share the same call shape.
    yield


# ... 13 more trigger functions, one per admission-pipeline arm ...


# The 2 backend-specific triggers — these are FORWARD DECLARATIONS
# pointing at the per-backend implementation. Each backend's conftest
# (or test module) provides a fixture matching this name; the
# parametrised harness depends on whichever fixture the active backend
# context provides.

@asynccontextmanager
async def _trigger_sandbox_backend_unavailable(backend, ctx):  # type: ignore[no-untyped-def]
    """Backend-specific: requires the backend fixture to expose a
    ``_simulate_api_down`` hook. DockerSiblingBackend's fixture
    monkeypatches ``backend._docker.containers.create`` to raise
    aiodocker.exceptions.DockerError(503, "Daemon unreachable").
    KubernetesPodBackend's fixture (lands at T8B-b) monkeypatches
    ``backend._kube.CoreV1Api.create_namespaced_pod`` to raise
    kubernetes_asyncio.client.exceptions.ApiException(status=500,
    reason="Service Unavailable").
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_warm_pool_drained(backend, ctx):  # type: ignore[no-untyped-def]
    """warm_pool.py:400 — raises when checkout is attempted on a
    drained pool. Trigger drains the backend's warm pool first.
    """
    if backend._warm_pool is not None:
        await backend._warm_pool.drain()
    yield


TRIGGERS_BY_REASON: dict[str, TriggerFactory] = {
    "sandbox_credential_adapter_not_configured": _trigger_sandbox_credential_adapter_not_configured,
    "sandbox_runtime_deps_unsupported_in_production": _trigger_sandbox_runtime_deps_unsupported_in_production,
    "sandbox_high_risk_tier_refused_pre_13_5": _trigger_sandbox_high_risk_tier_refused_pre_13_5,
    "sandbox_image_digest_not_in_canonical_catalog": _trigger_sandbox_image_digest_not_in_canonical_catalog,
    "sandbox_image_cosign_verification_failed": _trigger_sandbox_image_cosign_verification_failed,
    "sandbox_image_sbom_check_failed": _trigger_sandbox_image_sbom_check_failed,
    "sandbox_image_digest_format_invalid": _trigger_sandbox_image_digest_format_invalid,
    "sandbox_policy_exceeds_tenant_max_cpu": _trigger_sandbox_policy_exceeds_tenant_max_cpu,
    "sandbox_policy_exceeds_tenant_max_memory": _trigger_sandbox_policy_exceeds_tenant_max_memory,
    "sandbox_policy_exceeds_tenant_max_walltime": _trigger_sandbox_policy_exceeds_tenant_max_walltime,
    "sandbox_policy_egress_host_invalid": _trigger_sandbox_policy_egress_host_invalid,
    "sandbox_policy_egress_protocol_not_http": _trigger_sandbox_policy_egress_protocol_not_http,
    "sandbox_policy_rego_denied": _trigger_sandbox_policy_rego_denied,
    "sandbox_backend_unavailable": _trigger_sandbox_backend_unavailable,
    "sandbox_warm_pool_drained": _trigger_sandbox_warm_pool_drained,
}
```

Implementor MUST write the 13 missing trigger function bodies (lines marked `... 13 more trigger functions`). Each follows the same shape — `@asynccontextmanager` decorator, `async def _trigger_<name>(backend, ctx): yield`. Bodies that set up backend state OR monkeypatch the policy MUST do so inside the `try` part before the `yield`; cleanup (if any) goes in the implicit finally after the `yield`. The 13 admission-arm triggers are backend-agnostic — most are simple `yield` no-ops because the trigger semantics live in the policy/context the caller passes to `backend.create()`.

- [ ] **Step 5: Run the regression — MUST PASS now**

Run: `uv run pytest tests/conformance/sandbox/test_refusal_taxonomy.py -v`
Expected: **PASS** — both regressions green (registration coverage + value-count guard).

- [ ] **Step 6: Verify the regression is load-bearing via TM-revert per `feedback_security_regression_hardening`**

Manually delete one key from `TRIGGERS_BY_REASON` (e.g., remove `"sandbox_warm_pool_drained"`). Re-run pytest. Expected: `test_triggers_cover_every_refusal_reason_value` FAILS with `missing: ['sandbox_warm_pool_drained']`. Restore the key. Re-run. PASS. Document TM-revert in commit body per `feedback_security_regression_hardening`.

- [ ] **Step 7: Halt-before-commit gate ladder**

Run in sequence:
```bash
uv run ruff check .                                       # expect: All checks passed!
uv run ruff format --check .                              # expect: N files already formatted
uv run mypy src tests                                     # expect: Success: no issues found
uv run pytest tests/conformance/sandbox/ -q               # expect: K passed
git diff --check                                          # expect: clean
git add -N tests/conformance/sandbox/test_refusal_taxonomy.py
git diff --check                                          # expect: clean (new file whitespace)
```

- [ ] **Step 8: Produce halt-before-commit summary + AWAIT explicit commit token**

Halt summary MUST include: scope statement; files modified + LoC delta; the 5 gate-ladder results; the TM-revert proof of load-bearingness; the explicit "this is REGISTRATION coverage, NOT behavioral coverage per tightening edit A" disclaimer; mapping of user-stated watchpoints to pinning regressions; suggested commit message. END with `await full-word commit token: commit / commit it / commit without pytest`.

- [ ] **Step 9: Commit**

```bash
git add tests/conformance/sandbox/conftest.py tests/conformance/sandbox/test_refusal_taxonomy.py
git commit -m "$(cat <<'EOF'
feat(sprint-8b): T8B-a — cross-backend refusal-taxonomy + conformance harness expansion (CC-ADJ)

Closes the deferred Sprint-8A T2 plan §T10c gap — adds the
TRIGGERS_BY_REASON dispatch + a closed-enum membership pin at
tests/conformance/sandbox/test_refusal_taxonomy.py.

Per the tightening edit A locked at Sprint 8B preflight (2026-05-17):
this delivers REGISTRATION coverage, NOT BEHAVIORAL coverage. Per-
value behavior coverage lives in the focused suites
(test_admission_pipeline.py for 13/15 admission arms; test_warm_pool.py
for sandbox_warm_pool_drained; per-backend tests for
sandbox_backend_unavailable). Drift between the production
SandboxRefusalReason Literal and TRIGGERS_BY_REASON now fails CI
with a clean diagnostic on every PR.

TM-revert verified load-bearing per feedback_security_regression_hardening:
deleting any key from TRIGGERS_BY_REASON fails the membership
regression with a structured "missing: [...]" message.

Backend-specific arms (sandbox_backend_unavailable +
sandbox_warm_pool_drained) carry forward-declarations pointing at
the per-backend fixture that provides the trigger; DockerSibling
already has one (added inline), KubernetesPod fixture lands at T8B-b.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task T8B-b — KubernetesPodSandboxBackend skeleton + lifecycle (CC)

**Scope:** Implement the K8s Pod-based `SandboxBackend` for the lifecycle methods (`create` + `destroy` + `health`). Defer `exec` body to T8B-c. Same Protocol surface as DockerSibling; same 8-event audit taxonomy; same admission pipeline reuse; same canonical image catalog.

**Why CC:** New CC module. Substantive enforcement boundary — a bug in pod-spec SecurityContext OR NetworkPolicy egress permits attacker escape to the bank's cluster.

**Critical: Step 1 is dep + API verification BEFORE any code shape lock per the user-locked decision at 8B preflight.**

**Files:**
- Modify: `pyproject.toml` (+ `uv.lock`)
- Modify: `src/cognic_agentos/sandbox/__init__.py`
- Create: `src/cognic_agentos/sandbox/backends/kubernetes_pod.py`
- Create: `tests/unit/sandbox/backends/test_kubernetes_pod_pure_helpers.py`
- Create: `tests/unit/sandbox/backends/test_kubernetes_pod_admission_integration.py`
- Create: `tests/unit/sandbox/backends/test_kubernetes_pod_lifecycle.py`

- [ ] **Step 1 (LOCK GATE per user decision): Verify dep + API availability BEFORE locking code shape**

Run:
```bash
# Verify kubernetes-asyncio is published + actively maintained
pip index versions kubernetes-asyncio 2>&1 | head -5

# Verify the API surface for pod create + pods/exec
python -c "
import kubernetes_asyncio
from kubernetes_asyncio import client, config
import inspect

# Confirm the namespaces we expect to use
print('kubernetes_asyncio version:', kubernetes_asyncio.__version__)
print('CoreV1Api.create_namespaced_pod signature:',
      inspect.signature(client.CoreV1Api.create_namespaced_pod))
print('CoreV1Api.delete_namespaced_pod signature:',
      inspect.signature(client.CoreV1Api.delete_namespaced_pod))
print('CoreV1Api.read_namespaced_pod_status signature:',
      inspect.signature(client.CoreV1Api.read_namespaced_pod_status))
print('NetworkingV1Api.create_namespaced_network_policy signature:',
      inspect.signature(client.NetworkingV1Api.create_namespaced_network_policy))

# Confirm the stream exec API — Docker's API surface here was the
# T10b R1 P1.1 bug class (Stream is NOT async-iterable; required
# .read_out() per-Message consumption). K8s has its own pattern.
from kubernetes_asyncio.stream import WsApiClient
print('WsApiClient class:', WsApiClient.__mro__)
"
```

Verify each:
- [ ] (a) `kubernetes-asyncio` is on PyPI; latest stable version is recorded
- [ ] (b) `CoreV1Api.create_namespaced_pod` accepts a `V1Pod` body as expected
- [ ] (c) `CoreV1Api.delete_namespaced_pod` accepts `name` + `namespace` + optional `grace_period_seconds`
- [ ] (d) `NetworkingV1Api.create_namespaced_network_policy` exists
- [ ] (e) The async stream API for `pods/exec` is callable from async code (kubernetes-asyncio uses websockets via `stream.WsApiClient` — verify the exact method name BEFORE coding the exec body in T8B-c)

If ANY assumption fails, STOP. Commit a plan-amendment per `feedback_consumer_owned_protocol_for_unlanded_dep`:
```bash
git commit --allow-empty -m "chore(sprint-8b): T8B-b implementation notes — kubernetes_asyncio API drift correction

[document the actual API surface vs the plan's assumptions; propose
the corrected code shape; halt for user review before re-attempting
T8B-b step 2]"
```

- [ ] **Step 2: Add `sandbox-k8s` extra to pyproject.toml**

Modify `pyproject.toml` at line 176 (after the `sandbox-docker` block) to add:

```toml
sandbox-k8s = [
    # Sprint 8B — KubernetesPodSandboxBackend uses kubernetes-asyncio
    # as the async K8s API client. NOT in [project] base deps so a
    # DockerSibling-only deployment (Sprint 8A, dev/CI) does not pull
    # the kubernetes-asyncio + websockets stack it does not use. The
    # KubernetesPod backend module imports kubernetes_asyncio at
    # module level — installs without this extra do NOT import the
    # backend module (the sandbox package re-export is wrapped behind
    # a try/except ImportError that surfaces a structured
    # NotImplementedError pointing at this extra when missing —
    # mirrors the sandbox-docker pattern).
    "kubernetes-asyncio>=<LOCKED-AT-STEP-1>",
]
```

Replace `<LOCKED-AT-STEP-1>` with the actual minimum version verified in step 1.

Run: `uv lock` to regenerate `uv.lock`. Verify the lockfile diff is minimal (only the new dep + transitives).

- [ ] **Step 3: Write the failing protocol-conformance test FIRST (TDD red phase)**

Create `tests/unit/sandbox/backends/test_kubernetes_pod_pure_helpers.py`:

```python
"""Sprint 8B T8B-b — KubernetesPodSandboxBackend pure-helper tests.

NON-env-gated. Mirrors the Sprint-8A pattern at
tests/unit/sandbox/backends/test_docker_sibling_pure_helpers.py — pins
the pure-functional helpers that build Pod specs, NetworkPolicy specs,
and SecurityContext dictionaries.

Per the canonical-artifact doctrine (feedback_canonical_artifact_not_oss_substitute):
the tests use fake image digests (sha256: + "a"*64 etc.) — the canonical
Sprint-8A image catalog publishes the real digests at supply-chain
pipeline build time; these tests do NOT pull real images.
"""

from __future__ import annotations

import pytest

# Per feedback_verify_dep_availability_at_implementation — gracefully
# degrade collection without the sandbox-k8s extra so kernel-only
# venvs do not fail collection on this file.
pytest.importorskip("kubernetes_asyncio")

from cognic_agentos.sandbox import PackAdmissionContext, SandboxPolicy
from cognic_agentos.sandbox.backends.kubernetes_pod import (
    _NON_ROOT_USER_RANGE_PLACEHOLDER,
    _build_pod_spec,
    _build_network_policy_spec,
    _build_security_context,
)


_POLICY = SandboxPolicy(
    cpu_cores=0.5,
    cpu_time_budget_s=None,
    memory_mb=256,
    walltime_s=30.0,
    runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
    egress_allow_list=(),
    vault_path=None,
)
_PACK_CTX = PackAdmissionContext(
    pack_id="cognic.test_pack",
    pack_version="v1.0.0",
    pack_artifact_digest="sha256:" + "1" * 64,
    risk_tier="internal_write",
    declares_dynamic_install=False,
    profile="production",
)


class TestBuildSecurityContext:
    """OpenShift-compatible SecurityContext per ADR-004 §30.

    No --privileged; matches restricted-by-default SCC. Non-root user
    via runAsNonRoot=True. capabilities.drop=[ALL]. readOnlyRootFilesystem=True.
    allowPrivilegeEscalation=False.
    """

    def test_security_context_drops_all_capabilities(self) -> None:
        ctx = _build_security_context()
        assert ctx["capabilities"]["drop"] == ["ALL"]

    def test_security_context_forbids_privilege_escalation(self) -> None:
        ctx = _build_security_context()
        assert ctx["allowPrivilegeEscalation"] is False

    def test_security_context_requires_non_root(self) -> None:
        ctx = _build_security_context()
        assert ctx["runAsNonRoot"] is True

    def test_security_context_uses_readonly_root_filesystem(self) -> None:
        ctx = _build_security_context()
        assert ctx["readOnlyRootFilesystem"] is True

    def test_security_context_omits_privileged_field(self) -> None:
        """OpenShift restricted SCC refuses privileged=True. The pod
        spec MUST NOT carry the field at all (omission is safer than
        explicit False — defends against future K8s API changes that
        might default differently)."""
        ctx = _build_security_context()
        assert "privileged" not in ctx

    def test_security_context_omits_runAsUser_for_openshift_compat(
        self,
    ) -> None:
        """OpenShift restricted-v2 SCC assigns runAsUser from the
        namespace-allocated UID range (MustRunAsRange). Hard-coded
        runAsUser=65534 collides on OpenShift; namespace assignment is
        the canonical pattern. The pod spec MUST NOT set runAsUser
        explicitly in production profile."""
        ctx = _build_security_context()
        assert "runAsUser" not in ctx


class TestBuildPodSpec:
    """Two-container Pod sharing localhost — sandbox + egress proxy
    sidecar. Egress posture: sandbox HTTP_PROXY=http://localhost:8080
    targets the sidecar via shared Pod localhost (kubernetes pods'
    containers share network namespace).
    """

    def test_pod_spec_has_exactly_two_containers(self) -> None:
        spec = _build_pod_spec(
            policy=_POLICY, session_id="s-1", tenant_id="t-1"
        )
        assert len(spec["spec"]["containers"]) == 2

    def test_pod_spec_sandbox_container_uses_canonical_runtime_image(
        self,
    ) -> None:
        spec = _build_pod_spec(
            policy=_POLICY, session_id="s-1", tenant_id="t-1"
        )
        sandbox = next(c for c in spec["spec"]["containers"] if c["name"] == "sandbox")
        assert sandbox["image"] == _POLICY.runtime_image

    def test_pod_spec_proxy_sidecar_uses_canonical_egress_image(
        self,
    ) -> None:
        spec = _build_pod_spec(
            policy=_POLICY, session_id="s-1", tenant_id="t-1"
        )
        proxy = next(c for c in spec["spec"]["containers"] if c["name"] == "egress-proxy")
        assert proxy["image"].startswith("cognic/sandbox-egress-proxy:")

    def test_pod_spec_sandbox_container_sets_http_proxy_to_localhost(
        self,
    ) -> None:
        """Per feedback_sandbox_network_isolation_precision — the two
        containers share network namespace inside a single Pod; the
        sandbox's HTTP_PROXY targets the proxy sidecar via shared
        localhost. NOT a separate ClusterIP Service."""
        spec = _build_pod_spec(
            policy=_POLICY, session_id="s-1", tenant_id="t-1"
        )
        sandbox = next(c for c in spec["spec"]["containers"] if c["name"] == "sandbox")
        env_dict = {e["name"]: e["value"] for e in sandbox.get("env", [])}
        assert env_dict["HTTP_PROXY"] == "http://localhost:8080"
        assert env_dict["HTTPS_PROXY"] == "http://localhost:8080"

    def test_pod_spec_does_not_set_no_proxy(self) -> None:
        """Per Sprint 8A T10a doctrine — NO_PROXY env var would create
        an egress-bypass class. Pod spec MUST NOT set NO_PROXY."""
        spec = _build_pod_spec(
            policy=_POLICY, session_id="s-1", tenant_id="t-1"
        )
        sandbox = next(c for c in spec["spec"]["containers"] if c["name"] == "sandbox")
        env_dict = {e["name"]: e["value"] for e in sandbox.get("env", [])}
        assert "NO_PROXY" not in env_dict


class TestBuildNetworkPolicySpec:
    """Per-session NetworkPolicy — deny-all egress except the
    canonical egress-proxy sidecar's external upstream destinations.
    """

    def test_network_policy_targets_session_pod_via_label_selector(
        self,
    ) -> None:
        spec = _build_network_policy_spec(session_id="s-1", tenant_id="t-1")
        # Pod selector keys the policy to the specific session
        # via the cognic.agentos.sandbox.session_id label.
        assert spec["spec"]["podSelector"]["matchLabels"][
            "cognic.agentos.sandbox.session_id"
        ] == "s-1"

    def test_network_policy_denies_all_egress_by_default(self) -> None:
        spec = _build_network_policy_spec(session_id="s-1", tenant_id="t-1")
        # PolicyTypes MUST include Egress; empty/missing Egress rules
        # = deny-all (per K8s NetworkPolicy semantics).
        assert "Egress" in spec["spec"]["policyTypes"]
```

(NOTE: 8 more pure-helper tests for resource-cap derivation, label conventions, namespace mapping, etc. — implementor writes the remaining ~8 tests following the pattern above.)

- [ ] **Step 4: Run failing tests**

Run: `uv run pytest tests/unit/sandbox/backends/test_kubernetes_pod_pure_helpers.py -v`
Expected: **FAIL** with `ImportError: cannot import name '_build_pod_spec' from 'cognic_agentos.sandbox.backends.kubernetes_pod'` — module does not exist yet. Good failure mode.

- [ ] **Step 5: Write `src/cognic_agentos/sandbox/backends/kubernetes_pod.py` pure helpers**

Implement the pure-functional helpers FIRST (no I/O; no K8s client; no admission). Mirrors Sprint 8A's `test_docker_sibling_pure_helpers.py` pattern where helpers ship before the orchestrator. Module skeleton:

```python
"""Sprint 8B T8B-b — KubernetesPodSandboxBackend.

Wave-1 SandboxBackend implementation for Kubernetes/OpenShift per
ADR-004 amendment + project_openshift_deployment_target. Conforms to
the same SandboxBackend Protocol as DockerSiblingSandboxBackend
(src/cognic_agentos/sandbox/protocol.py:254). Emits the same 8-event
audit taxonomy (src/cognic_agentos/sandbox/audit.py:65) + the same
15-value SandboxRefusalReason closed-enum
(src/cognic_agentos/sandbox/protocol.py:34-50).

OpenShift compatibility: no --privileged container; matches
restricted-by-default SCC. SecurityContext omits runAsUser to let
OpenShift's MustRunAsRange policy assign the UID from the namespace-
allocated range.

Network isolation per feedback_sandbox_network_isolation_precision:
two-container Pod sharing localhost (proxy sidecar via shared Pod
network namespace); per-session NetworkPolicy denies all egress except
proxy upstream. Sandbox container's HTTP_PROXY points at
http://localhost:8080 inside the shared Pod netns.

Production-grade per feedback_canonical_artifact_not_oss_substitute:
canonical 4-image catalog (Sprint 8A T6 — runtime-python, runtime-shell,
runtime-data, egress-proxy) is the only acceptable source; OSS
substitution refused fail-loud.
"""

from __future__ import annotations

from typing import Any

import kubernetes_asyncio  # raised at module top; sandbox-k8s extra required

# ... constants ...
_NON_ROOT_USER_RANGE_PLACEHOLDER = "openshift-assigned"  # documents the
# fact that the spec omits runAsUser; OpenShift restricted-v2 SCC
# assigns from the namespace UID range.


def _build_security_context() -> dict[str, Any]:
    """Construct the OpenShift-compatible SecurityContext dict.

    See test_kubernetes_pod_pure_helpers.py::TestBuildSecurityContext
    for the contract pins.
    """
    return {
        "capabilities": {"drop": ["ALL"]},
        "allowPrivilegeEscalation": False,
        "runAsNonRoot": True,
        "readOnlyRootFilesystem": True,
        # Intentionally NO "privileged" field — see test_security_context_omits_privileged_field
        # Intentionally NO "runAsUser" field — see test_security_context_omits_runAsUser_for_openshift_compat
    }


def _build_pod_spec(
    *, policy: "SandboxPolicy", session_id: str, tenant_id: str
) -> dict[str, Any]:
    """Construct the V1Pod body dict for the two-container Pod.

    See test_kubernetes_pod_pure_helpers.py::TestBuildPodSpec for the
    contract pins.
    """
    sandbox_env = [
        {"name": "HTTP_PROXY", "value": "http://localhost:8080"},
        {"name": "HTTPS_PROXY", "value": "http://localhost:8080"},
        # Intentionally NO NO_PROXY — see test_pod_spec_does_not_set_no_proxy
    ]
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": session_id,
            "labels": {
                "cognic.agentos.sandbox.session_id": session_id,
                "cognic.agentos.sandbox.tenant_id": tenant_id,
            },
        },
        "spec": {
            "containers": [
                {
                    "name": "sandbox",
                    "image": policy.runtime_image,
                    "env": sandbox_env,
                    "securityContext": _build_security_context(),
                    # ... resources.limits derivation lives in a helper ...
                },
                {
                    "name": "egress-proxy",
                    "image": "cognic/sandbox-egress-proxy:v1@sha256:" + "d" * 64,
                    "securityContext": _build_security_context(),
                },
            ],
            "restartPolicy": "Never",
        },
    }


def _build_network_policy_spec(
    *, session_id: str, tenant_id: str
) -> dict[str, Any]:
    """Construct the V1NetworkPolicy body dict for per-session egress
    enforcement. Deny-all egress + explicit allow for the proxy
    sidecar's upstream destinations.

    See test_kubernetes_pod_pure_helpers.py::TestBuildNetworkPolicySpec
    for the contract pins.
    """
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": f"sandbox-{session_id}",
            "labels": {
                "cognic.agentos.sandbox.session_id": session_id,
                "cognic.agentos.sandbox.tenant_id": tenant_id,
            },
        },
        "spec": {
            "podSelector": {
                "matchLabels": {
                    "cognic.agentos.sandbox.session_id": session_id,
                }
            },
            "policyTypes": ["Egress"],
            # Empty/missing egress rules = deny-all per K8s semantics.
            # The proxy sidecar's upstream destinations are governed by
            # the cluster-wide egress-proxy NetworkPolicy installed by
            # the deployment kit (Sprint 14), NOT by this per-session
            # policy. This per-session policy ONLY locks down the
            # sandbox container's namespace-internal egress.
        },
    }
```

- [ ] **Step 6: Run pure-helper tests — MUST PASS**

Run: `uv run pytest tests/unit/sandbox/backends/test_kubernetes_pod_pure_helpers.py -v`
Expected: **PASS** — all 14+ pure-helper tests green.

- [ ] **Step 7: Write the admission-integration test (TDD red)**

Create `tests/unit/sandbox/backends/test_kubernetes_pod_admission_integration.py`:

```python
"""Sprint 8B T8B-b — KubernetesPodSandboxBackend admission integration.

Pins that backend.create() invokes admit_policy with the right kwargs
BEFORE any pod creation. Mirrors Sprint 8A's
tests/unit/sandbox/test_admission_pipeline.py mock pattern.

The K8s backend MUST reuse the existing 9-step Stage-2 admission
pipeline at src/cognic_agentos/sandbox/admission.py:177 — backend-
agnostic. A refactor that bypasses admit_policy on the K8s path would
allow untrusted images / forbidden risk tiers / cap-exceeding policies
to reach pod creation. These regressions are the load-bearing pins.
"""

from __future__ import annotations

import pytest

pytest.importorskip("kubernetes_asyncio")

from unittest.mock import AsyncMock, MagicMock

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox import (
    PackAdmissionContext,
    SandboxLifecycleRefused,
    SandboxPolicy,
)
from cognic_agentos.sandbox.backends.kubernetes_pod import (
    KubernetesPodSandboxBackend,
)


# ... fixtures + the regression bodies ...

class TestKubernetesPodBackendInvokesAdmitPolicy:
    @pytest.mark.asyncio
    async def test_create_calls_admit_policy_before_pod_creation(
        self, monkeypatch
    ) -> None:
        """The backend's create() MUST call admit_policy before
        invoking the K8s API. Pin via mock.spy + assertion order."""
        # ... orchestration ...
```

(Implementor writes the full body — 8-12 admission-integration regressions following the test_docker_sibling_admission_integration.py shape if it exists, or test_admission_pipeline.py shape if not.)

- [ ] **Step 8: Implement `KubernetesPodSandboxBackend.create / destroy / health`**

The backend class lands in `src/cognic_agentos/sandbox/backends/kubernetes_pod.py` AFTER the pure helpers from step 5. Skeleton:

```python
class KubernetesPodSandboxBackend:
    """SandboxBackend implementation for Kubernetes/OpenShift.

    Per ADR-004 amendment: Wave-1 backend for bank production.
    Conforms to the same SandboxBackend Protocol as
    DockerSiblingSandboxBackend. exec() body lands at T8B-c.
    """

    def __init__(
        self,
        *,
        kube_api_client: kubernetes_asyncio.client.ApiClient,
        namespace: str,
        image_catalog: "CatalogProtocol",
        credential_adapter: "CredentialAdapter",
        rego_engine: "OPAEngine",
        audit_store: "AuditStore",
        decision_history_store: "DecisionHistoryStore",
        settings: "Settings",
        warm_pool: "SandboxWarmPool | None" = None,
    ) -> None:
        self._kube = kube_api_client
        self._namespace = namespace
        self._catalog = image_catalog
        self._credential_adapter = credential_adapter
        self._rego = rego_engine
        self._audit = audit_store
        self._dh = decision_history_store
        self._settings = settings
        self._warm_pool = warm_pool

    async def create(
        self,
        policy: "SandboxPolicy",
        *,
        actor: "Actor",
        tenant_id: str,
        pack_context: "PackAdmissionContext",
        use_warm_pool: bool = True,
    ) -> "SandboxSession":
        # 1. Warm-pool checkout (mirrors DockerSibling pattern at
        #    docker_sibling.py:769-805)
        if use_warm_pool and self._warm_pool is not None:
            warm = await self._warm_pool.checkout(...)
            if warm is not None:
                # ... same emit-lifecycle-created envelope as Docker
                return warm

        # 2. Cold-create — admission FIRST per the 9-step pipeline at
        #    admission.py:240-369. Backend-agnostic.
        await admit_policy(
            policy,
            tenant_id=tenant_id,
            actor=actor,
            pack_context=pack_context,
            catalog=self._catalog,
            credential_adapter=self._credential_adapter,
            rego_engine=self._rego,
            settings=self._settings,
        )

        # 3. Mint session_id; build pod + NetworkPolicy specs via
        #    pure helpers from step 5.
        session_id = _uuid.uuid4().hex
        pod_spec = _build_pod_spec(
            policy=policy, session_id=session_id, tenant_id=tenant_id
        )
        netpol_spec = _build_network_policy_spec(
            session_id=session_id, tenant_id=tenant_id
        )

        # 4. Create NetworkPolicy FIRST (egress lockdown active
        #    BEFORE the Pod starts; defends against the brief window
        #    a Pod might start with default-namespace egress).
        try:
            await self._create_network_policy(netpol_spec)
            await self._create_pod(pod_spec)
            await self._wait_for_pod_ready(session_id)
        except Exception:
            # Rollback envelope — teardown anything we created
            await self._teardown_session_state(session_id=session_id)
            raise

        # 5. Emit lifecycle.created — mirrors Docker's
        #    _emit_lifecycle_created pattern
        await self._emit_lifecycle_created(
            session=session, actor=actor, warm_pool_hit=False
        )
        return session

    async def exec(
        self,
        session: "SandboxSession",
        command: list[str],
        *,
        timeout_s: float | None = None,
    ) -> "SandboxExecResult":
        # DEFERRED to T8B-c
        raise NotImplementedError(
            "KubernetesPodSandboxBackend.exec lands at T8B-c "
            "(Sprint 8B T8B-c — exec + cap enforcement)"
        )

    async def destroy(self, session: "SandboxSession") -> None:
        # ... teardown pod + NetworkPolicy + emit lifecycle.destroyed
        ...

    async def health(self) -> "SandboxBackendHealth":
        # ... K8s API readiness probe
        try:
            await self._kube.CoreV1Api(self._kube).list_namespaced_pod(
                namespace=self._namespace, limit=1
            )
        except Exception as e:
            return SandboxBackendHealth(
                status="unavailable",
                detail=f"k8s api unreachable: {e}",
            )
        return SandboxBackendHealth(status="ok")
```

- [ ] **Step 9: Run admission-integration tests — MUST PASS**

Run: `uv run pytest tests/unit/sandbox/backends/test_kubernetes_pod_admission_integration.py -v`
Expected: PASS.

- [ ] **Step 10: Write env-gated integration tests (TDD red against real K8s)**

Create `tests/unit/sandbox/backends/test_kubernetes_pod_lifecycle.py` (env-gated; mirrors test_docker_sibling_lifecycle.py pattern). Tests run only when `COGNIC_RUN_K8S_SANDBOX=1` + a real K8s cluster is configured via `KUBECONFIG`. SKIP with structured message naming the env-flag otherwise. NO `kind` integration — per the user-locked decision at preflight.

- [ ] **Step 11: Update `src/cognic_agentos/sandbox/__init__.py` for conditional re-export**

Mirror the `DockerSiblingSandboxBackend` re-export pattern. Wrap the K8s backend re-export in `try/except ImportError` so kernel installs without the `sandbox-k8s` extra do NOT crash on import; surface a structured `NotImplementedError` pointing at the extra when callers attempt to instantiate without it.

- [ ] **Step 12: Halt-before-commit gate ladder + commit**

Per cross-task invariant #2: ruff + format + mypy full-tree + narrow pytest on backends/ + git diff --check. End with halt summary + await commit token. Suggested message: `feat(sprint-8b): T8B-b — KubernetesPodSandboxBackend skeleton + lifecycle (CRITICAL CONTROLS)`.

---

## Task T8B-c — exec + cap enforcement + backend factory + cross-backend conformance wire-up (CC)

**Scope:** Land `KubernetesPodSandboxBackend.exec` (deferred from T8B-b); wire K8s-specific cap-violation classification (OOMKilled via `ContainerStatus.lastState.terminated.reason`; walltime; cpu-budget via metrics-server OR cgroup stats — choice locked at step 1); land `sandbox/backend_factory.py` + `core/config.py` Settings field for AgentOS-owned backend selection; wire both backends into the T8B-a conformance harness via parametrised fixtures.

**Files:**
- Modify: `src/cognic_agentos/sandbox/backends/kubernetes_pod.py` (add `exec` body + cap helpers + proxy log readback)
- Create: `src/cognic_agentos/sandbox/backend_factory.py`
- Modify: `src/cognic_agentos/core/config.py` (add `sandbox_backend` Setting field)
- Create: `tests/unit/sandbox/test_backend_factory.py`
- Create: `tests/unit/sandbox/backends/test_kubernetes_pod_exec_classification.py`
- Modify: `tests/conformance/sandbox/conftest.py` (parametrise existing `backend` fixture over both backends)
- Create: `tests/unit/sandbox/backends/test_kubernetes_pod_resource_caps.py`

- [ ] **Step 1 (LOCK GATE): Verify the actual K8s exec stream + metrics-server APIs**

Run:
```bash
python -c "
import kubernetes_asyncio
from kubernetes_asyncio import client
from kubernetes_asyncio.stream import WsApiClient
import inspect

# pods/exec subresource — confirm the actual method name + sig
api = client.CoreV1Api
print('connect_get_namespaced_pod_exec signature:',
      inspect.signature(api.connect_get_namespaced_pod_exec))

# Metrics-server (optional dep — confirms cluster availability)
try:
    from kubernetes_asyncio.client.api.custom_objects_api import CustomObjectsApi
    print('CustomObjectsApi available — metrics-server queryable')
except Exception as e:
    print('metrics-server access: degraded - {}'.format(e))
"
```

If the actual stream API differs from `connect_get_namespaced_pod_exec` (e.g., deprecated in favor of `ws_client.WsApiClient`), commit a plan-amendment per the cross-task invariant #6 BEFORE proceeding.

- [ ] **Step 2: Write the failing exec-classification tests**

Create `tests/unit/sandbox/backends/test_kubernetes_pod_exec_classification.py` mirroring `test_docker_sibling_exec_classification.py`. Pins:
- Walltime exceeded → `walltime_cap_exceeded` (AgentOS-side timer; same precedence as Docker)
- OOMKilled detection — read `ContainerStatus.state.terminated.reason == "OOMKilled"` from the pod's status; exit_code 137 alone is NOT sufficient (matches Docker's `State.OOMKilled` authority pattern)
- cpu-budget exceeded → `cpu_time_budget_exceeded` (background asyncio task polls cgroup cpuacct.usage_us OR metrics-server depending on step-1 verification)

- [ ] **Step 3: Implement `exec()` + cap helpers**

(Pure code — no source code shown here to keep the plan tight. Follow `docker_sibling.py` patterns 935-1175 line-by-line, substituting K8s API calls.)

- [ ] **Step 4: Land `core/config.py` Settings field**

Add to `core/config.py`:

```python
class Settings(BaseSettings):
    # ... existing fields ...
    sandbox_backend: Literal["docker_sibling", "kubernetes_pod"] = Field(
        default="docker_sibling",
        description=(
            "Sprint 8B — selects the SandboxBackend implementation. "
            "AgentOS owns the default selection seam per the 2026-05-17 "
            "preflight decision. Bank overlays MAY override via the "
            "COGNIC_SANDBOX_BACKEND env var per ADR-004 amendment §32. "
            "Default preserves Sprint 8A behavior on existing deployments."
        ),
    )
```

- [ ] **Step 5: Land `sandbox/backend_factory.py`**

```python
"""Sprint 8B T8B-c — SandboxBackend factory.

AgentOS-owned default backend selection seam per the 2026-05-17
preflight decision. Per ADR-004 amendment §32: backend swappable via
COGNIC_SANDBOX_BACKEND env var (consumed by Settings); per-tenant
routing deferred to Sprint 14 deployment kit.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cognic_agentos.core.config import Settings
    from cognic_agentos.sandbox.protocol import SandboxBackend


def get_backend(settings: "Settings", *, **kwargs) -> "SandboxBackend":
    """Construct the SandboxBackend selected by settings.sandbox_backend.

    Raises NotImplementedError with a structured message pointing at
    the missing extra when the selected backend's optional dep is not
    installed (mirrors the sandbox/__init__.py re-export pattern).
    """
    if settings.sandbox_backend == "docker_sibling":
        try:
            from cognic_agentos.sandbox.backends.docker_sibling import (
                DockerSiblingSandboxBackend,
            )
        except ImportError as e:
            raise NotImplementedError(
                "sandbox_backend='docker_sibling' requires the "
                "'sandbox-docker' extra; install via "
                "`uv sync --extra sandbox-docker`"
            ) from e
        return DockerSiblingSandboxBackend(**kwargs)
    elif settings.sandbox_backend == "kubernetes_pod":
        try:
            from cognic_agentos.sandbox.backends.kubernetes_pod import (
                KubernetesPodSandboxBackend,
            )
        except ImportError as e:
            raise NotImplementedError(
                "sandbox_backend='kubernetes_pod' requires the "
                "'sandbox-k8s' extra; install via "
                "`uv sync --extra sandbox-k8s`"
            ) from e
        return KubernetesPodSandboxBackend(**kwargs)
    else:
        # mypy + Literal narrows this branch out; runtime guard for
        # defence-in-depth against future Literal extensions.
        raise ValueError(
            f"unknown sandbox_backend={settings.sandbox_backend!r}; "
            f"expected 'docker_sibling' | 'kubernetes_pod'"
        )
```

- [ ] **Step 6: Wire conformance harness to parametrise both backends**

Modify `tests/conformance/sandbox/conftest.py` `backend` fixture to be parametrised over both implementations:

```python
@pytest.fixture(params=["docker_sibling", "kubernetes_pod"])
async def backend(request, docker_client, kube_client, catalog):
    if request.param == "docker_sibling":
        # ... existing Docker fixture body ...
    else:
        # ... K8s fixture body using mocked kubernetes_asyncio client ...
```

- [ ] **Step 7: Halt + commit per cross-task invariant #2**

---

## Task T8B-d — AGENTS.md doctrine + critical-controls gate promotion (CC, doctrine + gate)

**Scope:** Promote `sandbox/backends/kubernetes_pod.py` to the durable critical-controls coverage gate at 95%/90%. Extend AGENTS.md "Critical-controls rule" subsection. Update `tools/check_critical_coverage.py` `_CRITICAL_FILES` + the count-guard test.

**Critical: tightening edit B — run actual coverage gate against fresh `coverage.json` BEFORE commit; NOT just count-guard.**

**Files:**
- Modify: `tools/check_critical_coverage.py`
- Modify: `tests/unit/tools/test_check_critical_coverage.py`
- Modify: `AGENTS.md`
- (POSSIBLY create) `tests/unit/sandbox/backends/test_kubernetes_pod_coverage_branches.py` — focused regressions for any missing-line/branch surface uncovered after T8B-b + T8B-c

- [ ] **Step 1: Add the K8s backend to `_CRITICAL_FILES`**

Modify `tools/check_critical_coverage.py` `_CRITICAL_FILES` tuple — append the new entry after the Sprint 8A section:

```python
    # Sprint 8B T8B-d — KubernetesPodSandboxBackend (CC; 8B's substantive
    # backend-specific enforcement surface; OpenShift restricted-SCC
    # SecurityContext + NetworkPolicy egress + per-session pod
    # teardown). Same 95%/90% floor as 8A backends; promotion is
    # source-verified by running this gate against fresh coverage in
    # the SAME commit per the user-locked tightening edit B (2026-05-17
    # preflight) + feedback_verify_promotion_meets_floor_at_promotion_time.
    ("src/cognic_agentos/sandbox/backends/kubernetes_pod.py", 0.95, 0.90),
```

- [ ] **Step 2: Bump the count guard in the self-test**

Modify `tests/unit/tools/test_check_critical_coverage.py`:

```python
_EXPECTED_ENTRY_COUNT = 71  # was 70; +1 for KubernetesPodSandboxBackend (Sprint 8B T8B-d)

_SPRINT_8B_GATE_MODULES = (
    "src/cognic_agentos/sandbox/backends/kubernetes_pod.py",
)

def test_sprint_8b_modules_present_with_standard_floors():
    # ... mirrors the 8A T12 count-guard test pattern ...
```

- [ ] **Step 3 (TIGHTENING EDIT B — REQUIRED): Run the ACTUAL coverage gate against fresh coverage**

Run in sequence — do NOT skip:
```bash
# Step 3a: regenerate fresh coverage.json against the full suite minus postgres/oracle
uv run pytest --cov=cognic_agentos --cov-branch --cov-report=json --cov-report=term \
  -m "not postgres and not oracle" -q

# Step 3b: run the actual gate against the fresh coverage.json
uv run python tools/check_critical_coverage.py
```

Expected:
- Step 3a: ~6500+ passed (depends on T8B-a + T8B-b + T8B-c test additions); coverage.json freshly regenerated
- Step 3b: **passed: 71/71 modules** — every CC module at or above 95/90, INCLUDING the new K8s backend

If `kubernetes_pod.py` is BELOW floor at step 3b:
- DO NOT lower the floor (per 8A doctrine on this exact incident)
- DO NOT demote the module from the gate
- DO add focused regressions to `tests/unit/sandbox/backends/test_kubernetes_pod_coverage_branches.py` mirroring the Sprint 8A T12-coverage-repair pattern (commit `be356f1`)
- Re-run 3a + 3b until the gate passes
- Per `feedback_strict_review_off_gate`: "coverage gap is test-suite incompleteness, NOT off-gate justification"

- [ ] **Step 4: Extend AGENTS.md**

Add `sandbox/backends/kubernetes_pod.py` entry to the `*Sandbox primitive (Sprint 8A):*` subsection of "Critical-controls rule" in `AGENTS.md`. Final structure: rename heading to `*Sandbox primitive (Sprints 8A + 8B):*` OR add companion `*Sandbox primitive (Sprint 8B):*` subsection — implementor decides based on whichever keeps the doctrine prose cleanest.

- [ ] **Step 5: Halt-before-commit gate ladder**

Per cross-task invariants #2 + #3. Halt summary MUST explicitly cite:
- `tools/check_critical_coverage.py` result (`passed: 71/71 modules`) with the actual coverage % for the new K8s backend module
- Count-guard test result (separate axis)
- Both gate axes verified — per tightening edit B

Suggested commit message: `chore(sprint-8b): T8B-d — AGENTS.md doctrine + critical-controls floor 70 → 71 (KubernetesPodSandboxBackend) (CRITICAL CONTROLS, doctrine + coverage gate)`

---

## Task T8B-e — Closeout + BUILD_PLAN flip (docs)

**Scope:** Sprint 8B closeout note + BUILD_PLAN §698 status flip + memory snapshot refresh.

**Files:**
- Create: `docs/closeouts/2026-05-??-sprint-8b-kubernetes-pod-backend.md`
- Modify: `docs/BUILD_PLAN.md` (§698 — flip Sprint 8B PLANNED → CLOSED with merge commit ref; §1142 schedule-risk row update if needed)
- Modify: `/Users/bmz/.claude/projects/-Users-bmz-development-cognic-agentos/memory/project_state_2026_05_??.md` (NEW snapshot)
- Modify: `/Users/bmz/.claude/projects/-Users-bmz-development-cognic-agentos/memory/MEMORY.md` (index entry)

- [ ] **Step 1: Read prior closeout for structure pattern**

Read `docs/closeouts/2026-05-17-sprint-8a-sandbox-primitive.md` — mirror its 13-section structure: scope, files, doctrine, threat model, coverage gate evolution, AGENTS.md additions, test+coverage state, ADR validation, reference table, Sprint 8C/8.5 hand-off, carryover, out-of-scope, next sprint.

- [ ] **Step 2: Write closeout per cross-task invariant #3**

Every claim in the closeout body that cites code MUST be verified at file:line in the same compose pass. Particularly:
- The exact `KubernetesPodSandboxBackend` line counts + method names
- The exact `_CRITICAL_FILES` count (71)
- The exact full coverage suite count from the T8B-d step 3a run
- The exact backend factory + Settings field names
- The exact AGENTS.md subsection structure

- [ ] **Step 3: Update BUILD_PLAN.md §698**

Replace the "8B (Wave-1 KubernetesPodSandboxBackend per `project_openshift_deployment_target` + ADR-004 amendment): **PLANNED**" block with a "**CLOSED**" status block matching the Sprint 8A flip pattern landed at PR #27.

- [ ] **Step 4: Refresh memory snapshot**

Create `project_state_2026_05_??.md` (date matches T8B-e commit day) per the cross-task invariant — read the canonical 2026-05-17 snapshot for the structure; mark it superseded for current-branch state. Update MEMORY.md index.

- [ ] **Step 5: Halt + commit**

Suggested: `docs(sprint-8b): T8B-e — Sprint 8B closeout + BUILD_PLAN §698 status flip (8B CLOSED)`

---

## Self-Review

After writing the complete plan, look at the spec (`docs/superpowers/specs/2026-05-16-sprint-8a-sandbox-primitive-design.md`) with fresh eyes + check the plan against it. Run inline; no subagent dispatch.

**Round 1 (this revision):** plan first cut. The structure mirrors Sprint 8A T2 plan-of-record patterns but is tighter (~1100 lines vs 8A's 4374) because 8B reuses 8A primitives wholesale. 5 tasks (T8B-a/b/c/d/e) vs 8A's 11+ — fewer because backend-agnostic primitives (admission, catalog, warm-pool, audit, proxy) are reused unchanged.

### 1. Spec coverage scan

Reading ADR-004 amendment §29-30 + §65 §sprint-8B section, every requirement maps to a T-task:
- "OpenShift-compatible pod SecurityContext (no `--privileged`; matches restricted-by-default SCC)" → T8B-b step 5 + tests at `TestBuildSecurityContext`
- "NetworkPolicy egress to proxy only" → T8B-b `_build_network_policy_spec` + tests at `TestBuildNetworkPolicySpec`
- "ServiceAccount + minimal RBAC" → covered in T8B-b pod spec (defaults to namespace-scoped SA per OpenShift restricted SCC); explicit minimal-RBAC bind deferred to Sprint 14 deployment kit per the cross-cutting concern split documented at the closeout
- "namespace/tenant routing config" → T8B-b __init__ takes `namespace: str`; tenant routing via labels (`cognic.agentos.sandbox.tenant_id`); full per-tenant namespace routing deferred to Sprint 14 deployment kit per ADR-004 §32
- "live-cluster conformance tests env-gated" → T8B-b step 10 (`COGNIC_RUN_K8S_SANDBOX=1`)
- "Same conformance suite as 8A; both backends conform to the same `SandboxBackend` Protocol" → T8B-c step 6 wires both backends through the T8B-a parametrised fixture

### 2. Placeholder scan

The plan has TWO intentional placeholders gated by step-1 verification work:
- `kubernetes-asyncio>=<LOCKED-AT-STEP-1>` in T8B-b step 2 — version locked AFTER step 1 dep verification per the user-locked decision
- `_NON_ROOT_USER_RANGE_PLACEHOLDER` — documents the OpenShift namespace-allocated UID range pattern; NOT a placeholder for missing code

These are NOT plan failures — they are explicit "verify before coding" gates. Other than these, no "TBD" / vague-requirement / "implement later" patterns.

### 3. Type consistency

`SandboxBackend` Protocol surface (4 methods: create / exec / destroy / health) cited from `protocol.py:254` is used identically across T8B-b + T8B-c. `SandboxRefusalReason` 15-value Literal cited from `protocol.py:34-50` is referenced in T8B-a (registration coverage) + closeout. Field names (`pack_context`, `pack_artifact_digest`, `runtime_image`, `vault_path`) match `policy.py` verbatim. Closed-enum names (`SandboxRefusalReason`, `SandboxPolicyViolationReason`, `SandboxLifecycleEvent`) match `protocol.py` verbatim.

### 4. Tightening edit drift check

Both user-locked tightening edits A + B are baked in:
- T8B-a header explicitly says "REGISTRATION coverage, NOT BEHAVIORAL coverage"; the test naming + commit message template both reinforce
- T8B-d step 3 is BLOCK-LABELLED "TIGHTENING EDIT B — REQUIRED" with the explicit pytest+gate sequence; halt summary requirement names the gate output explicitly

### 5. Decision-lock drift check

OPA-on-CI is documented as ALREADY DONE (commit `4aa6c7b` on main); no 8B task re-does it. K8s client = kubernetes-asyncio with mandatory dep+API verification at T8B-b step 1. Live cluster = mocked unit + env-gated live tests; no kind in CI. Backend selection = Settings field + factory in 8B. CI surface = inline env-gated; no separate K8s job. All 5 preflight decisions reflected.

### 6. Cross-task invariant coverage

Every T-task references the relevant cross-task invariants by number rather than restating them — keeps the plan focused, prevents drift. Invariants #1-9 cover halt-discipline, gate ladder, cite-from-source, drift detectors, evidence-boundary, plan-amendment, branch hygiene, canonical-artifact, immutable-runtime — all the doctrines that surfaced 12+ reviewer findings across Sprint 8A.

**No corrective revisions identified at Round 1.** Plan committed for user review before T8B-a execution.

---

## Execution Handoff

**Plan committed.** Two execution options per `superpowers:writing-plans` skill:

1. **Subagent-Driven (recommended)** — dispatch a fresh subagent per T-task; review between tasks; fast iteration. Each T's halt-before-commit summary returns to the orchestrator (this session) for user-token-gated commits. Same precedent as Sprint 8A which used subagent-per-T for T3 → T12.

2. **Inline Execution** — execute T-tasks in this session using `superpowers:executing-plans`; batch execution with checkpoints at each halt-before-commit.

**Recommend Subagent-Driven** — Sprint 8B has 5 implementation T-tasks; subagent-per-T keeps each task's context focused + lets reviewer rounds compose cleanly. T8B-b is the largest single task (~0.7 wu; pod spec + lifecycle + admission integration + helpers + tests) and is the strongest candidate for its own dispatched subagent.

**After this plan commits to the sprint branch as T8B-a's predecessor:** T8B-a starts. T8B-a is CC-ADJ — halt-before-commit applies per cross-task invariant #1. Author should re-read this plan + verify every cited file:line at the start of T8B-a execution (per cross-task invariant #3) BEFORE writing the test bodies.

**Branch:** `feat/sprint-8b-kubernetes-pod-backend` from `main` (`4aa6c7b`). Create at the start of T8B-a, NOT during plan-of-record commit (plan-of-record can land on main as a docs commit per the prior 8A T2 pattern — OR on the sprint branch as the first commit; user picks at plan-of-record commit token).
