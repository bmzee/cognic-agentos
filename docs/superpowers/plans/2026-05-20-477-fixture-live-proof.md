# #477 — Sandbox Fixture-Image Live-Proof Path — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the test-only fixture-image path + one narrow production seam that lets the env-gated cross-backend conformance suite prove `checkpoint`/`suspend`/`wake` against a live Docker daemon and a live OpenShift/CRC cluster.

**Architecture:** One narrowly-scoped production-code seam — an optional `egress_proxy_image` constructor kwarg on both Wave-1 backends, production default unchanged. Everything else is test-only: 2 fixture Dockerfiles, a `_FixtureOnlySandboxCatalog` test double, conftest wiring driven by 3 test-only env vars, a CRC runbook, and an evidence-results template. The live proof itself is the operator-run runbook; #477 stays open until its results are recorded.

**Tech Stack:** Python 3.12, `uv`, `pytest`, `aiodocker`, `kubernetes-asyncio`, Docker, OpenShift Local (CRC).

**Source spec:** `docs/superpowers/specs/2026-05-20-477-fixture-live-proof-design.md` (APPROVED, committed `d97b1f5`).

**Branch:** `feat/sprint-8.5-477-fixture-live-proof` (already created off the PR #30 tip `2f0a074`; the spec is committed at `d97b1f5`). All tasks land on this branch; no push/PR/merge without explicit user authorization.

---

## File Structure

**Production code (the one seam — CRITICAL CONTROLS):**
- `src/cognic_agentos/sandbox/backends/docker_sibling.py` — Modify: add `egress_proxy_image` kwarg + `_egress_proxy_image` attr; `_start_proxy_sidecar` reads it.
- `src/cognic_agentos/sandbox/backends/kubernetes_pod.py` — Modify: add `egress_proxy_image` kwarg + `_egress_proxy_image` attr; `_build_pod_spec` gets an `egress_proxy_image` parameter; call sites + the proxy catalog-gate digest extraction read the attr.

**Test-only code:**
- `tests/conformance/sandbox/fixture_catalog.py` — Create: `_FixtureOnlySandboxCatalog` test double.
- `tests/fixtures/sandbox/runtime-fixture.Dockerfile` — Create: minimal runtime fixture image.
- `tests/fixtures/sandbox/egress-proxy-fixture.Dockerfile` — Create: minimal egress-proxy fixture image.
- `tests/conformance/sandbox/conftest.py` — Modify: fixture-mode wiring (3 env vars, `_FixtureOnlySandboxCatalog`, `egress_proxy_image` kwarg, `runtime_image` fixture).
- (`tests/unit/sandbox/backends/conftest.py` is NOT touched — it serves the env-gated *unit* backend tests, not the conformance suite that is #477's live proof. See the T5 scope note.)
- `tests/conformance/sandbox/test_checkpoint_round_trip.py` — Modify: `_POLICY`'s `runtime_image` parameterized from the conftest fixture.
- `tests/conformance/sandbox/test_wake_session_tombstoned_conformance.py` — Modify: same.
- `tests/unit/sandbox/backends/test_docker_sibling_egress_proxy_seam.py` — Create: T1 seam tests.
- `tests/unit/sandbox/backends/test_kubernetes_pod_egress_proxy_seam.py` — Create: T2 seam tests.
- `tests/unit/sandbox/backends/test_kubernetes_pod_pure_helpers.py` — Modify: `_build_pod_spec` default/injected `egress_proxy_image` coverage.
- `tests/conformance/sandbox/test_fixture_catalog.py` — Create: `_FixtureOnlySandboxCatalog` behaviour tests.
- `tests/unit/architecture/test_fixture_path_not_in_src.py` — Create: import-regression guard (AC6/AC11).
- `tests/unit/sandbox/test_fixture_conftest_env.py` — Create: fixture-mode env-var validation tests (T5).

**Docs:**
- `docs/runbooks/477-live-sandbox-proof.md` — Create: the CRC live-proof runbook.
- `docs/evidence/477-live-proof-results.md` — Create: the evidence-results template.

---

## Task T0: Commit the spec §8 correction + the plan-of-record

**Files:**
- Modify: `docs/superpowers/specs/2026-05-20-477-fixture-live-proof-design.md` (the §8 scope correction — already present, uncommitted, in the working tree).
- Create: `docs/superpowers/plans/2026-05-20-477-fixture-live-proof.md` (this file).

- [ ] **Step 1: Commit the spec §8 scope correction**

The spec was committed at `d97b1f5`; §8 was later found to over-scope to "four test files / both conftests" when only three are needed (1 conformance conftest + 2 conformance test files — see the T5 scope note). The correction is already in the working tree; commit it FIRST so the spec stays the accurate source-of-truth doc:

```bash
git add docs/superpowers/specs/2026-05-20-477-fixture-live-proof-design.md
git diff --cached --check
git commit -m "docs(477): correct spec §8 — unit-backend conftest out of scope"
```

- [ ] **Step 2: Commit the plan-of-record**

```bash
git add docs/superpowers/plans/2026-05-20-477-fixture-live-proof.md
git diff --cached --check
git commit -m "docs(477): T0 — implementation plan-of-record"
```

---

## Task T1: Docker egress-proxy seam (CRITICAL CONTROLS — `docker_sibling.py`)

**Files:**
- Modify: `src/cognic_agentos/sandbox/backends/docker_sibling.py` (`__init__` at `:779`; `_start_proxy_sidecar` at `:1731`, proxy-image local at `:1767`).
- Test: `tests/unit/sandbox/backends/test_docker_sibling_egress_proxy_seam.py` (new).

`docker_sibling.py` is on the durable critical-controls coverage gate — this task is CC: halt-before-commit, the production default path must stay byte-identical, the new lines must keep the module ≥95% line / ≥90% branch.

- [ ] **Step 1: Write the failing seam tests**

Create `tests/unit/sandbox/backends/test_docker_sibling_egress_proxy_seam.py` with the concrete `make_docker_backend` fixture + 4 constructor tests. The `DockerSiblingSandboxBackend.__init__` (`:779`) is keyword-only and only *stores* its kwargs — no dep is exercised at construction — so MagicMock/AsyncMock deps are sufficient:

```python
"""T1 — DockerSibling egress-proxy image seam tests (#477 §5)."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.sandbox import SandboxPolicy
from cognic_agentos.sandbox.backends.docker_sibling import (
    DockerSiblingSandboxBackend,
    _CANONICAL_EGRESS_PROXY_IMAGE,
)

#: Minimal valid SandboxPolicy for the Step-5 AC10 test — the 7
#: required SandboxPolicy fields (policy.py:162-168; read_only_root +
#: any later fields carry defaults). Defined ONCE here so Step 5
#: reuses it; Step 5 adds no new imports.
_SEAM_POLICY = SandboxPolicy(
    cpu_cores=1.0,
    cpu_time_budget_s=None,
    memory_mb=256,
    walltime_s=60.0,
    runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
    egress_allow_list=(),
    vault_path=None,
)


def _default_catalog() -> MagicMock:
    cat = MagicMock()
    cat.is_canonical.return_value = True
    cat.is_tenant_allow_listed.return_value = False
    cat.verify_cosign_or_refuse = AsyncMock(return_value=None)
    cat.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
    return cat


@pytest.fixture
def make_docker_backend():
    """Build a DockerSiblingSandboxBackend with mocked deps; any
    constructor kwarg is overridable via **overrides (e.g.
    egress_proxy_image=..., image_catalog=...)."""

    def _make(**overrides):
        kwargs = dict(
            docker_client=MagicMock(),
            image_catalog=_default_catalog(),
            credential_adapter=MagicMock(),
            rego_engine=MagicMock(),
            audit_store=MagicMock(),
            decision_history_store=MagicMock(),
            settings=MagicMock(),
        )
        kwargs.update(overrides)
        # type: ignore[arg-type] mirrors test_docker_sibling_checkpoint.py:145
        # — mock deps stand in for the typed constructor params.
        return DockerSiblingSandboxBackend(**kwargs)  # type: ignore[arg-type]

    return _make


def test_default_constructor_uses_canonical_proxy_image(make_docker_backend):
    backend = make_docker_backend()  # no egress_proxy_image kwarg
    assert backend._egress_proxy_image == _CANONICAL_EGRESS_PROXY_IMAGE


def test_injected_proxy_image_is_stored(make_docker_backend):
    ref = "registry.example/cognic-sandbox-egress-proxy-fixture@sha256:" + "e" * 64
    backend = make_docker_backend(egress_proxy_image=ref)
    assert backend._egress_proxy_image == ref


def test_empty_proxy_image_raises_at_construction(make_docker_backend):
    with pytest.raises(ValueError, match="egress_proxy_image"):
        make_docker_backend(egress_proxy_image="")
    with pytest.raises(ValueError, match="egress_proxy_image"):
        make_docker_backend(egress_proxy_image="   ")


def test_none_is_not_treated_as_empty(make_docker_backend):
    # Explicit None-check semantics: None -> canonical default, not a raise.
    backend = make_docker_backend(egress_proxy_image=None)
    assert backend._egress_proxy_image == _CANONICAL_EGRESS_PROXY_IMAGE
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/unit/sandbox/backends/test_docker_sibling_egress_proxy_seam.py -v`
Expected: FAIL — `_CANONICAL_EGRESS_PROXY_IMAGE` is not importable and `egress_proxy_image` is not a constructor kwarg.

- [ ] **Step 3: Lift the proxy-image constant + add the seam**

In `docker_sibling.py`, near the other module constants (alongside `_PROXY_LOG_PATH` etc.), add a named constant — the value is exactly today's function-local string at `:1767`:

```python
#: Canonical egress-proxy image — Sprint 8A T6 catalog gate publishes
#: the cosign-signed digest. The default for the egress-proxy seam;
#: production callers get this byte-identical value (#477 §5).
_CANONICAL_EGRESS_PROXY_IMAGE: str = "cognic/sandbox-egress-proxy:v1@sha256:" + "d" * 64
```

In `__init__` (`:779`), add a trailing keyword-only param after `checkpoint_store`:

```python
        checkpoint_store: CheckpointStore | None = None,
        egress_proxy_image: str | None = None,
    ) -> None:
```

In the `__init__` body, after `self._checkpoint_store = checkpoint_store`, add:

```python
        # #477 §5 — narrow egress-proxy image seam. Explicit None-check
        # (NOT `or`): an empty string must fail fast, never silently
        # fall back to the placeholder canonical proxy.
        if egress_proxy_image is not None and not egress_proxy_image.strip():
            raise ValueError(
                "egress_proxy_image, when provided, must be a non-empty "
                "OCI ref; got an empty/blank string"
            )
        self._egress_proxy_image: str = (
            _CANONICAL_EGRESS_PROXY_IMAGE
            if egress_proxy_image is None
            else egress_proxy_image
        )
```

In `_start_proxy_sidecar` (`:1731`), replace the function-local at `:1767`:

```python
        proxy_image = self._egress_proxy_image
```

(Delete the old `proxy_image = "cognic/sandbox-egress-proxy:v1@sha256:" + "d" * 64` line and its preceding comment block; the constant + the §5 docstring carry the rationale.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/unit/sandbox/backends/test_docker_sibling_egress_proxy_seam.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Write the AC10 test — the injected image's digest flows through the proxy catalog gate**

`_start_proxy_sidecar` (`docker_sibling.py:1783-1795`) does `_, proxy_image_digest = proxy_image.rsplit("@", 1)` then `is_canonical` + `verify_cosign_or_refuse` + `verify_sbom_policy_or_refuse` on that digest. After Step 3 `proxy_image = self._egress_proxy_image`, so the injected ref's digest is what the gate sees. **Append** this to `test_docker_sibling_egress_proxy_seam.py` — it reuses the `make_docker_backend` fixture + `_SEAM_POLICY` + the `AsyncMock`/`MagicMock`/`pytest` imports already declared in Step 1, so **add no new import lines**:

```python
class _CatalogSpy:
    """Records every digest the proxy gate asks about; allows all."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, str]] = []

    def is_canonical(self, image_digest: str) -> bool:
        self.seen.append(("is_canonical", image_digest))
        return True

    def is_tenant_allow_listed(self, image_digest: str, tenant_id: str) -> bool:
        return False

    async def verify_cosign_or_refuse(self, image_digest: str, *, tenant_id: str) -> None:
        self.seen.append(("cosign", image_digest))

    async def verify_sbom_policy_or_refuse(self, image_digest: str, *, tenant_id: str) -> None:
        self.seen.append(("sbom", image_digest))


@pytest.mark.asyncio
async def test_injected_proxy_image_digest_goes_through_catalog_gate(make_docker_backend):
    injected_ref = (
        "registry.example/cognic-sandbox-egress-proxy-fixture@sha256:" + "e" * 64
    )
    injected_digest = "sha256:" + "e" * 64
    canonical_digest = "sha256:" + "d" * 64  # the placeholder default

    spy = _CatalogSpy()
    backend = make_docker_backend(egress_proxy_image=injected_ref, image_catalog=spy)

    # Mock only the Docker surface _start_proxy_sidecar touches.
    container = MagicMock()
    container.start = AsyncMock()
    backend._docker.containers.create_or_replace = AsyncMock(return_value=container)
    egress_net = MagicMock()
    egress_net.connect = AsyncMock()
    backend._docker.networks.get = AsyncMock(return_value=egress_net)

    await backend._start_proxy_sidecar(
        policy=_SEAM_POLICY,
        session_id="s-1",
        container_name="proxy-s-1",
        internal_net_name="internal-s-1",
        egress_net_name="egress-s-1",
        tenant_id="t-1",
    )

    assert ("is_canonical", injected_digest) in spy.seen
    assert ("cosign", injected_digest) in spy.seen
    assert ("sbom", injected_digest) in spy.seen
    # The canonical placeholder digest must NEVER reach the gate.
    assert all(digest != canonical_digest for _, digest in spy.seen)
```

Run: `uv run pytest tests/unit/sandbox/backends/test_docker_sibling_egress_proxy_seam.py -v`
Expected: PASS (5 tests — the 4 from Step 1 + this AC10 test).

- [ ] **Step 6: Full local gate for the touched scope + halt-before-commit**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy src tests`
Run: `uv run pytest tests/unit/sandbox/backends/test_docker_sibling_egress_proxy_seam.py tests/unit/sandbox/backends/test_docker_sibling_checkpoint.py -q`
Expected: all clean / pass. Then HALT — present a halt-before-commit summary (CC module). Do not commit until the human authorises.

- [ ] **Step 7: Commit**

```bash
git add src/cognic_agentos/sandbox/backends/docker_sibling.py tests/unit/sandbox/backends/test_docker_sibling_egress_proxy_seam.py
git commit -m "feat(477): T1 — DockerSibling egress-proxy image seam (CRITICAL CONTROLS)"
```

---

## Task T2: K8s egress-proxy seam (CRITICAL CONTROLS — `kubernetes_pod.py`)

**Files:**
- Modify: `src/cognic_agentos/sandbox/backends/kubernetes_pod.py` (`__init__` at `:708`; `_build_pod_spec` at `:384`; sidecar `"image"` field at `:528`; proxy catalog-gate digest extraction at `:831`; `_build_pod_spec` call sites at `:847` + `:1499`).
- Test: `tests/unit/sandbox/backends/test_kubernetes_pod_egress_proxy_seam.py` (new); `tests/unit/sandbox/backends/test_kubernetes_pod_pure_helpers.py` (modify).

`kubernetes_pod.py` is on the durable critical-controls coverage gate — CC task: halt-before-commit, byte-identical production default, ≥95/≥90 maintained. `_build_pod_spec` is a standalone module-level function (in `__all__`) — the seam threads a *parameter*, it cannot read `self.`.

- [ ] **Step 1: Write the failing pure-helper tests for `_build_pod_spec`**

In `tests/unit/sandbox/backends/test_kubernetes_pod_pure_helpers.py`, add:

```python
from cognic_agentos.sandbox.backends.kubernetes_pod import (
    _build_pod_spec,
    _CANONICAL_EGRESS_PROXY_IMAGE,
)


def _proxy_container(pod_spec):
    """Return the egress-proxy sidecar container dict from a pod spec."""
    containers = pod_spec["spec"]["containers"]
    return next(c for c in containers if c["name"] == "egress-proxy")


def _build_default_pod_spec(**kwargs):
    """Call _build_pod_spec with the canonical proxy image as default.

    Step 4 makes `egress_proxy_image` a REQUIRED keyword on
    `_build_pod_spec` (no silent canonical fallback in production —
    every src call site passes it explicitly). Every PRE-EXISTING
    `_build_pod_spec(...)` call in this test module must be rerouted
    through this wrapper so it keeps compiling — see the Step-1 tail
    instruction below.
    """
    kwargs.setdefault("egress_proxy_image", _CANONICAL_EGRESS_PROXY_IMAGE)
    return _build_pod_spec(**kwargs)


def test_build_pod_spec_default_proxy_image(valid_policy):
    spec = _build_pod_spec(
        policy=valid_policy,
        session_id="s-1",
        tenant_id="t-1",
        egress_proxy_image=_CANONICAL_EGRESS_PROXY_IMAGE,
    )
    assert _proxy_container(spec)["image"] == _CANONICAL_EGRESS_PROXY_IMAGE


def test_build_pod_spec_injected_proxy_image(valid_policy):
    ref = "registry.example/cognic-sandbox-egress-proxy-fixture@sha256:" + "e" * 64
    spec = _build_pod_spec(
        policy=valid_policy,
        session_id="s-1",
        tenant_id="t-1",
        egress_proxy_image=ref,
    )
    assert _proxy_container(spec)["image"] == ref
```

Reuse the existing `valid_policy` fixture / `_VALID_IMAGE_REF` constant already in the pure-helpers test module.

**Reroute every pre-existing call site.** `egress_proxy_image` becomes a REQUIRED keyword on `_build_pod_spec` (Step 4), so every PRE-EXISTING `_build_pod_spec(...)` call in `test_kubernetes_pod_pure_helpers.py` would otherwise stop compiling. As part of this step: `grep -n "_build_pod_spec(" tests/unit/sandbox/backends/test_kubernetes_pod_pure_helpers.py`, and rewrite each pre-existing call to `_build_default_pod_spec(...)` (the wrapper above — it injects the canonical proxy image). The TWO new tests above keep calling `_build_pod_spec` directly with an explicit `egress_proxy_image=`. Run `uv run pytest tests/unit/sandbox/backends/test_kubernetes_pod_pure_helpers.py -q` after Step 4 lands to confirm no pre-existing test broke.

- [ ] **Step 2: Write the failing seam tests (4 constructor tests + the K8s AC10 catalog-gate test)**

Create `tests/unit/sandbox/backends/test_kubernetes_pod_egress_proxy_seam.py` with the `make_k8s_backend` fixture, the 4 constructor tests, and the K8s AC10 test that pins the `create()`-step-4 proxy catalog gate (`kubernetes_pod.py:831-844`). `KubernetesPodSandboxBackend.__init__` (`:708`) is keyword-only and only stores its kwargs — mocked deps suffice:

```python
"""T2 — KubernetesPod egress-proxy image seam tests (#477 §5)."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.sandbox import PackAdmissionContext, SandboxPolicy
from cognic_agentos.sandbox.backends.kubernetes_pod import (
    KubernetesPodSandboxBackend,
    _CANONICAL_EGRESS_PROXY_IMAGE,
)

#: Minimal valid SandboxPolicy + PackAdmissionContext for the AC10
#: create()-path test (the required-field sets — policy.py:162-168
#: for SandboxPolicy, :116-121 for PackAdmissionContext).
_SEAM_POLICY = SandboxPolicy(
    cpu_cores=1.0,
    cpu_time_budget_s=None,
    memory_mb=256,
    walltime_s=60.0,
    runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
    egress_allow_list=(),
    vault_path=None,
)
_PACK_CONTEXT = PackAdmissionContext(
    pack_id="p-fixture",
    pack_version="1.0.0",
    pack_artifact_digest="sha256:" + "1" * 64,
    risk_tier="read_only",
    declares_dynamic_install=False,
    profile="development",
)


def _default_catalog() -> MagicMock:
    cat = MagicMock()
    cat.is_canonical.return_value = True
    cat.is_tenant_allow_listed.return_value = False
    cat.verify_cosign_or_refuse = AsyncMock(return_value=None)
    cat.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
    return cat


class _CatalogSpy:
    """Records every digest the proxy gate asks about; allows all."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, str]] = []

    def is_canonical(self, image_digest: str) -> bool:
        self.seen.append(("is_canonical", image_digest))
        return True

    def is_tenant_allow_listed(self, image_digest: str, tenant_id: str) -> bool:
        return False

    async def verify_cosign_or_refuse(self, image_digest: str, *, tenant_id: str) -> None:
        self.seen.append(("cosign", image_digest))

    async def verify_sbom_policy_or_refuse(self, image_digest: str, *, tenant_id: str) -> None:
        self.seen.append(("sbom", image_digest))


@pytest.fixture
def make_k8s_backend():
    """Build a KubernetesPodSandboxBackend with mocked deps; any
    constructor kwarg is overridable via **overrides."""

    def _make(**overrides):
        kwargs = dict(
            kube_api_client=MagicMock(),
            namespace="cognic-sandbox-test",
            image_catalog=_default_catalog(),
            credential_adapter=MagicMock(),
            rego_engine=MagicMock(),
            audit_store=MagicMock(),
            decision_history_store=MagicMock(),
            settings=MagicMock(),
        )
        kwargs.update(overrides)
        # type: ignore[arg-type] — mock deps stand in for typed params.
        return KubernetesPodSandboxBackend(**kwargs)  # type: ignore[arg-type]

    return _make


def test_default_constructor_uses_canonical_proxy_image(make_k8s_backend):
    backend = make_k8s_backend()  # no egress_proxy_image kwarg
    assert backend._egress_proxy_image == _CANONICAL_EGRESS_PROXY_IMAGE


def test_injected_proxy_image_is_stored(make_k8s_backend):
    ref = "registry.example/cognic-sandbox-egress-proxy-fixture@sha256:" + "e" * 64
    backend = make_k8s_backend(egress_proxy_image=ref)
    assert backend._egress_proxy_image == ref


def test_empty_proxy_image_raises_at_construction(make_k8s_backend):
    with pytest.raises(ValueError, match="egress_proxy_image"):
        make_k8s_backend(egress_proxy_image="")
    with pytest.raises(ValueError, match="egress_proxy_image"):
        make_k8s_backend(egress_proxy_image="   ")


def test_none_is_not_treated_as_empty(make_k8s_backend):
    # Explicit None-check semantics: None -> canonical default, not a raise.
    backend = make_k8s_backend(egress_proxy_image=None)
    assert backend._egress_proxy_image == _CANONICAL_EGRESS_PROXY_IMAGE


@pytest.mark.asyncio
async def test_injected_proxy_image_digest_goes_through_k8s_catalog_gate(
    make_k8s_backend, monkeypatch
):
    """AC10 (K8s leg) — the injected proxy image's digest reaches the
    create()-step-4 catalog gate (kubernetes_pod.py:831-844), and the
    canonical placeholder digest never does. admit_policy (create()
    steps 2-3) is patched out — it has its own admission tests; this
    test pins ONLY the proxy gate. create()'s signature is
    create(policy, *, actor, tenant_id, pack_context, ...) and
    admit_policy is an async fire-or-raise function (returns None on
    pass, raises SandboxLifecycleRefused on refuse) — both verified
    against current source."""
    injected_ref = (
        "registry.example/cognic-sandbox-egress-proxy-fixture@sha256:" + "e" * 64
    )
    injected_digest = "sha256:" + "e" * 64
    canonical_digest = "sha256:" + "d" * 64

    spy = _CatalogSpy()
    backend = make_k8s_backend(egress_proxy_image=injected_ref, image_catalog=spy)

    # Patch admission (steps 2-3) + the post-gate K8s API calls (steps
    # 6-7) so create() runs exactly through the step-4 proxy gate.
    monkeypatch.setattr(
        "cognic_agentos.sandbox.backends.kubernetes_pod.admit_policy",
        AsyncMock(return_value=None),
    )
    monkeypatch.setattr(backend, "_create_network_policy", AsyncMock())
    monkeypatch.setattr(backend, "_create_pod", AsyncMock())
    monkeypatch.setattr(backend, "_emit_lifecycle_created", AsyncMock())

    actor = MagicMock(subject="op-1")
    await backend.create(
        policy=_SEAM_POLICY,
        actor=actor,
        tenant_id="t-1",
        pack_context=_PACK_CONTEXT,
    )

    assert ("is_canonical", injected_digest) in spy.seen
    assert ("cosign", injected_digest) in spy.seen
    assert ("sbom", injected_digest) in spy.seen
    # The canonical placeholder digest must NEVER reach the gate.
    assert all(digest != canonical_digest for _, digest in spy.seen)
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `uv run pytest tests/unit/sandbox/backends/test_kubernetes_pod_egress_proxy_seam.py tests/unit/sandbox/backends/test_kubernetes_pod_pure_helpers.py -v`
Expected: FAIL — `_build_pod_spec` has no `egress_proxy_image` parameter; `egress_proxy_image` is not a constructor kwarg.

- [ ] **Step 4: Add the `_build_pod_spec` parameter**

In `kubernetes_pod.py`, change `_build_pod_spec`'s signature (`:384`) to add a keyword-only `egress_proxy_image: str` parameter:

```python
def _build_pod_spec(
    *,
    policy: SandboxPolicy,
    session_id: str,
    tenant_id: str,
    egress_proxy_image: str,
) -> dict[str, Any]:
```

At the sidecar container `"image"` field (`:528`), replace `_CANONICAL_EGRESS_PROXY_IMAGE` with `egress_proxy_image`:

```python
                    "image": egress_proxy_image,
```

`egress_proxy_image` is **required** (no default) — every production call site passes it explicitly (Step 5), so no caller silently gets the canonical placeholder. This is why Step 1's tail reroutes the pre-existing `test_kubernetes_pod_pure_helpers.py` calls through `_build_default_pod_spec`: a required param breaks any call that omits it. After this step, run the pure-helper suite (`uv run pytest tests/unit/sandbox/backends/test_kubernetes_pod_pure_helpers.py -q`) — if any pre-existing test errors with a missing-argument `TypeError`, a call site was missed in Step 1.

- [ ] **Step 5: Add the backend seam + thread the parameter**

In `__init__` (`:708`), add the trailing keyword-only param after `checkpoint_store` and the same None-check + non-empty guard + attribute resolution as T1 Step 3 (identical code; the canonical default is the existing module constant `_CANONICAL_EGRESS_PROXY_IMAGE` at `:196`):

```python
        checkpoint_store: CheckpointStore | None = None,
        egress_proxy_image: str | None = None,
    ) -> None:
```

```python
        # #477 §5 — narrow egress-proxy image seam. Explicit None-check
        # (NOT `or`): an empty string must fail fast.
        if egress_proxy_image is not None and not egress_proxy_image.strip():
            raise ValueError(
                "egress_proxy_image, when provided, must be a non-empty "
                "OCI ref; got an empty/blank string"
            )
        self._egress_proxy_image: str = (
            _CANONICAL_EGRESS_PROXY_IMAGE
            if egress_proxy_image is None
            else egress_proxy_image
        )
```

At both `_build_pod_spec` call sites (`:847`, `:1499`), pass the attribute:

```python
        pod_spec = _build_pod_spec(
            policy=policy,
            session_id=session_id,
            tenant_id=tenant_id,
            egress_proxy_image=self._egress_proxy_image,
        )
```

At the proxy catalog-gate digest extraction (`:831` — currently `_, proxy_image_digest = _CANONICAL_EGRESS_PROXY_IMAGE.rsplit("@", 1)`), replace the constant with `self._egress_proxy_image` so the injected proxy image's digest is what goes through the gate. Update the adjacent message string referencing `_CANONICAL_EGRESS_PROXY_IMAGE` (`:836`) to use `self._egress_proxy_image` too.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `uv run pytest tests/unit/sandbox/backends/test_kubernetes_pod_egress_proxy_seam.py tests/unit/sandbox/backends/test_kubernetes_pod_pure_helpers.py -v`
Expected: PASS.

- [ ] **Step 7: Full local gate for the touched scope + halt-before-commit**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy src tests`
Run: `uv run pytest tests/unit/sandbox/backends/ -k "kubernetes_pod" -q`
Expected: clean / pass. Then HALT — halt-before-commit summary (CC module). Pay attention: every `_build_pod_spec` call site must be updated (grep `_build_pod_spec(` to confirm none was missed) — a missed site would not type-check (the new param is required).

- [ ] **Step 8: Commit**

```bash
git add src/cognic_agentos/sandbox/backends/kubernetes_pod.py tests/unit/sandbox/backends/test_kubernetes_pod_egress_proxy_seam.py tests/unit/sandbox/backends/test_kubernetes_pod_pure_helpers.py
git commit -m "feat(477): T2 — KubernetesPod egress-proxy image seam (CRITICAL CONTROLS)"
```

---

## Task T3: `_FixtureOnlySandboxCatalog` + architecture import-regression test

**Files:**
- Create: `tests/conformance/sandbox/fixture_catalog.py`.
- Create: `tests/conformance/sandbox/test_fixture_catalog.py`.
- Create: `tests/unit/architecture/test_fixture_path_not_in_src.py`.

Per spec §7: a `CatalogProtocol`-conformant test double allowlisting exactly the 2 fixture *digests* derived from the 2 fixture *refs*.

- [ ] **Step 1: Write the failing behaviour tests**

Create `tests/conformance/sandbox/test_fixture_catalog.py`:

```python
import pytest

from cognic_agentos.sandbox.admission import SandboxLifecycleRefused
from tests.conformance.sandbox.fixture_catalog import _FixtureOnlySandboxCatalog

_RUNTIME_REF = "reg.example/cognic-sandbox-runtime-fixture@sha256:" + "a" * 64
_PROXY_REF = "reg.example/cognic-sandbox-egress-proxy-fixture@sha256:" + "b" * 64
_RUNTIME_DIGEST = "sha256:" + "a" * 64
_PROXY_DIGEST = "sha256:" + "b" * 64
_OTHER_DIGEST = "sha256:" + "c" * 64

pytestmark = pytest.mark.asyncio


def _catalog():
    return _FixtureOnlySandboxCatalog(runtime_ref=_RUNTIME_REF, proxy_ref=_PROXY_REF)


def test_is_canonical_true_for_both_fixture_digests():
    cat = _catalog()
    assert cat.is_canonical(_RUNTIME_DIGEST) is True
    assert cat.is_canonical(_PROXY_DIGEST) is True


def test_is_canonical_false_for_any_other_digest():
    assert _catalog().is_canonical(_OTHER_DIGEST) is False


def test_is_tenant_allow_listed_always_false():
    assert _catalog().is_tenant_allow_listed(_RUNTIME_DIGEST, "t-1") is False


async def test_verify_cosign_passes_for_fixture_digests():
    cat = _catalog()
    await cat.verify_cosign_or_refuse(_RUNTIME_DIGEST, tenant_id="t-1")
    await cat.verify_cosign_or_refuse(_PROXY_DIGEST, tenant_id="t-1")


async def test_verify_cosign_refuses_other_digest():
    with pytest.raises(SandboxLifecycleRefused):
        await _catalog().verify_cosign_or_refuse(_OTHER_DIGEST, tenant_id="t-1")


async def test_verify_sbom_passes_for_fixture_digests_refuses_other():
    cat = _catalog()
    await cat.verify_sbom_policy_or_refuse(_RUNTIME_DIGEST, tenant_id="t-1")
    with pytest.raises(SandboxLifecycleRefused):
        await cat.verify_sbom_policy_or_refuse(_OTHER_DIGEST, tenant_id="t-1")
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/conformance/sandbox/test_fixture_catalog.py -v`
Expected: FAIL — `fixture_catalog` module does not exist.

- [ ] **Step 3: Implement `_FixtureOnlySandboxCatalog`**

Create `tests/conformance/sandbox/fixture_catalog.py`:

```python
"""TEST-ONLY catalog double for the #477 fixture-image live-proof path.

Active only under COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES=1 (the
conftest wires it; see #477 spec §7). Allowlists exactly the two named
fixture image digests; no-op-passes cosign / SBOM verification for
those two digests only. This is NOT a supply-chain proof — supply-chain
admission has its own dedicated tests; see the #477 spec §1.

MUST NOT be imported by any src/ module — pinned by
tests/unit/architecture/test_fixture_path_not_in_src.py.
"""

from __future__ import annotations

from cognic_agentos.sandbox.admission import SandboxLifecycleRefused


def _digest_of(ref: str) -> str:
    """Extract the sha256:<digest> from a digest-pinned OCI ref."""
    if "@" not in ref:
        raise ValueError(f"fixture ref is not digest-pinned: {ref!r}")
    return ref.rsplit("@", 1)[1]


class _FixtureOnlySandboxCatalog:
    """CatalogProtocol-conformant test double — see module docstring."""

    def __init__(self, *, runtime_ref: str, proxy_ref: str) -> None:
        self._allowed = frozenset({_digest_of(runtime_ref), _digest_of(proxy_ref)})

    def is_canonical(self, image_digest: str) -> bool:
        return image_digest in self._allowed

    def is_tenant_allow_listed(self, image_digest: str, tenant_id: str) -> bool:
        # Fixtures pass via the canonical path, not the per-tenant
        # escape hatch.
        return False

    async def verify_cosign_or_refuse(self, image_digest: str, *, tenant_id: str) -> None:
        if image_digest not in self._allowed:
            raise SandboxLifecycleRefused("sandbox_image_cosign_verification_failed")

    async def verify_sbom_policy_or_refuse(self, image_digest: str, *, tenant_id: str) -> None:
        if image_digest not in self._allowed:
            raise SandboxLifecycleRefused("sandbox_image_sbom_check_failed")
```

`SandboxLifecycleRefused`'s constructor is `__init__(self, reason, *, detail="")` (verified against source) — so `SandboxLifecycleRefused("sandbox_image_cosign_verification_failed")` (positional reason) above is correct.

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/conformance/sandbox/test_fixture_catalog.py -v`
Expected: PASS.

- [ ] **Step 5: Write the architecture import-regression test**

Create `tests/unit/architecture/test_fixture_path_not_in_src.py` — an AST/text scan of every `src/cognic_agentos/**/*.py` asserting no reference to the fixture catalog or the 3 env vars:

```python
"""#477 AC6/AC11 — the fixture-image path is unreachable from production.

Scans every src/ module: no import or textual reference to
_FixtureOnlySandboxCatalog or any of the 3 test-only env vars.
"""

import pathlib

_SRC = pathlib.Path(__file__).resolve().parents[3] / "src" / "cognic_agentos"
_FORBIDDEN = (
    "_FixtureOnlySandboxCatalog",
    "fixture_catalog",
    "COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES",
    "COGNIC_FIXTURE_RUNTIME_IMAGE_REF",
    "COGNIC_FIXTURE_PROXY_IMAGE_REF",
)


def test_no_src_module_references_the_fixture_path():
    offenders = []
    for path in _SRC.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for token in _FORBIDDEN:
            if token in text:
                offenders.append(f"{path}: {token}")
    assert not offenders, (
        "src/ must not reference the #477 test-only fixture path: "
        + "; ".join(offenders)
    )
```

- [ ] **Step 6: Run + commit**

Run: `uv run pytest tests/conformance/sandbox/test_fixture_catalog.py tests/unit/architecture/test_fixture_path_not_in_src.py -v`
Expected: PASS.

```bash
git add tests/conformance/sandbox/fixture_catalog.py tests/conformance/sandbox/test_fixture_catalog.py tests/unit/architecture/test_fixture_path_not_in_src.py
git commit -m "test(477): T3 — _FixtureOnlySandboxCatalog double + src-isolation guard"
```

---

## Task T4: The 2 fixture Dockerfiles

**Files:**
- Create: `tests/fixtures/sandbox/runtime-fixture.Dockerfile`.
- Create: `tests/fixtures/sandbox/egress-proxy-fixture.Dockerfile`.

Not pytest-TDD-able — the verification is `docker build` (covered by the runbook). Each carries the mandated header comment.

- [ ] **Step 1: Write `runtime-fixture.Dockerfile`**

```dockerfile
# TEST FIXTURE — not a canonical/production sandbox image.
# See docs/superpowers/specs/2026-05-20-477-fixture-live-proof-design.md
#
# Minimal sandbox runtime fixture (#477 §4.1): bash + GNU coreutils +
# GNU tar (all in the debian-slim base — busybox tar has symlink/xattr
# edge cases that would muddy the AC4 symlink + exec-bit proof).
#
# /workspace writability under read-only rootfs: DockerSibling sets
# HostConfig.ReadonlyRootfs from policy.read_only_root (default True,
# policy.py:169) and mounts NOTHING writable at /workspace
# (docker_sibling.py HostConfig has no Tmpfs/Binds/Mounts for it). The
# VOLUME declaration is what keeps /workspace writable — Docker
# auto-creates a fresh anonymous volume there at container start, and
# a volume mount is writable even under ReadonlyRootfs=True. chmod
# 0777 (world-writable) is acceptable for a throwaway test fixture and
# sidesteps UID-matching across Docker's non-root user
# (65534:65534 per docker_sibling.py:147) and OpenShift
# restricted-v2 arbitrary UIDs. The image still declares USER
# 65534:65534 so Kubernetes runAsNonRoot can prove the image default
# is non-root before the container starts; OpenShift restricted-v2 may
# still assign a namespace-range UID at admission. Under K8s the
# backend's own emptyDir mount at /workspace supersedes the VOLUME —
# harmless.
FROM debian:bookworm-slim
RUN mkdir -p /workspace && chmod 0777 /workspace
VOLUME ["/workspace"]
WORKDIR /workspace
USER 65534:65534
CMD ["sleep", "infinity"]
```

(`debian:bookworm-slim` ships `bash`, GNU `coreutils`, and GNU `tar` in the base — no extra install needed.)

- [ ] **Step 2: Write `egress-proxy-fixture.Dockerfile`**

```dockerfile
# TEST FIXTURE — not a canonical/production sandbox image.
# See docs/superpowers/specs/2026-05-20-477-fixture-live-proof-design.md
#
# Minimal egress-proxy fixture (#477 §4.2). It does NOT filter or
# forward traffic. It only: (a) creates a present + readable
# /var/log/cognic-proxy/access.jsonl, and (b) stays alive for the
# sidecar's lifetime so the backend's proxy-log read succeeds (a dead
# sidecar / absent file is the egress_audit_unreadable failure mode).
# An EMPTY access.jsonl is valid — the backend parser
# _parse_proxy_log_jsonl returns () on empty input.
#
# access.jsonl MUST be created at RUNTIME, not build time: both
# DockerSibling (the VOLUME anonymous volume) and KubernetesPod (its
# emptyDir mount) mount a fresh empty dir over /var/log/cognic-proxy,
# which HIDES any file baked into the image layer — a build-time
# `touch` would be shadowed and the sidecar would present an absent
# log -> egress_audit_unreadable. So the CMD touches the file after
# the mount is in place, then stays alive. chmod 0777 + VOLUME keeps
# the dir writable under ReadonlyRootfs=True for the Docker leg;
# under K8s the backend's emptyDir mount supersedes the VOLUME. USER
# 65534:65534 lets Kubernetes runAsNonRoot validate the image default
# before container start; OpenShift restricted-v2 may still assign a
# namespace-range UID at admission.
FROM debian:bookworm-slim
RUN mkdir -p /var/log/cognic-proxy && chmod 0777 /var/log/cognic-proxy
VOLUME ["/var/log/cognic-proxy"]
USER 65534:65534
CMD ["sh", "-c", "touch /var/log/cognic-proxy/access.jsonl && exec sleep infinity"]
```

- [ ] **Step 3: Verify the Dockerfiles parse (best-effort, non-gating)**

If Docker is reachable from this session, run `docker build -f tests/fixtures/sandbox/runtime-fixture.Dockerfile -t cognic-sandbox-runtime-fixture:477 tests/fixtures/sandbox/` and the proxy equivalent; otherwise note that the runbook (T6) owns the build step. Either way the build is exercised for real during the live-proof run.

- [ ] **Step 4: Commit**

```bash
git add tests/fixtures/sandbox/runtime-fixture.Dockerfile tests/fixtures/sandbox/egress-proxy-fixture.Dockerfile
git commit -m "test(477): T4 — minimal sandbox runtime + egress-proxy fixture Dockerfiles"
```

---

## Task T5: Conftest wiring + conformance-test policy parameterization

**Files:**
- Modify: `tests/conformance/sandbox/conftest.py` — fixture-mode wiring in the `backend` fixture + a `fixture_runtime_image` fixture.
- Modify: `tests/conformance/sandbox/test_checkpoint_round_trip.py` (`_POLICY` constant at `:66` → a `policy` fixture).
- Modify: `tests/conformance/sandbox/test_wake_session_tombstoned_conformance.py` (`_POLICY` constant at `:87` → a `policy` fixture).
- Create: `tests/unit/sandbox/test_fixture_conftest_env.py`.

**Scope note (review round 6).** `tests/unit/sandbox/backends/conftest.py` is **NOT** modified. It serves the env-gated *unit* backend tests (`test_docker_sibling_lifecycle.py` / `_resource_caps.py` / `_egress.py`) — not the conformance suite. #477's live proof is the conformance suite only (runbook §9 step 6 runs `tests/conformance/sandbox/`); the unit backend tests stay canonical-only (Sprint 14). The spec §8 originally listed both conftests — a slight over-scope. The correction is **already applied** to the spec file in the working tree (§8 + the self-review consistency line); **T0 Step 1 commits it** as `docs(477): correct spec §8 …` before the plan commit.

- [ ] **Step 1: Write the failing env-var-validation tests**

The fixture-mode env-var read+validate is the testable logic. Put the read+validate in a small pure helper so it is unit-testable without spinning a backend. Create `tests/unit/sandbox/test_fixture_conftest_env.py`:

```python
import pytest

from tests.conformance.sandbox.fixture_catalog import resolve_fixture_refs


def test_resolve_returns_none_when_flag_unset(monkeypatch):
    monkeypatch.delenv("COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES", raising=False)
    assert resolve_fixture_refs() is None


def test_resolve_returns_refs_when_flag_and_vars_set(monkeypatch):
    rt = "reg/x-runtime-fixture@sha256:" + "a" * 64
    px = "reg/x-proxy-fixture@sha256:" + "b" * 64
    monkeypatch.setenv("COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES", "1")
    monkeypatch.setenv("COGNIC_FIXTURE_RUNTIME_IMAGE_REF", rt)
    monkeypatch.setenv("COGNIC_FIXTURE_PROXY_IMAGE_REF", px)
    assert resolve_fixture_refs() == (rt, px)


def test_resolve_fails_fast_when_flag_set_but_ref_missing(monkeypatch):
    monkeypatch.setenv("COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES", "1")
    monkeypatch.delenv("COGNIC_FIXTURE_RUNTIME_IMAGE_REF", raising=False)
    monkeypatch.setenv("COGNIC_FIXTURE_PROXY_IMAGE_REF", "reg/p@sha256:" + "b" * 64)
    with pytest.raises(RuntimeError, match="COGNIC_FIXTURE_RUNTIME_IMAGE_REF"):
        resolve_fixture_refs()


@pytest.mark.parametrize(
    "bad_ref",
    [
        # malformed digest (valid repo, bad digest)
        "reg/x-runtime:tag-only",                # no @sha256: digest at all
        "reg/x-runtime@sha256:bad",              # digest far too short
        "reg/x-runtime@sha256:" + "a" * 63,      # 63 hex — off by one
        "reg/x-runtime@sha256:" + "A" * 64,      # uppercase — not lowercase hex
        "reg/x-runtime@sha256:" + "g" * 64,      # 'g' is not a hex digit
        # malformed repository (valid digest, bad repo shape)
        "@sha256:" + "a" * 64,                   # empty repository part
        "/bad@sha256:" + "a" * 64,               # leading-slash repository
        "reg//x@sha256:" + "a" * 64,             # empty path component
    ],
)
def test_resolve_fails_fast_on_malformed_runtime_ref(monkeypatch, bad_ref):
    monkeypatch.setenv("COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES", "1")
    monkeypatch.setenv("COGNIC_FIXTURE_RUNTIME_IMAGE_REF", bad_ref)
    monkeypatch.setenv("COGNIC_FIXTURE_PROXY_IMAGE_REF", "reg/p@sha256:" + "b" * 64)
    with pytest.raises(RuntimeError, match="digest-pinned"):
        resolve_fixture_refs()


@pytest.mark.parametrize(
    "bad_ref",
    [
        "reg/p@sha256:bad",                      # malformed digest
        "reg/p@sha256:" + "z" * 64,              # non-hex digest
        "reg/p:tag-only",                        # no digest at all
        "/bad@sha256:" + "b" * 64,               # malformed repository
    ],
)
def test_resolve_fails_fast_on_malformed_proxy_ref(monkeypatch, bad_ref):
    monkeypatch.setenv("COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES", "1")
    monkeypatch.setenv("COGNIC_FIXTURE_RUNTIME_IMAGE_REF", "reg/r@sha256:" + "a" * 64)
    monkeypatch.setenv("COGNIC_FIXTURE_PROXY_IMAGE_REF", bad_ref)
    with pytest.raises(RuntimeError, match="digest-pinned"):
        resolve_fixture_refs()
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/unit/sandbox/test_fixture_conftest_env.py -v`
Expected: FAIL — `resolve_fixture_refs` does not exist.

- [ ] **Step 3: Implement `resolve_fixture_refs`**

Add to `tests/conformance/sandbox/fixture_catalog.py`:

```python
import os

from cognic_agentos.sandbox.admission import SandboxLifecycleRefused
# _validate_image_ref is the SOURCE-OF-TRUTH Stage-1 OCI-ref validator
# (repository shape via _OCI_REPO_TAG_RE + digest via _SHA256_DIGEST_RE).
# Importing this underscore-prefixed src helper into test-support code
# is intentional: test code MAY import src internals — the forbidden
# direction is src -> test (pinned by T3's architecture guard). Reusing
# it means the conftest boundary rejects EXACTLY what admission rejects,
# with zero drift, and a bare `"@sha256:" in val` substring check
# (which would accept `reg/p@sha256:bad`) is avoided.
from cognic_agentos.sandbox.policy import _validate_image_ref

_FLAG = "COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES"
_RUNTIME_VAR = "COGNIC_FIXTURE_RUNTIME_IMAGE_REF"
_PROXY_VAR = "COGNIC_FIXTURE_PROXY_IMAGE_REF"


def resolve_fixture_refs() -> tuple[str, str] | None:
    """Return (runtime_ref, proxy_ref) when fixture mode is on, else None.

    Fail-fast (RuntimeError) if the flag is set but a ref env var is
    missing or not a valid digest-pinned OCI ref (#477 §4.3). Ref shape
    is validated by the source-of-truth Stage-1 validator
    ``cognic_agentos.sandbox.policy._validate_image_ref`` — the same
    check admission runs. No silent skip, no placeholder fallback.
    """
    if os.environ.get(_FLAG) != "1":
        return None
    refs = []
    for var in (_RUNTIME_VAR, _PROXY_VAR):
        val = os.environ.get(var, "").strip()
        if not val:
            raise RuntimeError(
                f"{_FLAG}=1 but {var} is unset — see "
                "docs/runbooks/477-live-sandbox-proof.md"
            )
        try:
            _validate_image_ref(val)
        except SandboxLifecycleRefused as exc:
            raise RuntimeError(
                f"{var}={val!r} is not a valid digest-pinned OCI ref "
                "(repository[:tag]@sha256:<64 lowercase hex>)"
            ) from exc
        refs.append(val)
    return refs[0], refs[1]
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/unit/sandbox/test_fixture_conftest_env.py -v`
Expected: PASS.

- [ ] **Step 5: Wire `tests/conformance/sandbox/conftest.py` for fixture mode**

The conformance conftest's `backend` fixture (parametrized over `docker_sibling` / `kubernetes_pod`) builds a `CanonicalImageCatalog` from `_CANONICAL_SPRINT_8A_IMAGES` in each arm. Add a module-level helper + a `fixture_runtime_image` fixture near the top (after `_CANONICAL_SPRINT_8A_IMAGES`):

```python
from tests.conformance.sandbox.fixture_catalog import (
    _FixtureOnlySandboxCatalog,
    resolve_fixture_refs,
)


def _resolve_image_layer(tmp_path):
    """Return (preflight_image_set, catalog, egress_proxy_image).

    Fixture mode (COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES=1): the 2
    fixture refs + a _FixtureOnlySandboxCatalog + the proxy ref.
    Default: the 4 canonical refs + a real CanonicalImageCatalog +
    None (the backend's egress_proxy_image seam then resolves to its
    canonical default — byte-identical to today's behaviour).
    """
    fixture_refs = resolve_fixture_refs()
    if fixture_refs is not None:
        runtime_ref, proxy_ref = fixture_refs
        catalog = _FixtureOnlySandboxCatalog(
            runtime_ref=runtime_ref, proxy_ref=proxy_ref
        )
        return (runtime_ref, proxy_ref), catalog, proxy_ref
    from cognic_agentos.sandbox.catalog import CanonicalImageCatalog

    trust_root = tmp_path / "cognic-cosign.pub"
    trust_root.write_text("# fixture trust root for conformance suite")
    catalog = CanonicalImageCatalog(
        canonical_refs=frozenset(_CANONICAL_SPRINT_8A_IMAGES),
        tenant_trust_roots={"t-conformance": trust_root},
        tenant_allow_lists={"t-conformance": frozenset()},
    )
    return _CANONICAL_SPRINT_8A_IMAGES, catalog, None


@pytest.fixture
def fixture_runtime_image() -> str:
    """The runtime image ref the conformance SandboxPolicy must use:
    the runtime fixture ref in fixture mode, else the canonical
    placeholder (today's value — env-gated modules skip in CI anyway)."""
    fixture_refs = resolve_fixture_refs()
    if fixture_refs is not None:
        return fixture_refs[0]
    return "cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64
```

**`docker_sibling` arm — concrete before/after.** `_resolve_image_layer(tmp_path)` MUST be the first statement inside the arm's `try:` block (before the preflight loop, so `image_set` exists). Also delete the arm's branch-local `from cognic_agentos.sandbox.catalog import CanonicalImageCatalog` import — `_resolve_image_layer` owns that import now, and leaving it triggers a ruff F401 unused-import.

BEFORE (inside the `docker_sibling` arm's `try:`):
```python
        try:
            for ref in _CANONICAL_SPRINT_8A_IMAGES:
                try:
                    await docker.images.inspect(ref)
                except aiodocker.exceptions.DockerError as e:
                    _backend_unavailable(request, f"canonical artifact {ref!r} not pullable ...")

            trust_root = tmp_path / "cognic-cosign.pub"
            trust_root.write_text("# fixture trust root for conformance suite")
            catalog = CanonicalImageCatalog(
                canonical_refs=frozenset(_CANONICAL_SPRINT_8A_IMAGES),
                tenant_trust_roots={"t-conformance": trust_root},
                tenant_allow_lists={"t-conformance": frozenset()},
            )
            rego = AsyncMock()
            # ... (rego/decision/settings/_build_checkpoint_layer unchanged) ...
            yield DockerSiblingSandboxBackend(
                docker_client=docker,
                image_catalog=catalog,
                # ... other kwargs unchanged ...
                checkpoint_store=checkpoint_store,
            )
```
AFTER:
```python
        try:
            image_set, catalog, egress_proxy_image = _resolve_image_layer(tmp_path)
            for ref in image_set:
                try:
                    await docker.images.inspect(ref)
                except aiodocker.exceptions.DockerError as e:
                    _backend_unavailable(request, f"canonical artifact {ref!r} not pullable ...")

            rego = AsyncMock()
            # ... (rego/decision/settings/_build_checkpoint_layer unchanged) ...
            yield DockerSiblingSandboxBackend(
                docker_client=docker,
                image_catalog=catalog,
                # ... other kwargs unchanged ...
                checkpoint_store=checkpoint_store,
                egress_proxy_image=egress_proxy_image,
            )
```

**`kubernetes_pod` arm — concrete before/after.** No preflight loop (the arm relies on the cluster image cache), so only the catalog block + the constructor change. Delete the arm's branch-local `CanonicalImageCatalog` import too.

BEFORE (inside the `kubernetes_pod` arm's `try:`):
```python
        try:
            trust_root = tmp_path / "cognic-cosign.pub"
            trust_root.write_text("# fixture trust root for conformance suite")
            catalog = CanonicalImageCatalog(
                canonical_refs=frozenset(_CANONICAL_SPRINT_8A_IMAGES),
                tenant_trust_roots={"t-conformance": trust_root},
                tenant_allow_lists={"t-conformance": frozenset()},
            )
            rego = AsyncMock()
            # ... unchanged ...
            yield KubernetesPodSandboxBackend(
                kube_api_client=api_client,
                namespace=os.environ.get("COGNIC_K8S_SANDBOX_NAMESPACE", "cognic-sandbox"),
                image_catalog=catalog,
                # ... other kwargs unchanged ...
                checkpoint_store=checkpoint_store,
            )
```
AFTER:
```python
        try:
            _image_set, catalog, egress_proxy_image = _resolve_image_layer(tmp_path)
            rego = AsyncMock()
            # ... unchanged ...
            yield KubernetesPodSandboxBackend(
                kube_api_client=api_client,
                namespace=os.environ.get("COGNIC_K8S_SANDBOX_NAMESPACE", "cognic-sandbox"),
                image_catalog=catalog,
                # ... other kwargs unchanged ...
                checkpoint_store=checkpoint_store,
                egress_proxy_image=egress_proxy_image,
            )
```
(`_image_set` is unused in the K8s arm — the leading underscore tells ruff that is intentional.)

When the flag is unset, `_resolve_image_layer` returns the canonical triple with `egress_proxy_image=None` → the backend §5 seam resolves to its canonical default → behaviour byte-identical to today. The existing `_bypass_catalog_trust_gate` helper in the conformance test files is unchanged — it monkeypatches `verify_cosign_or_refuse`/`verify_sbom_policy_or_refuse`, which on `_FixtureOnlySandboxCatalog` already no-op-pass, so the patch is harmless/idempotent in fixture mode.

- [ ] **Step 6: Parameterize the conformance test policies**

Both `test_checkpoint_round_trip.py` and `test_wake_session_tombstoned_conformance.py` define a module-level `_POLICY = SandboxPolicy(...)` whose `runtime_image` is the placeholder canonical ref. Replace the constant with a `policy` pytest fixture taking the conftest `fixture_runtime_image` fixture. For `test_checkpoint_round_trip.py` (`_POLICY` at `:66`):

```python
@pytest.fixture
def policy(fixture_runtime_image: str) -> SandboxPolicy:
    """Conformance SandboxPolicy — runtime_image flows from the conftest
    fixture (runtime fixture ref in fixture mode, canonical placeholder
    otherwise). All other fields unchanged from the pre-#477 _POLICY."""
    return SandboxPolicy(
        cpu_cores=0.5,
        cpu_time_budget_s=None,
        memory_mb=256,
        walltime_s=30.0,
        runtime_image=fixture_runtime_image,
        egress_allow_list=(),
        vault_path=None,
    )
```

Delete the module-level `_POLICY` constant. Every test function in `test_checkpoint_round_trip.py` that referenced `_POLICY` gains a `policy` parameter and uses it in its `backend.create(policy, ...)` call.

**`test_wake_session_tombstoned_conformance.py` — spelled out (it differs structurally).** This file does NOT call `_POLICY` from the test bodies — the module-level helper `_tombstoned_session(backend, monkeypatch)` (`:130`) owns the `backend.create(_POLICY, ...)` call (`:144-150`), and it is invoked by all 3 test methods (`test_case_a` `:160`, `test_case_b` `:174`, `test_case_c` `:229`). So the exact transform is:
1. Delete the module-level `_POLICY` constant (`:87-95`).
2. Add the `policy` fixture — same field values as the deleted `_POLICY` (`cpu_cores=0.5`, `cpu_time_budget_s=None`, `memory_mb=256`, `walltime_s=30.0`, `runtime_image=fixture_runtime_image`, `egress_allow_list=()`, `vault_path=None`) — identical body to the `test_checkpoint_round_trip.py` `policy` fixture above.
3. Change `_tombstoned_session`'s signature to `async def _tombstoned_session(backend, monkeypatch, policy: SandboxPolicy)` and its body to `await backend.create(policy, actor=_ACTOR, tenant_id=_TENANT, pack_context=_PACK_CTX, use_warm_pool=False)`.
4. Each of the 3 test methods gains a `policy` parameter (`test_case_a(self, backend, monkeypatch, policy)`, etc.) and passes it: `await _tombstoned_session(backend, monkeypatch, policy)`.

- [ ] **Step 7: Run the non-env-gated scope to prove the default path is unchanged**

Run: `uv run pytest tests/conformance/sandbox/ tests/unit/sandbox/test_fixture_conftest_env.py tests/conformance/sandbox/test_fixture_catalog.py -q`
Expected: PASS / SKIP exactly as before when the flag is unset — the conformance modules still SKIP (symmetric env-gate), `test_fixture_conftest_env.py` + `test_fixture_catalog.py` PASS. No behaviour change in the default (flag-unset) path.

- [ ] **Step 8: Commit**

```bash
git add tests/conformance/sandbox/conftest.py tests/conformance/sandbox/test_checkpoint_round_trip.py tests/conformance/sandbox/test_wake_session_tombstoned_conformance.py tests/conformance/sandbox/fixture_catalog.py tests/unit/sandbox/test_fixture_conftest_env.py
git commit -m "test(477): T5 — fixture-mode conformance conftest wiring + policy parameterization"
```

---

## Task T6: CRC live-proof runbook

**Files:**
- Create: `docs/runbooks/477-live-sandbox-proof.md`.

- [ ] **Step 1: Write the runbook**

Author `docs/runbooks/477-live-sandbox-proof.md` following spec §9's 7-step structure: prereqs (Docker Desktop + CRC) → `crc start` + expose the internal registry route + `oc registry login` → `docker build` the 2 fixtures → push + capture each `RepoDigest` → export the 5 env vars (`COGNIC_RUN_DOCKER_SANDBOX=1`, `COGNIC_RUN_K8S_SANDBOX=1`, `COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES=1`, `COGNIC_FIXTURE_RUNTIME_IMAGE_REF=<captured>`, `COGNIC_FIXTURE_PROXY_IMAGE_REF=<captured>`) → single acceptance run. Include the exact `pytest` invocation:

```
uv run pytest tests/conformance/sandbox/test_checkpoint_round_trip.py \
  tests/conformance/sandbox/test_wake_session_tombstoned_conformance.py -v
```

State the DO-NOT-SPLIT rule (both modules need both backend env vars) and the alternate remote-OpenShift target + the "plain K8s/kind not authoritative" note.

- [ ] **Step 2: Commit**

```bash
git add docs/runbooks/477-live-sandbox-proof.md
git commit -m "docs(477): T6 — CRC live-proof runbook"
```

---

## Task T7: Evidence-results template

**Files:**
- Create: `docs/evidence/477-live-proof-results.md`.

- [ ] **Step 1: Write the template**

Author `docs/evidence/477-live-proof-results.md` as a placeholder template (no fabricated results) capturing, per run: date, operator, CRC / OpenShift / Docker versions, the 2 captured fixture image RepoDigests exercised, the `pytest` output of the single symmetric acceptance run (both backend arms + tombstone-first wake), and a pass/fail line per AC1-AC5. Include a header stating: "#477 stays OPEN until a passing run is recorded below." The 2026-05-21 live run later filled this template with witnessed passing output, which is recorded in the evidence file.

- [ ] **Step 2: Commit**

```bash
git add docs/evidence/477-live-proof-results.md
git commit -m "docs(477): T7 — live-proof evidence-results template"
```

---

## Task T8: Wrap — full gate ladder + non-live AC verification

**Files:** none new — verification + a status note.

- [ ] **Step 1: Full local gate ladder**

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy src tests
uv run pytest --cov=cognic_agentos --cov-branch --cov-report=json -m "not postgres and not oracle" -q
uv run python tools/check_critical_coverage.py
```
Expected: ruff/format/mypy clean; full suite green; `check_critical_coverage.py` EXIT 0 — **all 73 modules pass** (AC7: the T1/T2 seam must keep `docker_sibling.py` + `kubernetes_pod.py` ≥95% line / ≥90% branch; #477 promotes no module, so the count stays 73).

- [ ] **Step 2: Verify the non-live acceptance criteria**

Confirm AC6 (architecture import-regression test passes), AC7 (gate green), AC8-AC12 (the seam tests from T1/T2) all pass. AC1-AC5 are the **live** criteria — the original plan expected them to be proven later by an operator running the T6 runbook and recording results in the T7 evidence file. The 2026-05-21 run did exactly that: the evidence file now records the witnessed 8-pass Docker + CRC/OpenShift run.

- [ ] **Step 3: Halt-before-commit summary**

Produce a summary: artifacts delivered, the 2 planned CC seam commits (T1/T2) flagged, AC6-AC12 green, and AC1-AC5 status tied to the evidence file. After the 2026-05-21 live run, AC1-AC5 are no longer pending: `docs/evidence/477-live-proof-results.md` records the passing symmetric Docker + CRC/OpenShift acceptance run. No closeout doc — the evidence file is the closeout artifact for #477.

- [ ] **Step 4: Update task #477**

After the evidence file records a passing run, task #477 is eligible to close. If the evidence block is absent or failing, leave #477 `pending`.

---

## Self-Review

**1. Spec coverage:**
- §4.1/§4.2 fixture images → T4. §4.3 digest materialization → T5 (`resolve_fixture_refs`) + T6 (runbook capture steps). §5 seam → T1 (Docker) + T2 (K8s). §6 env vars → T5. §7 `_FixtureOnlySandboxCatalog` + import-regression → T3. §8 conftest + conformance-test wiring → T5. §9 runbook → T6. §10 evidence file → T7. §11 ACs: AC6/AC8-AC12 → T1/T2/T3 tests; AC7 → T8; AC1-AC5 → live runbook (T6/T7), now satisfied by the witnessed 2026-05-21 evidence entry. Live execution also surfaced extra KubernetesPod backend fixes (create readiness, delete wait, OpenShift-safe restore flags) that were reconciled back into the spec as a live-proof amendment. No gaps.

**2. Placeholder scan:** No "TBD"/"handle edge cases"/"similar to". Every code step shows code; every command shows expected output. T4 step 3 and the live ACs are explicitly marked non-gating / operator-run, not placeholders.

**3. Type consistency:** `egress_proxy_image: str | None = None` constructor kwarg + `self._egress_proxy_image: str` attr + `_CANONICAL_EGRESS_PROXY_IMAGE` constant used identically in T1 and T2. `_build_pod_spec`'s new `egress_proxy_image: str` keyword-only param matches all call sites. `_FixtureOnlySandboxCatalog(runtime_ref=…, proxy_ref=…)` + `resolve_fixture_refs() -> tuple[str, str] | None` consistent across T3/T5. The 3 env-var names are consistent across T3/T5/spec.

**Open verification the executor must do:** grep all `_build_pod_spec(` src call sites (T2 Step 7) in case there are more than the two known at `:847`/`:1499` — the new required `egress_proxy_image` param would fail mypy on any missed site. (`SandboxLifecycleRefused`'s `__init__(self, reason, *, detail="")` and `create()`'s `(policy, *, actor, tenant_id, pack_context, ...)` signature are both verified against source — no longer open.)
