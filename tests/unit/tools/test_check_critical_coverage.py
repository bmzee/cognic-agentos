"""Sprint 7B.3 T11 — count-guard self-test for the critical-controls gate.

``tools/check_critical_coverage.py`` carries the durable per-file
critical-controls coverage gate as the module-level ``_CRITICAL_FILES``
tuple. The gate grows sprint-by-sprint; the failure mode this suite
guards against is a *silent shrink* — an edit that drops an entry (a
bad merge, an over-eager refactor) would weaken the gate without any
test noticing, because the production ``main()`` only checks the
coverage of whatever entries happen to be present.

This is the self-test the Round-19 plan patch mandates. It pins:
  * the exact entry count (see ``_EXPECTED_ENTRY_COUNT`` — bumped per sprint);
  * the presence + floors of the 5 Sprint 7B.3 modules promoted
    incrementally during T3-T7 (4 evidence panels + the 5-gate
    composer);
  * the *absence* of ``portal/api/packs/evidence_routes.py`` and
    ``portal/api/packs/router.py`` — the R19 user decision + the
    7B.2-T3 carve-out keep both off the durable gate;
  * the no-duplicate-paths invariant.

The ``tools/`` directory has no ``__init__.py`` (mirrors
``tests/unit/tools/test_generate_conformance_matrix_json.py``); the
gate script is loaded via :func:`importlib.util.spec_from_file_location`
from the repo-root path.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_GATE_TOOL_PATH = _REPO_ROOT / "tools" / "check_critical_coverage.py"

#: Entry count after the Sprint 10 Z1 promotions (63 at the 7B.4
#: T13 close + 7 Sprint-8A sandbox modules = 70; + 1 Sprint-8B K8s
#: backend = 71; + 2 Sprint-8.5 modules = 73; + 4 Sprint-9
#: compliance/iso42001 modules = 77; + 4 Sprint-9.5 Z1 Model Registry
#: modules (registry / storage / trust + portal lifecycle routes) = 81;
#: + 4 Sprint-10 Z1 Vault credential-leasing modules
#: (core/vault + core/_vault_transport + sandbox/credentials +
#: sandbox/backends/_shared_credentials per Round-7 Gap O) = 85).
#: Bump this in lockstep with any deliberate ``_CRITICAL_FILES`` change.
_EXPECTED_ENTRY_COUNT = 85

#: The 5 modules Sprint 7B.3 promoted to the durable gate, each by its
#: own landing commit (T3-T6 panels + T7 composer). All ride the
#: standard 95%-line / 90%-branch floor.
_SPRINT_7B3_GATE_MODULES = (
    "src/cognic_agentos/packs/evidence/data_governance.py",
    "src/cognic_agentos/packs/evidence/risk_tier.py",
    "src/cognic_agentos/packs/evidence/supply_chain.py",
    "src/cognic_agentos/packs/evidence/conformance_matrix.py",
    "src/cognic_agentos/packs/approval_gates.py",
)

#: Modules the Sprint 7B.3 plan deliberately keeps OFF the durable
#: gate — ``evidence_routes.py`` per the R19 user decision (R32
#: doctrine: no Human-only-decisions boundary, no actor_type
#: chain-payload provenance surface; T10 audit-emit routes through the
#: on-gate ``packs/storage.py``); ``router.py`` per the 7B.2-T3
#: scaffolding-only carve-out.
_SPRINT_7B3_OFF_GATE_MODULES = (
    "src/cognic_agentos/portal/api/packs/evidence_routes.py",
    "src/cognic_agentos/portal/api/packs/router.py",
)


#: The 3 modules Sprint 7B.4 T13 promoted to the durable gate (T11
#: action_routes + T10 stream_routes + T8 elicitation_gate). All
#: ride the standard 95%-line / 90%-branch floor.
_SPRINT_7B4_GATE_MODULES = (
    "src/cognic_agentos/portal/api/ui/action_routes.py",
    "src/cognic_agentos/portal/api/ui/stream_routes.py",
    "src/cognic_agentos/portal/api/ui/elicitation_gate.py",
)

#: Modules the Sprint 7B.4 plan deliberately keeps OFF the durable
#: gate (each carries an in-source carve-out rationale documented in
#: the 7B.4 docstring section of ``tools/check_critical_coverage.py``):
#:
#: - ``dto.py`` (T9): pure type-only DTOs — Pydantic parse + static
#:   types catch drift; same precedent as ``portal/api/packs/dto.py``.
#: - ``router.py`` (T12): composition factory — carrier file only.
#: - ``well_known_routes.py`` (T12): schema publication — load-bearing
#:   regression is the snapshot-pinned drift test, not coverage.
#: - ``protocol/elicitation_adapter.py``: pure type-contract module
#:   (narrow ``@runtime_checkable`` Protocol + frozen dataclasses
#:   ``ElicitationContext`` / ``ElicitationResult`` + the
#:   ``ElicitationBackendError`` exception class). Off-floor because
#:   every meaningful invariant (Protocol method shape, dataclass
#:   field set, exception identity) is enforced at the call site —
#:   the on-floor ``portal/api/ui/elicitation_gate.py`` covers the
#:   runtime contract; coverage on a pure-Protocol module would
#:   measure runtime-import + decoration lines only. See the matching
#:   "Off-floor rationale" entry in
#:   ``tools/check_critical_coverage.py``'s 7B.4 docstring section.
_SPRINT_7B4_OFF_GATE_MODULES = (
    "src/cognic_agentos/portal/api/ui/dto.py",
    "src/cognic_agentos/portal/api/ui/router.py",
    "src/cognic_agentos/portal/api/ui/well_known_routes.py",
    "src/cognic_agentos/protocol/elicitation_adapter.py",
)


def _load_gate_tool() -> ModuleType:
    """Load the ``tools/`` gate script as an importable module.

    Loaded under its own module name (not ``__main__``) so the
    ``if __name__ == "__main__"`` guard does not fire ``main()``.
    """
    spec = importlib.util.spec_from_file_location("check_critical_coverage", _GATE_TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gate_tool() -> ModuleType:
    return _load_gate_tool()


def test_critical_files_count_is_expected(gate_tool: ModuleType) -> None:
    """The gate carries exactly the expected number of entries.

    A silent shrink (dropped entry) or an undocumented add both fail
    here, forcing a deliberate ``_EXPECTED_ENTRY_COUNT`` bump alongside
    the ``_CRITICAL_FILES`` change.
    """
    assert len(gate_tool._CRITICAL_FILES) == _EXPECTED_ENTRY_COUNT


def test_sprint_7b3_modules_present_with_standard_floors(
    gate_tool: ModuleType,
) -> None:
    """All 5 Sprint 7B.3 promotions are on the gate at the 95/90 floor."""
    by_path = {path: (line, branch) for path, line, branch in gate_tool._CRITICAL_FILES}
    for module in _SPRINT_7B3_GATE_MODULES:
        assert module in by_path, f"Sprint 7B.3 module missing from gate: {module}"
        assert by_path[module] == (0.95, 0.90), (
            f"{module} must ride the standard 95%-line / 90%-branch floor"
        )


@pytest.mark.parametrize("off_gate_module", _SPRINT_7B3_OFF_GATE_MODULES)
def test_sprint_7b3_off_gate_modules_absent(gate_tool: ModuleType, off_gate_module: str) -> None:
    """``evidence_routes.py`` + ``router.py`` stay OFF the durable gate.

    Pins the R19 user decision (evidence_routes.py) + the 7B.2-T3
    scaffolding-only carve-out (router.py). A future edit that promotes
    either without revisiting the doctrine fails here.
    """
    paths = {path for path, _line, _branch in gate_tool._CRITICAL_FILES}
    assert off_gate_module not in paths


def test_no_duplicate_paths(gate_tool: ModuleType) -> None:
    """Every ``_CRITICAL_FILES`` path is unique.

    A duplicate would silently double-count an entry against
    ``_EXPECTED_ENTRY_COUNT`` and let a genuine module slip off the
    gate while the count still looks right.
    """
    paths = [path for path, _line, _branch in gate_tool._CRITICAL_FILES]
    assert len(paths) == len(set(paths)), "duplicate path(s) in _CRITICAL_FILES"


def test_sprint_7b4_modules_present_with_standard_floors(
    gate_tool: ModuleType,
) -> None:
    """All 3 Sprint 7B.4 T13 promotions are on the gate at the 95/90 floor."""
    by_path = {path: (line, branch) for path, line, branch in gate_tool._CRITICAL_FILES}
    for module in _SPRINT_7B4_GATE_MODULES:
        assert module in by_path, f"Sprint 7B.4 module missing from gate: {module}"
        assert by_path[module] == (0.95, 0.90), (
            f"{module} must ride the standard 95%-line / 90%-branch floor"
        )


@pytest.mark.parametrize("off_gate_module", _SPRINT_7B4_OFF_GATE_MODULES)
def test_sprint_7b4_off_gate_modules_absent(gate_tool: ModuleType, off_gate_module: str) -> None:
    """4 Sprint 7B.4 modules stay OFF the durable gate per the in-source
    7B.4 docstring carve-outs (``dto.py`` / ``router.py`` /
    ``well_known_routes.py`` / ``protocol/elicitation_adapter.py``).

    A future edit that promotes any of them without revisiting the
    doctrine fails here, forcing a deliberate review."""
    paths = {path for path, _line, _branch in gate_tool._CRITICAL_FILES}
    assert off_gate_module not in paths


#: The 7 modules Sprint 8A T12 promoted to the durable gate. Per the
#: Sprint-8A design spec §17 "Critical-controls scope". All ride the
#: standard 95%-line / 90%-branch floor.
_SPRINT_8A_GATE_MODULES = (
    "src/cognic_agentos/sandbox/protocol.py",
    "src/cognic_agentos/sandbox/policy.py",
    "src/cognic_agentos/sandbox/admission.py",
    "src/cognic_agentos/sandbox/catalog.py",
    "src/cognic_agentos/sandbox/proxy.py",
    "src/cognic_agentos/sandbox/warm_pool.py",
    "src/cognic_agentos/sandbox/backends/docker_sibling.py",
)

#: Modules the Sprint 8A spec §17 deliberately keeps OFF the durable
#: gate (each carries an in-source carve-out rationale documented in
#: the 8A docstring section of ``tools/check_critical_coverage.py``):
#:
#: - ``sandbox/audit.py``: thin chain-row converter for the 8 sandbox
#:   lifecycle event taxonomies. Substantive audit-chain invariants
#:   (hash-chain, canonical-form, ISO control tagging) are enforced
#:   upstream by the on-gate ``core/audit.py`` +
#:   ``core/decision_history.py`` + ``core/canonical.py``. Bugs in the
#:   event-payload-rendering surface through the 8-event taxonomy unit
#:   test + the integration tests of ``backends/docker_sibling.py``.
#:
#: NOTE — ``sandbox/credentials.py`` was an off-gate carve-out at
#: Sprint 8A (re-export shim covering the canonical home at
#: ``sandbox/admission.py``) but was PROMOTED to the durable gate at
#: Sprint 10 Z1 alongside the real ``VaultCredentialAdapter``
#: implementation (per AGENTS.md L188's "Sprint 10's real adapter
#: goes ON the gate when it lands" promise). The Sprint-10 Z1
#: promotion test ``test_sprint_10_modules_present_with_standard_floors``
#: now pins it on-gate; removed from this 8A off-gate list.
_SPRINT_8A_OFF_GATE_MODULES = ("src/cognic_agentos/sandbox/audit.py",)


def test_sprint_8a_modules_present_with_standard_floors(
    gate_tool: ModuleType,
) -> None:
    """All 7 Sprint 8A T12 promotions are on the gate at the 95/90 floor."""
    by_path = {path: (line, branch) for path, line, branch in gate_tool._CRITICAL_FILES}
    for module in _SPRINT_8A_GATE_MODULES:
        assert module in by_path, f"Sprint 8A module missing from gate: {module}"
        assert by_path[module] == (0.95, 0.90), (
            f"{module} must ride the standard 95%-line / 90%-branch floor"
        )


@pytest.mark.parametrize("off_gate_module", _SPRINT_8A_OFF_GATE_MODULES)
def test_sprint_8a_off_gate_modules_absent(gate_tool: ModuleType, off_gate_module: str) -> None:
    """1 remaining Sprint 8A module stays OFF the durable gate per the
    in-source 8A docstring carve-out (``sandbox/audit.py`` thin
    chain-row converter; ``sandbox/credentials.py`` was promoted at
    Sprint 10 Z1 per the AGENTS.md L188 promise).

    A future edit that promotes ``sandbox/audit.py`` without
    revisiting the spec §17 rationale fails here, forcing a deliberate
    review."""
    paths = {path for path, _line, _branch in gate_tool._CRITICAL_FILES}
    assert off_gate_module not in paths


# ---------------------------------------------------------------------------
# Sprint 8B T8B-d — Wave-1 K8s/OpenShift backend gate promotion (+1 → 71)
# ---------------------------------------------------------------------------

#: The 1 module Sprint 8B T8B-d promotes to the durable gate. The
#: tightening edit B from Sprint 8B preflight (2026-05-17) requires
#: this commit also run ``tools/check_critical_coverage.py`` against
#: fresh ``coverage.json`` — NOT just this count-guard bump. See
#: ``feedback_verify_promotion_meets_floor_at_promotion_time``.
_SPRINT_8B_GATE_MODULES = ("src/cognic_agentos/sandbox/backends/kubernetes_pod.py",)

#: Modules T8B-c landed that Sprint 8B deliberately keeps OFF the
#: durable gate (each carries an in-source carve-out rationale in
#: ``tools/check_critical_coverage.py``'s Sprint 8B docstring section):
#:
#: - ``sandbox/backend_factory.py``: pure selection seam (130 LoC).
#:   Wire-protocol-public contract is the ``Settings.sandbox_backend``
#:   Literal + ``COGNIC_SANDBOX_BACKEND`` env-var override per ADR-004
#:   §32; drift detector at
#:   ``tests/unit/sandbox/test_backend_factory.py::TestBackendFactoryEnumerateCoverage``
#:   pins the Literal-arm-set lockstep + the settings-injection
#:   contract is pinned by ``TestBackendFactoryRoutesByLiteral``
#:   (TM-revert verified post the user-found P1 fix at T8B-c). The
#:   substantive enforcement lives in the chosen backend's methods
#:   (both backends ON the gate). Off-gate per the same Sprint-7A T17
#:   R4 P3 #5 doctrine that kept ``cli/conformance.py`` off-gate when
#:   the dispatched matrix is already CC.
#: - ``sandbox/backends/_shared_exec.py``: pure-functional helper
#:   (101 LoC: ``_classify_exec_failure`` + ``_ProxyLogReadFailure``).
#:   Consumer-owned by ``kubernetes_pod`` per
#:   ``feedback_consumer_owned_protocol_for_unlanded_dep``;
#:   docker_sibling keeps its inline copies UNCHANGED per the sandbox
#:   isolation-boundary stop-rule. Behavioural lockstep across both
#:   backends pinned by the test-only drift detector at
#:   ``test_exec_classification_cross_backend_drift.py``. CC risk
#:   covered by the on-gate ``kubernetes_pod.py`` consumer +
#:   ``docker_sibling.py`` consumer; promoting here would
#:   double-count the same enforcement.
_SPRINT_8B_OFF_GATE_MODULES = (
    "src/cognic_agentos/sandbox/backend_factory.py",
    "src/cognic_agentos/sandbox/backends/_shared_exec.py",
)


def test_sprint_8b_modules_present_with_standard_floors(
    gate_tool: ModuleType,
) -> None:
    """The 1 Sprint 8B T8B-d promotion is on the gate at the 95/90 floor."""
    by_path = {path: (line, branch) for path, line, branch in gate_tool._CRITICAL_FILES}
    for module in _SPRINT_8B_GATE_MODULES:
        assert module in by_path, f"Sprint 8B module missing from gate: {module}"
        assert by_path[module] == (0.95, 0.90), (
            f"{module} must ride the standard 95%-line / 90%-branch floor"
        )


@pytest.mark.parametrize("off_gate_module", _SPRINT_8B_OFF_GATE_MODULES)
def test_sprint_8b_off_gate_modules_absent(gate_tool: ModuleType, off_gate_module: str) -> None:
    """2 Sprint 8B modules (``backend_factory.py`` + ``_shared_exec.py``)
    stay OFF the durable gate per the in-source 8B docstring carve-outs.

    A future edit that promotes either without revisiting the carve-out
    rationale fails here, forcing a deliberate review."""
    paths = {path for path, _line, _branch in gate_tool._CRITICAL_FILES}
    assert off_gate_module not in paths


# ---------------------------------------------------------------------------
# Sprint 8.5 T12 — resumable-session-API gate promotion (+2 → 73)
# ---------------------------------------------------------------------------

#: The 2 modules Sprint 8.5 T12 promotes to the durable gate. The
#: tightening edit B (``feedback_verify_promotion_meets_floor_at_promotion_time``)
#: requires this commit ALSO run ``tools/check_critical_coverage.py``
#: against fresh ``coverage.json`` — NOT just this count-guard bump. The
#: 2026-05-20 promotion run found BOTH below floor on fresh data and
#: landed the same-commit focused negative-path repair
#: (``test_checkpoint_store_coverage.py`` +
#: ``test_local_object_store_adapter_coverage.py``).
_SPRINT_8_5_GATE_MODULES = (
    "src/cognic_agentos/sandbox/checkpoint_store.py",
    "src/cognic_agentos/db/adapters/local_object_store_adapter.py",
)

#: The 1 NEW Sprint 8.5 module deliberately kept OFF the durable gate
#: per spec §4.2 + Doctrine F — ``sandbox/reaper.py`` is a thin asyncio
#: loop wrapping the on-gate ``checkpoint_store.py`` ``purge_expired()``;
#: the substantive retention enforcement is already gated.
_SPRINT_8_5_OFF_GATE_MODULES = ("src/cognic_agentos/sandbox/reaper.py",)


def test_sprint_8_5_modules_present_with_standard_floors(
    gate_tool: ModuleType,
) -> None:
    """The 2 Sprint 8.5 T12 promotions are on the gate at the 95/90 floor."""
    by_path = {path: (line, branch) for path, line, branch in gate_tool._CRITICAL_FILES}
    for module in _SPRINT_8_5_GATE_MODULES:
        assert module in by_path, f"Sprint 8.5 module missing from gate: {module}"
        assert by_path[module] == (0.95, 0.90), (
            f"{module} must ride the standard 95%-line / 90%-branch floor"
        )


@pytest.mark.parametrize("off_gate_module", _SPRINT_8_5_OFF_GATE_MODULES)
def test_sprint_8_5_off_gate_modules_absent(gate_tool: ModuleType, off_gate_module: str) -> None:
    """``sandbox/reaper.py`` stays OFF the durable gate per the spec
    §4.2 + Doctrine F carve-out. A future edit that promotes it without
    revisiting the rationale fails here, forcing a deliberate review."""
    paths = {path for path, _line, _branch in gate_tool._CRITICAL_FILES}
    assert off_gate_module not in paths


# ---------------------------------------------------------------------------
# Sprint 9 T10 — ISO 42001 control-mapping gate promotion (+4 → 77)
# ---------------------------------------------------------------------------

#: The 4 modules Sprint 9 T10 promotes to the durable gate — the
#: compliance/iso42001 evidence layer (ADR-006). Per
#: ``feedback_verify_promotion_meets_floor_at_promotion_time`` the T10
#: commit ALSO runs ``tools/check_critical_coverage.py`` against fresh
#: ``coverage.json`` — not just this count-guard bump.
_SPRINT_9_GATE_MODULES = (
    "src/cognic_agentos/compliance/iso42001/controls.py",
    "src/cognic_agentos/compliance/iso42001/merkle.py",
    "src/cognic_agentos/compliance/iso42001/signing.py",
    "src/cognic_agentos/compliance/iso42001/evidence_pack.py",
)

#: The 3 NEW Sprint 9 portal route modules deliberately kept OFF the
#: durable gate — ``portal/api/compliance/`` is portal-surface routing,
#: not the iso42001 runtime; same off-gate treatment as the Sprint-7B.2
#: ``inspection_routes.py`` precedent. The substantive evidence logic is
#: gated via the 4 ``_SPRINT_9_GATE_MODULES`` above.
_SPRINT_9_OFF_GATE_MODULES = (
    "src/cognic_agentos/portal/api/compliance/router.py",
    "src/cognic_agentos/portal/api/compliance/evidence_pack_routes.py",
    "src/cognic_agentos/portal/api/compliance/trace_routes.py",
)


def test_sprint_9_modules_present_with_standard_floors(
    gate_tool: ModuleType,
) -> None:
    """The 4 Sprint 9 T10 promotions are on the gate at the 95/90 floor."""
    by_path = {path: (line, branch) for path, line, branch in gate_tool._CRITICAL_FILES}
    for module in _SPRINT_9_GATE_MODULES:
        assert module in by_path, f"Sprint 9 module missing from gate: {module}"
        assert by_path[module] == (0.95, 0.90), (
            f"{module} must ride the standard 95%-line / 90%-branch floor"
        )


@pytest.mark.parametrize("off_gate_module", _SPRINT_9_OFF_GATE_MODULES)
def test_sprint_9_off_gate_modules_absent(gate_tool: ModuleType, off_gate_module: str) -> None:
    """The ``portal/api/compliance/`` route modules stay OFF the durable
    gate. A future edit that promotes one without revisiting the
    rationale fails here, forcing a deliberate review."""
    paths = {path for path, _line, _branch in gate_tool._CRITICAL_FILES}
    assert off_gate_module not in paths


#: The 4 Sprint 10 Z1 promotions (Vault credential-leasing quartet).
#: All ride the standard 95%-line / 90%-branch floor. The 4th entry
#: (``sandbox/backends/_shared_credentials.py``) was added per the
#: Round-7 Gap O doctrinal-fit decision — wire-protocol-public
#: artifact owner (Vault exception → ``SandboxRefusalReason`` closed-
#: enum mapping), not consumer-owned helper.
_SPRINT_10_GATE_MODULES = (
    "src/cognic_agentos/core/vault.py",
    "src/cognic_agentos/core/_vault_transport.py",
    "src/cognic_agentos/sandbox/credentials.py",
    "src/cognic_agentos/sandbox/backends/_shared_credentials.py",
)


#: Sandbox-tree modules that explicitly STAY OFF the gate per the
#: Doctrine F carve-out precedent (consumer-owned helpers /
#: thin-glue modules whose substantive enforcement lives in their
#: on-gate consumers). A future promotion of any of these would
#: revisit the doctrinal-fit rationale at the consumer-owned-helper
#: vs wire-public-artifact-owner boundary — distinct from the Gap O
#: Sprint-10 decision that promoted ``_shared_credentials.py``
#: precisely because it's NOT consumer-owned.
_SPRINT_10_OFF_GATE_MODULES = (
    # Consumer-owned: K8s primary consumer; Docker inlines the equivalent.
    "src/cognic_agentos/sandbox/backends/_shared_exec.py",
    # Thin chain-row converter for the sandbox lifecycle event taxonomies;
    # substantive audit-chain invariants enforced upstream by the on-gate
    # core/audit.py + core/decision_history.py + core/canonical.py.
    "src/cognic_agentos/sandbox/audit.py",
    # Pure selection seam (~130 LoC); wire-protocol-public contract is
    # the Settings.sandbox_backend Literal arm set + the
    # COGNIC_SANDBOX_BACKEND env-var override per ADR-004 §32 (drift
    # detector at tests/unit/sandbox/test_backend_factory.py pins
    # lockstep). Substantive enforcement lives in the chosen backend's
    # methods which ARE both on the gate.
    "src/cognic_agentos/sandbox/backend_factory.py",
)


def test_sprint_10_modules_present_with_standard_floors(
    gate_tool: ModuleType,
) -> None:
    """The 4 Sprint 10 Z1 promotions are on the gate at the 95/90 floor."""
    by_path = {path: (line, branch) for path, line, branch in gate_tool._CRITICAL_FILES}
    for module in _SPRINT_10_GATE_MODULES:
        assert module in by_path, f"Sprint 10 module missing from gate: {module}"
        assert by_path[module] == (0.95, 0.90), (
            f"{module} must ride the standard 95%-line / 90%-branch floor"
        )


@pytest.mark.parametrize("off_gate_module", _SPRINT_10_OFF_GATE_MODULES)
def test_sprint_10_off_gate_modules_absent(gate_tool: ModuleType, off_gate_module: str) -> None:
    """The 3 sandbox-tree Doctrine F carve-outs stay OFF the durable
    gate. A future edit that promotes one without revisiting the
    consumer-owned-helper vs wire-public-artifact-owner doctrinal
    fit fails here, forcing a deliberate review (the Round-7 Gap O
    pre-flight is the precedent: ``_shared_credentials.py`` got
    promoted ONLY after the wire-public-artifact-owner case was
    explicit; same scrutiny required for any future sandbox-tree
    promotion)."""
    paths = {path for path, _line, _branch in gate_tool._CRITICAL_FILES}
    assert off_gate_module not in paths
