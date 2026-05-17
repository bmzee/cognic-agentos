"""Sprint 7B.3 T11 — count-guard self-test for the critical-controls gate.

``tools/check_critical_coverage.py`` carries the durable per-file
critical-controls coverage gate as the module-level ``_CRITICAL_FILES``
tuple. The gate grows sprint-by-sprint; the failure mode this suite
guards against is a *silent shrink* — an edit that drops an entry (a
bad merge, an over-eager refactor) would weaken the gate without any
test noticing, because the production ``main()`` only checks the
coverage of whatever entries happen to be present.

This is the self-test the Round-19 plan patch mandates. It pins:
  * the exact entry count (60 after the Sprint 7B.3 T3-T7 promotions);
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

#: Entry count after the Sprint 8A T12 promotions (63 at the 7B.4
#: T13 close + 7 sandbox modules = 70). Bump this in lockstep with
#: any deliberate ``_CRITICAL_FILES`` change.
_EXPECTED_ENTRY_COUNT = 70

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
#: - ``sandbox/credentials.py``: re-export shim (38 lines; zero new
#:   logic). Canonical home of ``CredentialAdapter`` +
#:   ``KernelDefaultCredentialAdapter`` is ``sandbox/admission.py``
#:   (which IS on the gate); ``sandbox/credentials.py`` re-exports so
#:   Sprint 10's real ``VaultCredentialAdapter`` can replace the
#:   canonical-home module without rewriting consumers. Sprint 10's
#:   real adapter goes ON the gate when it lands.
_SPRINT_8A_OFF_GATE_MODULES = (
    "src/cognic_agentos/sandbox/audit.py",
    "src/cognic_agentos/sandbox/credentials.py",
)


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
    """2 Sprint 8A modules stay OFF the durable gate per the in-source
    8A docstring carve-outs (``sandbox/audit.py`` thin chain-row
    converter + ``sandbox/credentials.py`` re-export shim).

    A future edit that promotes either without revisiting the spec §17
    rationale fails here, forcing a deliberate review."""
    paths = {path for path, _line, _branch in gate_tool._CRITICAL_FILES}
    assert off_gate_module not in paths
