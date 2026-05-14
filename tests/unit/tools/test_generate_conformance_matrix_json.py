"""Sprint 7B.3 T6 Slice A — conformance-matrix JSON generator + drift detector.

Per the plan-of-record Round Flag #8 (R10 LOCKED): the conformance
matrix data source is a **static-shipped JSON projection generated at
build time**. ``tools/generate_conformance_matrix_json.py`` parses the
two authoritative conformance docs (``docs/MCP-CONFORMANCE.md`` +
``docs/A2A-CONFORMANCE.md``) once at build time → emits
``src/cognic_agentos/packs/evidence/conformance_matrix.json`` which the
T6 panel projector loads at module import. Runtime NEVER parses
Markdown.

This module is the **build-time drift detector** R10 mandates: it
re-runs the generator over the live Markdown sources + asserts the
result matches the committed JSON byte-for-byte. A docs edit that
changes a capability's Wave-1 posture without regenerating the JSON
fails this test — forcing a deliberate regenerate-and-review.

The generator is a ``tools/`` script (no ``__init__.py`` in ``tools/``;
mirrors ``tools/check_critical_coverage.py``); the test loads it via
:func:`importlib.util.spec_from_file_location` from the repo-root path.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_GENERATOR_PATH = _REPO_ROOT / "tools" / "generate_conformance_matrix_json.py"
_COMMITTED_JSON_PATH = (
    _REPO_ROOT / "src" / "cognic_agentos" / "packs" / "evidence" / "conformance_matrix.json"
)

_VALID_WAVE_1_POSTURES: frozenset[str] = frozenset({"supported", "restricted", "forbidden"})


def _load_generator() -> ModuleType:
    """Load the ``tools/`` generator script as an importable module."""
    spec = importlib.util.spec_from_file_location(
        "generate_conformance_matrix_json", _GENERATOR_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def generator() -> ModuleType:
    return _load_generator()


class TestSprint7B3T6SliceAGeneratorShape:
    """The generator extracts an ``{mcp, a2a}`` two-protocol projection."""

    def test_top_level_keys_are_mcp_and_a2a(self, generator: ModuleType) -> None:
        matrix = generator.generate_conformance_matrix()
        assert set(matrix.keys()) == {"mcp", "a2a"}

    def test_each_entry_carries_wave_1_posture(self, generator: ModuleType) -> None:
        matrix = generator.generate_conformance_matrix()
        for protocol_features in matrix.values():
            assert protocol_features  # non-empty
            for slug, entry in protocol_features.items():
                assert isinstance(slug, str) and slug
                assert entry["wave_1"] in _VALID_WAVE_1_POSTURES
                assert isinstance(entry["wave_2_promoted"], bool)


class TestSprint7B3T6SliceAMcpExtraction:
    """MCP capability rows classify by the Wave-1 emoji convention."""

    def test_tools_capability_is_supported(self, generator: ModuleType) -> None:
        matrix = generator.generate_conformance_matrix()
        assert matrix["mcp"]["tools"]["wave_1"] == "supported"

    def test_sampling_capability_is_restricted(self, generator: ModuleType) -> None:
        # `⚠️` in the Wave-1 cell → restricted posture.
        matrix = generator.generate_conformance_matrix()
        assert matrix["mcp"]["sampling"]["wave_1"] == "restricted"

    def test_roots_capability_is_restricted(self, generator: ModuleType) -> None:
        matrix = generator.generate_conformance_matrix()
        assert matrix["mcp"]["roots"]["wave_1"] == "restricted"

    def test_caching_capability_is_wave_2_promoted(self, generator: ModuleType) -> None:
        # MCP caching: ✅ Optional in Wave 1, `Required` in the Wave-2 column.
        matrix = generator.generate_conformance_matrix()
        assert matrix["mcp"]["caching"]["wave_1"] == "supported"
        assert matrix["mcp"]["caching"]["wave_2_promoted"] is True


class TestSprint7B3T6SliceAA2aExtraction:
    """A2A feature rows classify by the Wave-1 emoji convention."""

    def test_agent_cards_feature_is_supported(self, generator: ModuleType) -> None:
        matrix = generator.generate_conformance_matrix()
        assert matrix["a2a"]["agent_cards"]["wave_1"] == "supported"

    def test_multi_modal_payloads_feature_is_forbidden(self, generator: ModuleType) -> None:
        # `❌` in the Wave-1 cell → forbidden posture.
        matrix = generator.generate_conformance_matrix()
        assert matrix["a2a"]["multi_modal_payloads"]["wave_1"] == "forbidden"

    def test_federated_a2a_feature_is_forbidden(self, generator: ModuleType) -> None:
        matrix = generator.generate_conformance_matrix()
        assert matrix["a2a"]["federated_a2a_across_organisations"]["wave_1"] == "forbidden"

    def test_push_notification_config_is_restricted_and_wave_2_promoted(
        self, generator: ModuleType
    ) -> None:
        # `⚠️` Wave-1 + `Required` Wave-2 → restricted now, promoted later.
        matrix = generator.generate_conformance_matrix()
        entry = matrix["a2a"]["push_notification_config"]
        assert entry["wave_1"] == "restricted"
        assert entry["wave_2_promoted"] is True


class TestSprint7B3T6SliceADriftDetector:
    """R10 build-time drift detector — committed JSON MUST match the
    generator's output over the live Markdown sources."""

    def test_committed_json_matches_generator_output(self, generator: ModuleType) -> None:
        assert _COMMITTED_JSON_PATH.exists(), (
            f"committed conformance matrix JSON missing at {_COMMITTED_JSON_PATH} — "
            "run `python tools/generate_conformance_matrix_json.py` to regenerate"
        )
        committed = json.loads(_COMMITTED_JSON_PATH.read_text(encoding="utf-8"))
        regenerated = generator.generate_conformance_matrix()
        assert committed == regenerated, (
            "conformance_matrix.json is stale vs the Markdown sources — "
            "regenerate via `python tools/generate_conformance_matrix_json.py`"
        )

    def test_committed_json_is_deterministically_sorted(self) -> None:
        """The committed file is sorted (keys + 2-space indent) so a
        regenerate produces a minimal, reviewable diff."""
        raw = _COMMITTED_JSON_PATH.read_text(encoding="utf-8")
        parsed = json.loads(raw)
        canonical = json.dumps(parsed, indent=2, sort_keys=True) + "\n"
        assert raw == canonical
