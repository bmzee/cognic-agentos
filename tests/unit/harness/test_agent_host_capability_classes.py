"""D-S1 Task 4: compose signed per-tool capability-class declarations."""

from collections.abc import Iterator
from typing import Any

import pytest

from cognic_agentos.harness import agent_host
from cognic_agentos.harness.agent_host import build_tool_capability_classes
from cognic_agentos.protocol.mcp_manifest import (
    PackManifestMalformedError,
    PackManifestNotFoundError,
)
from cognic_agentos.protocol.plugin_registry import RegisteredPackCandidate


class _FakeRegistry:
    """Structural registry stub carrying the real candidate projection."""

    def __init__(self, candidates: list[RegisteredPackCandidate]) -> None:
        self._candidates = candidates

    def iter_registered_pack_candidates(self) -> Iterator[RegisteredPackCandidate]:
        return iter(self._candidates)


def _candidate(
    distribution_name: str,
    *,
    package_name: str,
) -> RegisteredPackCandidate:
    return RegisteredPackCandidate(
        distribution_name=distribution_name,
        package_name=package_name,
        signature_digest="sha256:" + "ab" * 32,
    )


def test_map_is_keyed_by_full_ref_and_uses_candidate_package_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests = {
        "cognic-tool-oracle-schema": {
            "tool": {
                "cognic": {
                    "tools": [
                        {
                            "name": "run_readonly_query",
                            "capability_class": "data_query",
                        },
                        {"name": "list_schemas", "capability_class": "unscoped"},
                    ]
                }
            }
        }
    }
    extraction_calls: list[tuple[str, str]] = []

    def _extract(
        *,
        distribution_name: str,
        package_name: str,
    ) -> dict[str, Any]:
        extraction_calls.append((distribution_name, package_name))
        return manifests[distribution_name]

    monkeypatch.setattr(agent_host, "extract_pack_manifest", _extract)
    registry = _FakeRegistry(
        [
            _candidate(
                "cognic-tool-oracle-schema",
                package_name="signed_oracle_package",
            )
        ]
    )

    assert build_tool_capability_classes(registry) == {
        "cognic-tool-oracle-schema/run_readonly_query": "data_query",
        "cognic-tool-oracle-schema/list_schemas": "unscoped",
    }
    assert extraction_calls == [("cognic-tool-oracle-schema", "signed_oracle_package")]


def test_a_pack_with_no_tools_block_contributes_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        agent_host,
        "extract_pack_manifest",
        lambda **_kwargs: {"tool": {"cognic": {"mcp": {}}}},
    )
    registry = _FakeRegistry([_candidate("legacy-pack", package_name="legacy_package")])

    assert build_tool_capability_classes(registry) == {}


@pytest.mark.parametrize(
    "error_type",
    [PackManifestNotFoundError, PackManifestMalformedError],
)
def test_unreadable_registered_manifest_contributes_nothing(
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[Exception],
) -> None:
    def _raise(**_kwargs: Any) -> dict[str, Any]:
        raise error_type("broken-pack")

    monkeypatch.setattr(agent_host, "extract_pack_manifest", _raise)
    registry = _FakeRegistry([_candidate("broken-pack", package_name="broken_package")])

    assert build_tool_capability_classes(registry) == {}


def test_only_nonempty_string_name_and_class_entries_are_projected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = {
        "tool": {
            "cognic": {
                "tools": [
                    7,
                    {"name": "missing-class"},
                    {"capability_class": "unscoped"},
                    {"name": "", "capability_class": "unscoped"},
                    {"name": "valid", "capability_class": "future_class"},
                ]
            }
        }
    }
    monkeypatch.setattr(
        agent_host,
        "extract_pack_manifest",
        lambda **_kwargs: manifest,
    )
    registry = _FakeRegistry([_candidate("mixed-pack", package_name="mixed_package")])

    assert build_tool_capability_classes(registry) == {"mixed-pack/valid": "future_class"}
