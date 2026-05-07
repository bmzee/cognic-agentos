"""Sprint 6 T11 — protocol/a2a_capability_negotiation.py contract tests.

Backs ``GET /api/v1/a2a/capabilities``. Reads pack manifests'
declarations under the canonical FLAT ``[tool.cognic.a2a]`` block
(per ``docs/A2A-CONFORMANCE.md`` §"What pack authors must declare"
+ ``docs/BUILD_PLAN.md``) and returns the Wave-1-filtered
:class:`A2ACapabilities` response.

T11 R1 doctrines pinned by these tests:

  - **Flat manifest shape (R1 P2 #1).** Reader navigates to the
    FLAT ``[tool.cognic.a2a]`` block, NOT a nested
    ``[tool.cognic.a2a.capabilities]`` sub-section. Manifest
    field names match the canonical schema:
    ``capabilities_supported`` (list[str]), ``streaming`` (bool),
    ``push_notification_config`` (bool — Wave-2),
    ``artifacts_supported`` (bool), ``extended_agent_card`` (bool),
    ``extensions`` (list[str]).

  - **Strict bool typing (R1 P2 #2).** Boolean fields require the
    actual ``bool`` Python type — non-bool values (truthy strings,
    non-empty dicts/lists, ``None``) are treated as ``False``
    regardless of truthiness. Pack authors who want a flag enabled
    MUST declare an actual TOML ``true`` / ``false``.

  - **Declared subset only.** The returned subset is ⊆ what the
    manifest declared; never invents capabilities.

  - **Wave-2 filtered.** ``push_notification_config = true``
    forced to false; surfaced in ``deferred_wave2_features``.
"""

from __future__ import annotations

from typing import Any

import pytest

from cognic_agentos.protocol.a2a_capability_negotiation import (
    A2ACapabilities,
    read_pack_capabilities,
)

# =============================================================================
# Helper: build a manifest with FLAT [tool.cognic.a2a] fields
# =============================================================================


def _manifest(**fields: Any) -> dict[str, Any]:
    """Build a parsed-TOML-shaped dict with the canonical FLAT
    ``[tool.cognic.a2a]`` block."""
    return {"tool": {"cognic": {"a2a": fields}}}


# =============================================================================
# Module shape
# =============================================================================


class TestModuleShape:
    def test_a2a_capabilities_required_fields(self) -> None:
        import dataclasses

        fields = {f.name for f in dataclasses.fields(A2ACapabilities)}
        required = {
            "capabilities_supported",
            "streaming",
            "push_notifications",
            "extended_agent_card",
            "artifacts_supported",
            "extensions",
            "deferred_wave2_features",
        }
        assert required <= fields, f"missing fields: {required - fields}"

    def test_a2a_capabilities_defaults(self) -> None:
        caps = A2ACapabilities()
        assert caps.capabilities_supported == ()
        assert caps.streaming is False
        assert caps.push_notifications is False
        assert caps.extended_agent_card is False
        assert caps.artifacts_supported is False
        assert caps.extensions == ()
        assert caps.deferred_wave2_features == ()


# =============================================================================
# Empty / absent / malformed shapes — fail-closed
# =============================================================================


class TestEmptyManifest:
    def test_completely_empty_manifest(self) -> None:
        assert read_pack_capabilities({}) == A2ACapabilities()

    def test_no_tool_section(self) -> None:
        assert read_pack_capabilities({"project": {"name": "x"}}) == A2ACapabilities()

    def test_no_cognic_section(self) -> None:
        assert read_pack_capabilities({"tool": {"poetry": {}}}) == A2ACapabilities()

    def test_no_a2a_section(self) -> None:
        assert read_pack_capabilities({"tool": {"cognic": {"identity": {}}}}) == A2ACapabilities()

    def test_a2a_section_not_a_dict(self) -> None:
        """Defence against malformed manifests — ``[tool.cognic.a2a]``
        MUST be a dict; anything else treated as absent."""
        manifest = {"tool": {"cognic": {"a2a": "not-a-dict"}}}
        assert read_pack_capabilities(manifest) == A2ACapabilities()

    def test_top_level_a2a_section_not_a_dict(self) -> None:
        """R24 P2 #1: defensive against malformed top-level ``[a2a]``
        too. A scalar value at the top-level key falls through to the
        legacy fallback path."""
        manifest = {"a2a": "not-a-dict"}
        assert read_pack_capabilities(manifest) == A2ACapabilities()

    def test_top_level_tool_not_a_dict_falls_through(self) -> None:
        """R24 P2 #1: ``[tool]`` set to a scalar (improbable but
        possible from a malformed manifest) does not crash the path
        walker — the runtime reader returns an empty result instead."""
        assert read_pack_capabilities({"tool": "not-a-table"}) == A2ACapabilities()

    def test_top_level_tool_cognic_not_a_dict_falls_through(self) -> None:
        """R24 P2 #1: ``[tool.cognic]`` set to a scalar is also
        defended."""
        assert read_pack_capabilities({"tool": {"cognic": "not-a-table"}}) == A2ACapabilities()


# =============================================================================
# R24 P2 #1 — top-level [a2a] shape (T5 cognic-pack-manifest canonical)
# =============================================================================


class TestTopLevelA2AShape:
    """Sprint-7A T5 introduced cognic-pack-manifest.toml's top-level
    ``[a2a]`` layout. The runtime reader accepts that shape directly so
    a scaffolded pack's declared capabilities reach runtime registration
    without re-arrangement. The historical ``[tool.cognic.a2a]`` shape
    stays supported as a backward-compat fallback."""

    def test_top_level_a2a_streaming_round_trip(self) -> None:
        manifest = {"a2a": {"streaming": True}}
        caps = read_pack_capabilities(manifest)
        assert caps.streaming is True

    def test_top_level_a2a_capabilities_supported(self) -> None:
        manifest = {"a2a": {"capabilities_supported": ["regulatory_qa", "citation_grounded"]}}
        caps = read_pack_capabilities(manifest)
        assert caps.capabilities_supported == ("regulatory_qa", "citation_grounded")

    def test_top_level_a2a_wave2_field_filtered_to_deferred(self) -> None:
        """``push_notification_config = true`` at top-level is still
        Wave-2-filtered; the runtime reader surfaces it under
        ``deferred_wave2_features`` with ``push_notifications=False``."""
        manifest = {"a2a": {"push_notification_config": True}}
        caps = read_pack_capabilities(manifest)
        assert caps.push_notifications is False
        assert "push_notification_config" in caps.deferred_wave2_features

    def test_top_level_a2a_takes_precedence_over_legacy(self) -> None:
        """If a manifest carries BOTH shapes (unusual but possible
        during a migration), the canonical top-level shape wins —
        otherwise scaffold + runtime would disagree on what's
        advertised."""
        manifest = {
            "a2a": {"streaming": True},
            "tool": {"cognic": {"a2a": {"streaming": False, "artifacts_supported": True}}},
        }
        caps = read_pack_capabilities(manifest)
        # Top-level wins → streaming=True, artifacts_supported=False
        # (the legacy block's True is ignored).
        assert caps.streaming is True
        assert caps.artifacts_supported is False


class TestScaffoldRuntimeLifecycle:
    """R24 P2 #1 lifecycle pinner: T5's ``agentos init-agent``
    scaffolder produces a cognic-pack-manifest.toml whose ``[a2a]``
    block flows cleanly into the runtime reader. Without this pinner,
    a future scaffold-template drift would silently hide capabilities
    from runtime callers (the original break R24 caught)."""

    def test_scaffolded_agent_pack_capabilities_reach_runtime_reader(self, tmp_path: Any) -> None:
        import tomllib

        from cognic_agentos.cli.init import scaffold

        pack_root = scaffold(kind="agent", pack_name="example", parent_dir=tmp_path)
        manifest_text = (pack_root / "cognic-pack-manifest.toml").read_text()
        # Flip a Wave-1 capability so we can assert the runtime reader
        # actually surfaces it (default scaffold has streaming=false).
        manifest_text = manifest_text.replace("streaming = false", "streaming = true").replace(
            "artifacts_supported = false", "artifacts_supported = true"
        )
        manifest = tomllib.loads(manifest_text)

        caps = read_pack_capabilities(manifest)
        assert caps.streaming is True, (
            "scaffolded agent pack's streaming capability did not reach "
            "the runtime reader; scaffold + reader are out of alignment"
        )
        assert caps.artifacts_supported is True
        # Also confirm the Wave-1-clean default scaffold doesn't emit
        # spurious deferred Wave-2 features.
        assert caps.deferred_wave2_features == ()


# =============================================================================
# Wave-1 manifest fields — flat schema
# =============================================================================


class TestFlatManifestSchema:
    """T11 R1 P2 #1 — fields are read from the FLAT
    ``[tool.cognic.a2a]`` block per the canonical conformance shape."""

    def test_canonical_full_manifest(self) -> None:
        """A canonical manifest matching the A2A-CONFORMANCE.md
        example block round-trips cleanly through the reader."""
        manifest = _manifest(
            spec_version="1.0",
            agent_card_url="https://packs.cognic.ai/agent_cards/policy_qa.json",
            agent_card_jws_path="agent_cards/policy_qa.jws",
            capabilities_supported=["regulatory_qa", "citation_grounded"],
            streaming=True,
            push_notification_config=False,
            artifacts_supported=True,
            auth_scheme="bearer",
        )
        caps = read_pack_capabilities(manifest)
        assert caps.capabilities_supported == ("regulatory_qa", "citation_grounded")
        assert caps.streaming is True
        assert caps.push_notifications is False  # Wave-2, always False
        assert caps.artifacts_supported is True
        assert caps.deferred_wave2_features == ()  # nothing was filtered

    def test_capabilities_supported_passthrough(self) -> None:
        caps = read_pack_capabilities(_manifest(capabilities_supported=["a", "b", "c"]))
        assert caps.capabilities_supported == ("a", "b", "c")

    def test_capabilities_supported_filters_non_strings(self) -> None:
        caps = read_pack_capabilities(_manifest(capabilities_supported=["a", 42, "b", None, "c"]))
        assert caps.capabilities_supported == ("a", "b", "c")

    def test_capabilities_supported_non_list_treated_empty(self) -> None:
        caps = read_pack_capabilities(_manifest(capabilities_supported="not-a-list"))
        assert caps.capabilities_supported == ()

    def test_streaming_true(self) -> None:
        caps = read_pack_capabilities(_manifest(streaming=True))
        assert caps.streaming is True

    def test_streaming_false(self) -> None:
        caps = read_pack_capabilities(_manifest(streaming=False))
        assert caps.streaming is False

    def test_artifacts_supported_true(self) -> None:
        caps = read_pack_capabilities(_manifest(artifacts_supported=True))
        assert caps.artifacts_supported is True

    def test_extended_agent_card_true(self) -> None:
        caps = read_pack_capabilities(_manifest(extended_agent_card=True))
        assert caps.extended_agent_card is True

    def test_extensions_list(self) -> None:
        caps = read_pack_capabilities(_manifest(extensions=["urn:a2a:ext:foo", "urn:a2a:ext:bar"]))
        assert caps.extensions == ("urn:a2a:ext:foo", "urn:a2a:ext:bar")


# =============================================================================
# Strict bool typing (T11 R1 P2 #2)
# =============================================================================


class TestStrictBoolTyping:
    """T11 R1 P2 #2 — boolean fields require the actual ``bool``
    Python type. Truthy non-bool shapes (``"false"``, ``"no"``,
    ``[0]``, ``{"x": 0}``) MUST be treated as ``False``, not
    silently promoted via ``bool(value)`` truthiness coercion."""

    @pytest.mark.parametrize(
        "truthy_non_bool",
        [
            "false",  # truthy non-empty string
            "no",
            "0",
            "True",  # str(True), still a string
            [0],  # truthy list
            [False],
            {"key": "value"},  # truthy dict
            42,  # truthy int (1, 42 — both "True"-promoting under bool())
            1,
        ],
    )
    def test_streaming_non_bool_treated_false(self, truthy_non_bool: Any) -> None:
        caps = read_pack_capabilities(_manifest(streaming=truthy_non_bool))
        assert caps.streaming is False, (
            f"streaming={truthy_non_bool!r} (type {type(truthy_non_bool).__name__}) "
            f"MUST be treated as False — strict bool typing per R1 P2 #2"
        )

    @pytest.mark.parametrize(
        "truthy_non_bool",
        ["false", "no", [0], {"key": "v"}, 1, 42],
    )
    def test_artifacts_supported_non_bool_treated_false(self, truthy_non_bool: Any) -> None:
        caps = read_pack_capabilities(_manifest(artifacts_supported=truthy_non_bool))
        assert caps.artifacts_supported is False

    @pytest.mark.parametrize(
        "truthy_non_bool",
        ["false", "no", [0], {"key": "v"}, 1, 42],
    )
    def test_extended_agent_card_non_bool_treated_false(self, truthy_non_bool: Any) -> None:
        caps = read_pack_capabilities(_manifest(extended_agent_card=truthy_non_bool))
        assert caps.extended_agent_card is False

    @pytest.mark.parametrize(
        "truthy_non_bool",
        ["true", "yes", [1], {"key": "v"}, 1, 42],
    )
    def test_push_notification_non_bool_does_not_trigger_deferred(
        self, truthy_non_bool: Any
    ) -> None:
        """A manifest declaring ``push_notification_config = "true"``
        (truthy string) MUST NOT enter ``deferred_wave2_features``
        — it's not a valid declaration. Only an actual bool ``True``
        triggers the Wave-2 filter + deferred-tracking."""
        caps = read_pack_capabilities(_manifest(push_notification_config=truthy_non_bool))
        assert caps.push_notifications is False
        assert caps.deferred_wave2_features == ()

    def test_none_treated_false(self) -> None:
        """Explicit ``None`` value (TOML allows nulls in some
        dialects, JSON-converted manifests carry them) MUST be
        ``False``."""
        caps = read_pack_capabilities(_manifest(streaming=None))
        assert caps.streaming is False


# =============================================================================
# Wave-2 filtering — push_notification_config (canonical manifest name)
# =============================================================================


class TestWave2Filtering:
    """Per Decision Lock #2: ``push_notification_config = true`` in
    the manifest is forced to false. The dropped declaration is
    surfaced via ``deferred_wave2_features`` so operators see what
    was filtered."""

    def test_push_notification_config_true_filtered(self) -> None:
        caps = read_pack_capabilities(_manifest(streaming=True, push_notification_config=True))
        assert caps.streaming is True
        assert caps.push_notifications is False
        assert "push_notification_config" in caps.deferred_wave2_features

    def test_push_notification_config_false_no_deferred_entry(self) -> None:
        caps = read_pack_capabilities(_manifest(streaming=True, push_notification_config=False))
        assert caps.deferred_wave2_features == ()

    def test_push_notification_config_absent_no_deferred_entry(self) -> None:
        caps = read_pack_capabilities(_manifest(streaming=True))
        assert caps.deferred_wave2_features == ()


# =============================================================================
# Subset invariant — never invent capabilities
# =============================================================================


class TestSubsetInvariant:
    def test_streaming_true_only_when_declared(self) -> None:
        assert read_pack_capabilities({}).streaming is False
        assert read_pack_capabilities(_manifest(streaming=True)).streaming is True
        assert read_pack_capabilities(_manifest(streaming=False)).streaming is False

    def test_capabilities_supported_subset_of_declarations(self) -> None:
        declared = ["urn:a2a:cap:a", "urn:a2a:cap:b"]
        caps = read_pack_capabilities(_manifest(capabilities_supported=declared))
        assert set(caps.capabilities_supported) == set(declared)

    def test_artifacts_supported_only_when_declared(self) -> None:
        assert read_pack_capabilities({}).artifacts_supported is False
        assert (
            read_pack_capabilities(_manifest(artifacts_supported=True)).artifacts_supported is True
        )
