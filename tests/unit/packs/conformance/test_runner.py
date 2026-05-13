"""Tests for the thin OWASP-conformance → chain-payload adapter (Sprint 7B.2 T9).

Per the user-locked T9 Slice-2 contract:

- ``packs/conformance/runner.py`` is the WIRE-SHAPE boundary between the
  :mod:`packs.conformance.owasp_agentic` check matrix and the
  :data:`DecisionRecord.payload["conformance"]` chain-row key.
- The single public seam :func:`run_owasp_conformance_for_chain_payload`
  consumes a manifest dict and returns a JSON-serialisable ``dict[str, Any]``
  whose top-level keys EXACTLY match the
  :class:`cognic_agentos.packs.conformance.checks.ConformanceReport` 4-field
  shape: ``overall_status`` / ``results`` / ``summary`` /
  ``errored_categories``.  T9 Slice 4 promoted this adapter to the durable
  critical-controls coverage gate alongside ``packs/conformance/checks.py``
  + ``packs/conformance/owasp_agentic.py`` at the 95%/90% floor.

This file pins the wire-protocol-public shape against the same drift class
(``dataclasses.asdict`` vs. hand-rolled dict) that :class:`ConformanceReport`'s
4-field-order test in ``test_owasp_runner.py`` defends — the chain-payload-
serialised shape MUST round-trip the dataclass shape verbatim so T9 chain rows
remain readable by 7B.3 reviewer evidence consumers.
"""

from __future__ import annotations

from typing import Any

_BASE_TOOL_MANIFEST: dict[str, Any] = {
    "pack": {"kind": "tool", "name": "demo", "version": "1.0.0"},
    "identity": {
        "agent_id": "cognic.demo.v1",
        "display_name": "Demo",
        "provider_organization": "Acme",
        "provider_url": "https://acme.example",
    },
    "risk_tier": {"tier": "read_only"},
}


class TestSprint7B2T9RunnerAdapter:
    """Pin the chain-payload serialization adapter's wire-shape contract."""

    def test_run_owasp_conformance_for_chain_payload_is_callable(self) -> None:
        from cognic_agentos.packs.conformance.runner import (
            run_owasp_conformance_for_chain_payload,
        )

        assert callable(run_owasp_conformance_for_chain_payload)

    def test_returns_a_dict(self) -> None:
        from cognic_agentos.packs.conformance.runner import (
            run_owasp_conformance_for_chain_payload,
        )

        result = run_owasp_conformance_for_chain_payload(_BASE_TOOL_MANIFEST)
        assert isinstance(result, dict)

    def test_returns_exactly_four_top_level_keys(self) -> None:
        """User-locked Slice-2 contract: the chain-payload-serialised dict
        carries EXACTLY the 4 fields of :class:`ConformanceReport` — drift in
        either direction (missing key OR extra key) breaks 7B.3 reviewer
        consumers AND the chain-payload byte-shape stability invariant."""
        from cognic_agentos.packs.conformance.runner import (
            run_owasp_conformance_for_chain_payload,
        )

        result = run_owasp_conformance_for_chain_payload(_BASE_TOOL_MANIFEST)
        assert set(result.keys()) == {
            "overall_status",
            "results",
            "summary",
            "errored_categories",
        }

    def test_overall_status_is_green_red_or_yellow_string(self) -> None:
        from cognic_agentos.packs.conformance.runner import (
            run_owasp_conformance_for_chain_payload,
        )

        result = run_owasp_conformance_for_chain_payload(_BASE_TOOL_MANIFEST)
        assert isinstance(result["overall_status"], str)
        assert result["overall_status"] in {"green", "red", "yellow"}

    def test_results_is_dict_keyed_by_owasp_category_strings(self) -> None:
        import typing

        from cognic_agentos.packs.conformance.checks import OWASPCheckCategory
        from cognic_agentos.packs.conformance.runner import (
            run_owasp_conformance_for_chain_payload,
        )

        result = run_owasp_conformance_for_chain_payload(_BASE_TOOL_MANIFEST)
        assert isinstance(result["results"], dict)
        # Every key is one of the 10 OWASP-category Literal values.
        for key in result["results"]:
            assert key in set(typing.get_args(OWASPCheckCategory))

    def test_summary_is_string(self) -> None:
        from cognic_agentos.packs.conformance.runner import (
            run_owasp_conformance_for_chain_payload,
        )

        result = run_owasp_conformance_for_chain_payload(_BASE_TOOL_MANIFEST)
        assert isinstance(result["summary"], str)
        assert "pass" in result["summary"]

    def test_errored_categories_is_list_after_asdict_conversion(self) -> None:
        """``dataclasses.asdict`` recursively converts tuples → lists; the
        chain-payload-serialised shape carries ``errored_categories`` as a
        list (NOT a tuple).  Tests pin the post-conversion shape so JSON
        serializers (which already coerce tuples → lists) round-trip
        deterministically through the chain row."""
        from cognic_agentos.packs.conformance.runner import (
            run_owasp_conformance_for_chain_payload,
        )

        result = run_owasp_conformance_for_chain_payload(_BASE_TOOL_MANIFEST)
        assert isinstance(result["errored_categories"], list)

    def test_per_check_result_carries_category_status_findings_keys(self) -> None:
        """Each value in ``results`` is itself a dict (``ConformanceCheckResult``
        dataclass after ``asdict``) carrying the 3 expected keys."""
        from cognic_agentos.packs.conformance.runner import (
            run_owasp_conformance_for_chain_payload,
        )

        result = run_owasp_conformance_for_chain_payload(_BASE_TOOL_MANIFEST)
        for category, per_check in result["results"].items():
            assert isinstance(per_check, dict), (
                f"{category}: expected dict, got {type(per_check).__name__}"
            )
            assert set(per_check.keys()) == {"category", "status", "findings"}

    def test_round_trip_through_json_serializer_preserves_shape(self) -> None:
        """The chain-payload-serialised dict MUST be JSON-serializable
        deterministically; pin via round-trip through stdlib ``json``."""
        import json

        from cognic_agentos.packs.conformance.runner import (
            run_owasp_conformance_for_chain_payload,
        )

        result = run_owasp_conformance_for_chain_payload(_BASE_TOOL_MANIFEST)
        rehydrated = json.loads(json.dumps(result))
        assert set(rehydrated.keys()) == set(result.keys())
        assert rehydrated["overall_status"] == result["overall_status"]
