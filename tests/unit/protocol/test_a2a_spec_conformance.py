"""Sprint-6 T13 — A2A 1.0 conformance fixture runner.

Walks every JSON fixture under ``tests/fixtures/a2a-conformance/``
and dispatches each against the appropriate Sprint-6 validator:

  - ``valid/`` — fixture MUST be accepted by the matching validator.
  - ``invalid/`` — fixture MUST be rejected with the spec error code
    declared in the sibling ``<name>_expected.json``.

Fixtures are JSON-RPC-2.0 envelopes / protobuf-JSON ``StreamResponse``
encodings / declarative ``fixture_kind`` shapes that target a
specific validator (the kinds map to T6 protobuf parse, T8 version
negotiator, T11 capability reader, or T9's wave2 classifier — no
single fixture exercises all of them).

The runner is parameterised on the fixture filenames so a future
addition to either directory grows the test count automatically.
This is the test net that catches drift between the shipped Sprint-6
modules and the A2A 1.0 spec contract.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Fixture discovery
# ---------------------------------------------------------------------------


_REPO_ROOT = Path(__file__).resolve().parents[3]
_CONFORMANCE_DIR = _REPO_ROOT / "tests" / "fixtures" / "a2a-conformance"
_VALID_DIR = _CONFORMANCE_DIR / "valid"
_INVALID_DIR = _CONFORMANCE_DIR / "invalid"


def _valid_fixtures() -> list[Path]:
    return sorted(_VALID_DIR.glob("*.json"))


def _invalid_fixtures() -> list[Path]:
    """Pair each invalid fixture with its sibling _expected.json
    (the expected file is itself a *.json — filter those out so we
    don't iterate the metadata files as inputs)."""
    return sorted(p for p in _INVALID_DIR.glob("*.json") if not p.name.endswith("_expected.json"))


def _expected_for(fixture_path: Path) -> dict[str, Any]:
    expected_path = fixture_path.with_name(fixture_path.stem + "_expected.json")
    result: dict[str, Any] = json.loads(expected_path.read_text())
    return result


# ---------------------------------------------------------------------------
# Valid fixture runner
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture_path", _valid_fixtures(), ids=lambda p: p.stem)
class TestValidConformanceFixtures:
    """Each valid fixture MUST be accepted by the appropriate
    Sprint-6 validator. The runner inspects ``fixture_kind`` (or
    falls back to JSON-RPC envelope shape) to dispatch."""

    def test_valid_fixture_accepted(self, fixture_path: Path) -> None:
        data = json.loads(fixture_path.read_text())
        kind = data.get("fixture_kind") or _infer_kind(data)
        if kind == "version_header":
            self._assert_version_header_accepted(data)
        elif kind == "manifest_capabilities":
            self._assert_capabilities_accepted(data)
        elif kind == "task_request":
            self._assert_task_request_well_formed(data)
        elif kind == "stream_response":
            self._assert_stream_response_well_formed(data)
        elif kind == "cancellation_request":
            self._assert_cancellation_request_well_formed(data)
        else:  # pragma: no cover (defensive — every fixture has a kind)
            pytest.fail(f"unknown fixture_kind for {fixture_path.name}: {kind}")

    @staticmethod
    def _assert_version_header_accepted(data: dict[str, Any]) -> None:
        from cognic_agentos.protocol.a2a_version import (
            negotiate_inbound_version,
        )

        decision = negotiate_inbound_version(a2a_version_header=data["header_value"])
        assert decision.outcome in ("accepted", "higher_minor_degraded"), (
            f"valid version-header fixture {data['header_value']!r} got "
            f"unexpected outcome {decision.outcome!r}"
        )

    @staticmethod
    def _assert_capabilities_accepted(data: dict[str, Any]) -> None:
        from cognic_agentos.protocol.a2a_capability_negotiation import (
            read_pack_capabilities,
        )

        caps = read_pack_capabilities(data["manifest"])
        # Passes iff the read returns a populated A2ACapabilities (the
        # manifest declared at least one Wave-1 field).
        assert caps.streaming or caps.artifacts_supported or caps.capabilities_supported, (
            "valid capabilities fixture produced an empty A2ACapabilities — "
            "manifest declarations should pass through verbatim"
        )

    @staticmethod
    def _assert_task_request_well_formed(data: dict[str, Any]) -> None:
        # JSON-RPC 2.0 envelope checks: jsonrpc=2.0, method present,
        # params is a dict.
        assert data.get("jsonrpc") == "2.0"
        assert isinstance(data.get("method"), str)
        assert isinstance(data.get("params"), dict)

    @staticmethod
    def _assert_stream_response_well_formed(data: dict[str, Any]) -> None:
        # Protobuf-JSON StreamResponse: exactly one of the four oneof
        # fields (statusUpdate / artifactUpdate / task / message)
        # MUST be present.
        oneof_fields = {"statusUpdate", "artifactUpdate", "task", "message"}
        present = oneof_fields & set(data.keys())
        assert len(present) == 1, (
            f"valid stream-response fixture must have exactly one of "
            f"{sorted(oneof_fields)}; found {sorted(present)}"
        )

    @staticmethod
    def _assert_cancellation_request_well_formed(data: dict[str, Any]) -> None:
        # JSON-RPC 2.0 envelope shape.
        assert data.get("jsonrpc") == "2.0"
        assert data.get("method") == "tasks/cancel"
        assert isinstance(data.get("params"), dict)
        # T13 R1 P2 #3: ``params`` MUST round-trip through the
        # pinned A2A 1.0 SDK ``CancelTaskRequest`` (fields are
        # ``tenant`` / ``id`` / ``metadata`` — there is no
        # ``name`` field).
        from google.protobuf import json_format

        from cognic_agentos.protocol.a2a_schema import CancelTaskRequest

        json_format.ParseDict(data["params"], CancelTaskRequest())


def _infer_kind(data: dict[str, Any]) -> str:
    """Fall back to JSON-RPC method / StreamResponse oneof to infer
    the fixture kind when ``fixture_kind`` isn't declared."""
    method = data.get("method")
    if method == "tasks/cancel":
        return "cancellation_request"
    if method in ("message/send", "message/stream"):
        return "task_request"
    if "statusUpdate" in data or "artifactUpdate" in data or "task" in data or "message" in data:
        return "stream_response"
    return "unknown"


# ---------------------------------------------------------------------------
# Invalid fixture runner
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture_path", _invalid_fixtures(), ids=lambda p: p.stem)
class TestInvalidConformanceFixtures:
    """Each invalid fixture MUST be rejected with the spec error
    code declared in the sibling ``_expected.json``. The runner
    dispatches by ``fixture_kind`` to the appropriate validator
    (version negotiator / wave2 classifier / capability reader /
    walker bound)."""

    def test_invalid_fixture_rejected(self, fixture_path: Path) -> None:
        data = json.loads(fixture_path.read_text())
        expected = _expected_for(fixture_path)
        kind = data.get("fixture_kind", "unknown")

        if kind == "version_header":
            self._assert_version_header_rejected(data, expected)
        elif kind == "wave2_payload":
            self._assert_wave2_payload_refused(data, expected)
        elif kind == "wave2_payload_oversized":
            self._assert_oversized_payload_unscannable(data, expected)
        elif kind == "manifest_capabilities":
            self._assert_capabilities_filtered(data, expected)
        else:  # pragma: no cover
            pytest.fail(f"unknown invalid-fixture kind: {kind}")

    @staticmethod
    def _assert_version_header_rejected(data: dict[str, Any], expected: dict[str, Any]) -> None:
        from cognic_agentos.protocol.a2a_version import (
            negotiate_inbound_version,
        )

        decision = negotiate_inbound_version(a2a_version_header=data["header_value"])
        assert decision.outcome == expected["outcome"], (
            f"version-header fixture {data['header_value']!r} expected "
            f"outcome {expected['outcome']!r}, got {decision.outcome!r}"
        )
        # The spec wire code surfaces as version_not_supported per
        # T9's _on_version_negotiation_failure path.
        assert expected["spec_code"] == "version_not_supported"

    @staticmethod
    def _assert_wave2_payload_refused(data: dict[str, Any], expected: dict[str, Any]) -> None:
        from cognic_agentos.protocol.a2a_endpoint import A2AEndpoint

        payload_bytes = data["payload_bytes"].encode("utf-8")
        feature = A2AEndpoint._classify_wave2_feature(payload_bytes)
        assert feature == expected["wave2_feature"], (
            f"wave2 fixture expected feature {expected['wave2_feature']!r}, got {feature!r}"
        )

    @staticmethod
    def _assert_oversized_payload_unscannable(
        data: dict[str, Any], expected: dict[str, Any]
    ) -> None:
        """Construct a deeply-nested JSON payload at runtime
        (committing the bytes would bloat the repo). Verify the
        wave-2 classifier returns ``"payload_unscannable"`` —
        either via the iterative walker's depth bound (T9 R3 P2)
        or via json.loads' RecursionError mapping (T9 R5 P2).
        """
        from cognic_agentos.protocol.a2a_endpoint import A2AEndpoint

        depth = data["depth"]
        leaf = data["leaf"]
        # Build nested {"a": {"a": ... "x"}} at the configured depth.
        opens = b'{"a":' * depth
        closes = b"}" * depth
        payload_bytes = opens + b'"' + leaf.encode() + b'"' + closes
        feature = A2AEndpoint._classify_wave2_feature(payload_bytes)
        assert feature == expected["wave2_feature"]

    @staticmethod
    def _assert_capabilities_filtered(data: dict[str, Any], expected: dict[str, Any]) -> None:
        """Capability reader filters fixtures don't raise — they
        return an :class:`A2ACapabilities` with the offending
        declaration filtered. The expected metadata declares which
        field was filtered + what value it should land at."""
        from cognic_agentos.protocol.a2a_capability_negotiation import (
            read_pack_capabilities,
        )

        caps = read_pack_capabilities(data["manifest"])
        if "expect_streaming_value" in expected:
            assert caps.streaming is expected["expect_streaming_value"]
        if "expect_push_notifications_value" in expected:
            assert caps.push_notifications is expected["expect_push_notifications_value"]
        if "expect_deferred_contains" in expected:
            assert expected["expect_deferred_contains"] in caps.deferred_wave2_features


# ---------------------------------------------------------------------------
# Coverage drift detector
# ---------------------------------------------------------------------------


class TestFixtureSetCoverage:
    """Pin the fixture-set count so a future deletion trips this
    test before the parameterised runners silently skip a case."""

    def test_valid_fixture_count(self) -> None:
        # Sprint-6 T13 ships 10 valid fixtures.
        assert len(_valid_fixtures()) == 10

    def test_invalid_fixture_count(self) -> None:
        # Sprint-6 T13 ships 9 invalid fixtures.
        assert len(_invalid_fixtures()) == 9

    def test_every_invalid_has_expected_sibling(self) -> None:
        for fixture in _invalid_fixtures():
            expected = fixture.with_name(fixture.stem + "_expected.json")
            assert expected.is_file(), (
                f"invalid fixture {fixture.name} missing sibling {expected.name}"
            )

    def test_every_invalid_expected_has_validator(self) -> None:
        """Pin that every expected file declares which validator
        surfaces the rejection — keeps the test runner's dispatch
        table aligned with the fixture set."""
        for fixture in _invalid_fixtures():
            expected = _expected_for(fixture)
            assert expected.get("validator"), (
                f"{fixture.name}_expected.json missing 'validator' field"
            )
