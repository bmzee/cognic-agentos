# mypy: disable-error-code="misc,unused-ignore"
"""Sprint-7A T3 — `agentos_sdk.testing` fixtures + assertion helpers.

Public pack-author API. Pack ``conftest.py`` re-imports the fixture
names + uses them by name in tests; the assertion helpers are called
directly. Per Doctrine Decision E, every commit touching this surface
halts before commit (semver-stability concern).

Test arms:

  (a) ``fixture_settings`` — returns a real ``Settings`` instance
      pointed at memory-backed adapters (rooted at ``tmp_path``).
  (b) ``fixture_tool_registry`` — returns a ``ToolRegistry``-conformant
      object built from the live ``cognic.tools`` entry-point group.
  (c) ``fixture_audit_capture`` — yields a callable that returns a
      list of ``AuditEvent`` projections of every event appended to
      the captured in-memory ``AuditStore``.
  (d) ``assert_manifest_validates`` — runs the ``agentos validate``
      pipeline against ``pack_path``; raises ``NotImplementedError``
      pointing at Sprint-7A T6 if the orchestrator isn't yet wired.
      (T6 wiring drops the NotImplementedError + makes this test
      flip to a real-validation assertion.)
  (e) ``assert_a2a_envelope_well_formed`` — parses the envelope
      through the A2A 1.0 SDK re-export (``StreamResponse`` then
      ``Task``); ``AssertionError`` on neither matching.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# (a) fixture_settings
# ---------------------------------------------------------------------------


def test_fixture_settings_is_a_pytest_fixture() -> None:
    """The exported name carries pytest's fixture marker so pack-author
    ``conftest.py`` can re-export it via plain ``from … import …``."""
    from cognic_agentos.sdk import testing as sdk_testing

    assert hasattr(sdk_testing.fixture_settings, "_fixture_function_marker")


def test_fixture_settings_returns_memory_adapter_settings(tmp_path: Path) -> None:
    """Calling the fixture's underlying function with ``tmp_path``
    yields a ``Settings`` instance whose driver fields all point at
    ``"memory"`` and whose object-store root is ``tmp_path``."""
    from cognic_agentos.core.config import Settings
    from cognic_agentos.sdk.testing import fixture_settings

    fn = fixture_settings.__wrapped__  # type: ignore[attr-defined]
    s = fn(tmp_path)

    assert isinstance(s, Settings)
    assert s.db_driver == "memory"
    assert s.vector_driver == "memory"
    assert s.secret_driver == "memory"
    assert s.embed_driver == "memory"
    assert s.obs_driver == "memory"
    assert s.local_object_store_root == tmp_path


# ---------------------------------------------------------------------------
# (b) fixture_tool_registry
# ---------------------------------------------------------------------------


def test_fixture_tool_registry_is_a_pytest_fixture() -> None:
    from cognic_agentos.sdk import testing as sdk_testing

    assert hasattr(sdk_testing.fixture_tool_registry, "_fixture_function_marker")


def test_fixture_tool_registry_conforms_to_protocol() -> None:
    """The fixture's underlying function returns an object that
    structurally satisfies the ``ToolRegistry`` Protocol — at minimum
    it has callable ``get`` and ``list_tools`` attributes."""
    from cognic_agentos.sdk.registry import ToolRegistry
    from cognic_agentos.sdk.testing import fixture_tool_registry

    fn = fixture_tool_registry.__wrapped__  # type: ignore[attr-defined]
    registry = fn()

    # Structural conformance via the runtime_checkable Protocol.
    assert isinstance(registry, ToolRegistry)


def test_fixture_tool_registry_lists_zero_tools_when_no_entry_points() -> None:
    """In the AgentOS dev environment there are no registered
    ``cognic.tools`` entry-point providers (those land in pack repos),
    so the discovered list is empty. Pack-author tests run inside an
    installed pack where the entry-point group is non-empty; the
    AgentOS-side regression pins the empty case as the failure-loud
    guarantee."""
    from cognic_agentos.sdk.testing import fixture_tool_registry

    fn = fixture_tool_registry.__wrapped__  # type: ignore[attr-defined]
    registry = fn()

    assert registry.list_tools() == []


# ---------------------------------------------------------------------------
# (c) fixture_audit_capture
# ---------------------------------------------------------------------------


def test_fixture_audit_capture_is_a_pytest_fixture() -> None:
    from cognic_agentos.sdk import testing as sdk_testing

    assert hasattr(sdk_testing.fixture_audit_capture, "_fixture_function_marker")


async def test_fixture_audit_capture_records_appended_events(tmp_path: Path) -> None:
    """The fixture wires an in-memory ``AuditStore`` + post-commit
    hook; calling the returned closure flushes captured events.
    After appending one event, the closure returns a one-element
    list whose ``event_type`` matches what was appended."""
    from cognic_agentos.core.audit import AuditEvent
    from cognic_agentos.sdk.testing import _build_audit_capture_pair

    # Use the underlying builder rather than the fixture's pytest
    # wrapper so the test exercises the wiring directly without
    # nesting fixture-machinery.
    store, engine, capture = await _build_audit_capture_pair(tmp_path)
    try:
        await store.append(
            AuditEvent(
                event_type="tool_invocation",
                request_id="r-1",
                payload={"tool": "echo"},
                tenant_id="bank-acme",
            )
        )
        events = capture()
        assert len(events) == 1
        assert events[0].event_type == "tool_invocation"
        assert events[0].request_id == "r-1"
        assert events[0].tenant_id == "bank-acme"
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# (d) assert_manifest_validates — T6 forward dependency
# ---------------------------------------------------------------------------


def test_assert_manifest_validates_refuses_pack_without_manifest(tmp_path: Path) -> None:
    """T6 wired ``cognic_agentos.cli.validate.run_validators``. The
    SDK helper now delegates into it: when ``pack_path`` has no
    manifest, the orchestrator returns one refusal-severity finding
    and ``assert_manifest_validates`` raises ``AssertionError`` with
    the closed-enum reason in the rendered remediation copy.

    (Pre-T6 this test asserted ``NotImplementedError`` against the
    forward-declared stub; the flip pins the working behaviour.)
    """
    from cognic_agentos.sdk.testing import assert_manifest_validates

    with pytest.raises(AssertionError, match="manifest_not_found"):
        assert_manifest_validates(tmp_path)


def test_assert_manifest_validates_passes_pack_with_clean_manifest(tmp_path: Path) -> None:
    """Happy path: a manifest that passes the orchestrator's shape
    gate AND every per-concern validator that has shipped at this
    commit (T7 identity).

    The [identity] block carries every Wave-1 mandatory field
    populated with realistic values so T7 returns no refusals; the
    Wave-1 warning ``identity_oasf_capability_set_missing`` is
    silenced by declaring ``oasf_capability_set``. T8-T12 are still
    stubs returning ``[]`` so this manifest currently passes; once
    those validators ship real refusals the test's manifest grows
    to cover their clean-pass shape too."""
    from cognic_agentos.sdk.testing import assert_manifest_validates

    (tmp_path / "cognic-pack-manifest.toml").write_text(
        """\
[pack]
pack_id = "cognic-tool-test"
kind = "tool"

[identity]
agent_id = "did:web:example.com:tools:test"
display_name = "Test Tool"
provider_organization = "Example Org"
provider_url = "https://example.com"
oasf_capability_set = ["test.v1"]

[data_governance]
data_classes = ["public", "internal"]
purpose = "operational_telemetry"
retention_policy = "none"

[risk_tier]
tier = "read_only"

[supply_chain]
"""
    )
    # No exception — orchestrator returns no refusals.
    assert_manifest_validates(tmp_path)


# ---------------------------------------------------------------------------
# (e) assert_a2a_envelope_well_formed
# ---------------------------------------------------------------------------


def test_assert_a2a_envelope_well_formed_accepts_valid_stream_response() -> None:
    """A protobuf-JSON serialised ``StreamResponse`` round-trip
    matches the SDK re-export's wire format and the helper returns
    None."""
    from google.protobuf.json_format import MessageToDict

    from cognic_agentos.protocol.a2a_schema import StreamResponse, Task
    from cognic_agentos.sdk.testing import assert_a2a_envelope_well_formed

    # Build via the SDK class itself — the canonical valid envelope.
    sr = StreamResponse(task=Task(id="t-1", context_id="c-1"))
    envelope = MessageToDict(sr, preserving_proto_field_name=False)

    assert_a2a_envelope_well_formed(envelope)


def test_assert_a2a_envelope_well_formed_rejects_garbage() -> None:
    """An envelope with no field that maps to any A2A 1.0 top-level
    shape raises ``AssertionError``."""
    from cognic_agentos.sdk.testing import assert_a2a_envelope_well_formed

    with pytest.raises(AssertionError, match="A2A"):
        assert_a2a_envelope_well_formed({"not_an_a2a_field": True})


def test_assert_a2a_envelope_well_formed_takes_dict_and_returns_none() -> None:
    """Signature shape pin: ``(envelope: dict[str, Any]) -> None``.
    The static signature is the contract pack-authors write against."""
    from cognic_agentos.sdk.testing import assert_a2a_envelope_well_formed

    sig = inspect.signature(assert_a2a_envelope_well_formed)
    params = list(sig.parameters.values())
    assert len(params) == 1
    assert params[0].name == "envelope"
    assert sig.return_annotation in (None, type(None), "None")


# ---------------------------------------------------------------------------
# (e.bis) R15 P2 #1 — presence checks reject semantically empty envelopes
# ---------------------------------------------------------------------------


def test_assert_a2a_envelope_well_formed_rejects_empty_dict() -> None:
    """``{}`` parses as both a default ``StreamResponse`` AND a
    default ``Task`` — the wire layer would accept it, but a Wave-1
    envelope with no active payload arm is not meaningful. R15 P2 #1
    pins the rejection so pack tests cannot bless empty output."""
    from cognic_agentos.sdk.testing import assert_a2a_envelope_well_formed

    with pytest.raises(AssertionError, match="payload oneof arm"):
        assert_a2a_envelope_well_formed({})


def test_assert_a2a_envelope_well_formed_rejects_default_task_arm() -> None:
    """``{"task": {}}`` parses with active oneof arm ``"task"`` but
    the embedded Task has empty ``id`` / ``context_id``. The presence
    check refuses this even though wire-shape parse succeeds."""
    from cognic_agentos.sdk.testing import assert_a2a_envelope_well_formed

    with pytest.raises(AssertionError, match="missing one or more required"):
        assert_a2a_envelope_well_formed({"task": {}})


def test_assert_a2a_envelope_well_formed_rejects_partial_task_top_level() -> None:
    """``{"id": "t-1"}`` parses as a Task with ``id`` set but
    ``context_id`` empty — the Task fallback path's presence check
    refuses this."""
    from cognic_agentos.sdk.testing import assert_a2a_envelope_well_formed

    with pytest.raises(AssertionError, match="id, context_id"):
        assert_a2a_envelope_well_formed({"id": "t-1"})


def test_assert_a2a_envelope_well_formed_rejects_default_status_update_arm() -> None:
    """``{"statusUpdate": {}}`` parses with active arm
    ``"status_update"`` but missing ``task_id`` — refused."""
    from cognic_agentos.sdk.testing import assert_a2a_envelope_well_formed

    with pytest.raises(AssertionError, match="status_update"):
        assert_a2a_envelope_well_formed({"statusUpdate": {}})


def test_assert_a2a_envelope_well_formed_accepts_populated_task_top_level() -> None:
    """Happy path on the Task fallback: top-level Task with both
    required identifiers populated parses + passes presence check."""
    from cognic_agentos.sdk.testing import assert_a2a_envelope_well_formed

    assert_a2a_envelope_well_formed({"id": "t-1", "contextId": "c-1"})
