"""Sprint 6 T6 — protocol/a2a_schema.py contract tests.

Pins the schema module's two invariants:

1. **Kernel-image admission-side import safety** — the module imports
   cleanly without ``a2a-sdk`` installed (the SDK is in the
   ``adapters`` extras only, not the kernel image). Module-level
   constants (``A2A_SPEC_VERSION``, ``_PINNED_PROTOBUF_DIGEST``,
   ``_UPSTREAM_PROTOBUF_URL``) remain accessible without the SDK.

2. **SDK type re-export contract** — every name in
   :data:`_REEXPORTED_TYPE_NAMES` resolves to the actual ``a2a.types``
   class on first access (and only then — lazy via PEP 562
   ``__getattr__``). The 7 types serialize + round-trip through the
   protobuf wire-format.

Per Sprint-6 plan-of-record §T6 + T2 R1 P2 reviewer correction: the
correct SDK type names are ``StreamResponse`` (NOT
``StreamingMessage``), ``CancelTaskRequest`` (NOT
``CancellationRequest``), and per-error-code typed classes (NOT a
single ``ErrorResponse``). Verified against ``a2a-sdk == 1.0.2``.
"""

from __future__ import annotations

import importlib

import pytest

from cognic_agentos.protocol.a2a_schema import (
    _PINNED_PROTOBUF_DIGEST,
    _REEXPORTED_TYPE_NAMES,
    _UPSTREAM_PROTOBUF_URL,
    A2A_SPEC_VERSION,
    get_pinned_spec_version,
)


class TestSpecVersionPin:
    """:data:`A2A_SPEC_VERSION` + :func:`get_pinned_spec_version` are
    the single source of truth for the pinned A2A spec version."""

    def test_spec_version_matches_doctrine(self) -> None:
        """Per ADR-003 + A2A-CONFORMANCE.md: pinned to A2A 1.0."""
        assert A2A_SPEC_VERSION == "1.0"

    def test_get_pinned_spec_version_returns_constant(self) -> None:
        assert get_pinned_spec_version() == A2A_SPEC_VERSION


class TestPinnedDigestShape:
    """The pinned protobuf digest is a SHA-256 hex string captured
    at T6 commit time from the canonical upstream URL."""

    def test_pinned_digest_is_64_char_hex(self) -> None:
        assert len(_PINNED_PROTOBUF_DIGEST) == 64
        # SHA-256 hex digests are lowercase hex; the placeholder
        # "0" * 64 would also satisfy this — that's fine, the
        # drift gate (env-gated) is the actual content check.
        assert all(c in "0123456789abcdef" for c in _PINNED_PROTOBUF_DIGEST)

    def test_pinned_digest_not_zero_placeholder(self) -> None:
        """T6 captured a real digest from the upstream URL; the
        ``"0" * 64`` placeholder from the plan-of-record skeleton was
        replaced with the actual SHA-256 at commit time."""
        assert _PINNED_PROTOBUF_DIGEST != "0" * 64, (
            "Placeholder digest still in place — T6 capture-time work "
            "did not populate the real digest"
        )

    def test_upstream_url_pinned_to_v1_tag(self) -> None:
        """Pin to the ``v1.0.0`` git tag (NOT ``main``) so spec-
        authors' WIP on main doesn't trip the gate; only a deliberate
        spec-author decision to update v1.0.0 (or our own decision to
        bump the pinned tag) trips it."""
        assert "v1.0.0" in _UPSTREAM_PROTOBUF_URL
        assert "/a2aproject/A2A/" in _UPSTREAM_PROTOBUF_URL
        assert _UPSTREAM_PROTOBUF_URL.endswith("/specification/a2a.proto")


class TestReexportedTypeNamesContract:
    """Pin the 7-type re-export set so a future edit that adds or
    drops a name must update both the source module and this test
    surface."""

    def test_reexported_set_has_seven_types(self) -> None:
        """The Wave-1 wire-format surface comprises exactly 7 types
        per the plan-of-record §File Structure."""
        assert len(_REEXPORTED_TYPE_NAMES) == 7

    def test_reexported_set_matches_doctrine(self) -> None:
        """The exact 7 names per T2 R1 P2 reviewer correction —
        verified against ``a2a-sdk == 1.0.2``'s ``a2a.types``
        exports."""
        expected = {
            "AgentCard",
            "Artifact",
            "CancelTaskRequest",
            "StreamResponse",
            "Task",
            "TaskArtifactUpdateEvent",
            "TaskStatusUpdateEvent",
        }
        assert set(_REEXPORTED_TYPE_NAMES) == expected

    def test_pre_T2_R1_P2_drafted_names_NOT_in_reexport_set(self) -> None:
        """**T2 R1 P2 contract test:** the pre-correction draft used
        ``StreamingMessage`` / ``CancellationRequest`` /
        ``ErrorResponse`` — names that DO NOT exist in
        ``a2a-sdk == 1.0.2``. This regression pins the corrected
        names so a future edit that re-introduces the wrong names
        trips immediately."""
        assert "StreamingMessage" not in _REEXPORTED_TYPE_NAMES
        assert "CancellationRequest" not in _REEXPORTED_TYPE_NAMES
        assert "ErrorResponse" not in _REEXPORTED_TYPE_NAMES


class TestLazyAttributeResolution:
    """The 7 SDK types resolve via PEP 562 ``__getattr__`` on first
    access. Pattern: module imports without SDK (admission-side
    invariant); attribute access fires ``require_a2a()`` then
    returns the SDK class.

    This test class runs in the venv where ``a2a-sdk`` IS installed
    (the unit suite uses ``--all-extras``). The kernel-image-import
    contract — module imports cleanly with the SDK absent — is
    pinned by ``test_optional_dep_loader.py`` via the
    ``stub_a2a_missing`` fixture.
    """

    @pytest.fixture(autouse=True)
    def _reset_module(self) -> None:
        """Reset the module's lazy-resolution cache between tests
        so each arm starts from a clean state. Without this reset,
        the first arm's lazy access caches the resolved name into
        globals() and subsequent arms wouldn't exercise
        ``__getattr__``."""
        import cognic_agentos.protocol.a2a_schema as schema_module

        for name in _REEXPORTED_TYPE_NAMES:
            schema_module.__dict__.pop(name, None)

    @pytest.mark.parametrize("name", sorted(_REEXPORTED_TYPE_NAMES))
    def test_each_reexported_name_resolves_to_sdk_class(self, name: str) -> None:
        """Each name resolves to the ``a2a.types`` class on first
        access. Confirms the lazy ``__getattr__`` finds the real SDK
        class (not a placeholder / not the wrong name)."""
        from a2a import types as a2a_types

        import cognic_agentos.protocol.a2a_schema as schema_module

        resolved = getattr(schema_module, name)
        expected = getattr(a2a_types, name)
        assert resolved is expected, (
            f"Lazy __getattr__ resolved {name!r} to a different class "
            f"than a2a.types.{name}; got {resolved} vs {expected}"
        )

    def test_first_access_caches_in_module_dict(self) -> None:
        """After the first attribute access, the resolved name is
        cached into the module's ``__dict__`` so subsequent accesses
        skip ``__getattr__``."""
        import cognic_agentos.protocol.a2a_schema as schema_module

        # Before access — name not in dict.
        assert "AgentCard" not in schema_module.__dict__
        # First access fires __getattr__.
        first = schema_module.AgentCard
        # After access — name cached in dict.
        assert "AgentCard" in schema_module.__dict__
        # Subsequent access returns the same cached object (no
        # second __getattr__ call would produce a different one,
        # but pin the identity equality for clarity).
        second = schema_module.AgentCard
        assert first is second

    def test_unknown_name_raises_attribute_error(self) -> None:
        """Names NOT in :data:`_REEXPORTED_TYPE_NAMES` fall through
        to ``AttributeError`` — typos in ``from a2a_schema import X``
        surface immediately rather than being silently silently
        looked up in ``a2a.types``."""
        import cognic_agentos.protocol.a2a_schema as schema_module

        with pytest.raises(AttributeError) as exc:
            _ = schema_module.NonExistentTypo
        assert "NonExistentTypo" in str(exc.value)


class TestProtobufRoundTrip:
    """The 7 re-exported types are protobuf message classes —
    serialize via ``.SerializeToString()`` and round-trip via
    ``Class.FromString(bytes)``. Round-trip equality across the
    full type set proves the re-exports are usable + the wire-format
    is intact (catches a future SDK change that breaks serialization
    without changing the type names).

    NB: protobuf message types do NOT carry a ``model_validate`` /
    ``model_dump`` Pydantic surface — the plan's draft mentioned
    "Pydantic round-trip" but the actual SDK ships protobuf-
    generated classes. T6 corrects to protobuf round-trip via
    ``SerializeToString`` / ``FromString``.
    """

    def test_agent_card_protobuf_roundtrip(self) -> None:
        from cognic_agentos.protocol.a2a_schema import AgentCard

        original = AgentCard(
            name="cognic_test_agent",
            description="Sprint-6 T6 round-trip canary",
            version="1.0.0",
        )
        wire = original.SerializeToString()
        restored = AgentCard.FromString(wire)
        assert restored.name == "cognic_test_agent"
        assert restored.description == "Sprint-6 T6 round-trip canary"
        assert restored.version == "1.0.0"

    def test_task_protobuf_roundtrip(self) -> None:
        from cognic_agentos.protocol.a2a_schema import Task

        original = Task(id="task-001", context_id="ctx-abc")
        wire = original.SerializeToString()
        restored = Task.FromString(wire)
        assert restored.id == "task-001"
        assert restored.context_id == "ctx-abc"

    def test_artifact_protobuf_roundtrip(self) -> None:
        from cognic_agentos.protocol.a2a_schema import Artifact

        original = Artifact(artifact_id="art-001", name="evidence-pack")
        wire = original.SerializeToString()
        restored = Artifact.FromString(wire)
        assert restored.artifact_id == "art-001"
        assert restored.name == "evidence-pack"

    def test_cancel_task_request_protobuf_roundtrip(self) -> None:
        from cognic_agentos.protocol.a2a_schema import CancelTaskRequest

        # Per a2a-sdk == 1.0.2 schema: CancelTaskRequest fields are
        # ``tenant`` / ``id`` / ``metadata``.
        original = CancelTaskRequest(tenant="bank_a", id="task-001")
        wire = original.SerializeToString()
        restored = CancelTaskRequest.FromString(wire)
        assert restored.tenant == "bank_a"
        assert restored.id == "task-001"

    def test_stream_response_is_message_class(self) -> None:
        """``StreamResponse`` is the streaming-update envelope.
        Verify it's a protobuf Message class with the expected
        DESCRIPTOR — full round-trip needs a populated payload
        which the streaming module (T10) constructs."""
        from cognic_agentos.protocol.a2a_schema import StreamResponse

        assert hasattr(StreamResponse, "DESCRIPTOR")
        assert hasattr(StreamResponse, "SerializeToString")
        assert hasattr(StreamResponse, "FromString")

    def test_task_artifact_update_event_roundtrip(self) -> None:
        from cognic_agentos.protocol.a2a_schema import TaskArtifactUpdateEvent

        original = TaskArtifactUpdateEvent(task_id="task-001", context_id="ctx-abc")
        wire = original.SerializeToString()
        restored = TaskArtifactUpdateEvent.FromString(wire)
        assert restored.task_id == "task-001"
        assert restored.context_id == "ctx-abc"

    def test_task_status_update_event_roundtrip(self) -> None:
        from cognic_agentos.protocol.a2a_schema import TaskStatusUpdateEvent

        original = TaskStatusUpdateEvent(task_id="task-001", context_id="ctx-abc")
        wire = original.SerializeToString()
        restored = TaskStatusUpdateEvent.FromString(wire)
        assert restored.task_id == "task-001"
        assert restored.context_id == "ctx-abc"


class TestModuleAdmissionSideInvariant:
    """The module is on the admission-side floor per
    :data:`_A2A_ADMISSION_SIDE_MODULES` in
    ``test_optional_dep_loader.py``. This class adds light
    smoke-tests that the module's NON-SDK surface (constants,
    ``__all__``, ``get_pinned_spec_version``) is reachable without
    triggering SDK loading."""

    def test_module_constants_accessible_without_lazy_resolution(self) -> None:
        """:data:`A2A_SPEC_VERSION` + :data:`_PINNED_PROTOBUF_DIGEST`
        + :data:`_UPSTREAM_PROTOBUF_URL` are eager module-level
        constants — accessing them does NOT fire the lazy SDK
        loader.

        ``importlib.reload`` is necessary because earlier tests in
        this module may have cached lazy resolutions into the
        module's ``__dict__``. The reload re-runs the module body,
        producing a fresh dict containing only the eager constants.
        Note: ``importlib.reload`` does NOT re-import dependencies
        — the ``from cognic_agentos.protocol import require_a2a``
        line still resolves to the already-imported package — so
        the admission-side invariant under test is preserved
        regardless of import order."""
        import cognic_agentos.protocol.a2a_schema as schema_module

        # Clear lazy-cached names BEFORE reload so the reload
        # rebuilds a clean dict from the module body alone.
        for name in _REEXPORTED_TYPE_NAMES:
            schema_module.__dict__.pop(name, None)

        importlib.reload(schema_module)
        # Eager constants — accessible, no SDK touch.
        assert schema_module.A2A_SPEC_VERSION == "1.0"
        assert len(schema_module._PINNED_PROTOBUF_DIGEST) == 64
        assert "v1.0.0" in schema_module._UPSTREAM_PROTOBUF_URL
        # SDK type names NOT yet in module dict (lazy).
        for name in _REEXPORTED_TYPE_NAMES:
            assert name not in schema_module.__dict__, (
                f"SDK type {name!r} eagerly bound at module load — "
                f"breaks the admission-side import contract"
            )

    def test_all_lists_public_surface_only(self) -> None:
        """``__all__`` covers the public surface: the spec-version
        constant + the version accessor + the 7 lazy SDK types. The
        pinned-digest + upstream-URL constants are module-private
        (underscore-prefixed) by convention and are NOT in ``__all__``;
        the drift CI gate reads them via explicit named import."""
        import cognic_agentos.protocol.a2a_schema as schema_module

        all_names = set(schema_module.__all__)
        # Public eager constants + accessor
        assert "A2A_SPEC_VERSION" in all_names
        assert "get_pinned_spec_version" in all_names
        # All 7 lazy SDK types
        assert all_names >= _REEXPORTED_TYPE_NAMES
        # Module-private constants stay out of __all__ by convention.
        assert "_PINNED_PROTOBUF_DIGEST" not in all_names
        assert "_UPSTREAM_PROTOBUF_URL" not in all_names
