"""Sprint-7A T3 — `agentos_sdk.testing` pytest fixtures + assertion helpers.

Pack-author API. A pack's ``conftest.py`` imports the fixtures by
name + uses them as fixture parameters in tests::

    # pack/tests/conftest.py
    from cognic_agentos.sdk.testing import (
        fixture_settings,
        fixture_tool_registry,
        fixture_audit_capture,
    )  # noqa: F401  (pytest fixture-discovery)

    # pack/tests/test_my_tool.py
    def test_my_tool_emits_audit(fixture_audit_capture):
        ...
        events = fixture_audit_capture()
        assert events[0].event_type == "tool_invocation"

The assertion helpers are called directly:

    from cognic_agentos.sdk.testing import (
        assert_manifest_validates,
        assert_a2a_envelope_well_formed,
    )

Per Doctrine Decision E, every commit touching this surface halts
before commit (semver-stability concern — banks build their pack
test suites against this contract).

Forward dependency:
  - :func:`assert_manifest_validates` lazy-imports the validate
    orchestrator from :mod:`cognic_agentos.cli.validate` (Sprint-7A
    T6). Until T6 lands, the helper raises ``NotImplementedError``
    citing the sprint task; once T6 lands, the import resolves and
    the helper delegates without code change here.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import importlib.util
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import (
    AppendedEventSnapshot,
    AuditEvent,
    AuditStore,
    _chain_heads,
    _metadata,
)
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.config import Settings, build_settings_without_env_file
from cognic_agentos.sdk.registry import ToolRegistry

if TYPE_CHECKING:
    from cognic_agentos.sdk.tool import Tool


# ---------------------------------------------------------------------------
# Settings fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def fixture_settings(tmp_path: Path) -> Settings:
    """Return a real :class:`Settings` instance pointed at memory-
    backed adapters.

    All driver fields collapse to ``"memory"`` so pack tests exercise
    governance + lifespan + ``/readyz`` without standing up Postgres
    / Qdrant / Vault / Ollama / Langfuse. The local-fs object-store
    root is ``tmp_path`` so per-test artifact writes stay isolated.

    Mirrors the AgentOS-internal ``memory_settings`` fixture in
    ``tests/conftest.py``; the SDK-side copy is what pack-author
    tests pull in via plain import.
    """
    return build_settings_without_env_file().model_copy(
        update={
            "db_driver": "memory",
            "vector_driver": "memory",
            "secret_driver": "memory",
            "embed_driver": "memory",
            "obs_driver": "memory",
            "local_object_store_root": tmp_path,
        }
    )


# ---------------------------------------------------------------------------
# ToolRegistry fixture
# ---------------------------------------------------------------------------


class _FixtureToolRegistry:
    """Dict-backed registry built from the live ``cognic.tools``
    entry-point group.

    Discovers registered tools via :func:`importlib.metadata.entry_points`
    + instantiates each with no constructor arguments (the SDK
    :class:`Tool` base has no required init parameters; pack-specific
    state goes in ClassVars).

    Structurally satisfies :class:`ToolRegistry` — ``get(name) ->
    Tool`` raises :class:`KeyError` for unknown names (mirrors
    ``dict.__getitem__``); ``list_tools()`` returns the discovered
    pack-ids in registration order.
    """

    def __init__(self, tools: dict[str, Tool]) -> None:
        self._tools = tools

    def get(self, name: str) -> Tool:
        return self._tools[name]

    def list_tools(self) -> list[str]:
        return list(self._tools)


def _load_entry_point_tools() -> dict[str, Tool]:
    """Resolve ``cognic.tools`` entry-points → instantiated tool
    map. Pack authors register entries via their ``pyproject.toml``
    ``[project.entry-points."cognic.tools"]`` table; this helper is
    the mirror of how the runtime MCP host (Sprint 5) discovers
    them, scoped to the pack's own test process.
    """
    tools: dict[str, Tool] = {}
    for entry in importlib.metadata.entry_points(group="cognic.tools"):
        cls = entry.load()
        instance = cls()
        tools[instance.name] = instance
    return tools


@pytest.fixture
def fixture_tool_registry() -> ToolRegistry:
    """Return a :class:`ToolRegistry`-conformant object pre-populated
    with the calling pack's declared ``cognic.tools`` entry-points.

    In the AgentOS dev environment the discovered list is empty
    (tools live in pack repos); in a pack's test environment the
    pack's installed entry-points populate the registry.
    """
    return _FixtureToolRegistry(_load_entry_point_tools())


# ---------------------------------------------------------------------------
# Audit-capture fixture
# ---------------------------------------------------------------------------


def _project_snapshot_to_event(snapshot: AppendedEventSnapshot) -> AuditEvent:
    """Re-project a post-commit :class:`AppendedEventSnapshot` back
    into the caller-side :class:`AuditEvent` shape.

    The snapshot carries six extra fields (``record_id``, ``chain_id``,
    ``sequence``, ``new_hash``, ``created_at``) the pack-author
    ``AuditEvent`` shape doesn't expose. The capture-list returns
    ``AuditEvent`` per the Sprint-7A plan signature.
    """
    return AuditEvent(
        event_type=snapshot.event_type,
        request_id=snapshot.request_id,
        payload=snapshot.payload,
        tenant_id=snapshot.tenant_id,
        trace_id=snapshot.trace_id,
        span_id=snapshot.span_id,
        langfuse_trace_id=snapshot.langfuse_trace_id,
        provider_label=snapshot.provider_label,
        iso_controls=snapshot.iso_controls,
    )


async def _build_audit_capture_pair(
    tmp_path: Path,
) -> tuple[AuditStore, AsyncEngine, Callable[[], list[AuditEvent]]]:
    """Build an aiosqlite-backed :class:`AuditStore` + capture closure
    pair. Lifecycle (engine dispose) is the caller's responsibility.

    Returns ``(store, engine, capture)``: the engine is returned
    separately so the caller's teardown disposes it cleanly without
    reaching into ``store._engine``.

    Underscore-prefixed because pack-author code uses the pytest
    fixture wrapper, NOT this builder directly. Exposed for the
    AgentOS-side regression in ``test_testing_fixtures.py`` to
    exercise the wiring without nesting fixtures.
    """
    url = f"sqlite+aiosqlite:///{tmp_path / 'audit.db'}"
    engine: AsyncEngine = create_async_engine(url)
    async with engine.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        # Seed both chain heads (audit_event + decision_history) so
        # the audit-store append flow reads from a non-empty head.
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="audit_event",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=datetime.now(UTC),
            )
        )
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="decision_history",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=datetime.now(UTC),
            )
        )
    store = AuditStore(engine)
    captured: list[AuditEvent] = []

    async def _capture_hook(snapshot: AppendedEventSnapshot) -> None:
        captured.append(_project_snapshot_to_event(snapshot))

    store.register_append_hook(_capture_hook)

    def _flush() -> list[AuditEvent]:
        return list(captured)

    return store, engine, _flush


@pytest.fixture
async def fixture_audit_capture(
    tmp_path: Path,
) -> Any:  # AsyncGenerator[Callable[[], list[AuditEvent]], None]
    """Yield a callable that returns a list of every
    :class:`AuditEvent` appended to a per-test in-memory
    :class:`AuditStore`.

    Pack-author tests that emit audit events through the SDK seam
    (e.g., via the MCP-host runtime in integration tests) inspect
    what was written by calling the closure ``fixture_audit_capture()``
    — every call returns a fresh snapshot list of events captured
    so far.

    The underlying engine is disposed at fixture teardown.
    """
    store, engine, capture = await _build_audit_capture_pair(tmp_path)
    try:
        # The fixture exposes BOTH the store (so pack tests can append)
        # and the capture closure. Returning a tuple would change the
        # plan-of-record contract (callable, not (store, callable));
        # instead, attach the store to the closure as an attribute so
        # pack tests can reach it via ``fixture_audit_capture.store``.
        capture.store = store  # type: ignore[attr-defined]
        yield capture
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# Manifest-validation assertion
# ---------------------------------------------------------------------------


def assert_manifest_validates(pack_path: Path) -> None:
    """Run the ``agentos validate`` pipeline against ``pack_path``;
    fail the calling test if any validator emits a refusal-severity
    finding.

    Forward dependency on Sprint-7A T6 (``cognic_agentos.cli.validate``).
    Until T6 lands, this raises :class:`NotImplementedError` citing
    the sprint task. Once T6 lands, the helper resolves the orchestrator
    via lazy import + delegates — no change required here.

    The lazy-import-on-call shape means:

      - T3 ships the helper name + signature (semver-stable surface).
      - T6 wires the orchestrator + drops the NotImplementedError.
      - Pack-author tests written against T3 do not need to be
        rewritten when T6 lands; their first run after the upgrade
        just starts working.
    """
    # R15 P3 #1 reviewer correction: gate on ``find_spec`` rather than
    # catching ``ModuleNotFoundError`` blanket. A blanket catch swallows
    # transitive-dep import failures inside the validate module after
    # T6 lands (e.g., a missing optional dep raised mid-import) and
    # rewrites them as the T6 forward-declared stub — masking real
    # bugs. ``find_spec`` answers "does THIS module exist on the
    # import path" without executing it, so transitive imports remain
    # uncaught.
    if importlib.util.find_spec("cognic_agentos.cli.validate") is None:
        raise NotImplementedError(
            "assert_manifest_validates requires the agentos validate "
            "orchestrator at cognic_agentos.cli.validate, which lands "
            "in Sprint-7A T6. Until T6 ships, this helper exists as "
            "a forward-declared semver-stable surface that pack "
            "authors can reference; calling it raises this error so "
            "the gap is visible. After T6 ships the import will "
            "resolve + the helper will delegate."
        )
    validate_module = importlib.import_module("cognic_agentos.cli.validate")
    run_validators = getattr(validate_module, "run_validators", None)
    if run_validators is None:
        raise NotImplementedError(
            "cognic_agentos.cli.validate is importable but does not "
            "yet expose run_validators(...). Sprint-7A T6 wires this "
            "symbol; until then assert_manifest_validates remains a "
            "forward-declared SDK helper."
        )
    findings = run_validators(pack_path)
    refusals = [f for f in findings if f.affects_exit_code]
    if refusals:
        rendered = "\n".join(f"  - {f.reason}: {f.message}" for f in refusals)
        raise AssertionError(f"manifest validation refused for {pack_path}:\n{rendered}")


# ---------------------------------------------------------------------------
# A2A-envelope assertion
# ---------------------------------------------------------------------------


#: Per-arm minimum-presence fields for a populated
#: :class:`StreamResponse.payload` oneof. R15 P2 #1 reviewer correction:
#: protobuf-JSON ``Parse`` accepts default-valued messages
#: (``{}``, ``{"task": {}}``), so a presence check is the only way to
#: refuse semantically empty envelopes the wire layer would otherwise
#: bless. Keys are oneof arm names; values are tuples of message-field
#: names that must be non-empty for the arm to count as populated.
_STREAM_RESPONSE_ARM_MINIMUM_FIELDS: dict[str, tuple[str, ...]] = {
    "task": ("id", "context_id"),
    "message": ("message_id",),
    "status_update": ("task_id",),
    "artifact_update": ("task_id",),
}


def _stream_response_arm_is_populated(envelope_msg: Any, arm: str) -> bool:
    """True iff every minimum-required field on the populated oneof
    arm is non-empty. The arm message is reached via
    ``getattr(envelope_msg, arm)``; protobuf3 default values are
    empty string / 0 / etc., so non-empty truthiness is the
    presence signal."""
    arm_msg = getattr(envelope_msg, arm)
    return all(getattr(arm_msg, field) for field in _STREAM_RESPONSE_ARM_MINIMUM_FIELDS[arm])


def assert_a2a_envelope_well_formed(envelope: dict[str, Any]) -> None:
    """Parse ``envelope`` through the A2A 1.0 SDK re-export; raise
    :class:`AssertionError` if it does not match a meaningfully
    populated :class:`StreamResponse` or :class:`Task` shape.

    Wave-1 ``Message`` envelopes are exchanged as the ``message``
    arm of ``StreamResponse.payload`` — the StreamResponse parse
    accepts that case automatically, so packs can validate any of
    the three semantic shapes through this single helper.

    Two-phase check (R15 P2 #1):

      1. Wire-shape: ``google.protobuf.json_format.Parse`` against the
         SDK protobuf class — rejects unknown fields + type mismatches.
      2. Presence: the parsed message MUST carry an active oneof arm
         (for StreamResponse) or non-empty identifiers (for Task).
         protobuf-JSON Parse accepts ``{}``, ``{"task": {}}``, and
         partial envelopes with default-only fields; without a
         presence check, pack tests could bless semantically empty
         output as well-formed.

    Implementation detail: matches how :func:`encode_stream_response`
    / :func:`decode_stream_response` round-trip the wire bytes.
    """
    from google.protobuf.json_format import Parse, ParseError

    from cognic_agentos.protocol.a2a_schema import StreamResponse, Task

    serialized = json.dumps(envelope)

    # Phase 1: try StreamResponse — most common Wave-1 shape (covers
    # task / message / status_update / artifact_update arms).
    try:
        sr = Parse(serialized, StreamResponse())
    except ParseError as stream_err:
        sr_err: ParseError | None = stream_err
        sr = None
    else:
        sr_err = None
        active_arm = sr.WhichOneof("payload")
        if active_arm is None:
            raise AssertionError(
                "envelope parses as StreamResponse but carries no active "
                "payload oneof arm (one of task / message / status_update "
                "/ artifact_update is required for a Wave-1 envelope to "
                "count as well-formed)."
            )
        if not _stream_response_arm_is_populated(sr, active_arm):
            required = ", ".join(_STREAM_RESPONSE_ARM_MINIMUM_FIELDS[active_arm])
            raise AssertionError(
                f"envelope parses as StreamResponse with active arm "
                f"{active_arm!r}, but the arm message is missing one or "
                f"more required identifiers ({required}). The wire layer "
                "would accept this, but pack tests should refuse "
                "semantically empty envelopes."
            )
        return

    # Phase 1 fallback: try Task — top-level shape returned by
    # tasks/get + tasks/cancel responses.
    try:
        task = Parse(serialized, Task())
    except ParseError as task_err:
        raise AssertionError(
            "envelope does not match any A2A 1.0 top-level shape "
            "(StreamResponse / Task / Message-via-StreamResponse). "
            f"StreamResponse parse error: {sr_err}; Task parse error: "
            f"{task_err}."
        ) from task_err

    if not task.id or not task.context_id:
        raise AssertionError(
            "envelope parses as Task but is missing one or more required "
            "identifiers (id, context_id). The wire layer would accept "
            "this, but pack tests should refuse semantically empty "
            "envelopes."
        )


__all__ = [
    "assert_a2a_envelope_well_formed",
    "assert_manifest_validates",
    "fixture_audit_capture",
    "fixture_settings",
    "fixture_tool_registry",
]
