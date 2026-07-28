"""M5 (ADR-008 + ADR-017) — harness hook-registry boot loader.

``build_dlp_guard`` walks the ALREADY-TRUSTED registry candidates (trust is
upstream), admits each verified hook pack's ``[hooks]`` declarations into a
``HookRegistry`` (digest-pinned via ``register_pack``), and assembles the
``DLPGuard`` the MCP host consumes. Per-pack fail-closed: a malformed hook
pack is skipped + logged (mirrors the MCP mapper's warn-skip doctrine); the
guard still builds — and the skipped pack's hook ids then fail CLOSED at
scan time (``dlp_hook_id_unresolved``), never silently pass.

The admit test fabricates a REAL ``importlib.metadata.EntryPoint`` whose
value points at a hook class in THIS module, so ``EntryPoint.load()`` (the
deferred-load contract — pack code is NOT imported at manifest walk) is
genuinely exercised. ``importlib.metadata`` access is patched at the
module-under-test's ``md`` attribute so the stdlib stays untouched.
"""

from __future__ import annotations

import dataclasses
import importlib.metadata as md
import logging
import types
import uuid
from collections.abc import Iterator
from typing import Any, ClassVar

import pytest

from cognic_agentos.cli._governance_vocab import HookPhase
from cognic_agentos.core.agent._types import LoadedAgentRecord
from cognic_agentos.core.audit import AuditEvent
from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.core.config import Settings, build_settings_without_env_file
from cognic_agentos.core.decision_history import DecisionRecord
from cognic_agentos.harness.hook_registry import (
    ConversationHookGuardAdapter,
    _dual_evidence_emitter,
    build_dlp_guard,
    build_hook_runtime,
)
from cognic_agentos.packs.hooks.dispatcher import HookDispatcher, HookDispatchEvidenceError
from cognic_agentos.packs.hooks.registry import HookRegistry
from cognic_agentos.protocol.plugin_registry import RegisteredPackCandidate
from cognic_agentos.sdk.hook import Hook, HookContext, HookResult

_DIST = "cognic-hook-schema-guard"
_PKG = "cognic_hook_schema_guard"


class _RefuseForbiddenHook(Hook):
    """Real hook the fabricated entry-point loads FROM THIS MODULE — the
    admit test proves a genuine deferred ``EntryPoint.load()`` resolves it
    AND that its code actually runs (pass + refuse arms)."""

    hook_id: ClassVar[str] = "refuse_forbidden_schema_arg"
    phase: ClassVar[HookPhase] = "dlp_pre"

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        if b"__FORBIDDEN__" in payload:
            return HookResult(
                decision="refuse",
                redacted_payload=None,
                policy_reason="forbidden_schema_arg",
            )
        return HookResult(decision="pass", redacted_payload=None, policy_reason=None)


class _ConversationRefuseHook(Hook):
    hook_id: ClassVar[str] = "conversation_refuse"
    phase: ClassVar[HookPhase] = "conversation_output"

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        return HookResult(
            decision="refuse",
            redacted_payload=None,
            policy_reason="customer_secret",
        )


class _ConversationInputPassHook(Hook):
    hook_id: ClassVar[str] = "conversation_input_pass"
    phase: ClassVar[HookPhase] = "conversation_input"

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        return HookResult(decision="pass", redacted_payload=None, policy_reason=None)


class _StubRegistry:
    def __init__(self, candidates: list[RegisteredPackCandidate]) -> None:
        self._c = candidates

    def iter_registered_pack_candidates(self) -> Iterator[RegisteredPackCandidate]:
        return iter(self._c)


class _RecordingStore:
    def __init__(self, *, error: Exception | None = None) -> None:
        self.events: list[object] = []
        self._error = error

    async def append(self, event: object) -> None:
        self.events.append(event)
        if self._error is not None:
            raise self._error


class _RecordingDispatcher:
    def __init__(
        self,
        *,
        outcome: str = "passed",
        final_payload: bytes = b"screened",
        timeout_budgets: dict[str, float] | None = None,
        evidence_emission_configured: bool = True,
    ) -> None:
        self.calls: list[dict[str, Any]] = []
        self._outcome = outcome
        self._final_payload = final_payload
        self._timeout_budgets = timeout_budgets or {
            "conversation_input": 1.25,
            "conversation_output": 2.5,
        }
        self.evidence_emission_configured = evidence_emission_configured

    async def dispatch(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        return types.SimpleNamespace(
            outcome=self._outcome,
            final_payload=self._final_payload,
            hook_decision_count=1,
        )

    def phase_timeout_budget_s(self, phase: HookPhase) -> float:
        return self._timeout_budgets[phase]

    def has_phase_hooks(self, phase: HookPhase) -> bool:
        return phase in {"conversation_input", "conversation_output"}


def _agent_record(
    *,
    pack_id: str = "cognic-agent-advisor",
    data_classes: tuple[str, ...] = ("customer_pii", "internal"),
    purpose: str = "customer_support",
) -> LoadedAgentRecord:
    return LoadedAgentRecord(
        agent_id="advisor",
        persona_body="body",
        persona_sha256="a" * 64,
        requested_skills=(),
        requested_tools=(),
        max_steps=4,
        risk_tier="customer_data_read",
        pack_version="0.1.0",
        signed_artefact_digest="sha256:" + "b" * 64,
        registered=True,
        pack_id=pack_id,
        manifest_data_classes=data_classes,
        manifest_purpose=purpose,
    )


def _cand(digest: str | None = "sha256:" + "c" * 64) -> RegisteredPackCandidate:
    return RegisteredPackCandidate(
        distribution_name=_DIST, package_name=_PKG, signature_digest=digest
    )


_DECLARATION: dict[str, Any] = {
    "hook_id": "refuse_forbidden_schema_arg",
    "phase": "dlp_pre",
    "ordering_class": "input_validation",
    "timeout_seconds": 1.0,
    "fail_policy": "fail_closed",
}

_REAL_EP = md.EntryPoint(
    name="refuse_forbidden_schema_arg",
    value="tests.unit.harness.test_hook_registry_builder:_RefuseForbiddenHook",
    group="cognic.hooks",
)
_CONVERSATION_EP = md.EntryPoint(
    name="conversation_refuse",
    value="tests.unit.harness.test_hook_registry_builder:_ConversationRefuseHook",
    group="cognic.hooks",
)
_CONVERSATION_INPUT_EP = md.EntryPoint(
    name="conversation_input_pass",
    value="tests.unit.harness.test_hook_registry_builder:_ConversationInputPassHook",
    group="cognic.hooks",
)


def _fake_md(*eps: md.EntryPoint, version: str = "0.1.0", missing: bool = False) -> Any:
    """A namespace standing in for ``hook_registry.md`` — ``distribution``
    returns a dist-like carrying the given entry-points (or raises
    PackageNotFoundError when ``missing``)."""

    def _distribution(name: str) -> Any:
        if missing:
            raise md.PackageNotFoundError(name)
        return types.SimpleNamespace(entry_points=list(eps), version=version)

    return types.SimpleNamespace(
        distribution=_distribution, PackageNotFoundError=md.PackageNotFoundError
    )


def _patch(monkeypatch: pytest.MonkeyPatch, *, manifest: Any, md_ns: Any) -> None:
    monkeypatch.setattr(
        "cognic_agentos.harness.hook_registry.extract_pack_manifest",
        lambda **kw: manifest,
    )
    monkeypatch.setattr("cognic_agentos.harness.hook_registry.md", md_ns)


@pytest.fixture
def settings() -> Settings:
    return build_settings_without_env_file()


def _ctx_template(pack_id: str = "cognic-tool-oracle-schema") -> HookContext:
    return HookContext(
        hook_id="",
        phase="dlp_pre",
        pack_id=pack_id,
        tenant_id="tenant-1",
        request_id="req-1",
        trace_id=None,
        parent_trace_id=None,
        manifest_data_classes=("internal",),
        manifest_purpose="operational_telemetry",
    )


# ---------------------------------------------------------------------------
# Admission — verified pack resolves + its real hook code runs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "manifest",
    [
        {"hooks": {"declarations": [_DECLARATION]}},
        {"tool": {"cognic": {"hooks": {"declarations": [_DECLARATION]}}}},
    ],
    ids=["canonical-hooks-block", "legacy-tool-cognic-hooks-block"],
)
async def test_build_dlp_guard_admits_verified_hook_pack(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, manifest: dict[str, Any]
) -> None:
    _patch(monkeypatch, manifest=manifest, md_ns=_fake_md(_REAL_EP))
    guard = build_dlp_guard(registry=_StubRegistry([_cand()]), settings=settings)
    # the declared hook resolves (NOT dlp_hook_id_unresolved) and its REAL
    # loaded code runs: a permitted payload passes...
    outcome = await guard.scan_pre(
        payload=canonical_bytes({"table": "EMPLOYEES"}),
        declared_hook_ids=("refuse_forbidden_schema_arg",),
        context_template=_ctx_template(),
    )
    assert outcome.outcome == "passed"
    # ...and the forbidden sentinel refuses through the SAME loaded hook.
    refused = await guard.scan_pre(
        payload=canonical_bytes({"table": "__FORBIDDEN__"}),
        declared_hook_ids=("refuse_forbidden_schema_arg",),
        context_template=_ctx_template(),
    )
    assert refused.outcome == "refused"
    assert refused.refusal_reason == "dlp_dispatcher_refused"
    assert refused.underlying_policy_reason == "forbidden_schema_arg"


async def test_build_hook_runtime_shares_dispatcher_and_dual_writes_value_free_evidence(
    monkeypatch: pytest.MonkeyPatch, settings: Settings
) -> None:
    _patch(
        monkeypatch,
        manifest={"hooks": {"declarations": [_DECLARATION]}},
        md_ns=_fake_md(_REAL_EP),
    )
    audit = _RecordingStore()
    history = _RecordingStore()

    runtime = build_hook_runtime(
        registry=_StubRegistry([_cand()]),
        settings=settings,
        audit_store=audit,
        decision_history_store=history,
    )

    assert runtime.dlp_guard._dispatcher is runtime.dispatcher
    outcome = await runtime.dispatcher.dispatch(
        phase="dlp_pre",
        payload=canonical_bytes({"table": "EMPLOYEES"}),
        context_template=_ctx_template(),
    )

    assert outcome.outcome == "passed"
    assert len(audit.events) == 1
    assert len(history.events) == 1
    audit_event = audit.events[0]
    decision_record = history.events[0]
    assert isinstance(audit_event, AuditEvent)
    assert isinstance(decision_record, DecisionRecord)
    assert audit_event.event_type == "hook.decision"
    assert decision_record.decision_type == "hook.decision"
    assert audit_event.request_id == decision_record.request_id == "req-1"
    assert audit_event.tenant_id == decision_record.tenant_id == "tenant-1"
    assert audit_event.payload == decision_record.payload
    assert audit_event.payload["hook_id"] == "refuse_forbidden_schema_arg"
    assert audit_event.payload["decision"] == "pass"
    assert "EMPLOYEES" not in repr(audit_event.payload)


async def test_conversation_refusal_dual_evidence_is_value_free_and_correlated(
    monkeypatch: pytest.MonkeyPatch, settings: Settings
) -> None:
    declaration = {
        "hook_id": "conversation_refuse",
        "phase": "conversation_output",
        "ordering_class": "output_validation",
        "timeout_seconds": 1.0,
        "fail_policy": "fail_closed",
    }
    _patch(
        monkeypatch,
        manifest={"hooks": {"declarations": [declaration]}},
        md_ns=_fake_md(_CONVERSATION_EP),
    )
    audit = _RecordingStore()
    history = _RecordingStore()
    runtime = build_hook_runtime(
        registry=_StubRegistry([_cand()]),
        settings=settings,
        audit_store=audit,
        decision_history_store=history,
    )

    result = await runtime.dispatcher.dispatch(
        phase="conversation_output",
        payload=b'{"answer":"customer_secret"}',
        context_template=dataclasses.replace(
            _ctx_template(),
            phase="conversation_output",
            conversation_id="12345678-1234-5678-1234-567812345678",
            conversation_turn_seq=3,
            agent_run_id="agent-run-3",
            output_origin="agent_run",
            approval_delivery_id=None,
        ),
        require_nonempty=True,
    )

    assert result.outcome == "refused"
    assert len(audit.events) == len(history.events) == 1
    audit_event = audit.events[0]
    decision_record = history.events[0]
    assert isinstance(audit_event, AuditEvent)
    assert isinstance(decision_record, DecisionRecord)
    for event in (audit_event, decision_record):
        assert event.payload["policy_reason"] is None
        assert event.payload["conversation_id"] == "12345678-1234-5678-1234-567812345678"
        assert event.payload["conversation_turn_seq"] == 3
        assert event.payload["output_origin"] == "agent_run"
        assert event.payload["agent_run_id"] == "agent-run-3"
        assert event.payload["approval_delivery_id"] is None
        assert "customer_secret" not in repr(event)


async def test_conversation_adapter_uses_frozen_governance_and_shared_dispatcher() -> None:
    dispatcher = _RecordingDispatcher(final_payload=b"transformed")
    record = _agent_record()

    def validate_transformed_payload(_: bytes) -> None:
        return None

    def project_value(_: bytes) -> bytes:
        return b"bound scalar"

    adapter = ConversationHookGuardAdapter(
        dispatcher=dispatcher,  # type: ignore[arg-type]
        agent_records={"advisor": record},
    )

    governance = adapter.governance_for_agent(agent_id="advisor")
    result = await adapter.scan(
        phase="conversation_input",
        payload=b"canonical",
        governance=governance,
        tenant_id="tenant-1",
        request_id="req-conversation-1",
        conversation_id=uuid.UUID("12345678-1234-5678-1234-567812345678"),
        turn_seq=7,
        agent_run_id=None,
        output_origin=None,
        approval_delivery_id=None,
        validate_transformed_payload=validate_transformed_payload,
        evidence_value_projector=project_value,
        evidence_input_value=b"bound scalar",
    )

    assert result.outcome == "passed"
    assert result.final_payload == b"transformed"
    assert governance.pack_id == "cognic-agent-advisor"
    assert governance.declared_data_classes == ("customer_pii", "internal")
    assert governance.manifest_purpose == "customer_support"
    call = dispatcher.calls[0]
    assert call["phase"] == "conversation_input"
    assert call["require_nonempty"] is True
    assert call["transformed_payload_validator"] is validate_transformed_payload
    assert call["evidence_value_projector"] is project_value
    assert call["evidence_input_value"] == b"bound scalar"
    context = call["context_template"]
    assert context.conversation_id == "12345678-1234-5678-1234-567812345678"
    assert context.conversation_turn_seq == 7
    assert context.agent_run_id is None
    assert context.output_origin is None
    assert context.approval_delivery_id is None
    assert adapter.turn_timeout_budget_s() == 3.75
    assert call["payload"] == b"canonical"
    context = call["context_template"]
    assert context.hook_id == ""
    assert context.pack_id == governance.pack_id
    assert context.manifest_data_classes == governance.declared_data_classes
    assert context.manifest_purpose == governance.manifest_purpose


@pytest.mark.parametrize("missing_phase", ["conversation_input", "conversation_output"])
def test_conversation_adapter_refuses_when_required_phase_is_empty(
    missing_phase: HookPhase,
) -> None:
    dispatcher = _RecordingDispatcher()
    dispatcher.has_phase_hooks = (  # type: ignore[method-assign]
        lambda phase: phase != missing_phase
    )

    with pytest.raises(ValueError, match=missing_phase):
        ConversationHookGuardAdapter(
            dispatcher=dispatcher,  # type: ignore[arg-type]
            agent_records={"advisor": _agent_record()},
        )


def test_conversation_adapter_refuses_dispatcher_without_evidence_sink() -> None:
    with pytest.raises(ValueError, match="fail-loud evidence emission"):
        ConversationHookGuardAdapter(
            dispatcher=_RecordingDispatcher(  # type: ignore[arg-type]
                evidence_emission_configured=False
            ),
            agent_records={"advisor": _agent_record()},
        )


def test_conversation_adapter_refuses_real_dispatcher_without_evidence_sink(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dispatcher = HookDispatcher(
        registry=HookRegistry(max_timeout_seconds=30.0),
        max_payload_bytes=1_000,
        max_timeout_seconds_runtime=30.0,
        audit_emitter=None,
    )
    # Isolate the sink guard from the independently tested nonempty-phase
    # admission check while retaining the production dispatcher property.
    monkeypatch.setattr(dispatcher, "has_phase_hooks", lambda _phase: True)

    with pytest.raises(ValueError, match="fail-loud evidence emission"):
        ConversationHookGuardAdapter(
            dispatcher=dispatcher,
            agent_records={"advisor": _agent_record()},
        )


def test_conversation_adapter_refuses_unknown_or_incomplete_governance() -> None:
    dispatcher = _RecordingDispatcher()
    adapter = ConversationHookGuardAdapter(
        dispatcher=dispatcher,  # type: ignore[arg-type]
        agent_records={"legacy": _agent_record(pack_id="", data_classes=(), purpose="")},
    )

    with pytest.raises(LookupError):
        adapter.governance_for_agent(agent_id="unknown")
    with pytest.raises(ValueError, match="pack_id"):
        adapter.governance_for_agent(agent_id="legacy")
    assert dispatcher.calls == []


@pytest.mark.parametrize("failing_store", ["audit", "decision_history"])
async def test_build_hook_runtime_propagates_evidence_failure(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    failing_store: str,
) -> None:
    _patch(
        monkeypatch,
        manifest={"hooks": {"declarations": [_DECLARATION]}},
        md_ns=_fake_md(_REAL_EP),
    )
    audit = _RecordingStore(
        error=RuntimeError("audit unavailable") if failing_store == "audit" else None
    )
    history = _RecordingStore(
        error=RuntimeError("history unavailable") if failing_store == "decision_history" else None
    )
    runtime = build_hook_runtime(
        registry=_StubRegistry([_cand()]),
        settings=settings,
        audit_store=audit,
        decision_history_store=history,
    )

    with pytest.raises(HookDispatchEvidenceError, match="hook evidence emission failed"):
        await runtime.dispatcher.dispatch(
            phase="dlp_pre",
            payload=b"{}",
            context_template=_ctx_template(),
        )

    if failing_store == "audit":
        assert history.events == []
    else:
        # The two existing stores have no shared transaction. Audit is first,
        # so a history failure leaves one value-free orphan audit row while the
        # exception still makes the governed hook result unusable.
        assert len(audit.events) == 1
        assert isinstance(audit.events[0], AuditEvent)


# ---------------------------------------------------------------------------
# Per-pack fail-closed skips — the guard still builds; skipped hook ids
# fail CLOSED at scan time
# ---------------------------------------------------------------------------


async def test_declared_hook_without_entry_point_skips_pack_not_fatal(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    # [hooks] declares a hook_id the distribution ships NO cognic.hooks
    # entry-point for → the whole pack is skipped (logged); guard builds.
    _patch(
        monkeypatch,
        manifest={"hooks": {"declarations": [_DECLARATION]}},
        md_ns=_fake_md(),  # no entry-points
    )
    with caplog.at_level(logging.WARNING):
        guard = build_dlp_guard(registry=_StubRegistry([_cand()]), settings=settings)
    assert "hook.declaration_no_entry_point" in caplog.text
    outcome = await guard.scan_pre(
        payload=b"{}",
        declared_hook_ids=("refuse_forbidden_schema_arg",),
        context_template=_ctx_template(),
    )
    assert outcome.outcome == "refused"
    assert outcome.refusal_reason == "dlp_hook_id_unresolved"


def test_pack_without_hooks_block_is_ignored(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    # non-hook packs (no [hooks]) contribute nothing — silent, guard builds.
    _patch(
        monkeypatch,
        manifest={"tool": {"cognic": {"mcp": {"transport": "streamable-http"}}}},
        md_ns=_fake_md(_REAL_EP),
    )
    with caplog.at_level(logging.WARNING):
        guard = build_dlp_guard(registry=_StubRegistry([_cand()]), settings=settings)
    assert guard is not None
    assert len(caplog.records) == 0


@pytest.mark.parametrize(
    "manifest",
    [
        {"hooks": "not-a-table"},
        {"tool": "not-a-table"},
        {"hooks": {"declarations": []}},
        {"hooks": {"declarations": "not-a-list"}},
        {"hooks": {"declarations": [_DECLARATION, "not-a-table"]}},
        {"tool": {"cognic": {"hooks": {"declarations": ["not-a-table"]}}}},
    ],
    ids=[
        "canonical-block-not-table",
        "legacy-path-not-table",
        "empty-declarations",
        "declarations-not-list",
        "canonical-non-table-entry",
        "legacy-non-table-entry",
    ],
)
async def test_malformed_hooks_block_skips_pack_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    caplog: pytest.LogCaptureFixture,
    manifest: dict[str, Any],
) -> None:
    # Present-but-malformed hook blocks are NOT silently treated as absent and
    # are NOT partially admitted. The whole pack is skipped fail-closed.
    _patch(monkeypatch, manifest=manifest, md_ns=_fake_md(_REAL_EP))
    with caplog.at_level(logging.WARNING):
        guard = build_dlp_guard(registry=_StubRegistry([_cand()]), settings=settings)
    assert "hook.block_malformed" in caplog.text
    outcome = await guard.scan_pre(
        payload=b"{}",
        declared_hook_ids=("refuse_forbidden_schema_arg",),
        context_template=_ctx_template(),
    )
    assert outcome.outcome == "refused"
    assert outcome.refusal_reason == "dlp_hook_id_unresolved"


def test_duplicate_declarations_warn_skip_the_whole_pack(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _patch(
        monkeypatch,
        manifest={"hooks": {"declarations": [_DECLARATION, _DECLARATION]}},
        md_ns=_fake_md(_REAL_EP),
    )

    with caplog.at_level(logging.WARNING):
        guard = build_dlp_guard(registry=_StubRegistry([_cand()]), settings=settings)

    assert guard is not None
    assert [record.getMessage() for record in caplog.records] == ["hook.pack_malformed"]


@pytest.mark.parametrize(
    "row",
    [
        {"request_id": "request", "tenant_id": "tenant"},
        {"event_type": "event", "tenant_id": "tenant"},
        {"event_type": "event", "request_id": "request"},
    ],
    ids=["event-type", "request-id", "tenant-id"],
)
async def test_dual_evidence_emitter_refuses_missing_identity_fields(
    row: dict[str, object],
) -> None:
    emit = _dual_evidence_emitter(
        audit_store=_RecordingStore(),
        decision_history_store=_RecordingStore(),
    )

    with pytest.raises(ValueError, match="must be a non-empty string"):
        await emit(row)


async def test_missing_signature_digest_refuses_pack(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    # register_pack fail-closed (pack_not_verified) on an empty digest — the
    # pack is skipped (logged); its hook id then fails closed at scan time.
    _patch(
        monkeypatch,
        manifest={"hooks": {"declarations": [_DECLARATION]}},
        md_ns=_fake_md(_REAL_EP),
    )
    with caplog.at_level(logging.WARNING):
        guard = build_dlp_guard(registry=_StubRegistry([_cand(digest=None)]), settings=settings)
    assert "hook.registry_refused" in caplog.text
    outcome = await guard.scan_pre(
        payload=b"{}",
        declared_hook_ids=("refuse_forbidden_schema_arg",),
        context_template=_ctx_template(),
    )
    assert outcome.outcome == "refused"
    assert outcome.refusal_reason == "dlp_hook_id_unresolved"


def test_malformed_declaration_field_skips_pack(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    # a declaration HookDeclaration refuses at construction (ValueError —
    # non-numeric timeout) → warn-skip, guard builds.
    bad = dict(_DECLARATION, timeout_seconds="not-a-number")
    _patch(
        monkeypatch,
        manifest={"hooks": {"declarations": [bad]}},
        md_ns=_fake_md(_REAL_EP),
    )
    with caplog.at_level(logging.WARNING):
        guard = build_dlp_guard(registry=_StubRegistry([_cand()]), settings=settings)
    assert guard is not None
    assert "hook.declaration_malformed" in caplog.text


def test_conversation_fail_open_manifest_is_warn_skipped_and_not_ready(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    caplog: pytest.LogCaptureFixture,
) -> None:
    declarations = [
        {
            "hook_id": "conversation_input_pass",
            "phase": "conversation_input",
            "ordering_class": "input_validation",
            "timeout_seconds": 1.0,
            "fail_policy": "fail_open",
            "fail_open_exception": "RuntimeError",
        },
        {
            "hook_id": "conversation_refuse",
            "phase": "conversation_output",
            "ordering_class": "output_validation",
            "timeout_seconds": 1.0,
            "fail_policy": "fail_closed",
        },
    ]
    _patch(
        monkeypatch,
        manifest={"hooks": {"declarations": declarations}},
        md_ns=_fake_md(_CONVERSATION_INPUT_EP, _CONVERSATION_EP),
    )
    with caplog.at_level(logging.WARNING):
        runtime = build_hook_runtime(
            registry=_StubRegistry([_cand()]),
            settings=settings,
            audit_store=_RecordingStore(),
            decision_history_store=_RecordingStore(),
        )

    malformed = [
        record for record in caplog.records if record.getMessage() == "hook.declaration_malformed"
    ]
    assert len(malformed) == 1
    assert vars(malformed[0])["error"] == (
        "conversation hook phases require fail_policy='fail_closed'"
    )
    with pytest.raises(ValueError, match="requires admitted hooks for both phases"):
        ConversationHookGuardAdapter(
            dispatcher=runtime.dispatcher,
            agent_records={"advisor": _agent_record()},
        )


def test_distribution_not_found_skips_pack(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    # the candidate's distribution is not importable-metadata-visible →
    # warn-skip (the trust registry saw it, the venv lost it — fail closed).
    _patch(
        monkeypatch,
        manifest={"hooks": {"declarations": [_DECLARATION]}},
        md_ns=_fake_md(missing=True),
    )
    with caplog.at_level(logging.WARNING):
        guard = build_dlp_guard(registry=_StubRegistry([_cand()]), settings=settings)
    assert guard is not None
    assert "hook.distribution_not_found" in caplog.text


def test_manifest_not_found_silent_skip(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    from cognic_agentos.protocol.mcp_manifest import PackManifestNotFoundError

    def _raise(**kw: Any) -> Any:
        raise PackManifestNotFoundError("no manifest")

    monkeypatch.setattr("cognic_agentos.harness.hook_registry.extract_pack_manifest", _raise)
    with caplog.at_level(logging.WARNING):
        guard = build_dlp_guard(registry=_StubRegistry([_cand()]), settings=settings)
    assert guard is not None
    assert len(caplog.records) == 0  # no hook intent → silent (mapper doctrine)


def test_manifest_malformed_warns_and_skips(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    from cognic_agentos.protocol.mcp_manifest import PackManifestMalformedError

    def _raise(**kw: Any) -> Any:
        raise PackManifestMalformedError("bad toml")

    monkeypatch.setattr("cognic_agentos.harness.hook_registry.extract_pack_manifest", _raise)
    with caplog.at_level(logging.WARNING):
        guard = build_dlp_guard(registry=_StubRegistry([_cand()]), settings=settings)
    assert guard is not None
    assert "hook.pack_manifest_malformed" in caplog.text
