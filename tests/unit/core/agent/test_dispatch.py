"""M8 Task A10 (ADR-027) — AgentDispatcher chokepoint tests (CRITICAL CONTROLS).

Every capability call an LLM authors passes through ``AgentDispatcher.dispatch``
— the single seam owning ALL dispatch authority. This suite pins the pipeline
ORDER (each gate spy-proven to fire before the next), the read_skill skill_id
sub-gate (the forced BAR-2 shape), the signed query-context stamp round-trip,
the ``build_llm_tool_specs`` schema-exclusion contract, the safe-message
discipline on backend failures, and the digest-only ``agent.run.dispatch``
evidence row (exactly ONE per dispatch, on EVERY arm) per the
chain-payload-is-evidence-snapshot doctrine.

Stubs: entitlements / tool proxy / skill reader / memory factory / decision
history are cheap spies; gate 3 runs a REAL :class:`AgentDispatchPolicy` over a
stub OPA engine (the ``test_policy.py`` house pattern). The query-context
round-trip uses a REAL RSA-2048 keypair generated at test time (never
hardcoded) + the REAL ``verify_query_context``.
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import json
import logging
import pathlib
import time
import uuid
from collections.abc import Mapping
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import cognic_agentos.core.agent.dispatch as dispatch_module
from cognic_agentos.core.agent._types import (
    CapabilityRef,
    GrantedCapabilities,
    LoadedAgentRecord,
)
from cognic_agentos.core.agent.action_context import ACTION_CONTEXT_ARGUMENT
from cognic_agentos.core.agent.dispatch import (
    _BUILTIN_NAMES,
    _QUERY_CONTEXT_ARG,
    AgentDispatcher,
    AgentRunContext,
    AgentToolProxy,
    DispatchOutcome,
    _assignment_verified,
    _granted_tool_name_map,
    _validated_read_skill_id,
    build_llm_tool_specs,
)
from cognic_agentos.core.agent.policy import AgentDispatchPolicy
from cognic_agentos.core.agent.query_context import verify_query_context
from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.core.decision_history import DecisionRecord
from cognic_agentos.core.entitlements import DataScope
from cognic_agentos.core.policy.engine import Decision, OpaNotInstalledError
from cognic_agentos.llm.gateway import GatewayToolCall

# --- Shared fixture identities ------------------------------------------------

_TENANT = "tenant-a"
_ORIGINATOR = "human:analyst@bank"
_AGENT_ID = "bank-analyst"
_ORACLE_REF = "cognic-tool-oracle-schema/run_readonly_query"
_OTHER_REF = "srv-b/other_tool"
_TOOL_CAPABILITY_CLASSES = {
    _ORACLE_REF: "data_query",
    _OTHER_REF: "unscoped",
}
_GRANTED_SKILL = "schema-summary"
_SCOPE_ID = "customer-data"
_SCOPE = DataScope(
    scope_id=_SCOPE_ID,
    schema_name="BANK",
    objects=("V_CUSTOMERS", "V_ACCOUNTS"),
    proxy_db_identity="AGENT_RO",
)

#: The EXACT ``agent.run.dispatch`` payload key set (the chain-payload-is-
#: evidence-snapshot doctrine — an exact-key-set assertion, not subset).
_EXPECTED_PAYLOAD_KEYS = frozenset(
    {
        "run_id",
        "agent_id",
        "originator_subject",
        "capability_kind",
        "capability_ref",
        "scope_id",
        "step_index",
        "outcome",
        "refusal_reason",
        "args_sha256",
        "result_sha256",
        "result_bytes",
    }
)


def _generate_keypair() -> tuple[bytes, bytes]:
    """Generate an RSA-2048 keypair at test time → (private_pem, public_pem)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


@pytest.fixture(scope="module")
def keypair() -> tuple[bytes, bytes]:
    return _generate_keypair()


# --- Builders -------------------------------------------------------------------


def _record(**overrides: Any) -> LoadedAgentRecord:
    base: dict[str, Any] = {
        "agent_id": _AGENT_ID,
        "persona_body": "You are the bank analyst.",
        "persona_sha256": hashlib.sha256(b"You are the bank analyst.").hexdigest(),
        "requested_skills": (_GRANTED_SKILL,),
        "requested_tools": (_ORACLE_REF, _OTHER_REF),
        "max_steps": 6,
        "risk_tier": "customer_data_read",
        "pack_version": "0.1.0",
        "signed_artefact_digest": None,
        "registered": True,
    }
    base.update(overrides)
    return LoadedAgentRecord(**base)


def _run(**overrides: Any) -> AgentRunContext:
    base: dict[str, Any] = {
        "run_id": "run-0001",
        "tenant_id": _TENANT,
        "originator_subject": _ORIGINATOR,
        "agent_id": _AGENT_ID,
        "granted": GrantedCapabilities(
            skills=frozenset({_GRANTED_SKILL}),
            tools=frozenset({_ORACLE_REF, _OTHER_REF}),
        ),
        "max_steps": 6,
        "record": _record(),
    }
    base.update(overrides)
    return AgentRunContext(**base)


def _call(name: str, **arguments: Any) -> GatewayToolCall:
    return GatewayToolCall(id="call_0", name=name, arguments=arguments)


# --- Spies / stubs ----------------------------------------------------------------


class _StubEntitlements:
    """Spy conformer for the two EntitlementStore reads gate 2 makes."""

    def __init__(
        self,
        *,
        entitled: frozenset[str],
        scopes: dict[str, DataScope],
        action_entitled: bool,
    ) -> None:
        self._entitled = entitled
        self._scopes = scopes
        self._action_entitled = action_entitled
        self.entitled_calls: list[dict[str, str]] = []
        self.resolve_calls: list[dict[str, str]] = []
        self.action_calls: list[dict[str, str]] = []

    async def entitled_scope_ids(self, *, tenant_id: str, subject: str) -> frozenset[str]:
        self.entitled_calls.append({"tenant_id": tenant_id, "subject": subject})
        return self._entitled

    async def resolve_scope(self, *, tenant_id: str, scope_id: str) -> DataScope | None:
        self.resolve_calls.append({"tenant_id": tenant_id, "scope_id": scope_id})
        return self._scopes.get(scope_id)

    async def entitled_action(
        self,
        *,
        tenant_id: str,
        subject: str,
        tool_identity: str,
    ) -> bool:
        self.action_calls.append(
            {
                "tenant_id": tenant_id,
                "subject": subject,
                "tool_identity": tool_identity,
            }
        )
        return self._action_entitled


class _StubOPAEngine:
    """Fixed-verdict (or raising) OPA engine behind the REAL AgentDispatchPolicy.
    ``seen_inputs`` doubles as the gate-3-consulted spy for ordering pins."""

    def __init__(self, *, allow: bool = True, exc: type[Exception] | None = None) -> None:
        self._allow = allow
        self._exc = exc
        self.seen_inputs: list[dict[str, Any]] = []

    async def evaluate(self, *, decision_point: str, input: dict[str, Any]) -> Decision:
        self.seen_inputs.append(input)
        if self._exc is not None:
            raise self._exc("stub opa failure")
        return Decision(
            allow=self._allow,
            rule_matched=decision_point,
            reasoning="stub",
            decision_data=None,
        )


class _SpyToolProxy:
    """AgentToolProxy conformer recording every call; configurable result/raise."""

    def __init__(
        self, *, result: dict[str, Any] | None = None, exc: Exception | None = None
    ) -> None:
        self._result = result if result is not None else {"rows": []}
        self._exc = exc
        self.calls: list[dict[str, Any]] = []

    async def call_tool(
        self,
        *,
        server_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        request_id: str,
        tenant_id: str,
        originator_subject: str,
        approval_request_id: uuid.UUID | None,
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "server_id": server_id,
                "tool_name": tool_name,
                "arguments": dict(arguments),
                "request_id": request_id,
                "tenant_id": tenant_id,
                "originator_subject": originator_subject,
                "approval_request_id": approval_request_id,
            }
        )
        if self._exc is not None:
            raise self._exc
        return self._result


class _SpySkillReader:
    def __init__(self, *, bodies: dict[str, tuple[str, str]] | None = None) -> None:
        self._bodies = bodies if bodies is not None else {}
        self.calls: list[str] = []

    def read(self, skill_id: str) -> tuple[str, str] | None:
        self.calls.append(skill_id)
        return self._bodies.get(skill_id)


class _SpyMemoryApi:
    def __init__(self) -> None:
        self.remember_calls: list[dict[str, Any]] = []

    async def remember(
        self,
        key: str,
        value: object,
        *,
        tier: str,
        data_classes: tuple[str, ...],
        purpose: str,
    ) -> uuid.UUID:
        self.remember_calls.append(
            {
                "key": key,
                "value": value,
                "tier": tier,
                "data_classes": data_classes,
                "purpose": purpose,
            }
        )
        return uuid.uuid4()


class _SpyMemoryFactory:
    def __init__(self) -> None:
        self.api = _SpyMemoryApi()
        self.contexts: list[Any] = []

    def __call__(self, context: Any) -> Any:
        self.contexts.append(context)
        return self.api


class _RecordingDecisionHistory:
    """DecisionHistoryStore-like recording stub (append signature mirrored)."""

    def __init__(self) -> None:
        self.records: list[DecisionRecord] = []

    async def append(self, record: DecisionRecord) -> tuple[uuid.UUID, bytes]:
        self.records.append(record)
        return (uuid.uuid4(), b"\x00" * 32)


@dataclasses.dataclass
class _Harness:
    dispatcher: AgentDispatcher
    entitlements: _StubEntitlements
    opa: _StubOPAEngine
    proxy: _SpyToolProxy
    reader: _SpySkillReader
    memory: _SpyMemoryFactory
    dh: _RecordingDecisionHistory


def _harness(
    *,
    entitled: frozenset[str] = frozenset({_SCOPE_ID}),
    scopes: dict[str, DataScope] | None = None,
    allow: bool = True,
    opa_exc: type[Exception] | None = None,
    proxy_result: dict[str, Any] | None = None,
    proxy_exc: Exception | None = None,
    bodies: dict[str, tuple[str, str]] | None = None,
    signing_key_pem: bytes | None = None,
    ttl_s: float = 300.0,
    tool_capability_classes: Mapping[str, str] | None = None,
    action_entitled: bool = False,
) -> _Harness:
    entitlements = _StubEntitlements(
        entitled=entitled,
        scopes=scopes if scopes is not None else {_SCOPE_ID: _SCOPE},
        action_entitled=action_entitled,
    )
    opa = _StubOPAEngine(allow=allow, exc=opa_exc)
    policy = AgentDispatchPolicy(opa_engine=opa)  # type: ignore[arg-type]
    proxy = _SpyToolProxy(result=proxy_result, exc=proxy_exc)
    reader = _SpySkillReader(
        bodies=bodies
        if bodies is not None
        else {_GRANTED_SKILL: ("Schema summary", "# SKILL body")}
    )
    memory = _SpyMemoryFactory()
    dh = _RecordingDecisionHistory()
    dispatcher = AgentDispatcher(
        entitlements=entitlements,  # type: ignore[arg-type]
        policy=policy,
        tool_proxy=proxy,
        skill_reader=reader,
        memory_factory=memory,
        decision_history=dh,  # type: ignore[arg-type]
        query_context_signing_key_pem=signing_key_pem,
        query_context_ttl_s=ttl_s,
        tool_capability_classes=(
            tool_capability_classes
            if tool_capability_classes is not None
            else _TOOL_CAPABILITY_CLASSES
        ),
    )
    return _Harness(
        dispatcher=dispatcher,
        entitlements=entitlements,
        opa=opa,
        proxy=proxy,
        reader=reader,
        memory=memory,
        dh=dh,
    )


def _only_row(harness: _Harness) -> DecisionRecord:
    assert len(harness.dh.records) == 1
    return harness.dh.records[0]


# --- Module constants -------------------------------------------------------------


class TestModuleConstants:
    def test_builtin_names_closed_set(self) -> None:
        assert frozenset({"read_skill", "remember"}) == _BUILTIN_NAMES

    def test_query_context_arg_name(self) -> None:
        assert _QUERY_CONTEXT_ARG == "_cognic_query_context"

    def test_tool_proxy_protocol_is_runtime_checkable(self) -> None:
        assert isinstance(_SpyToolProxy(), AgentToolProxy)


# --- Pin 1 + 10 — resolution -------------------------------------------------------


class TestResolution:
    async def test_hallucinated_tool_name_refuses_without_consulting_anything(self) -> None:
        """An LLM-hallucinated name is by definition unassigned: refuse at
        resolution; entitlements + policy + proxy ALL untouched (gate order);
        exactly ONE refusal evidence row carrying the raw call name."""
        h = _harness()
        out = await h.dispatcher.dispatch(call=_call("made_up_tool"), step_index=0, run=_run())
        assert out == DispatchOutcome(
            refused=True,
            reason="agent_capability_not_assigned",
            message="capability 'made_up_tool' is not assigned to this agent",
            result=None,
        )
        assert h.proxy.calls == []
        assert h.entitlements.entitled_calls == []
        assert h.entitlements.resolve_calls == []
        assert h.opa.seen_inputs == []
        row = _only_row(h)
        assert row.payload["outcome"] == "refused"
        assert row.payload["refusal_reason"] == "agent_capability_not_assigned"
        assert row.payload["capability_ref"] == "made_up_tool"
        # Resolution failed — the kind is honestly unknown (None), never guessed.
        assert row.payload["capability_kind"] is None

    async def test_duplicate_tool_name_across_grants_is_unresolvable(self) -> None:
        """Pin 10 — a duplicate tool_name across two granted refs makes that
        LLM-facing name unresolvable (deterministic, fail-closed)."""
        run = _run(
            granted=GrantedCapabilities(
                skills=frozenset(),
                tools=frozenset({"srv-a/query", "srv-b/query"}),
            )
        )
        h = _harness()
        out = await h.dispatcher.dispatch(call=_call("query"), step_index=0, run=run)
        assert out.refused is True
        assert out.reason == "agent_capability_not_assigned"
        assert h.proxy.calls == []
        assert len(h.dh.records) == 1

    async def test_malformed_granted_ref_is_unresolvable(self) -> None:
        """A granted ref without the ``server_id/tool_name`` shape can never be
        addressed — defensively skipped from the name map (fail-closed)."""
        run = _run(granted=GrantedCapabilities(skills=frozenset(), tools=frozenset({"noslash"})))
        h = _harness()
        out = await h.dispatcher.dispatch(call=_call("noslash"), step_index=0, run=run)
        assert out.refused is True
        assert out.reason == "agent_capability_not_assigned"

    def test_granted_tool_name_map_pure_helper(self) -> None:
        mapping = _granted_tool_name_map(frozenset({_ORACLE_REF, _OTHER_REF}))
        assert mapping == {
            "run_readonly_query": _ORACLE_REF,
            "other_tool": _OTHER_REF,
        }

    def test_granted_tool_name_map_drops_duplicates(self) -> None:
        assert _granted_tool_name_map(frozenset({"srv-a/query", "srv-b/query"})) == {}
        # A THIRD (and any further) occurrence stays dropped — the
        # already-in-duplicates arm.
        assert (
            _granted_tool_name_map(frozenset({"srv-a/query", "srv-b/query", "srv-c/query"})) == {}
        )

    def test_granted_tool_name_map_drops_malformed_refs(self) -> None:
        assert _granted_tool_name_map(frozenset({"noslash", "srv/", "/name"})) == {}


# --- Pin 2 — gate 1 (assignment) + THE read_skill sub-gate --------------------------


class TestAssignmentGate:
    def test_assignment_verified_pure_helper_all_kinds(self) -> None:
        """The defensive skill arm is unreachable via the M8 resolver — direct-
        tested on the pure helper (the A4 ``_validate_and_partition`` precedent)."""
        granted = GrantedCapabilities(
            skills=frozenset({_GRANTED_SKILL}), tools=frozenset({_ORACLE_REF})
        )
        assert _assignment_verified(CapabilityRef(kind="tool", ref=_ORACLE_REF), granted)
        assert not _assignment_verified(CapabilityRef(kind="tool", ref="srv/unknown"), granted)
        assert _assignment_verified(CapabilityRef(kind="skill", ref=_GRANTED_SKILL), granted)
        assert not _assignment_verified(CapabilityRef(kind="skill", ref="atm-recon"), granted)
        assert _assignment_verified(CapabilityRef(kind="builtin", ref="read_skill"), granted)
        assert _assignment_verified(CapabilityRef(kind="builtin", ref="remember"), granted)

    async def test_defensive_skill_kind_refused_through_dispatch(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Defense in depth: even if a future resolver produced a skill-kind
        ref outside the granted set, gate 1 refuses it at the dispatch level
        with ONE refusal evidence row."""
        monkeypatch.setattr(
            dispatch_module,
            "_resolve_capability",
            lambda name, granted: CapabilityRef(kind="skill", ref="never-granted-skill"),
        )
        h = _harness()
        out = await h.dispatcher.dispatch(call=_call("anything"), step_index=0, run=_run())
        assert out.refused is True
        assert out.reason == "agent_capability_not_assigned"
        row = _only_row(h)
        assert row.payload["capability_kind"] == "skill"
        assert row.payload["capability_ref"] == "never-granted-skill"

    async def test_read_skill_subgate_refuses_unassigned_skill_id(self) -> None:
        """THE read_skill sub-gate (the forced BAR-2 shape): the LLM-authored
        ``skill_id`` argument is itself a capability selection and must clear
        the granted set BEFORE the reader is consulted."""
        h = _harness()
        out = await h.dispatcher.dispatch(
            call=_call("read_skill", skill_id="atm-recon"), step_index=0, run=_run()
        )
        assert out.refused is True
        assert out.reason == "agent_capability_not_assigned"
        assert out.message == "capability 'atm-recon' is not assigned to this agent"
        assert h.reader.calls == []  # NEVER consulted for an unassigned skill_id
        row = _only_row(h)
        assert row.payload["refusal_reason"] == "agent_capability_not_assigned"
        assert row.payload["capability_kind"] == "builtin"
        assert row.payload["capability_ref"] == "read_skill"

    async def test_read_skill_granted_returns_body(self) -> None:
        h = _harness()
        out = await h.dispatcher.dispatch(
            call=_call("read_skill", skill_id=_GRANTED_SKILL), step_index=0, run=_run()
        )
        assert out.refused is False
        assert out.result == {
            "skill_id": _GRANTED_SKILL,
            "description": "Schema summary",
            "body": "# SKILL body",
        }
        assert h.reader.calls == [_GRANTED_SKILL]
        row = _only_row(h)
        assert row.payload["outcome"] == "ok"

    @pytest.mark.parametrize(
        "arguments",
        [{}, {"skill_id": 7}, {"skill_id": None}, {"skill_id": ["schema-summary"]}],
        ids=["missing", "int", "none", "list"],
    )
    async def test_read_skill_missing_or_non_str_skill_id_refuses(
        self, arguments: dict[str, Any]
    ) -> None:
        h = _harness()
        out = await h.dispatcher.dispatch(
            call=_call("read_skill", **arguments), step_index=0, run=_run()
        )
        assert out.refused is True
        assert out.reason == "agent_capability_not_assigned"
        assert h.reader.calls == []
        assert len(h.dh.records) == 1

    def test_validated_read_skill_id_pure_helper(self) -> None:
        granted = GrantedCapabilities(skills=frozenset({_GRANTED_SKILL}), tools=frozenset())
        assert _validated_read_skill_id({"skill_id": _GRANTED_SKILL}, granted) == _GRANTED_SKILL
        assert _validated_read_skill_id({"skill_id": "atm-recon"}, granted) is None
        assert _validated_read_skill_id({}, granted) is None
        assert _validated_read_skill_id({"skill_id": 7}, granted) is None


# --- D-S1 — signed capability-class gate -------------------------------------------


class TestCapabilityClassGate:
    async def test_undeclared_tool_refuses(self) -> None:
        """An absent declaration is never treated as implicitly unscoped."""
        h = _harness(tool_capability_classes={})

        outcome = await h.dispatcher.dispatch(call=_call("other_tool"), step_index=0, run=_run())

        assert outcome.reason == "agent_capability_class_invalid"
        assert h.entitlements.entitled_calls == []
        assert h.opa.seen_inputs == []
        assert h.proxy.calls == []
        assert _only_row(h).payload["refusal_reason"] == ("agent_capability_class_invalid")

    async def test_unknown_class_refuses(self) -> None:
        h = _harness(tool_capability_classes={_OTHER_REF: "nonsense"})

        outcome = await h.dispatcher.dispatch(call=_call("other_tool"), step_index=0, run=_run())

        assert outcome.reason == "agent_capability_class_invalid"
        assert h.proxy.calls == []

    async def test_reserved_retrieval_class_refuses(self) -> None:
        h = _harness(tool_capability_classes={_OTHER_REF: "retrieval"})

        outcome = await h.dispatcher.dispatch(call=_call("other_tool"), step_index=0, run=_run())

        assert outcome.reason == "agent_capability_class_invalid"
        assert h.proxy.calls == []

    async def test_entitlement_verified_cannot_be_true_without_a_store_read(
        self,
    ) -> None:
        """A data-query attestation is derived from gate 2, never asserted."""
        h = _harness(allow=False)

        outcome = await h.dispatcher.dispatch(
            call=_call("run_readonly_query", scope_id=_SCOPE_ID, sql="SELECT 1"),
            step_index=0,
            run=_run(),
        )

        assert outcome.reason == "agent_policy_denied"
        assert len(h.entitlements.entitled_calls) == 1
        assert len(h.entitlements.resolve_calls) == 1
        assert h.opa.seen_inputs[0]["entitlement_verified"] is True

        source = pathlib.Path(dispatch_module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        policy_inputs = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "AgentPolicyInput"
        ]
        assert len(policy_inputs) == 1
        keyword = next(
            item for item in policy_inputs[0].keywords if item.arg == "entitlement_verified"
        )
        assert isinstance(keyword.value, ast.IfExp)
        expression_names = {
            node.id for node in ast.walk(keyword.value) if isinstance(node, ast.Name)
        }
        assert {
            "scope_id",
            "capability_class",
            "_ENTITLEMENT_REQUIRED_CLASSES",
        } <= expression_names

    async def test_unscoped_class_dispatches_without_an_entitlement_read(
        self,
    ) -> None:
        h = _harness(tool_capability_classes={_OTHER_REF: "unscoped"})

        outcome = await h.dispatcher.dispatch(call=_call("other_tool"), step_index=0, run=_run())

        assert outcome.reason is None
        assert h.entitlements.entitled_calls == []
        assert h.entitlements.resolve_calls == []

    async def test_unentitled_action_refuses_before_policy_or_proxy(self) -> None:
        h = _harness(tool_capability_classes={_OTHER_REF: "action"})

        outcome = await h.dispatcher.dispatch(call=_call("other_tool"), step_index=0, run=_run())

        assert outcome.reason == "agent_scope_not_entitled"
        assert h.entitlements.action_calls == [
            {
                "tenant_id": _TENANT,
                "subject": _ORIGINATOR,
                "tool_identity": _OTHER_REF,
            }
        ]
        assert h.entitlements.entitled_calls == []
        assert h.opa.seen_inputs == []
        assert h.proxy.calls == []

    async def test_entitled_action_dispatches_without_data_scope_authority(self) -> None:
        """Action authority comes from the exact tool entitlement, never scope_id."""
        h = _harness(
            tool_capability_classes={_OTHER_REF: "action"},
            action_entitled=True,
        )

        outcome = await h.dispatcher.dispatch(
            call=_call("other_tool", scope_id=_SCOPE_ID),
            step_index=0,
            run=_run(),
        )

        assert outcome.reason is None
        assert outcome.result == {"rows": []}
        assert h.entitlements.action_calls[0]["tool_identity"] == _OTHER_REF
        assert h.entitlements.entitled_calls == []
        assert h.entitlements.resolve_calls == []
        assert h.opa.seen_inputs[0]["entitlement_verified"] is True
        assert len(h.proxy.calls) == 1

    async def test_entitled_action_pending_is_typed_and_evidenced(self) -> None:
        pending_id = str(uuid.uuid4())
        pending = dispatch_module.AgentToolApprovalPending(
            approval_request_id=pending_id,
            flow="require_assigned",
        )
        h = _harness(
            tool_capability_classes={_OTHER_REF: "action"},
            action_entitled=True,
            proxy_exc=pending,
        )

        outcome = await h.dispatcher.dispatch(
            call=_call("other_tool", amount=10),
            step_index=0,
            run=_run(),
        )

        assert outcome == DispatchOutcome(
            refused=False,
            reason=None,
            message=None,
            result=None,
            pending=True,
            approval_request_id=pending_id,
        )
        row = _only_row(h)
        assert row.payload["outcome"] == "pending_approval"
        assert row.payload["approval_request_id"] == pending_id
        assert row.payload["refusal_reason"] is None


def test_the_hardcoded_stamped_tool_list_is_gone() -> None:
    """Tool authority comes from signed manifests, never a kernel name list."""
    source = pathlib.Path(dispatch_module.__file__).read_text(encoding="utf-8")
    assert "_QUERY_CONTEXT_STAMPED_TOOLS" not in source


# --- Pin 3 — gate 2 (entitlement) ----------------------------------------------------


class TestEntitlementGate:
    async def test_unentitled_scope_refuses_before_policy(self) -> None:
        """Gate 2 fires BEFORE gate 3 (spy-proven: the policy evaluator is
        never consulted) and before the proxy."""
        h = _harness(entitled=frozenset())
        out = await h.dispatcher.dispatch(
            call=_call("run_readonly_query", scope_id=_SCOPE_ID, sql="SELECT 1"),
            step_index=0,
            run=_run(),
        )
        assert out.refused is True
        assert out.reason == "agent_scope_not_entitled"
        assert out.message == f"data scope '{_SCOPE_ID}' is not entitled for this request"
        assert h.opa.seen_inputs == []  # gate 2 before gate 3 — pinned
        assert h.proxy.calls == []
        row = _only_row(h)
        assert row.payload["scope_id"] == _SCOPE_ID
        assert row.payload["refusal_reason"] == "agent_scope_not_entitled"

    @pytest.mark.parametrize(
        "arguments",
        [
            {"sql": "SELECT 1"},
            {"scope_id": 7, "sql": "SELECT 1"},
            {"scope_id": "", "sql": "SELECT 1"},
        ],
        ids=["missing", "non-str", "empty"],
    )
    async def test_missing_or_invalid_scope_id_refuses(self, arguments: dict[str, Any]) -> None:
        h = _harness()
        out = await h.dispatcher.dispatch(
            call=_call("run_readonly_query", **arguments), step_index=0, run=_run()
        )
        assert out.refused is True
        assert out.reason == "agent_scope_not_entitled"
        assert h.opa.seen_inputs == []
        assert h.proxy.calls == []
        row = _only_row(h)
        assert row.payload["scope_id"] is None

    async def test_resolve_scope_none_refuses(self) -> None:
        """Entitled but unresolvable (absent OR cross-tenant — the wire-collapse
        None) refuses the same closed-enum reason."""
        h = _harness(scopes={})
        out = await h.dispatcher.dispatch(
            call=_call("run_readonly_query", scope_id=_SCOPE_ID, sql="SELECT 1"),
            step_index=0,
            run=_run(),
        )
        assert out.refused is True
        assert out.reason == "agent_scope_not_entitled"
        assert h.entitlements.resolve_calls == [{"tenant_id": _TENANT, "scope_id": _SCOPE_ID}]
        assert h.opa.seen_inputs == []

    async def test_non_stamped_tool_skips_entitlement_gate(self) -> None:
        """Gate 2 fires ONLY for stamped tools; a plain granted tool skips it
        (entitlement_verified=True per the None-scope rule) and receives NO
        query-context stamp."""
        h = _harness()
        out = await h.dispatcher.dispatch(call=_call("other_tool", q="x"), step_index=0, run=_run())
        assert out.refused is False
        assert h.entitlements.entitled_calls == []
        assert h.entitlements.resolve_calls == []
        assert _QUERY_CONTEXT_ARG not in h.proxy.calls[0]["arguments"]

    async def test_entitlement_reads_are_tenant_and_subject_scoped(
        self, keypair: tuple[bytes, bytes]
    ) -> None:
        private_pem, _ = keypair
        h = _harness(signing_key_pem=private_pem)
        await h.dispatcher.dispatch(
            call=_call("run_readonly_query", scope_id=_SCOPE_ID, sql="SELECT 1"),
            step_index=0,
            run=_run(),
        )
        assert h.entitlements.entitled_calls == [{"tenant_id": _TENANT, "subject": _ORIGINATOR}]
        assert h.entitlements.resolve_calls == [{"tenant_id": _TENANT, "scope_id": _SCOPE_ID}]


# --- Pin 4 — gate 3 (policy) ---------------------------------------------------------


class TestPolicyGate:
    async def test_policy_deny_refuses_and_proxy_untouched(self) -> None:
        h = _harness(allow=False)
        out = await h.dispatcher.dispatch(call=_call("other_tool", q="x"), step_index=0, run=_run())
        assert out.refused is True
        assert out.reason == "agent_policy_denied"
        assert out.message == "policy refused this dispatch"
        assert h.proxy.calls == []
        row = _only_row(h)
        assert row.payload["refusal_reason"] == "agent_policy_denied"

    async def test_opa_unavailable_fails_closed_to_policy_denied(self) -> None:
        """opa_unavailable also lands on ``agent_policy_denied`` (fail-closed;
        the reason is mapped regardless of policy_reason)."""
        h = _harness(opa_exc=OpaNotInstalledError)
        out = await h.dispatcher.dispatch(call=_call("other_tool", q="x"), step_index=0, run=_run())
        assert out.refused is True
        assert out.reason == "agent_policy_denied"
        assert h.proxy.calls == []

    async def test_policy_deny_on_stamped_tool_after_entitlement(self) -> None:
        """Order pin: gate 2 ran (spied), gate 3 denied, proxy untouched."""
        h = _harness(allow=False)
        out = await h.dispatcher.dispatch(
            call=_call("run_readonly_query", scope_id=_SCOPE_ID, sql="SELECT 1"),
            step_index=0,
            run=_run(),
        )
        assert out.refused is True
        assert out.reason == "agent_policy_denied"
        assert len(h.entitlements.entitled_calls) == 1
        assert len(h.opa.seen_inputs) == 1
        assert h.proxy.calls == []

    async def test_policy_input_carries_computed_attestations_and_context(
        self, keypair: tuple[bytes, bytes]
    ) -> None:
        """The 12-key AgentPolicyInput is built AFTER gates 1+2 with the
        literally-computed attestations + the resolved scope id."""
        private_pem, _ = keypair
        h = _harness(signing_key_pem=private_pem)
        await h.dispatcher.dispatch(
            call=_call("run_readonly_query", scope_id=_SCOPE_ID, sql="SELECT 1"),
            step_index=3,
            run=_run(),
        )
        assert h.opa.seen_inputs == [
            {
                "tenant_id": _TENANT,
                "agent_id": _AGENT_ID,
                "originator_subject": _ORIGINATOR,
                "capability_kind": "tool",
                "capability_class": "data_query",
                "capability_ref": _ORACLE_REF,
                "scope_id": _SCOPE_ID,
                "pack_risk_tier": "customer_data_read",
                "step_index": 3,
                "max_steps": 6,
                "assignment_verified": True,
                "entitlement_verified": True,
            }
        ]

    async def test_policy_input_scope_id_none_for_non_stamped(self) -> None:
        h = _harness()
        await h.dispatcher.dispatch(call=_call("other_tool"), step_index=0, run=_run())
        assert h.opa.seen_inputs[0]["scope_id"] is None
        assert h.opa.seen_inputs[0]["entitlement_verified"] is True
        assert h.opa.seen_inputs[0]["capability_class"] == "unscoped"

    async def test_policy_input_builtins_use_the_unscoped_class(self) -> None:
        """Kernel-owned built-ins have no manifest class and ride as unscoped."""
        h = _harness()

        outcome = await h.dispatcher.dispatch(
            call=_call("remember", note="retain this"),
            step_index=0,
            run=_run(),
        )

        assert outcome.refused is False
        assert h.opa.seen_inputs[0]["capability_kind"] == "builtin"
        assert h.opa.seen_inputs[0]["capability_class"] == "unscoped"


# --- Pin 5 + 9 — the query-context stamp ---------------------------------------------


class TestQueryContextStamp:
    async def test_stamp_round_trips_with_real_verify(self, keypair: tuple[bytes, bytes]) -> None:
        private_pem, public_pem = keypair
        h = _harness(signing_key_pem=private_pem, ttl_s=300.0)
        original_args = {"scope_id": _SCOPE_ID, "sql": "SELECT * FROM V_CUSTOMERS", "max_rows": 10}
        call = _call("run_readonly_query", **original_args)
        out = await h.dispatcher.dispatch(call=call, step_index=0, run=_run())
        assert out.refused is False

        assert len(h.proxy.calls) == 1
        proxied = h.proxy.calls[0]
        assert proxied["server_id"] == "cognic-tool-oracle-schema"
        assert proxied["tool_name"] == "run_readonly_query"
        assert proxied["tenant_id"] == _TENANT
        assert proxied["originator_subject"] == _ORIGINATOR
        assert proxied["approval_request_id"] is None
        assert proxied["request_id"].startswith("agent-tool-")

        token = proxied["arguments"][_QUERY_CONTEXT_ARG]
        claims = verify_query_context(
            token=token,
            public_keys_pem=[public_pem],
            expected_aud=_ORACLE_REF,  # aud == the FULL tool ref
            now=int(time.time()),
        )
        assert claims.aud == _ORACLE_REF
        assert claims.sub == _ORIGINATOR
        assert claims.act == _AGENT_ID
        assert claims.tenant_id == _TENANT
        assert claims.scope_id == _SCOPE_ID
        assert claims.objects == _SCOPE.objects
        assert claims.proxy_db_identity == "AGENT_RO"
        # args_sha256 binds the LLM-AUTHORED args (PRE-stamp — the token key is
        # absent from the digest basis; the tool-side recompute strips it).
        assert claims.args_sha256 == hashlib.sha256(canonical_bytes(original_args)).hexdigest()
        assert claims.exp - claims.iat == 300
        assert len(claims.jti) == 32  # secrets.token_hex(16)

        # Execute-args = the original args + the token key, nothing else.
        stripped = {k: v for k, v in proxied["arguments"].items() if k != _QUERY_CONTEXT_ARG}
        assert stripped == original_args

    async def test_caller_arguments_dict_is_never_mutated(
        self, keypair: tuple[bytes, bytes]
    ) -> None:
        private_pem, _ = keypair
        h = _harness(signing_key_pem=private_pem)
        original_args = {"scope_id": _SCOPE_ID, "sql": "SELECT 1"}
        call = _call("run_readonly_query", **original_args)
        await h.dispatcher.dispatch(call=call, step_index=0, run=_run())
        assert call.arguments == original_args
        assert _QUERY_CONTEXT_ARG not in call.arguments

    async def test_signing_key_none_raises_runtime_error(self) -> None:
        """Pin 9 — a stamped dispatch without a signing key is a fail-loud
        DEPLOYMENT error (RuntimeError), NOT a closed-enum refusal; it aborts
        BEFORE any evidence row (nothing governed executed)."""
        h = _harness(signing_key_pem=None)
        with pytest.raises(RuntimeError):
            await h.dispatcher.dispatch(
                call=_call("run_readonly_query", scope_id=_SCOPE_ID, sql="SELECT 1"),
                step_index=0,
                run=_run(),
            )
        assert h.proxy.calls == []
        assert h.dh.records == []

    async def test_signing_key_none_leaves_non_stamped_paths_working(self) -> None:
        h = _harness(signing_key_pem=None)
        out = await h.dispatcher.dispatch(
            call=_call("read_skill", skill_id=_GRANTED_SKILL), step_index=0, run=_run()
        )
        assert out.refused is False


# --- Pin 6 — build_llm_tool_specs (the schema-exclusion pin) --------------------------


class TestBuildLlmToolSpecs:
    def test_run_readonly_query_schema_is_exactly_the_three_fields(self) -> None:
        specs = build_llm_tool_specs(run=_run(), capability_classes=_TOOL_CAPABILITY_CLASSES)
        by_name = {spec.name: spec for spec in specs}
        query_spec = by_name["run_readonly_query"]
        assert set(query_spec.parameters["properties"].keys()) == {"scope_id", "sql", "max_rows"}
        assert query_spec.parameters["required"] == ["scope_id", "sql"]
        assert query_spec.parameters["properties"]["scope_id"]["type"] == "string"
        assert query_spec.parameters["properties"]["sql"]["type"] == "string"
        assert query_spec.parameters["properties"]["max_rows"]["type"] == "integer"

    def test_no_spec_ever_mentions_the_query_context_arg(self) -> None:
        """THE schema-exclusion pin: the stamp key is kernel-owned — it must
        never be advertised to (or authorable by) the LLM. Ditto identity /
        tenant fields on the stamped tool."""
        specs = build_llm_tool_specs(run=_run(), capability_classes=_TOOL_CAPABILITY_CLASSES)
        assert specs, "granted run must produce specs"
        for spec in specs:
            assert _QUERY_CONTEXT_ARG not in json.dumps(spec.parameters)
        by_name = {spec.name: spec for spec in specs}
        query_properties = set(by_name["run_readonly_query"].parameters["properties"])
        assert query_properties.isdisjoint(
            {"tenant_id", "originator_subject", "sub", "act", "agent_id"}
        )

    def test_builtin_specs_present(self) -> None:
        specs = build_llm_tool_specs(run=_run(), capability_classes=_TOOL_CAPABILITY_CLASSES)
        by_name = {spec.name: spec for spec in specs}
        assert {"read_skill", "remember"} <= set(by_name)
        assert set(by_name["read_skill"].parameters["properties"].keys()) == {"skill_id"}
        assert set(by_name["remember"].parameters["properties"].keys()) == {"note"}

    def test_spec_names_are_tool_segments(self) -> None:
        names = {
            spec.name
            for spec in build_llm_tool_specs(
                run=_run(), capability_classes=_TOOL_CAPABILITY_CLASSES
            )
        }
        assert "other_tool" in names
        assert _OTHER_REF not in names

    def test_duplicate_and_malformed_grants_produce_no_spec(self) -> None:
        """Consistency with dispatch: an unresolvable name (duplicate across
        grants / malformed ref) is never advertised to the LLM either."""
        run = _run(
            granted=GrantedCapabilities(
                skills=frozenset(),
                tools=frozenset({"srv-a/query", "srv-b/query", "noslash"}),
            )
        )
        names = {
            spec.name
            for spec in build_llm_tool_specs(run=run, capability_classes=_TOOL_CAPABILITY_CLASSES)
        }
        assert names == {"read_skill", "remember"}

    def test_schema_selection_uses_full_ref_capability_class(self) -> None:
        run = _run(
            granted=GrantedCapabilities(
                skills=frozenset(),
                tools=frozenset({_ORACLE_REF, "srv-c/custom_query"}),
            )
        )
        specs = build_llm_tool_specs(
            run=run,
            capability_classes={
                _ORACLE_REF: "unscoped",
                "srv-c/custom_query": "data_query",
            },
        )
        by_name = {spec.name: spec for spec in specs}

        assert by_name["run_readonly_query"].parameters == {
            "type": "object",
            "properties": {},
            "additionalProperties": True,
        }
        assert set(by_name["custom_query"].parameters["properties"]) == {
            "scope_id",
            "sql",
            "max_rows",
        }
        assert by_name["custom_query"].parameters["additionalProperties"] is False

    def test_action_schema_is_closed_and_never_advertises_reserved_context_key(self) -> None:
        run = _run(
            granted=GrantedCapabilities(
                skills=frozenset(),
                tools=frozenset({_OTHER_REF}),
            )
        )
        (action_spec, *_) = build_llm_tool_specs(
            run=run,
            capability_classes={_OTHER_REF: "action"},
            action_tool_schemas={
                _OTHER_REF: {
                    "type": "object",
                    "properties": {
                        "start_date": {"type": "string"},
                        "end_date": {"type": "string"},
                        "leave_type": {"type": "string"},
                    },
                    "required": ["start_date", "end_date", "leave_type"],
                }
            },
        )
        assert action_spec.name == "other_tool"
        assert set(action_spec.parameters["properties"]) == {
            "start_date",
            "end_date",
            "leave_type",
        }
        assert action_spec.parameters["required"] == [
            "start_date",
            "end_date",
            "leave_type",
        ]
        assert action_spec.parameters["additionalProperties"] is False
        assert ACTION_CONTEXT_ARGUMENT not in action_spec.parameters["properties"]
        assert ACTION_CONTEXT_ARGUMENT not in action_spec.parameters.get("required", [])

    @pytest.mark.parametrize(
        "schemas",
        [
            {},
            {_OTHER_REF: {"type": "array"}},
            {
                _OTHER_REF: {
                    "type": "object",
                    "properties": {"amount": "not-a-schema"},
                }
            },
            {
                _OTHER_REF: {
                    "type": "object",
                    "properties": {ACTION_CONTEXT_ARGUMENT: {"type": "string"}},
                }
            },
            {
                _OTHER_REF: {
                    "type": "object",
                    "properties": {"amount": {"type": "integer"}},
                    "patternProperties": {".*": {}},
                }
            },
            {
                _OTHER_REF: {
                    "type": "object",
                    "properties": {"amount": {"type": "integer"}},
                    "required": ["missing"],
                }
            },
        ],
    )
    def test_action_without_a_safe_live_schema_is_not_advertised(
        self, schemas: dict[str, dict[str, Any]]
    ) -> None:
        run = _run(
            granted=GrantedCapabilities(
                skills=frozenset(),
                tools=frozenset({_OTHER_REF}),
            )
        )

        names = {
            spec.name
            for spec in build_llm_tool_specs(
                run=run,
                capability_classes={_OTHER_REF: "action"},
                action_tool_schemas=schemas,
            )
        }

        assert "other_tool" not in names


class TestReservedActionContext:
    async def test_model_authored_action_context_is_refused_before_approval_or_proxy(self) -> None:
        h = _harness(
            action_entitled=True,
            tool_capability_classes={_OTHER_REF: "action"},
        )
        out = await h.dispatcher.dispatch(
            call=_call("other_tool", amount=1, **{ACTION_CONTEXT_ARGUMENT: "forged"}),
            step_index=0,
            run=_run(),
        )
        assert out.refused is True
        assert out.reason == "agent_tool_dispatch_failed"
        assert h.proxy.calls == []


# --- Pin 7 — backend failure (safe message) -------------------------------------------


class TestDispatchFailure:
    async def test_proxy_exception_refuses_with_class_name_only(self) -> None:
        """The exception CLASS name is the ONLY diagnostic the LLM-visible
        message (and nothing at all in the chain payload) carries — a secret
        in the exception text never leaks."""
        secret = "SECRET-oracle-password-xyz"
        h = _harness(proxy_exc=RuntimeError(secret))
        out = await h.dispatcher.dispatch(call=_call("other_tool", q="x"), step_index=0, run=_run())
        assert out.refused is True
        assert out.reason == "agent_tool_dispatch_failed"
        assert out.message == "the tool call failed (RuntimeError)"
        assert secret not in (out.message or "")
        row = _only_row(h)
        assert row.payload["refusal_reason"] == "agent_tool_dispatch_failed"
        assert secret not in json.dumps(row.payload)

    async def test_granted_but_unhosted_read_skill_surfaces_as_dispatch_failed(self) -> None:
        """A granted-but-unhosted skill_id passes gate 1 then LookupErrors at
        the reader — surfaced through the exception arm (documented)."""
        h = _harness(bodies={})
        out = await h.dispatcher.dispatch(
            call=_call("read_skill", skill_id=_GRANTED_SKILL), step_index=0, run=_run()
        )
        assert out.refused is True
        assert out.reason == "agent_tool_dispatch_failed"
        assert out.message == "the tool call failed (LookupError)"
        assert h.reader.calls == [_GRANTED_SKILL]

    async def test_memory_backend_exception_refuses_dispatch_failed(self) -> None:
        class _ExplodingFactory:
            def __call__(self, context: Any) -> Any:
                raise ValueError("memory backend down")

        h = _harness()
        h_dispatcher = AgentDispatcher(
            entitlements=h.entitlements,  # type: ignore[arg-type]
            policy=AgentDispatchPolicy(opa_engine=h.opa),  # type: ignore[arg-type]
            tool_proxy=h.proxy,
            skill_reader=h.reader,
            memory_factory=_ExplodingFactory(),
            decision_history=h.dh,  # type: ignore[arg-type]
            query_context_signing_key_pem=None,
            query_context_ttl_s=300.0,
            tool_capability_classes=_TOOL_CAPABILITY_CLASSES,
        )
        out = await h_dispatcher.dispatch(
            call=_call("remember", note="n"), step_index=0, run=_run()
        )
        assert out.refused is True
        assert out.reason == "agent_tool_dispatch_failed"
        assert out.message == "the tool call failed (ValueError)"

    @pytest.mark.parametrize(
        "arguments", [{}, {"note": 7}, {"note": None}], ids=["missing", "int", "none"]
    )
    async def test_remember_missing_or_non_str_note_refuses_dispatch_failed(
        self, arguments: dict[str, Any]
    ) -> None:
        """A missing/non-str note is a malformed LLM argument — fail-closed
        via the exception arm (TypeError), never silently coerced; the memory
        factory is never consulted."""
        h = _harness()
        out = await h.dispatcher.dispatch(
            call=_call("remember", **arguments), step_index=0, run=_run()
        )
        assert out.refused is True
        assert out.reason == "agent_tool_dispatch_failed"
        assert out.message == "the tool call failed (TypeError)"
        assert h.memory.contexts == []
        assert len(h.dh.records) == 1


# --- Pin 8 — the agent.run.dispatch evidence row ---------------------------------------


class TestDispatchEvidence:
    async def test_noncanonical_tool_result_becomes_one_evidenced_refusal(self) -> None:
        """The result probe is a dispatcher invariant, independent of whether
        a real OPA binary is available for the composed integration packet."""
        h = _harness(proxy_result={"value": float("nan")})

        outcome = await h.dispatcher.dispatch(
            call=_call("other_tool"),
            step_index=0,
            run=_run(),
        )

        assert len(h.proxy.calls) == 1
        assert outcome.refused is True
        assert outcome.reason == "agent_tool_dispatch_failed"
        assert outcome.message == "the tool call failed (ValueError)"
        row = _only_row(h)
        assert row.payload["outcome"] == "refused"
        assert row.payload["refusal_reason"] == "agent_tool_dispatch_failed"
        assert row.payload["result_sha256"] is None
        assert row.payload["result_bytes"] is None

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param(float("nan"), id="nan"),
            pytest.param(float("inf"), id="positive-infinity"),
            pytest.param(float("-inf"), id="negative-infinity"),
        ],
    )
    async def test_direct_noncanonical_arguments_fail_loud_before_execution_or_evidence(
        self, value: float
    ) -> None:
        """The current evidence schema requires the real canonical argument
        digest, so direct callers may not fabricate a row for values that have
        no canonical bytes.  Production model ingress is closed in LLMGateway."""
        h = _harness()

        with pytest.raises(ValueError, match="non-finite float not allowed in canonical form"):
            await h.dispatcher.dispatch(
                call=_call("other_tool", nested={"value": value}),
                step_index=0,
                run=_run(),
            )

        assert h.proxy.calls == []
        assert h.dh.records == []

    async def test_valid_credential_rotation_ref_is_lifted_verbatim(self) -> None:
        rotation_ref = "2026-07-18T00:00:00+00:00"
        h = _harness(
            proxy_result={
                "rows": [],
                "credential_rotation_ref": rotation_ref,
            }
        )

        await h.dispatcher.dispatch(call=_call("other_tool"), step_index=0, run=_run())

        payload = _only_row(h).payload
        assert payload["credential_rotation_ref"] == rotation_ref
        assert set(payload) == set(_EXPECTED_PAYLOAD_KEYS) | {"credential_rotation_ref"}

    async def test_absent_credential_rotation_ref_is_omitted(self) -> None:
        h = _harness(proxy_result={"rows": []})

        await h.dispatcher.dispatch(call=_call("other_tool"), step_index=0, run=_run())

        assert "credential_rotation_ref" not in _only_row(h).payload

    @pytest.mark.parametrize(
        "rotation_ref",
        [
            pytest.param(7, id="non-string"),
            pytest.param("x" * 65, id="over-bound"),
            pytest.param("2026-07-18\nrotated", id="non-printable"),
        ],
    )
    async def test_malformed_credential_rotation_ref_is_omitted_and_logged_once(
        self,
        rotation_ref: object,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        h = _harness(
            proxy_result={
                "rows": [],
                "credential_rotation_ref": rotation_ref,
            }
        )

        with caplog.at_level(logging.INFO, logger=dispatch_module.__name__):
            await h.dispatcher.dispatch(call=_call("other_tool"), step_index=0, run=_run())

        assert "credential_rotation_ref" not in _only_row(h).payload
        ignored = [
            record
            for record in caplog.records
            if record.getMessage() == "agent.dispatch_rotation_ref_ignored"
        ]
        assert len(ignored) == 1
        assert rotation_ref not in tuple(vars(ignored[0]).values())

    async def test_refusal_and_pending_rows_never_carry_credential_rotation_ref(self) -> None:
        refused = _harness(proxy_exc=RuntimeError("dispatch failed"))
        await refused.dispatcher.dispatch(
            call=_call("other_tool"),
            step_index=0,
            run=_run(),
        )

        pending_id = str(uuid.uuid4())
        pending = _harness(
            tool_capability_classes={_OTHER_REF: "action"},
            action_entitled=True,
            proxy_exc=dispatch_module.AgentToolApprovalPending(
                approval_request_id=pending_id,
                flow="require_assigned",
            ),
        )
        await pending.dispatcher.dispatch(
            call=_call("other_tool"),
            step_index=0,
            run=_run(),
        )

        assert _only_row(refused).payload["outcome"] == "refused"
        assert "credential_rotation_ref" not in _only_row(refused).payload
        assert _only_row(pending).payload["outcome"] == "pending_approval"
        assert "credential_rotation_ref" not in _only_row(pending).payload

    async def test_ok_row_exact_key_set_digest_only(self) -> None:
        args_canary = "CANARY-ARGS-VALUE"
        result_canary = "CANARY-RESULT-VALUE"
        result = {"rows": [result_canary]}
        h = _harness(proxy_result=result)
        out = await h.dispatcher.dispatch(
            call=_call("other_tool", q=args_canary), step_index=2, run=_run()
        )
        assert out.refused is False
        assert out.result == result

        row = _only_row(h)
        assert row.decision_type == "agent.run.dispatch"
        assert row.request_id.startswith("agent-dispatch-")
        assert row.actor_id == _ORIGINATOR  # human accountability
        assert row.tenant_id == _TENANT
        assert row.iso_controls == ()

        payload = row.payload
        assert set(payload.keys()) == set(_EXPECTED_PAYLOAD_KEYS)
        assert payload["run_id"] == "run-0001"
        assert payload["agent_id"] == _AGENT_ID  # ADR-027 §f dual identity
        assert payload["originator_subject"] == _ORIGINATOR
        assert payload["capability_kind"] == "tool"
        assert payload["capability_ref"] == _OTHER_REF
        assert payload["scope_id"] is None
        assert payload["step_index"] == 2
        assert payload["outcome"] == "ok"
        assert payload["refusal_reason"] is None
        assert payload["args_sha256"] == (
            hashlib.sha256(canonical_bytes({"q": args_canary})).hexdigest()
        )
        assert payload["result_sha256"] == hashlib.sha256(canonical_bytes(result)).hexdigest()
        assert payload["result_bytes"] == len(canonical_bytes(result))

        # Digest-only: neither canary ever reaches the chain payload.
        rendered = json.dumps(payload)
        assert args_canary not in rendered
        assert result_canary not in rendered
        # The payload itself is canonical-form serializable (no tuples etc.).
        canonical_bytes(payload)

    async def test_refusal_row_exact_key_set(self) -> None:
        h = _harness()
        await h.dispatcher.dispatch(call=_call("made_up_tool", q="x"), step_index=1, run=_run())
        row = _only_row(h)
        payload = row.payload
        assert set(payload.keys()) == set(_EXPECTED_PAYLOAD_KEYS)
        assert payload["outcome"] == "refused"
        assert payload["refusal_reason"] == "agent_capability_not_assigned"
        assert payload["result_sha256"] is None
        assert payload["result_bytes"] is None
        assert payload["args_sha256"] == (hashlib.sha256(canonical_bytes({"q": "x"})).hexdigest())
        canonical_bytes(payload)

    async def test_stamped_ok_row_carries_scope_id(self, keypair: tuple[bytes, bytes]) -> None:
        private_pem, _ = keypair
        h = _harness(signing_key_pem=private_pem)
        await h.dispatcher.dispatch(
            call=_call("run_readonly_query", scope_id=_SCOPE_ID, sql="SELECT 1"),
            step_index=0,
            run=_run(),
        )
        row = _only_row(h)
        assert row.payload["scope_id"] == _SCOPE_ID
        assert row.payload["outcome"] == "ok"
        # args_sha256 in evidence == the PRE-stamp digest (token key absent).
        assert row.payload["args_sha256"] == (
            hashlib.sha256(canonical_bytes({"scope_id": _SCOPE_ID, "sql": "SELECT 1"})).hexdigest()
        )

    @pytest.mark.parametrize(
        "arm",
        [
            "unassigned",
            "class_invalid",
            "read_skill_subgate",
            "unentitled",
            "policy_denied",
            "dispatch_failed",
            "ok_tool",
            "ok_builtin",
        ],
    )
    async def test_exactly_one_evidence_row_per_dispatch(self, arm: str) -> None:
        """The count pin: EVERY arm — each refusal AND the ok path — emits
        exactly ONE ``agent.run.dispatch`` row per ``dispatch()`` call."""
        if arm == "unassigned":
            h = _harness()
            call = _call("made_up_tool")
        elif arm == "class_invalid":
            h = _harness(tool_capability_classes={})
            call = _call("other_tool")
        elif arm == "read_skill_subgate":
            h = _harness()
            call = _call("read_skill", skill_id="atm-recon")
        elif arm == "unentitled":
            h = _harness(entitled=frozenset())
            call = _call("run_readonly_query", scope_id=_SCOPE_ID, sql="SELECT 1")
        elif arm == "policy_denied":
            h = _harness(allow=False)
            call = _call("other_tool")
        elif arm == "dispatch_failed":
            h = _harness(proxy_exc=RuntimeError("boom"))
            call = _call("other_tool")
        elif arm == "ok_tool":
            h = _harness()
            call = _call("other_tool")
        else:
            h = _harness()
            call = _call("remember", note="check the ATM ledger")
        await h.dispatcher.dispatch(call=call, step_index=0, run=_run())
        assert len(h.dh.records) == 1
        assert h.dh.records[0].decision_type == "agent.run.dispatch"

    async def test_remember_through_dispatch_ok(self) -> None:
        h = _harness()
        out = await h.dispatcher.dispatch(
            call=_call("remember", note="check the ATM ledger"), step_index=4, run=_run()
        )
        assert out.refused is False
        assert out.result == {"remembered": True, "key": "agent-note-run-0001-4"}
        assert h.memory.api.remember_calls[0]["tier"] == "task"
        row = _only_row(h)
        assert row.payload["capability_kind"] == "builtin"
        assert row.payload["capability_ref"] == "remember"
        assert row.payload["outcome"] == "ok"
