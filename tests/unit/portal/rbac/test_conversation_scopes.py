"""ADR-028 M8.5-C — conversation.* RBAC scopes.

Mirrors the AgentRBACScope / SkillRBACScope / RunRBACScope additive-widening
pattern. The family is namespace-disjoint from every other family: conversing
with an agent is not the same authority as invoking one.
"""

from __future__ import annotations

from typing import get_args

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope
from cognic_agentos.portal.rbac.scopes import (
    AGENT_SCOPES,
    CONVERSATION_SCOPES,
    MCP_SCOPES,
    MEMORY_SCOPES,
    PACK_LIFECYCLE_SCOPES,
    RUN_SCOPES,
    SKILL_SCOPES,
    SUBAGENT_SCOPES,
    ConversationRBACScope,
)


def test_literal_and_frozenset_agree() -> None:
    assert set(get_args(ConversationRBACScope)) == CONVERSATION_SCOPES


def test_exactly_four_values_in_the_vertical_slice() -> None:
    """export / redact are compliance-role, human-gated, and land with M8.5-F."""
    assert len(CONVERSATION_SCOPES) == 4
    assert {
        "conversation.create",
        "conversation.read",
        "conversation.post_turn",
        "conversation.close",
    } == CONVERSATION_SCOPES


def test_every_value_is_namespaced() -> None:
    assert all(s.startswith("conversation.") for s in CONVERSATION_SCOPES)


def test_namespace_is_disjoint_from_every_other_family() -> None:
    for other in (
        AGENT_SCOPES,
        SKILL_SCOPES,
        RUN_SCOPES,
        SUBAGENT_SCOPES,
        MCP_SCOPES,
        MEMORY_SCOPES,
        PACK_LIFECYCLE_SCOPES,
    ):
        assert CONVERSATION_SCOPES.isdisjoint(other)


def test_export_and_redact_are_not_yet_in_the_vocabulary() -> None:
    """Guard against silently widening authority before the erasure slice."""
    assert "conversation.export" not in CONVERSATION_SCOPES
    assert "conversation.redact" not in CONVERSATION_SCOPES


def test_actor_accepts_a_conversation_scope() -> None:
    actor = Actor(
        subject="analyst",
        tenant_id="t1",
        scopes=frozenset({"conversation.create", "conversation.post_turn"}),
        actor_type="human",
    )
    assert "conversation.create" in actor.scopes


def test_require_scope_accepts_each_conversation_scope() -> None:
    for scope in sorted(CONVERSATION_SCOPES):
        assert RequireScope(scope) is not None
