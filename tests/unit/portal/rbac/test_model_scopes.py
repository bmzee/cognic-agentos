"""Sprint 9.5 B1 — ``ModelRBACScope`` closed-enum widening + ``Actor.scopes``
additive widening + ``RequireScope`` union extension + public ``bind_actor``
alias.

``portal/rbac/scopes.py`` + ``actor.py`` + ``enforcement.py`` are RBAC
stop-rule files per AGENTS.md + the "Wire-protocol contracts" stop rule.
Every 403 ``scope_not_held`` denial body carries the missing scope as a
closed-enum string; ANY drift in the ``ModelRBACScope`` vocabulary OR
the ``Actor.scopes`` union annotation OR the ``RequireScope`` accepted-
scope union is a wire-protocol break.

This module pins the user-locked Sprint-9.5 B1 invariants:

1. exact 8-value ``ModelRBACScope`` closed enum (including
   ``model.promote.deprecated`` — the +1 per spec §6.3 line 489 that
   BUILD_PLAN §796-802 didn't enumerate)
2. ``Actor.scopes`` widened ADDITIVELY (pre-9.5 actors still construct)
3. ``RequireScope(scope=...)`` accepts ``ModelRBACScope`` — Sprint 9 T5
   compliance-scope pattern, extended
4. tests pin all three files (closed enum + actor construction + RequireScope
   type hint + RequireScope construction for every model scope)
5. no ``scope_not_held`` wire-shape drift: the 3-key body
   ``{reason, required_scope, actor_subject}`` stays the same; only
   ``required_scope`` can now carry a ``model.*`` value
6. ``bind_actor`` public alias identity (the FastAPI sub-dep cache key
   must match ``_bind_actor`` so body-aware authz handlers can take
   ``Annotated[Actor, Depends(bind_actor)]`` alongside ``RequireScope``
   without re-resolving the actor twice per request)
"""

from __future__ import annotations

import typing
from typing import Any, get_args

import pytest
from fastapi import HTTPException

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import (
    RequireScope,
    _bind_actor,
    bind_actor,
)
from cognic_agentos.portal.rbac.scopes import (
    MODEL_LIFECYCLE_SCOPES,
    ComplianceRBACScope,
    ModelRBACScope,
    PackRBACScope,
    UIRBACScope,
)

#: Canonical 8-value pin — wire-protocol contract per spec §6.3 line
#: 485-492. Drift here is a wire-protocol break. Annotated as
#: ``frozenset[ModelRBACScope]`` (not ``frozenset[str]``) so the
#: parametrize tests below can pass elements directly into Actor /
#: RequireScope without mypy needing a per-call cast.
_EXPECTED_MODEL_SCOPES: frozenset[ModelRBACScope] = frozenset(
    {
        "model.register",
        "model.promote.eval_passed",
        "model.promote.tenant_approved",
        "model.promote.serving",
        "model.promote.deprecated",
        "model.retire",
        "model.audit.read",
        "model.usage.read",
    }
)


# ──────────────────────────────────────────────────────────────────────
# 1. ModelRBACScope vocabulary (portal/rbac/scopes.py)
# ──────────────────────────────────────────────────────────────────────


class TestModelRBACScopeVocabulary:
    """The 8-value vocabulary is the wire-protocol contract for every
    403 ``scope_not_held`` denial body on the model-registry surface.
    Each value corresponds 1:1 to a portal endpoint per spec §6.2 (with
    the four ``model.promote.*`` scopes resolved body-aware from the
    POST /promote target_state)."""

    def test_count_is_exactly_eight(self) -> None:
        assert len(get_args(ModelRBACScope)) == 8

    def test_expected_value_set(self) -> None:
        assert set(get_args(ModelRBACScope)) == _EXPECTED_MODEL_SCOPES

    def test_model_promote_deprecated_is_present(self) -> None:
        """User-locked B1 invariant — explicit named pin for the value
        the plan-of-record added per spec §6.3 line 489 (BUILD_PLAN
        §796-802 enumerated 7; ``model.promote.deprecated`` was the +1
        per spec §8)."""
        assert "model.promote.deprecated" in get_args(ModelRBACScope)

    def test_every_value_in_model_namespace(self) -> None:
        """Defence-in-depth namespace prefix — every value starts with
        ``model.``; prevents a future scope addition accidentally
        landing in the wrong family's Literal.
        """
        for value in get_args(ModelRBACScope):
            assert value.startswith("model."), f"model scope {value!r} does not start with 'model.'"

    def test_four_promote_scopes_match_lifecycle_states(self) -> None:
        """The four ``model.promote.*`` scopes correspond 1:1 to the
        four non-genesis non-retire ``ModelTransition`` target states
        (per models/registry.py + spec §6.2). Resolved body-aware from
        POST /promote target_state."""
        promote_scopes = {s for s in get_args(ModelRBACScope) if s.startswith("model.promote.")}
        assert promote_scopes == {
            "model.promote.eval_passed",
            "model.promote.tenant_approved",
            "model.promote.serving",
            "model.promote.deprecated",
        }


class TestModelLifecycleScopesFrozenset:
    """``MODEL_LIFECYCLE_SCOPES`` is the runtime convenience frozenset
    consumed by bank-overlay binders that mint a model-only actor scope
    set. MUST stay 1:1 with the ``ModelRBACScope`` Literal."""

    def test_frozenset_equals_literal(self) -> None:
        assert MODEL_LIFECYCLE_SCOPES == _EXPECTED_MODEL_SCOPES

    def test_frozenset_equals_get_args(self) -> None:
        assert frozenset(get_args(ModelRBACScope)) == MODEL_LIFECYCLE_SCOPES

    def test_frozenset_is_immutable(self) -> None:
        assert isinstance(MODEL_LIFECYCLE_SCOPES, frozenset)


# ──────────────────────────────────────────────────────────────────────
# 2. Namespace disjointness — no overlap with pack / UI / compliance
# ──────────────────────────────────────────────────────────────────────


class TestModelScopesDisjointFromOtherFamilies:
    """``ModelRBACScope`` MUST be value-disjoint from ``PackRBACScope``,
    ``UIRBACScope``, ``ComplianceRBACScope``. Overlap would create a
    wire-protocol ambiguity: a single denial reason string could match
    multiple scope families, leaving examiners + operator runbooks
    unable to determine which surface emitted the 403."""

    def test_disjoint_from_pack_scopes(self) -> None:
        model_set = set(get_args(ModelRBACScope))
        pack_set = set(get_args(PackRBACScope))
        overlap = model_set & pack_set
        assert overlap == set(), (
            f"ModelRBACScope and PackRBACScope MUST be value-disjoint; overlap: {overlap}"
        )

    def test_disjoint_from_ui_scopes(self) -> None:
        overlap = set(get_args(ModelRBACScope)) & set(get_args(UIRBACScope))
        assert overlap == set(), (
            f"ModelRBACScope and UIRBACScope MUST be value-disjoint; overlap: {overlap}"
        )

    def test_disjoint_from_compliance_scopes(self) -> None:
        overlap = set(get_args(ModelRBACScope)) & set(get_args(ComplianceRBACScope))
        assert overlap == set(), (
            f"ModelRBACScope and ComplianceRBACScope MUST be value-disjoint; overlap: {overlap}"
        )

    def test_no_other_family_uses_model_prefix(self) -> None:
        """Stronger pin: no value in PackRBACScope / UIRBACScope /
        ComplianceRBACScope starts with ``model.``."""
        for family_name, family in (
            ("PackRBACScope", PackRBACScope),
            ("UIRBACScope", UIRBACScope),
            ("ComplianceRBACScope", ComplianceRBACScope),
        ):
            for value in get_args(family):
                assert not value.startswith("model."), (
                    f"{family_name} value {value!r} pollutes the model.* namespace"
                )


# ──────────────────────────────────────────────────────────────────────
# 3. Actor.scopes additive widening (portal/rbac/actor.py)
# ──────────────────────────────────────────────────────────────────────


class TestActorAcceptsModelScopes:
    """``Actor.scopes`` widened additively to include ``ModelRBACScope``
    — a single bank-overlay actor can carry model scopes alongside any
    other scope family without needing multiple Actor instances. Pre-9.5
    actors that carried only pack / UI / compliance scopes still
    construct cleanly (additive invariant)."""

    @pytest.mark.parametrize("scope", sorted(_EXPECTED_MODEL_SCOPES))
    def test_actor_constructs_with_every_model_scope(self, scope: ModelRBACScope) -> None:
        """Parametrized over all 8 values per user-locked B1 invariant
        ("construction for every model scope")."""
        actor = Actor(
            subject="alice",
            tenant_id="tenant-acme",
            scopes=frozenset({scope}),
            actor_type="human",
        )
        assert scope in actor.scopes

    def test_actor_accepts_full_8_model_scope_set(self) -> None:
        """A model-only actor (e.g. a forge-bot service identity that
        registers + promotes all transitions) carries all 8 model
        scopes simultaneously."""
        actor = Actor(
            subject="forge-bot",
            tenant_id="tenant-acme",
            scopes=_EXPECTED_MODEL_SCOPES,
            actor_type="service",
        )
        assert actor.scopes == _EXPECTED_MODEL_SCOPES

    def test_actor_accepts_pack_scopes_unchanged(self) -> None:
        """Backward-compat regression: pre-9.5 pack-only actors MUST
        still construct cleanly (additive widening invariant)."""
        actor = Actor(
            subject="reviewer",
            tenant_id="tenant-acme",
            scopes=frozenset({"pack.submit", "pack.audit.read"}),
            actor_type="human",
        )
        assert "pack.submit" in actor.scopes
        assert "pack.audit.read" in actor.scopes

    def test_actor_accepts_mixed_four_family_union(self) -> None:
        """The reason for the widening: a bank-overlay actor can carry
        scopes from ALL four families (pack / UI / compliance / model)
        in one frozenset. A reviewer with model-registry approval
        responsibility is one Actor with scopes from all four."""
        scopes: frozenset[PackRBACScope | UIRBACScope | ComplianceRBACScope | ModelRBACScope] = (
            frozenset(
                {
                    "pack.review.approve",  # Sprint 7B.2
                    "ui.tenant_stream",  # Sprint 7B.4
                    "compliance.trace.read",  # Sprint 9
                    "model.promote.tenant_approved",  # Sprint 9.5
                }
            )
        )
        actor = Actor(
            subject="reviewer-tenant-approver",
            tenant_id="tenant-acme",
            scopes=scopes,
            actor_type="human",
        )
        assert actor.scopes == scopes


# ──────────────────────────────────────────────────────────────────────
# 4. RequireScope union extension (portal/rbac/enforcement.py)
# ──────────────────────────────────────────────────────────────────────


class TestRequireScopeAcceptsModelScopes:
    """``RequireScope(scope=...)`` is a closure factory that MUST accept
    ``ModelRBACScope`` arguments. Pinned both at the runtime level
    (callable construction) AND as a mypy-level type-union check
    (``typing.get_type_hints`` introspection)."""

    def test_scope_parameter_union_includes_model_rbac_scope(self) -> None:
        """Same pattern as Sprint 9 T5's
        ``test_require_scope_signature_accepts_compliance_scopes`` —
        the ``scope`` parameter union MUST flatten to include every
        ``ModelRBACScope`` value."""
        hints = typing.get_type_hints(RequireScope)
        accepted: set[str] = set()
        for member in get_args(hints["scope"]):
            accepted |= set(get_args(member))
        assert accepted >= _EXPECTED_MODEL_SCOPES

    def test_scope_parameter_union_keeps_pack_ui_compliance(self) -> None:
        """Backward-compat regression: the 7B.2 / 7B.4 / 9 unions MUST
        still be accepted after the 9.5 widening (additive)."""
        hints = typing.get_type_hints(RequireScope)
        accepted: set[str] = set()
        for member in get_args(hints["scope"]):
            accepted |= set(get_args(member))
        # Spot-check one value from each pre-9.5 family.
        assert "pack.submit" in accepted
        assert "ui.tenant_stream" in accepted
        assert "compliance.evidence_pack.read" in accepted

    @pytest.mark.parametrize("scope", sorted(_EXPECTED_MODEL_SCOPES))
    def test_require_scope_constructs_for_every_model_scope(self, scope: ModelRBACScope) -> None:
        """Smoke test — ``RequireScope`` builds a callable dependency
        for every ModelRBACScope value (parametrized per user-locked
        B1 invariant). End-to-end 403 behaviour is pinned by
        :class:`TestScopeNotHeldWireShapePreserved` below."""
        dep = RequireScope(scope)
        assert callable(dep)


# ──────────────────────────────────────────────────────────────────────
# 5. Wire-shape preservation — scope_not_held body unchanged
# ──────────────────────────────────────────────────────────────────────


class TestScopeNotHeldWireShapePreserved:
    """User-locked B1 invariant: the 403 ``scope_not_held`` denial body
    keyset stays ``{reason, required_scope, actor_subject}`` (the 7B.2
    contract); only the ``required_scope`` value's namespace can now
    be ``model.*``. Drift would break SIEM correlation + bank-overlay
    denial-handling consumers."""

    async def test_scope_not_held_body_has_3_keys_with_model_scope(self) -> None:
        """Trigger the closure directly with an actor lacking the
        required model scope; assert the HTTPException carries the
        expected 3-key body shape with the model-namespace value at
        ``required_scope``.
        """
        actor = Actor(
            subject="bob",
            tenant_id="tenant-acme",
            scopes=frozenset({"pack.audit.read"}),  # no model.* scope
            actor_type="human",
        )
        # Minimal Request stub that the dependency body uses for
        # request_id resolution + broker lookup. The dependency is
        # invoked with both args (actor pre-resolved); FastAPI's
        # normal sub-dep resolution path is bypassed for this
        # focused unit-level pin.
        request: Any = type("R", (), {})()
        request.state = type("S", (), {})()
        request.state.request_id = "req-test-b1-scope-not-held"
        request.app = type("A", (), {})()
        request.app.state = type("AS", (), {})()
        request.app.state.ui_event_broker = None  # broker is optional (R3 #3)

        dep = RequireScope("model.register")
        with pytest.raises(HTTPException) as exc_info:
            await dep(request, actor)

        assert exc_info.value.status_code == 403
        body = exc_info.value.detail
        assert isinstance(body, dict)
        # User-locked pin: 3-key keyset preserved (no drift from 7B.2
        # contract; required_scope is the only value that changes
        # namespace).
        assert set(body.keys()) == {"reason", "required_scope", "actor_subject"}
        assert body["reason"] == "scope_not_held"
        assert body["required_scope"] == "model.register"
        assert body["actor_subject"] == "bob"


# ──────────────────────────────────────────────────────────────────────
# 6. bind_actor public alias identity
# ──────────────────────────────────────────────────────────────────────


class TestBindActorPublicAlias:
    """``bind_actor`` is a public alias for the internal ``_bind_actor``
    FastAPI dependency so body-aware authz routes (POST /promote, where
    the required scope depends on the body's ``target_state``) can
    declare ``Annotated[Actor, Depends(bind_actor)]`` without crossing
    the ``_``-private boundary AND without breaking FastAPI's sub-dep
    cache (the cache keys on the dependency *object* identity, so the
    alias MUST be the same object — not a wrapper)."""

    def test_bind_actor_is_same_object_as_private(self) -> None:
        """Identity check (``is``, not ``==``) — pins that the alias
        is a direct rebinding, not a forwarding wrapper. A wrapper
        would break the FastAPI sub-dep cache (the body-aware promote
        handler would re-resolve the actor on every dependency that
        names ``bind_actor`` vs ``_bind_actor``)."""
        assert bind_actor is _bind_actor

    def test_bind_actor_is_callable(self) -> None:
        """Defence-in-depth: the alias must be the callable dependency
        itself, not a re-export of a class or module."""
        assert callable(bind_actor)
