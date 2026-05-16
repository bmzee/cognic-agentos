"""Sprint 7B.4 T5 — UIRBACScope closed-enum vocabulary + Actor.scopes
union widening regressions.

`portal/rbac/scopes.py` AND `portal/rbac/actor.py` are both on the
AGENTS.md critical-controls list + the "Wire-protocol contracts" stop
rule (every 403 `scope_not_held` denial body carries the missing scope
as a closed-enum string per ADR-012 §40). These regressions defend:

  - the 8-value `UIRBACScope` vocabulary (drift here = wire-protocol
    drift on UI denial bodies)
  - disjointness from the pre-existing `PackRBACScope` vocabulary
    (overlap would create ambiguous denial reasons — a single string
    could match either family, and the operator-side audit chain would
    not know which surface refused)
  - Actor.scopes accepts mixed unions at the Pydantic-validation
    boundary so a single bank-overlay actor can carry both pack
    lifecycle scopes (T2-era) AND UI action scopes (T5+) without
    needing two separate Actor instances
"""

from __future__ import annotations

from typing import get_args

import pydantic
import pytest

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.scopes import PackRBACScope, UIRBACScope


class TestUIRBACScopeShape:
    """The 8-value vocabulary is the wire-protocol contract for every
    403 `scope_not_held` denial body on the UI surface. Each value
    corresponds 1:1 to either an SSE-stream endpoint (`ui.run_stream`,
    `ui.tenant_stream`) or one of the 6 ActionClass values consumed
    by `POST /api/v1/ui/actions` per the design spec §4.4."""

    def test_count_is_8(self) -> None:
        assert len(get_args(UIRBACScope)) == 8

    def test_expected_values(self) -> None:
        assert set(get_args(UIRBACScope)) == {
            "ui.run_stream",
            "ui.tenant_stream",
            "ui.action.approve",
            "ui.action.deny",
            "ui.action.cancel_run",
            "ui.action.interrupt",
            "ui.action.resume",
            "ui.action.submit_elicitation",
        }

    def test_two_stream_scopes_present(self) -> None:
        """Defence-in-depth: ensure the 2 stream-surface scopes are
        spelled correctly + present. T10 GET endpoints depend on these."""
        assert "ui.run_stream" in get_args(UIRBACScope)
        assert "ui.tenant_stream" in get_args(UIRBACScope)

    def test_six_action_scopes_present(self) -> None:
        """Defence-in-depth: the 6 action-surface scopes match the
        6-value ActionClass Literal from the T9 dto.py spec — drift
        would mean a 403 emitted under a scope name that does NOT
        correspond to any submitable ActionClass."""
        action_scopes = {s for s in get_args(UIRBACScope) if s.startswith("ui.action.")}
        assert action_scopes == {
            "ui.action.approve",
            "ui.action.deny",
            "ui.action.cancel_run",
            "ui.action.interrupt",
            "ui.action.resume",
            "ui.action.submit_elicitation",
        }


class TestUIRBACScopeDisjointFromPackRBACScope:
    """`UIRBACScope` and `PackRBACScope` MUST be value-disjoint. Overlap
    would create a wire-protocol ambiguity: a single denial reason
    string could match either family, leaving examiners + operator
    runbooks unable to determine which surface emitted the 403.

    Verified at T5: the `ui.*` namespace and the `pack.*` namespace
    are structurally separate, but drift can still creep in (e.g. an
    accidentally-added `ui.audit.read` and an existing
    `pack.audit.read` would collide if someone removed the `pack.`
    prefix). The frozenset disjointness check pins this invariant."""

    def test_disjoint_from_pack_rbac_scope(self) -> None:
        ui_set = set(get_args(UIRBACScope))
        pack_set = set(get_args(PackRBACScope))
        overlap = ui_set & pack_set
        assert overlap == set(), (
            f"UIRBACScope and PackRBACScope MUST be value-disjoint; overlapping values: {overlap}"
        )

    def test_namespace_prefix_separation(self) -> None:
        """Stronger pin: every UIRBACScope starts with `ui.`; no
        PackRBACScope starts with `ui.`. Prevents the case where a
        future scope addition accidentally lands in the wrong family's
        Literal."""
        assert all(s.startswith("ui.") for s in get_args(UIRBACScope))
        assert all(not s.startswith("ui.") for s in get_args(PackRBACScope))


class TestActorScopesAcceptsUnion:
    """Actor.scopes annotation widened to `frozenset[PackRBACScope |
    UIRBACScope]` so a single bank-overlay actor can carry mixed-family
    scopes. The widening is ADDITIVE — every Actor that worked under
    the T2-era `frozenset[PackRBACScope]` shape still constructs
    cleanly (Pydantic does not enforce Literal at runtime, but the
    annotation governs type-checker behavior at every call site).
    """

    def test_actor_accepts_ui_scopes(self) -> None:
        actor = Actor(
            subject="u1",
            tenant_id="t1",
            actor_type="human",
            scopes=frozenset({"ui.run_stream", "ui.action.approve"}),
        )
        assert "ui.run_stream" in actor.scopes
        assert "ui.action.approve" in actor.scopes

    def test_actor_accepts_pack_scopes_unchanged(self) -> None:
        """Backward-compat regression: every pre-T5 actor that carried
        ONLY PackRBACScope values MUST still construct cleanly."""
        actor = Actor(
            subject="u1",
            tenant_id="t1",
            actor_type="human",
            scopes=frozenset({"pack.submit", "pack.audit.read"}),
        )
        assert "pack.submit" in actor.scopes
        assert "pack.audit.read" in actor.scopes

    def test_actor_accepts_mixed_union_scopes(self) -> None:
        """The reason for the widening: bank-overlay actors carrying
        BOTH pack lifecycle scopes AND UI action scopes in one frozenset.
        A reviewer who also drives the portal UI is one Actor with
        scopes from both families."""
        actor = Actor(
            subject="u1",
            tenant_id="t1",
            actor_type="human",
            scopes=frozenset(
                {
                    "pack.review.claim",
                    "pack.review.approve",
                    "ui.tenant_stream",
                    "ui.action.approve",
                    "ui.action.deny",
                }
            ),
        )
        # All 5 scopes present after Pydantic validation.
        assert actor.scopes == frozenset(
            {
                "pack.review.claim",
                "pack.review.approve",
                "ui.tenant_stream",
                "ui.action.approve",
                "ui.action.deny",
            }
        )

    def test_actor_frozen_invariant_preserved(self) -> None:
        """Pydantic frozen=True still applies after widening — Actor
        mutation must refuse with ValidationError on any field
        assignment (defence-in-depth check that the widening did not
        accidentally drop ``model_config.frozen=True``)."""
        actor = Actor(
            subject="u1",
            tenant_id="t1",
            actor_type="human",
            scopes=frozenset({"ui.run_stream"}),
        )
        with pytest.raises(pydantic.ValidationError):
            actor.subject = "u_mutated"
