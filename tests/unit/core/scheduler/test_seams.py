"""Sprint 10.5a T5 — `core/scheduler/_seams.py` Protocols + sentinels
+ `compute_child_budget` helper.

Consumer-owned Protocols per
[[feedback_consumer_owned_protocol_for_unlanded_dep]]: declares 3
Protocols (QuotaInterrogator, KillSwitchInterrogator,
ParentBudgetResolver) that point at modules NOT yet in the workspace
(Sprint 13.5 + Sprint 11). Each Protocol has a fail-loud `_Null*`
sentinel that raises NotImplementedError pointing at the owning
future sprint.

Per [[feedback_drift_detector_test_only_no_runtime_import]]: no
runtime cross-module imports for vocabulary pinning; this test module
imports the Protocols + sentinels + helper and asserts the contract
shape independently.
"""

from __future__ import annotations

import uuid

import pytest

from cognic_agentos.core.scheduler._seams import (
    KillSwitchInterrogator,
    PackStateInterrogator,
    ParentBudgetResolver,
    QuotaInterrogator,
    _NullKillSwitchInterrogator,
    _NullPackStateInterrogator,
    _NullParentBudgetResolver,
    _NullQuotaInterrogator,
    compute_child_budget,
)

# --- Protocol shape pins ---------------------------------------------------


class TestProtocolMethodNames:
    """Each Protocol declares the exact method names downstream sprints
    must structurally conform to. Method-name drift = wire-protocol
    regression for cross-sprint integration."""

    def test_quota_interrogator_declares_would_admit_and_release_reservation(self):
        # runtime_checkable Protocols expose declared methods on the class
        assert hasattr(QuotaInterrogator, "would_admit")
        assert hasattr(QuotaInterrogator, "release_reservation")

    def test_kill_switch_interrogator_declares_is_active(self):
        assert hasattr(KillSwitchInterrogator, "is_active")

    def test_parent_budget_resolver_declares_remaining_budget_for(self):
        assert hasattr(ParentBudgetResolver, "remaining_budget_for")

    def test_pack_state_interrogator_declares_is_installed(self):
        assert hasattr(PackStateInterrogator, "is_installed")


# --- Sentinel fail-loud contracts -----------------------------------------


class TestNullQuotaInterrogatorFailsLoud:
    async def test_would_admit_raises_not_implemented(self):
        sentinel = _NullQuotaInterrogator()
        with pytest.raises(NotImplementedError) as exc_info:
            await sentinel.would_admit(
                task_id=uuid.uuid4(),
                tenant_id="t",
                pack_id="p",
                estimated_tokens=100,
            )
        msg = str(exc_info.value)
        assert "Sprint 13.5" in msg
        assert "core/emergency/quotas" in msg

    async def test_release_reservation_raises_not_implemented(self):
        sentinel = _NullQuotaInterrogator()
        with pytest.raises(NotImplementedError):
            await sentinel.release_reservation(uuid.uuid4())


class TestNullKillSwitchInterrogatorFailsLoud:
    async def test_is_active_raises_not_implemented(self):
        sentinel = _NullKillSwitchInterrogator()
        with pytest.raises(NotImplementedError) as exc_info:
            await sentinel.is_active(tenant_id="t", pack_id="p")
        msg = str(exc_info.value)
        assert "Sprint 13.5" in msg
        assert "core/emergency/kill_switches" in msg


class TestNullPackStateInterrogatorFailsLoud:
    async def test_is_installed_raises_not_implemented(self):
        sentinel = _NullPackStateInterrogator()
        with pytest.raises(NotImplementedError) as exc_info:
            await sentinel.is_installed(tenant_id="t", pack_id="p")
        msg = str(exc_info.value)
        assert "PackStateInterrogator not wired" in msg
        assert "packs/storage" in msg


class TestNullParentBudgetResolverFailsLoud:
    async def test_remaining_budget_for_raises_not_implemented(self):
        sentinel = _NullParentBudgetResolver()
        with pytest.raises(NotImplementedError) as exc_info:
            await sentinel.remaining_budget_for(uuid.uuid4())
        msg = str(exc_info.value)
        assert "Sprint 11" in msg
        # Per locked round-4 sentinel docstring fix: fail-loud is the
        # contract; NOT translation to a closed-enum refused_policy_denied
        assert "NotImplementedError" in msg


# --- compute_child_budget pure-functional helper --------------------------


class TestComputeChildBudgetHappyPath:
    def test_returns_min_of_two_when_child_quota_is_lower(self):
        assert compute_child_budget(parent_remaining_budget=1000, child_pack_quota=500) == 500

    def test_returns_parent_remaining_when_parent_is_tighter(self):
        assert compute_child_budget(parent_remaining_budget=300, child_pack_quota=500) == 300

    def test_returns_zero_when_parent_exhausted(self):
        assert compute_child_budget(parent_remaining_budget=0, child_pack_quota=500) == 0

    def test_returns_zero_when_child_pack_quota_zero(self):
        assert compute_child_budget(parent_remaining_budget=500, child_pack_quota=0) == 0


class TestComputeChildBudgetRejectsNegativeInputs:
    def test_raises_value_error_on_negative_parent_remaining_budget(self):
        with pytest.raises(ValueError, match="parent_remaining_budget"):
            compute_child_budget(parent_remaining_budget=-1, child_pack_quota=500)

    def test_raises_value_error_on_negative_child_pack_quota(self):
        with pytest.raises(ValueError, match="child_pack_quota"):
            compute_child_budget(parent_remaining_budget=500, child_pack_quota=-1)


class TestComputeChildBudgetKeywordOnly:
    def test_rejects_positional_args(self):
        with pytest.raises(TypeError):
            compute_child_budget(1000, 500)  # type: ignore[misc]
