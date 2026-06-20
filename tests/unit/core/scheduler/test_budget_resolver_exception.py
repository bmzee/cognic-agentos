"""ParentTaskBudgetUnavailable typed exception + closed-enum reason (ADR-005)."""

from __future__ import annotations

import uuid
from typing import get_args

import pytest

from cognic_agentos.core.scheduler._seams import (
    ParentTaskBudgetUnavailable,
    ParentTaskBudgetUnavailableReason,
    _NullParentBudgetResolver,
)


def test_reason_literal_is_exactly_two_values() -> None:
    assert set(get_args(ParentTaskBudgetUnavailableReason)) == {
        "parent_not_found",
        "parent_terminal",
    }


def test_exception_carries_reason() -> None:
    exc = ParentTaskBudgetUnavailable("parent_not_found")
    assert exc.reason == "parent_not_found"
    assert isinstance(exc, Exception)


async def test_sentinel_still_fail_loud_with_tenant_kwarg() -> None:
    # The signature extension keeps the sentinel fail-loud (NotImplementedError),
    # NOT a closed-enum refusal — the seam doctrine is preserved.
    with pytest.raises(NotImplementedError):
        await _NullParentBudgetResolver().remaining_budget_for(uuid.uuid4(), tenant_id="t")
