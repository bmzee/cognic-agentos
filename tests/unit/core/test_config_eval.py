from __future__ import annotations

import pytest
from pydantic import ValidationError

from cognic_agentos.core.config import Settings


def test_eval_judge_tier_defaults_to_tier1() -> None:
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.eval_judge_tier == "tier1"


def test_eval_judge_tier_rejects_non_logical_tier() -> None:
    # An alias (not a logical tier) must be refused at config-load — the gateway
    # only knows logical tiers (tier1/tier2); a bad value must not reach runtime.
    with pytest.raises(ValidationError):
        # arg-type: passing a non-logical-tier literal is rejected statically by
        # mypy too (the Literal["tier1","tier2"] field) — exactly the guard under
        # test; suppressed so the runtime-refusal path stays exercised. call-arg:
        # _env_file is a BaseSettings runtime kwarg, not in the model signature.
        Settings(_env_file=None, eval_judge_tier="cognic-tier1-dev")  # type: ignore[call-arg, arg-type]
