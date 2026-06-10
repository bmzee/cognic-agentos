from __future__ import annotations

import json
import shutil
import subprocess
import typing
from pathlib import Path

import pytest

_BUNDLE = Path(__file__).resolve().parents[3] / "policies" / "_default" / "tools.rego"
_FLOW = "data.cognic.tools.approval.flow"
_opa_required = pytest.mark.skipif(shutil.which("opa") is None, reason="opa binary required")


def _flow(risk_tier: str) -> str:
    out = subprocess.run(
        ["opa", "eval", "--data", str(_BUNDLE), "--format", "json", "--stdin-input", _FLOW],
        input=json.dumps({"risk_tier": risk_tier}),
        capture_output=True,
        text=True,
        check=True,
    )
    value = json.loads(out.stdout)["result"][0]["expressions"][0]["value"]
    assert isinstance(value, str)
    return value


@_opa_required
@pytest.mark.parametrize(
    "tier,flow",
    [
        ("read_only", "auto_run"),
        ("internal_write", "auto_run"),
        ("customer_data_read", "require_single_approval"),
        ("customer_data_write", "require_single_approval"),
        ("payment_action", "require_4_eyes"),
        ("regulator_communication", "require_4_eyes"),
        ("cross_tenant", "require_4_eyes"),
        ("high_risk_custom", "require_4_eyes"),
        ("totally_unknown_tier", "require_4_eyes"),  # default fail-closed
    ],
)
def test_tier_to_flow(tier: str, flow: str) -> None:
    assert _flow(tier) == flow


def test_flow_vocab_pinned() -> None:
    from cognic_agentos.core.approval._types import ApprovalFlow

    assert set(typing.get_args(ApprovalFlow)) == {
        "auto_run",
        "require_single_approval",
        "require_4_eyes",
    }


@_opa_required
def test_emitted_flows_are_closed_vocab() -> None:
    # Doctrine pin (scheduler.rego precedent): the bundle NEVER emits a value
    # outside ApprovalFlow — every known tier plus several unknowns/edge inputs
    # stay within the 3-value closed enum.
    from cognic_agentos.core.approval._types import ApprovalFlow

    emitted = {
        _flow(t)
        for t in (
            "read_only",
            "internal_write",
            "customer_data_read",
            "customer_data_write",
            "payment_action",
            "regulator_communication",
            "cross_tenant",
            "high_risk_custom",
            "totally_unknown_tier",
            "",
            "customer",
        )
    }
    assert emitted <= set(typing.get_args(ApprovalFlow))
