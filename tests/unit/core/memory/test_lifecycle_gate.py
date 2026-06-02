"""T5 — check_lifecycle() guard on MemoryGate (sub-agent durable access refused).

Sprint 11.5b — core/ stop-rule per AGENTS.md (Memory governance enforcement,
ADR-019 §7.3 I2). check_lifecycle() is the forget/redact authz gate: a
sub-agent may NOT mutate durable memory (children are scratch-only).
"""

from __future__ import annotations

import pytest

from cognic_agentos.core.memory.gate import MemoryGate
from cognic_agentos.core.memory.tiers import MemoryOperationRefused

# --------------------------------------------------------------------------- #
# Fixtures                                                                     #
# --------------------------------------------------------------------------- #


def _make_gate(*, is_subagent: bool) -> MemoryGate:
    from cognic_agentos.core.dlp.scanner import ChecksumRegexGazetteerScanner
    from cognic_agentos.core.memory._context import MemoryCallerContext
    from cognic_agentos.core.memory.consent import ConsentValidator
    from cognic_agentos.core.memory.tiers import SubjectRef

    # Reuse conftest-compatible local conformers (no fixture injection needed
    # for gate-only tests — these are fully local).
    class _InactiveKS:
        async def is_write_frozen(self, *, tenant_id: str) -> bool:
            return False

    class _AllowAll:
        async def evaluate(self, *, decision_point: str, input: object) -> object:
            from cognic_agentos.core.policy.engine import Decision

            return Decision(
                allow=True,
                rule_matched=decision_point,
                reasoning="test",
                decision_data=None,
            )

    class _NullAudit:
        """Minimal DH store stub — ConsentValidator needs an audit arg."""

        async def append_with_precondition(self, **_: object) -> None:
            raise NotImplementedError

    ctx = MemoryCallerContext(
        tenant_id="t1",
        agent_id="kyc",
        actor_id="svc",
        served_subject=SubjectRef(kind="human", id="cust-7"),
        is_subagent=is_subagent,
        long_term_writes_allowed=True,
        cross_subject_recall=False,
        memory_read_capabilities=frozenset(
            {"memory_read.scratch", "memory_read.task", "memory_read.long_term"}
        ),
        declared_purposes=frozenset({"customer_support"}),
        declared_data_classes=frozenset({"public", "internal"}),
        risk_tier="read_only",
    )
    return MemoryGate(
        context=ctx,
        dlp=ChecksumRegexGazetteerScanner(),
        consent=ConsentValidator(audit=_NullAudit()),  # type: ignore[arg-type]
        policy=_AllowAll(),  # type: ignore[arg-type]
        kill_switch=_InactiveKS(),
    )


# --------------------------------------------------------------------------- #
# Tests                                                                        #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_check_lifecycle_refuses_subagent_durable() -> None:
    """§7.3 I2: a sub-agent gate raises memory_subagent_durable_access_refused."""
    gate = _make_gate(is_subagent=True)
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_lifecycle()
    assert ei.value.reason == "memory_subagent_durable_access_refused"


@pytest.mark.asyncio
async def test_check_lifecycle_allows_top_level_agent() -> None:
    """A non-sub-agent gate passes check_lifecycle() returning None (no exception)."""
    gate = _make_gate(is_subagent=False)
    await gate.check_lifecycle()  # must not raise
