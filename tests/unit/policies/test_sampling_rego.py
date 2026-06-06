"""Real-OPA parity test for the MCP sampling default-deny bundle (remediation §5).

The multi-agent review (2026-06-06) found ``policies/_default/sampling.rego`` shipped
with pre-OPA-1.0 Rego **v0** syntax (``default allow = false`` + a bodiless
``allow {``) that does NOT parse under the pinned OPA 1.x binary — making the bundle
dead-on-arrival (it fail-closes to deny, so security held, but the capability is
unreachable) and it was the only default bundle with no real-OPA parity test. This
file loads the REAL bundle through :class:`OPAEngine` and pins the four-condition gate:
all-four-true → allow; any single condition false → deny; empty input → deny (default).

Mirrors the parity pattern in ``test_scheduler_rego.py`` (``opa_required`` skipif +
a real OPAEngine over an in-memory audit/decision-history pair).
"""

from __future__ import annotations

import shutil
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.audit import AuditStore, _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.core.policy.engine import OPAEngine

opa_required = pytest.mark.skipif(
    shutil.which("opa") is None,
    reason="opa binary not installed — skip the direct-OPA sampling parity smoke",
)

SAMPLING_DECISION_POINT_ALLOW = "data.cognic.sampling.allow"
SAMPLING_BUNDLE_PATH = Path("policies/_default/sampling.rego")


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncGenerator[OPAEngine, None]:
    """Real :class:`OPAEngine` over the sampling bundle + an in-memory SQLite
    audit/decision-history pair (so the engine's policy.* audit emits don't error)."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'sampling_rego_test.db'}"
    sa_engine = create_async_engine(url)
    async with sa_engine.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        for chain_id in ("audit_event", "decision_history"):
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id=chain_id,
                    latest_sequence=0,
                    latest_hash=ZERO_HASH,
                    updated_at=datetime.now(UTC),
                )
            )
    audit = AuditStore(sa_engine)
    dh = DecisionHistoryStore(sa_engine)
    yield await OPAEngine.create(
        bundle_path=SAMPLING_BUNDLE_PATH,
        audit_store=audit,
        decision_history_store=dh,
    )
    await sa_engine.dispose()


def _all_true_input() -> dict[str, Any]:
    """The only input shape that yields allow=True — all four conditions hold."""
    return {
        "pack": {"sampling_supported": True},
        "tenant": {"sampling_permitted": True},
        "cloud_policy": {"tier_consistent": True, "allow_external_llm_consistent": True},
    }


@opa_required
class TestSamplingRegoFourConditionGate:
    """Direct-OPA parity for ``data.cognic.sampling.allow`` (the four-condition gate)."""

    @pytest.mark.asyncio
    async def test_empty_input_denies(self, engine: OPAEngine) -> None:
        d = await engine.evaluate(decision_point=SAMPLING_DECISION_POINT_ALLOW, input={})
        assert d.allow is False

    @pytest.mark.asyncio
    async def test_all_four_true_allows(self, engine: OPAEngine) -> None:
        d = await engine.evaluate(
            decision_point=SAMPLING_DECISION_POINT_ALLOW, input=_all_true_input()
        )
        assert d.allow is True

    @pytest.mark.asyncio
    async def test_pack_not_supported_denies(self, engine: OPAEngine) -> None:
        inp = _all_true_input()
        inp["pack"]["sampling_supported"] = False
        d = await engine.evaluate(decision_point=SAMPLING_DECISION_POINT_ALLOW, input=inp)
        assert d.allow is False

    @pytest.mark.asyncio
    async def test_tenant_not_permitted_denies(self, engine: OPAEngine) -> None:
        inp = _all_true_input()
        inp["tenant"]["sampling_permitted"] = False
        d = await engine.evaluate(decision_point=SAMPLING_DECISION_POINT_ALLOW, input=inp)
        assert d.allow is False

    @pytest.mark.asyncio
    async def test_tier_inconsistent_denies(self, engine: OPAEngine) -> None:
        inp = _all_true_input()
        inp["cloud_policy"]["tier_consistent"] = False
        d = await engine.evaluate(decision_point=SAMPLING_DECISION_POINT_ALLOW, input=inp)
        assert d.allow is False

    @pytest.mark.asyncio
    async def test_external_llm_inconsistent_denies(self, engine: OPAEngine) -> None:
        inp = _all_true_input()
        inp["cloud_policy"]["allow_external_llm_consistent"] = False
        d = await engine.evaluate(decision_point=SAMPLING_DECISION_POINT_ALLOW, input=inp)
        assert d.allow is False
