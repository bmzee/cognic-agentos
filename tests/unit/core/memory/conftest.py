from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.config import Settings
from cognic_agentos.core.decision_history import DecisionHistoryStore, _decision_history
from cognic_agentos.core.dlp.scanner import ChecksumRegexGazetteerScanner
from cognic_agentos.core.memory._context import MemoryCallerContext
from cognic_agentos.core.memory.api import MemoryAPI
from cognic_agentos.core.memory.consent import ConsentValidator
from cognic_agentos.core.memory.storage import PostgresMemoryAdapter, _memory_records
from cognic_agentos.core.memory.tiers import SubjectRef
from tests.unit.core.memory._builders import AGENT_SUBJECT, SUBJECT


@pytest.fixture
async def _mem_engine(tmp_path):
    eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'memory.db'}")
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)  # core chain tables
        await conn.run_sync(_memory_records.metadata.create_all)  # memory_records table (+ CHECK)
        for chain_id in ("audit_event", "decision_history"):
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id=chain_id,
                    latest_sequence=0,
                    latest_hash=ZERO_HASH,
                    updated_at=datetime.now(UTC),
                )
            )
    yield eng
    await eng.dispose()


@pytest.fixture
def dh_store(_mem_engine):
    return DecisionHistoryStore(_mem_engine)


@pytest.fixture
def memory_adapter(_mem_engine, dh_store):
    return PostgresMemoryAdapter(engine=_mem_engine, dh_store=dh_store)


# Sprint 11.5b T8 — routing tests use pg_adapter / engine fixture names
# (mirrors plan naming; aliases point to the same objects as memory_adapter / _mem_engine).
@pytest.fixture
def pg_adapter(_mem_engine, dh_store):
    return PostgresMemoryAdapter(engine=_mem_engine, dh_store=dh_store)


@pytest.fixture
def engine(_mem_engine):
    return _mem_engine


@pytest.fixture
def decision_history_rows(_mem_engine):
    # Zero-arg async reader of all decision_history rows ordered by sequence.
    async def _read():
        async with _mem_engine.begin() as conn:
            result = await conn.execute(
                select(_decision_history).order_by(_decision_history.c.sequence)
            )
            return list(result.all())

    return _read


# --------------------------------------------------------------------------- #
# MemoryAPI fixtures (Sprint 11.5a T10). DI-tested, not harness-injected.
# --------------------------------------------------------------------------- #


class _InactiveKillSwitch:
    """Structural MemoryKillSwitchInterrogator conformer — never frozen."""

    async def is_write_frozen(self, *, tenant_id):
        return False


class _AllowAllPolicy:
    """Structural OPAEngine conformer — every decision point allows.

    Real OPA is not available in unit tests; the gate's per-decision-point
    Rego helpers read ``decision.allow``, so a permissive conformer lets the
    happy-path API tests exercise the wiring without spinning OPA."""

    async def evaluate(self, *, decision_point, input):
        from cognic_agentos.core.policy.engine import Decision

        return Decision(
            allow=True, rule_matched=decision_point, reasoning="test", decision_data=None
        )


class _PurposeMatchPolicy:
    """Structural OPAEngine conformer modelling the DEFAULT-DENY purpose matrix:
    the ``purpose_compatible`` point allows ONLY when ``recall_purpose ==
    write_purpose``; every other decision point allows. Pins that the API threads
    the STORED write purpose into the recall gate — the pre-fix behaviour
    (passing ``write_purpose=None``) would refuse an otherwise-compatible recall,
    exactly as the real default-deny bundle does."""

    _PURPOSE_POINT = "data.cognic.memory.recall.purpose_compatible.allow"

    async def evaluate(self, *, decision_point, input):
        from cognic_agentos.core.policy.engine import Decision

        if decision_point == self._PURPOSE_POINT:
            allow = input.get("recall_purpose") == input.get("write_purpose")
        else:
            allow = True
        return Decision(
            allow=allow, rule_matched=decision_point, reasoning="test", decision_data=None
        )


_READ_CAPS = frozenset({"memory_read.scratch", "memory_read.task", "memory_read.long_term"})


def _ctx(*, served_subject: SubjectRef, agent_id: str) -> MemoryCallerContext:
    return MemoryCallerContext(
        tenant_id="t1",
        agent_id=agent_id,
        actor_id="svc",
        served_subject=served_subject,
        is_subagent=False,
        long_term_writes_allowed=True,
        cross_subject_recall=False,
        memory_read_capabilities=_READ_CAPS,
        declared_purposes=frozenset({"customer_support", "fraud_detection"}),
        declared_data_classes=frozenset({"public", "internal"}),
        risk_tier="read_only",
    )


def _build_api(
    ctx: MemoryCallerContext,
    memory_adapter: PostgresMemoryAdapter,
    dh_store: DecisionHistoryStore,
    policy: object | None = None,
) -> MemoryAPI:
    return MemoryAPI(
        context=ctx,
        adapter=memory_adapter,
        dlp=ChecksumRegexGazetteerScanner(),
        consent=ConsentValidator(audit=dh_store),
        # structural OPAEngine conformer (default: allow-all)
        policy=policy if policy is not None else _AllowAllPolicy(),  # type: ignore[arg-type]
        kill_switch=_InactiveKillSwitch(),
        audit=dh_store,
        settings=Settings(),
    )


@pytest.fixture
def api(memory_adapter, dh_store):  # human-served: remember/recall/list_for_subject
    return _build_api(_ctx(served_subject=SUBJECT, agent_id="kyc"), memory_adapter, dh_store)


@pytest.fixture
def agent_api(memory_adapter, dh_store):  # agent-served: block happy-paths (persona)
    return _build_api(_ctx(served_subject=AGENT_SUBJECT, agent_id="a"), memory_adapter, dh_store)


@pytest.fixture
def strict_purpose_api(memory_adapter, dh_store):  # human-served + default-deny purpose matrix
    return _build_api(
        _ctx(served_subject=SUBJECT, agent_id="kyc"),
        memory_adapter,
        dh_store,
        _PurposeMatchPolicy(),
    )


@pytest.fixture
def strict_purpose_agent_api(
    memory_adapter, dh_store
):  # agent-served + default-deny purpose matrix
    return _build_api(
        _ctx(served_subject=AGENT_SUBJECT, agent_id="a"),
        memory_adapter,
        dh_store,
        _PurposeMatchPolicy(),
    )
