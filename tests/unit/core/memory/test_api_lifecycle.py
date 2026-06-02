"""T9 — MemoryAPI.forget / .redact (8th + 9th ops) + real kill-switch proof. 11.5b.

CRITICAL CONTROL — core/ stop-rule per AGENTS.md (Memory governance enforcement,
ADR-019 §"Forget + redact"). Four pins:
  1. forget (soft) delegates to forget_op → tombstone; receipt.tombstoned and not
     receipt.purged.
  2. redact delegates to redact_op → new sealed version; receipt.redaction_version
     == 1 (the redactable ``account.number`` path exists in the seeded value).
  3. regulator_erasure + valid RegulatorErasureCommand → physical purge;
     receipt.purged is True. The custody ``subject_id`` matches the seeded row's
     subject id (``cust-7`` → ``human:cust-7``) so storage's subject-match guard
     passes.
  4. the REAL ``RedisMemoryWriteFreezeKillSwitch`` over a FROZEN fake-redis flows
     through MemoryGate.check_write and refuses ``remember`` with
     ``memory_write_frozen`` — proving the kill-switch wiring end-to-end, not a
     test sentinel.

Fixtures here (NOT conftest): ``memory_api`` (alias of the conftest ``api`` —
agent ``kyc``, served ``human:cust-7``), ``_seed_task`` / ``_seed_struct``
(record ids of seeded rows written THROUGH ``memory_api`` so they are scoped to
the same tenant/agent the lifecycle ops filter on), and ``memory_api_frozen``
(a MemoryAPI whose ``kill_switch=`` is the real Redis kill-switch over a frozen
fake redis). ``memory_adapter`` / ``dh_store`` come from conftest.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from cognic_agentos.core.config import Settings
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.core.dlp.scanner import ChecksumRegexGazetteerScanner
from cognic_agentos.core.emergency.kill_switches import (
    RedisMemoryWriteFreezeKillSwitch,
    _write_freeze_key,
)
from cognic_agentos.core.memory._context import (
    RedactionSpan,
    RegulatorErasureCommand,
)
from cognic_agentos.core.memory.api import MemoryAPI
from cognic_agentos.core.memory.consent import ConsentValidator
from cognic_agentos.core.memory.storage import PostgresMemoryAdapter
from cognic_agentos.core.memory.tiers import MemoryOperationRefused

from ._builders import SUBJECT
from .conftest import _AllowAllPolicy, _ctx

# --------------------------------------------------------------------------- #
# Fixtures                                                                     #
# --------------------------------------------------------------------------- #


@pytest.fixture
def memory_api(api: MemoryAPI) -> MemoryAPI:
    """The lifecycle-ops surface under test. Alias of the conftest ``api``
    fixture — human-served (``human:cust-7``), agent ``kyc``, inactive
    kill-switch — so the seeded rows + the forget/redact filters share one
    tenant/agent identity."""
    return api


@pytest.fixture
async def _seed_task(memory_api: MemoryAPI) -> uuid.UUID:
    """A ``task``-tier keyed record written THROUGH the API (so it is scoped to
    ``t1`` / ``kyc`` / ``human:cust-7`` — exactly what forget filters on).
    Returns the record id."""
    return await memory_api.remember(
        "greeting",
        "hello",
        tier="task",
        data_classes=("public",),
        purpose="customer_support",
    )


@pytest.fixture
async def _seed_struct(memory_api: MemoryAPI) -> uuid.UUID:
    """A ``task``-tier record whose value is a nested mapping with a redactable
    ``account.number`` leaf, written through the API. Returns the record id."""
    return await memory_api.remember(
        "profile",
        {"account": {"number": "1234-5678", "holder": "Pat"}},
        tier="task",
        data_classes=("public",),
        purpose="customer_support",
    )


class _FrozenFakeRedis:
    """Async KV duck-type whose ``get`` returns a FROZEN write-freeze document
    for the served tenant (``t1``). Structurally conforms to the kill-switch's
    ``_AsyncRedisKVLike`` Protocol (async ``get`` + ``set``)."""

    def __init__(self, *, tenant_id: str) -> None:
        self._key = _write_freeze_key(tenant_id)
        self._doc = json.dumps(
            {
                "frozen": True,
                "updated_at": datetime.now(UTC).isoformat(),
                "actor_id": "compliance-officer",
                "reason": "regulator_freeze",
            }
        )

    async def get(self, key: str) -> Any:
        return self._doc if key == self._key else None

    async def set(self, key: str, value: Any, **kwargs: Any) -> Any:  # pragma: no cover
        return None


@pytest.fixture
def memory_api_frozen(
    memory_adapter: PostgresMemoryAdapter, dh_store: DecisionHistoryStore
) -> MemoryAPI:
    """A MemoryAPI wired with the REAL ``RedisMemoryWriteFreezeKillSwitch`` over a
    fake redis that reports the served tenant (``t1``) FROZEN — proves the
    kill-switch threads through ``__init__`` → ``MemoryGate`` → ``check_write``.

    Built INLINE (not via the conftest ``_build_api``, which hardcodes the
    inactive sentinel) so the real kill-switch is the only seam that differs."""
    real_kill_switch = RedisMemoryWriteFreezeKillSwitch(
        redis_client=_FrozenFakeRedis(tenant_id="t1"),
        cache_ttl_s=30,
    )
    return MemoryAPI(
        context=_ctx(served_subject=SUBJECT, agent_id="kyc"),
        adapter=memory_adapter,
        dlp=ChecksumRegexGazetteerScanner(),
        consent=ConsentValidator(audit=dh_store),
        policy=_AllowAllPolicy(),  # type: ignore[arg-type]
        kill_switch=real_kill_switch,
        audit=dh_store,
        settings=Settings(),
    )


# --------------------------------------------------------------------------- #
# Tests                                                                        #
# --------------------------------------------------------------------------- #


async def test_api_forget_delegates_and_tombstones(
    memory_api: MemoryAPI, _seed_task: uuid.UUID
) -> None:
    receipt = await memory_api.forget(_seed_task, reason="user_request")
    assert receipt.tombstoned is True
    assert receipt.purged is False
    assert receipt.record_id == _seed_task


async def test_api_redact_delegates(memory_api: MemoryAPI, _seed_struct: uuid.UUID) -> None:
    receipt = await memory_api.redact(
        _seed_struct,
        span=RedactionSpan(path=("account", "number")),
        reason="pii_minimization",
    )
    assert receipt.redaction_version == 1
    assert receipt.record_id == _seed_struct
    assert receipt.new_version_id != _seed_struct


async def test_api_regulator_erasure_with_command_purges(
    memory_api: MemoryAPI, _seed_task: uuid.UUID
) -> None:
    # Custody subject_id must match the seeded row's subject id (cust-7 →
    # human:cust-7) or storage's subject-match guard refuses.
    cmd = RegulatorErasureCommand(
        regulator_order_id="O",
        requester_scope="memory.regulator_erasure",
        subject_id="cust-7",
    )
    receipt = await memory_api.forget(_seed_task, reason="regulator_erasure", erasure_command=cmd)
    assert receipt.purged is True
    assert receipt.tombstoned is True


async def test_api_write_refused_when_real_kill_switch_frozen(
    memory_api_frozen: MemoryAPI,
) -> None:
    with pytest.raises(MemoryOperationRefused) as ei:
        await memory_api_frozen.remember(
            "k",
            "v",
            tier="task",
            data_classes=("public",),
            purpose="customer_support",
        )
    assert ei.value.reason == "memory_write_frozen"
