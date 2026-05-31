import datetime as dt
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from cognic_agentos.core.memory.consent import ConsentToken, ConsentValidator
from cognic_agentos.core.memory.tiers import MemoryOperationRefused, SubjectRef

_SUBJ = SubjectRef(kind="human", id="cust-7")


def _token(**over: Any) -> ConsentToken:
    base: dict[str, Any] = dict(
        subject_ref="human:cust-7",
        data_classes=frozenset({"customer_pii"}),
        issued_at=dt.datetime(2026, 5, 1, tzinfo=dt.UTC),
        expires_at=dt.datetime(2030, 1, 1, tzinfo=dt.UTC),
        signature="sig",
    )
    base.update(over)
    return ConsentToken(**base)


async def _consent_rows(
    decision_history_rows: Callable[[], Awaitable[list[Any]]],
) -> list[Any]:
    rows = await decision_history_rows()
    return [r for r in rows if r.event_type == "memory.consent"]


async def test_valid_token_passes_and_emits_exactly_one_ledger_event(
    dh_store, decision_history_rows
):
    v = ConsentValidator(audit=dh_store)
    await v.validate(
        _token(),
        served_subject=_SUBJ,
        restricted_declared=frozenset({"customer_pii"}),
        tenant_id="t1",
        actor_id="svc",
    )
    consent = await _consent_rows(decision_history_rows)
    assert len(consent) == 1  # emits only on valid restricted consent
    payload = consent[-1].payload
    assert "consent_token_digest" in payload
    # Raw token/signature NEVER enter the chain — neither as a key nor as a value.
    assert "signature" not in payload
    assert "sig" not in payload.values()


async def test_no_restricted_class_needs_no_token_and_emits_no_row(dh_store, decision_history_rows):
    v = ConsentValidator(audit=dh_store)
    await v.validate(
        None,
        served_subject=_SUBJ,
        restricted_declared=frozenset(),
        tenant_id="t1",
        actor_id="svc",
    )  # no raise, no token needed
    assert await _consent_rows(decision_history_rows) == []


async def test_missing_token_for_restricted_raises_consent_required(
    dh_store, decision_history_rows
):
    v = ConsentValidator(audit=dh_store)
    with pytest.raises(MemoryOperationRefused) as ei:
        await v.validate(
            None,
            served_subject=_SUBJ,
            restricted_declared=frozenset({"customer_pii"}),
            tenant_id="t1",
            actor_id="svc",
        )
    assert ei.value.reason == "memory_consent_required"
    assert await _consent_rows(decision_history_rows) == []  # refusal emits no consent row


@pytest.mark.parametrize(
    "bad",
    [
        dict(expires_at=dt.datetime(2020, 1, 1, tzinfo=dt.UTC)),  # expired
        dict(subject_ref="human:cust-999"),  # subject mismatch
        dict(data_classes=frozenset({"public"})),  # restricted class not covered
    ],
)
async def test_invalid_token_raises_consent_invalid(dh_store, decision_history_rows, bad):
    v = ConsentValidator(audit=dh_store)
    with pytest.raises(MemoryOperationRefused) as ei:
        await v.validate(
            _token(**bad),
            served_subject=_SUBJ,
            restricted_declared=frozenset({"customer_pii"}),
            tenant_id="t1",
            actor_id="svc",
        )
    assert ei.value.reason == "memory_consent_invalid"
    assert await _consent_rows(decision_history_rows) == []  # refusal emits no consent row
