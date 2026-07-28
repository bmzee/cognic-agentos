"""Negative-path coverage for approval executor local invariants."""

from __future__ import annotations

import hashlib
from typing import Any, cast

import pytest
from tests.unit.core.approval.test_executor import (
    _REQUEST_ID,
    _TENANT,
    _History,
    _service,
)

from cognic_agentos.core.approval.executor import (
    _decode_stored_result,
    _encode_stored_result,
)
from cognic_agentos.core.approval.replay import ApprovalReplayUnavailable
from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.core.conversation._types import ConversationTurnRefused


@pytest.mark.asyncio
async def test_post_and_chain_refuses_half_bound_replay_custody() -> None:
    service, events, _, _, _, _ = _service()
    context = await service._resolve_context(request_id=_REQUEST_ID, tenant_id=_TENANT)
    assert context is not None
    events.clear()

    with pytest.raises(
        ValueError,
        match="stored outcome and execution timestamp must be present together",
    ):
        await service._post_and_chain(
            context=context,
            outcome="executed",
            result_canonical=canonical_bytes({"status": "applied"}),
            text="Approved and executed.",
            stored_outcome="executed",
        )

    assert events == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("approval_state", "outcome", "result_canonical", "message"),
    [
        (
            "granted",
            "executed",
            None,
            "execution outcome and result must be present together",
        ),
        (
            "granted",
            None,
            None,
            "granted delivery refusal requires an execution outcome",
        ),
        (
            "denied",
            "executed",
            canonical_bytes({"status": "applied"}),
            "denied delivery refusal cannot carry an execution outcome",
        ),
    ],
)
async def test_delivery_refusal_rejects_incoherent_execution_fields(
    approval_state: Any,
    outcome: Any,
    result_canonical: bytes | None,
    message: str,
) -> None:
    service, _, _, _, _, _ = _service()
    context = await service._resolve_context(request_id=_REQUEST_ID, tenant_id=_TENANT)
    assert context is not None

    with pytest.raises(ValueError, match=message):
        await service._append_delivery_refusal(
            context=context,
            exc=ConversationTurnRefused(
                "conversation_hook_refused",
                current_state="active",
            ),
            delivery_request_id="approval-system-" + "a" * 32,
            delivery_input=b"withheld",
            approval_state=approval_state,
            outcome=outcome,
            result_canonical=result_canonical,
        )


@pytest.mark.asyncio
async def test_uncorrelated_delivery_refusal_uses_delivery_input_digest() -> None:
    service, _, _, _, _, completer = _service()
    completer.exc = ConversationTurnRefused(
        "conversation_hook_refused",
        current_state="active",
    )

    assert await service.post_denied(
        request_id=_REQUEST_ID,
        tenant_id=_TENANT,
        approver_subject="approver.dana",
        reason="insufficient notice",
    )

    refusal = cast(_History, service._history).records[-1]
    rendered = b"Declined by approver.dana \xe2\x80\x94 insufficient notice."
    assert refusal.payload["delivery_output_sha256"] == hashlib.sha256(rendered).hexdigest()
    assert refusal.payload["delivery_output_bytes"] == len(rendered)


@pytest.mark.parametrize(
    "result_canonical",
    [
        b"{",
        canonical_bytes(["not", "an", "object"]),
    ],
)
def test_stored_result_encoder_refuses_unusable_results(result_canonical: bytes) -> None:
    with pytest.raises(ApprovalReplayUnavailable, match="replay_digest_mismatch"):
        _encode_stored_result(
            outcome="executed",
            result_canonical=result_canonical,
        )


@pytest.mark.parametrize(
    "stored_result",
    [
        b"{",
        canonical_bytes(["wrong-marker", "executed", {"status": "applied"}]),
        canonical_bytes(
            [
                "cognic.approval.replay-result.v1",
                "unknown-outcome",
                {"status": "applied"},
            ]
        ),
        canonical_bytes(
            [
                "cognic.approval.replay-result.v1",
                "executed",
                ["not", "an", "object"],
            ]
        ),
    ],
)
def test_stored_result_decoder_refuses_untrusted_envelopes(stored_result: bytes) -> None:
    with pytest.raises(ApprovalReplayUnavailable, match="replay_digest_mismatch"):
        _decode_stored_result(stored_result)
