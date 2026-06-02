"""Sprint 11.5b T1 — lifecycle DTOs.

RedactionSpan / RegulatorErasureCommand / ForgetReceipt / RedactionReceipt.
"""

import dataclasses
import uuid

import pytest

from cognic_agentos.core.memory._context import (
    ForgetReceipt,
    RedactionReceipt,
    RedactionSpan,
    RegulatorErasureCommand,
)


def test_redaction_span_is_field_path_with_default_replacement():
    span = RedactionSpan(path=("account", "number"))
    assert span.path == ("account", "number")
    assert span.replacement == "[REDACTED]"
    assert dataclasses.is_dataclass(span) and span.__dataclass_params__.frozen  # type: ignore[attr-defined]


def test_redaction_span_replacement_is_object_not_only_str():
    span = RedactionSpan(path=("balance",), replacement={"masked": True})
    assert span.replacement == {"masked": True}


def test_regulator_erasure_command_carries_chain_of_custody_fields():
    cmd = RegulatorErasureCommand(
        regulator_order_id="ORD-7",
        requester_scope="memory.regulator_erasure",
        subject_id="cust-9",
    )
    assert (cmd.regulator_order_id, cmd.requester_scope, cmd.subject_id) == (
        "ORD-7",
        "memory.regulator_erasure",
        "cust-9",
    )


def test_receipts_are_frozen_and_carry_record_id():
    rid = uuid.uuid4()
    fr = ForgetReceipt(record_id=rid, tombstoned=True, purged=False)
    rr = RedactionReceipt(record_id=rid, new_version_id=uuid.uuid4(), redaction_version=1)
    assert fr.record_id == rid and rr.record_id == rid
    with pytest.raises(dataclasses.FrozenInstanceError):
        fr.tombstoned = False  # type: ignore[misc]
