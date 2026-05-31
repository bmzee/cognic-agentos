import dataclasses

import pytest

from cognic_agentos.core.memory.tiers import (
    MemoryOperationRefused,
    SubjectRef,
)


def test_subjectref_canonical_human():
    assert SubjectRef(kind="human", id="cust-7").canonical == "human:cust-7"


def test_subjectref_canonical_agent():
    assert SubjectRef(kind="agent", id="kyc-agent").canonical == "agent:kyc-agent"


def test_subjectref_empty_id_refused():
    with pytest.raises(ValueError):
        SubjectRef(kind="human", id="")


def test_subjectref_frozen():
    s = SubjectRef(kind="agent", id="a")
    with pytest.raises(dataclasses.FrozenInstanceError):
        s.id = "b"  # type: ignore[misc]


def test_memory_operation_refused_carries_reason():
    exc = MemoryOperationRefused("memory_long_term_write_denied")
    assert exc.reason == "memory_long_term_write_denied"
