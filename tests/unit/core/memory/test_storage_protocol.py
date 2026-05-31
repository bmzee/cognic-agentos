from cognic_agentos.core.memory.storage import (
    MemoryAdapter,
    MemoryBackendUnavailable,
    _memory_records,
)
from cognic_agentos.core.memory.tiers import MemoryOperationRefused


class _Conformer:
    async def put(self, record): ...
    async def get(self, *, subject, tier, key=None, block_kind=None): ...
    async def list_for_subject(self, subject): ...
    async def list_blocks(self, subject): ...
    async def upsert_block(self, record): ...


def test_conformer_structurally_satisfies_protocol():
    assert isinstance(_Conformer(), MemoryAdapter)


def test_backend_unavailable_is_infra_exception_not_governance_refusal():
    # Infra failure, NOT a governance MemoryRefusalReason carrier.
    assert issubclass(MemoryBackendUnavailable, Exception)
    assert not issubclass(MemoryBackendUnavailable, MemoryOperationRefused)


def test_memory_records_has_exact_16_column_set():
    assert {c.name for c in _memory_records.columns} == {
        "record_id",
        "tenant_id",
        "subject_ref",
        "agent_id",
        "tier",
        "block_kind",
        "key",
        "value",
        "data_classes",
        "purpose",
        "retention_until",
        "tombstone",
        "redaction_version",
        "sealed_prior_version_ref",
        "vector_ref",
        "created_at",
    }


def test_memory_records_carries_named_xor_check():
    assert any(
        getattr(cc, "name", None) == "ck_memory_records_key_xor_block_kind"
        for cc in _memory_records.constraints
    )
