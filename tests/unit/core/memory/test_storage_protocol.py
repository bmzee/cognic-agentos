import inspect

from cognic_agentos.core.memory.storage import (
    MemoryAdapter,
    MemoryBackendUnavailable,
    _memory_records,
)
from cognic_agentos.core.memory.tiers import MemoryOperationRefused


class _Conformer:
    async def put(self, record): ...
    async def get(self, *, tenant_id, agent_id, subject, tier, key=None, block_kind=None): ...
    async def list_for_subject(self, *, tenant_id, agent_id, subject): ...
    async def list_blocks(self, *, tenant_id, agent_id, subject): ...
    async def upsert_block(self, record): ...
    # Sprint 11.5b T4 — erasure primitives added to the Protocol
    async def tombstone_record(self, *, tenant_id, agent_id, record_id, reason, actor_id): ...
    async def purge_record(self, *, tenant_id, agent_id, record_id, erasure_command, actor_id): ...
    async def purge_expired(self, *, tombstone_window_s): ...
    async def redact_record(self, *, tenant_id, agent_id, record_id, span, reason, actor_id): ...


def test_conformer_structurally_satisfies_protocol():
    assert isinstance(_Conformer(), MemoryAdapter)


def test_protocol_reads_require_tenant_and_agent_id_scoping():
    # @runtime_checkable Protocol checks method PRESENCE only — NOT signature —
    # so the isinstance conformance above stays green even if a read drops the
    # agent_id scope. Pin the two isolation boundaries explicitly: tenant_id AND
    # agent_id must be REQUIRED keyword-only params on every read method, so a
    # regression that removes (or defaults) either fails here.
    for method_name in ("get", "list_for_subject", "list_blocks"):
        params = inspect.signature(getattr(MemoryAdapter, method_name)).parameters
        for boundary in ("tenant_id", "agent_id"):
            assert boundary in params, f"MemoryAdapter.{method_name} must scope by {boundary}"
            assert params[boundary].kind is inspect.Parameter.KEYWORD_ONLY
            assert params[boundary].default is inspect.Parameter.empty


def test_protocol_mutators_require_tenant_and_agent_id_scoping():
    # T4 erasure mutators are tenant/agent-scoped authz boundaries — a record_id is
    # a PRIMARY KEY, NOT an authz boundary. Same @runtime_checkable presence-only gap
    # as the reads: pin tenant_id AND agent_id as REQUIRED keyword-only on
    # tombstone_record / purge_record / redact_record, so a regression that drops
    # (or defaults) either fails here. purge_expired is the GLOBAL system reaper and
    # is deliberately excluded.
    for method_name in ("tombstone_record", "purge_record", "redact_record"):
        params = inspect.signature(getattr(MemoryAdapter, method_name)).parameters
        for boundary in ("tenant_id", "agent_id"):
            assert boundary in params, f"MemoryAdapter.{method_name} must scope by {boundary}"
            assert params[boundary].kind is inspect.Parameter.KEYWORD_ONLY
            assert params[boundary].default is inspect.Parameter.empty
    # purge_expired is global (no per-row scope) — must NOT carry tenant/agent.
    purge_params = inspect.signature(MemoryAdapter.purge_expired).parameters
    assert "tenant_id" not in purge_params
    assert "agent_id" not in purge_params


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
