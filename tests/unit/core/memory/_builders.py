from cognic_agentos.core.memory._context import MemoryWriteRecord
from cognic_agentos.core.memory.tiers import SubjectRef

SUBJECT = SubjectRef(kind="human", id="cust-7")
AGENT_SUBJECT = SubjectRef(kind="agent", id="a")


def _task_record(
    *,
    value: object = "hello",
    tenant_id: str = "t1",
    purpose: str = "customer_support",
    data_classes: tuple[str, ...] = ("public",),
    key: str = "greeting",
) -> MemoryWriteRecord:
    return MemoryWriteRecord(
        tenant_id=tenant_id,
        agent_id="kyc",
        actor_id="svc",
        subject=SUBJECT,
        tier="task",
        purpose=purpose,
        data_classes=tuple(data_classes),
        value=value,
        request_id="memory-write-test",
        key=key,
    )


def _scratch_record(
    *,
    value: object = "ephemeral",
    tenant_id: str = "t1",
    key: str = "tmp",
    agent_id: str = "kyc",
) -> MemoryWriteRecord:
    return MemoryWriteRecord(
        tenant_id=tenant_id,
        agent_id=agent_id,
        actor_id="svc",
        subject=SUBJECT,
        tier="scratch",
        purpose="customer_support",
        data_classes=(),
        value=value,
        request_id="memory-write-test",
        key=key,
    )


def _long_term_record(
    *,
    value: object = "case",
    tenant_id: str = "t1",
    purpose: str = "fraud_detection",
) -> MemoryWriteRecord:
    return MemoryWriteRecord(
        tenant_id=tenant_id,
        agent_id="kyc",
        actor_id="svc",
        subject=SUBJECT,
        tier="long_term",
        purpose=purpose,
        data_classes=("internal",),
        value=value,
        request_id="memory-write-test",
        key="case-1",
    )


def _block_record(*, value: object = "v1", kind: str = "persona") -> MemoryWriteRecord:
    return MemoryWriteRecord(
        tenant_id="t1",
        agent_id="a",
        actor_id="svc",
        subject=AGENT_SUBJECT,
        tier="long_term",
        purpose="customer_support",
        data_classes=("internal",),
        value=value,
        request_id="memory-write-test",
        key=None,
        block_kind=kind,  # type: ignore[arg-type]
    )
