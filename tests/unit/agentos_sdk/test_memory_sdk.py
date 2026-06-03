"""Sprint 11.5a T12 — MemorySDK thin-facade forwarding contract.

``MemorySDK`` is a typed Layer-C facade over ``MemoryAPI``; every method
forwards to the LIVE ``MemoryAPI`` signature EXACTLY. These tests use recorder
doubles whose methods carry the REAL signatures (no ``**kwargs`` catch-all), so
a forwarder that passes a wrong kwarg name (e.g. ``retention_window`` instead of
``retention_window_s``) or a non-existent kwarg (e.g. a retention kwarg on
``upsert_block``) raises ``TypeError`` here — that is the point of the test.
"""

from typing import Any

from cognic_agentos.agentos_sdk.memory import MemorySDK
from cognic_agentos.core.memory.tiers import SubjectRef

_SUBJ = SubjectRef(kind="human", id="cust-7")


class _RecordingRememberAPI:
    """A double whose ``remember`` mirrors the REAL MemoryAPI.remember
    signature — NO ``**kwargs``. A forwarder using a wrong kwarg name TypeErrors."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def remember(
        self,
        key: str,
        value: object,
        *,
        tier: str,
        data_classes: tuple[str, ...] | list[str],
        purpose: str,
        consent_token: object | None = None,
        retention_window_s: int | None = None,
    ) -> str:
        self.calls.append(
            {
                "key": key,
                "value": value,
                "tier": tier,
                "data_classes": data_classes,
                "purpose": purpose,
                "consent_token": consent_token,
                "retention_window_s": retention_window_s,
            }
        )
        return "record-id-remember"


class _RecordingUpsertBlockAPI:
    """A double whose ``upsert_block`` mirrors the REAL signature — NO retention
    param and NO ``**kwargs``. A forwarder passing a retention kwarg TypeErrors."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def upsert_block(
        self,
        kind: str,
        *,
        subject: SubjectRef,
        value: object,
        data_classes: tuple[str, ...] | list[str],
        purpose: str,
        consent_token: object | None = None,
    ) -> str:
        self.calls.append(
            {
                "kind": kind,
                "subject": subject,
                "value": value,
                "data_classes": data_classes,
                "purpose": purpose,
                "consent_token": consent_token,
            }
        )
        return "record-id-upsert"


class _RecordingRecallEpisodesAPI:
    """A double whose ``recall_episodes`` mirrors the REAL MemoryAPI signature
    INCLUDING the 11.5c ``query`` kwarg — NO ``**kwargs``. A forwarder that drops
    ``query`` loses the value (None recorded); one that misnames it TypeErrors."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def recall_episodes(
        self,
        subject: SubjectRef,
        *,
        similarity_threshold: float,
        purpose: str,
        query: str | None = None,
    ) -> list[Any]:
        self.calls.append(
            {
                "subject": subject,
                "similarity_threshold": similarity_threshold,
                "purpose": purpose,
                "query": query,
            }
        )
        return []


class _SequenceRecordingAPI:
    """Records the method NAME for each of the 7 ops via ``__getattr__`` — only
    the call SEQUENCE matters here, so an attribute-synthesising recorder is
    fine (it does not pin per-op signatures; the two recorders above do that)."""

    def __init__(self) -> None:
        self.sequence: list[str] = []

    def __getattr__(self, name: str) -> Any:
        async def _record(*_args: Any, **_kwargs: Any) -> None:
            self.sequence.append(name)
            return None

        return _record


async def test_sdk_remember_forwards_to_api() -> None:
    """``remember`` forwards every kwarg by name, including ``retention_window_s``
    (NOT ``retention_window``). A forwarder using the wrong name TypeErrors on the
    real-signature double."""
    api = _RecordingRememberAPI()
    result = await MemorySDK(api).remember(  # type: ignore[arg-type]
        "k",
        "v",
        tier="task",
        data_classes=["public"],
        purpose="customer_support",
        retention_window_s=3600,
    )
    assert result == "record-id-remember"
    assert len(api.calls) == 1
    call = api.calls[0]
    assert call["retention_window_s"] == 3600
    assert call["consent_token"] is None
    assert call["key"] == "k"
    assert call["tier"] == "task"


async def test_sdk_upsert_block_forwards_without_retention() -> None:
    """``upsert_block`` forwards cleanly to the REAL signature (no retention
    param). A forwarder that injects a retention kwarg TypeErrors on the
    real-signature double."""
    api = _RecordingUpsertBlockAPI()
    result = await MemorySDK(api).upsert_block(  # type: ignore[arg-type]
        "persona",
        subject=_SUBJ,
        value="v",
        data_classes=["internal"],
        purpose="customer_support",
    )
    assert result == "record-id-upsert"
    assert len(api.calls) == 1
    call = api.calls[0]
    assert call["kind"] == "persona"
    assert call["subject"] is _SUBJ
    assert call["consent_token"] is None
    assert "retention_window_s" not in call


async def test_sdk_recall_episodes_forwards_query() -> None:
    """``recall_episodes`` forwards the 11.5c ``query`` kwarg by name, so a typed
    ``MemorySDK`` pack author CAN reach the vector path (P2, T7 review). The
    real-signature double has no ``**kwargs``: a forwarder that omits ``query``
    from its signature TypeErrors here, and one that accepts but does not forward
    it records ``None`` instead of the passed value."""
    api = _RecordingRecallEpisodesAPI()
    result = await MemorySDK(api).recall_episodes(  # type: ignore[arg-type]
        _SUBJ, similarity_threshold=0.5, purpose="fraud_detection", query="fraud case"
    )
    assert result == []
    assert len(api.calls) == 1
    call = api.calls[0]
    assert call["query"] == "fraud case"
    assert call["similarity_threshold"] == 0.5
    assert call["purpose"] == "fraud_detection"


async def test_sdk_forwards_all_seven_ops() -> None:
    """All 7 ops forward to the matching ``MemoryAPI`` method (call sequence)."""
    api = _SequenceRecordingAPI()
    sdk = MemorySDK(api)  # type: ignore[arg-type]

    await sdk.remember("k", "v", tier="task", data_classes=["public"], purpose="customer_support")
    await sdk.recall("k", tier="task", purpose="customer_support")
    await sdk.recall_episodes(_SUBJ, similarity_threshold=0.0, purpose="customer_support")
    await sdk.list_for_subject(_SUBJ)
    await sdk.upsert_block(
        "persona", subject=_SUBJ, value="v", data_classes=["internal"], purpose="customer_support"
    )
    await sdk.read_block("persona", subject=_SUBJ, purpose="customer_support")
    await sdk.list_blocks(_SUBJ)

    assert api.sequence == [
        "remember",
        "recall",
        "recall_episodes",
        "list_for_subject",
        "upsert_block",
        "read_block",
        "list_blocks",
    ]
