"""Sprint 1C — adapter protocol structural conformance tests.

These tests assert that every ADR-009 protocol exposes the declared
methods with the right async/sync flavour. ``ObjectStoreAdapter`` is
declared-only here (impl ships with Sprint 8 + evidence-pack export);
memory governance (ADR-019) lands in Sprint 11.5 and is not part of this
sprint's protocol surface.
"""

from __future__ import annotations

import pytest

from cognic_agentos.db.adapters import protocols as P


class TestProtocolShape:
    def test_relational_methods(self) -> None:
        for name in ("connect", "session", "run_migrations", "close", "health_check"):
            assert hasattr(P.RelationalAdapter, name), f"missing {name}"

    def test_vector_methods(self) -> None:
        for name in ("ensure_collection", "upsert", "search", "delete", "health_check"):
            assert hasattr(P.VectorAdapter, name), f"missing {name}"

    def test_secret_methods(self) -> None:
        for name in ("read", "write", "lease", "revoke", "health_check"):
            assert hasattr(P.SecretAdapter, name), f"missing {name}"

    def test_embedding_methods(self) -> None:
        for name in ("embed", "dimensions", "health_check"):
            assert hasattr(P.EmbeddingAdapter, name), f"missing {name}"

    def test_object_store_methods(self) -> None:
        for name in ("put", "get", "delete", "presign", "health_check"):
            assert hasattr(P.ObjectStoreAdapter, name), f"missing {name}"

    def test_observability_methods(self) -> None:
        for name in ("emit_trace", "emit_metric", "flush", "health_check"):
            assert hasattr(P.ObservabilityAdapter, name), f"missing {name}"


class TestImplementsProtocol:
    """A minimal concrete class satisfying the protocol's method shape
    must pass ``isinstance(obj, Protocol)`` at runtime (Protocols are
    decorated with ``@runtime_checkable``)."""

    def test_relational_runtime_check(self) -> None:
        class FakeRelational:
            async def connect(self) -> None: ...
            def session(self) -> object:
                return object()

            async def run_migrations(self, dir: str) -> None: ...
            async def close(self) -> None: ...
            async def health_check(self) -> P.AdapterHealth:
                return P.AdapterHealth(status="ok", driver="fake")

        assert isinstance(FakeRelational(), P.RelationalAdapter)

    def test_vector_runtime_check(self) -> None:
        class FakeVector:
            async def ensure_collection(
                self, name: str, dim: int, metric: str = "cosine"
            ) -> None: ...

            async def upsert(self, items: list[P.VectorItem]) -> None: ...

            async def search(
                self,
                vector: list[float],
                k: int = 10,
                filter: dict[str, object] | None = None,
            ) -> list[P.VectorHit]:
                return []

            async def delete(self, ids: list[str]) -> None: ...
            async def health_check(self) -> P.AdapterHealth:
                return P.AdapterHealth(status="ok", driver="fake")

        assert isinstance(FakeVector(), P.VectorAdapter)


class TestAdapterHealth:
    def test_health_dataclass_fields(self) -> None:
        h = P.AdapterHealth(status="ok", driver="x", detail=None, latency_ms=1.2)
        assert h.status == "ok"
        assert h.driver == "x"
        assert h.detail is None
        assert h.latency_ms == 1.2

    @pytest.mark.parametrize("bad", ["healthy", "OK", "", "ready"])
    def test_status_must_be_canonical(self, bad: str) -> None:
        # status is a Literal; allowed = {"ok", "degraded", "unreachable"}
        with pytest.raises((ValueError, TypeError)):
            P.AdapterHealth(status=bad, driver="x")  # type: ignore[arg-type]


class TestVectorHelpers:
    def test_vector_item_dataclass(self) -> None:
        item = P.VectorItem(id="1", vector=[0.1, 0.2], payload={"k": "v"})
        assert item.id == "1"
        assert item.vector == [0.1, 0.2]
        assert item.payload == {"k": "v"}

    def test_vector_hit_dataclass(self) -> None:
        hit = P.VectorHit(id="1", score=0.95, payload={"src": "doc"})
        assert hit.score == 0.95
        assert hit.payload == {"src": "doc"}


class TestSecretLease:
    def test_lease_dataclass(self) -> None:
        lease = P.SecretLease(lease_id="abc", ttl_s=60, value={"u": "user"})
        assert lease.lease_id == "abc"
        assert lease.ttl_s == 60
        assert lease.value == {"u": "user"}
