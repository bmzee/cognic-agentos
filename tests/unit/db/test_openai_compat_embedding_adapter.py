"""OpenAICompatEmbeddingAdapter — speaks the OpenAI /v1/embeddings
schema; covers vLLM / SGLang (no auth), OpenAI / Cohere (Bearer auth),
Azure-OpenAI / Bedrock when fronted by an OpenAI-compat proxy
(api-key + extra_headers)."""

from __future__ import annotations

import json

import respx
from httpx import ConnectError, Response

from cognic_agentos.db.adapters import bundled_registry
from cognic_agentos.db.adapters import protocols as P
from cognic_agentos.db.adapters.openai_compat_embedding_adapter import (
    OpenAICompatEmbeddingAdapter,
)

BASE = "http://vllm.test:8000"
MODEL = "BAAI/bge-large-en-v1.5"


def _adapter(**overrides: object) -> OpenAICompatEmbeddingAdapter:
    """Helper: build an adapter with sensible vLLM-no-auth defaults."""

    kwargs: dict[str, object] = dict(
        base_url=BASE,
        model=MODEL,
        dimensions=4,
        provider_label="vllm",
        api_key=None,
        api_key_header="Authorization",
        extra_headers={},
    )
    kwargs.update(overrides)
    return OpenAICompatEmbeddingAdapter(**kwargs)  # type: ignore[arg-type]


class TestRegistration:
    def test_openai_compat_registered_under_bundled(self) -> None:
        assert bundled_registry.has("embedding", "openai_compat")
        assert (
            bundled_registry.resolve("embedding", "openai_compat") is OpenAICompatEmbeddingAdapter
        )


class TestConstruction:
    def test_constructor_refuses_empty_base_url(self) -> None:
        import pytest

        with pytest.raises(ValueError, match="embedding_base_url"):
            _adapter(base_url=None)
        with pytest.raises(ValueError, match="embedding_base_url"):
            _adapter(base_url="")

    def test_provider_label_property(self) -> None:
        assert _adapter(provider_label="vllm").provider_label == "vllm"

    def test_dimensions_property(self) -> None:
        assert _adapter(dimensions=1024).dimensions == 1024


class TestEmbedNoAuth:
    """vLLM / SGLang local stacks expose /v1/embeddings without auth.
    No Authorization header should be sent when api_key is None."""

    @respx.mock
    async def test_embed_no_auth_header_when_api_key_none(self) -> None:
        route = respx.post(f"{BASE}/v1/embeddings").mock(
            return_value=Response(
                200,
                json={
                    "data": [{"embedding": [0.1, 0.2, 0.3, 0.4], "index": 0}],
                    "model": MODEL,
                    "object": "list",
                },
            )
        )
        a = _adapter(api_key=None)
        v = await a.embed(["foo"])
        assert len(v) == 1

        sent = route.calls.last.request
        # Must NOT have sent any auth header
        assert "authorization" not in {h.lower() for h in sent.headers}
        assert "api-key" not in {h.lower() for h in sent.headers}

    @respx.mock
    async def test_embed_posts_openai_v1_schema(self) -> None:
        """OpenAI v1 schema: ``POST /v1/embeddings`` with body
        ``{"input": [...], "model": "...", "encoding_format": "float"}``."""

        route = respx.post(f"{BASE}/v1/embeddings").mock(
            return_value=Response(
                200,
                json={
                    "data": [
                        {"embedding": [0.1, 0.2, 0.3, 0.4], "index": 0},
                        {"embedding": [0.5, 0.6, 0.7, 0.8], "index": 1},
                    ],
                    "model": MODEL,
                    "object": "list",
                    "usage": {"prompt_tokens": 4, "total_tokens": 4},
                },
            )
        )
        a = _adapter()
        v = await a.embed(["foo", "bar"])
        assert len(v) == 2
        assert v[0] == [0.1, 0.2, 0.3, 0.4]
        assert v[1] == [0.5, 0.6, 0.7, 0.8]

        sent = route.calls.last.request
        body = json.loads(sent.content)
        assert body["input"] == ["foo", "bar"]
        assert body["model"] == MODEL
        assert body["encoding_format"] == "float"

    @respx.mock
    async def test_embed_preserves_index_order(self) -> None:
        """OpenAI's response order matches request order via the ``index``
        field; the adapter sorts by index defensively in case providers
        respond out-of-order."""

        respx.post(f"{BASE}/v1/embeddings").mock(
            return_value=Response(
                200,
                json={
                    "data": [
                        {"embedding": [0.5, 0.6], "index": 1},
                        {"embedding": [0.1, 0.2], "index": 0},
                    ],
                    "model": MODEL,
                    "object": "list",
                },
            )
        )
        a = _adapter(provider_label="sglang", dimensions=2)
        v = await a.embed(["a", "b"])
        assert v[0] == [0.1, 0.2]
        assert v[1] == [0.5, 0.6]


class TestEmbedValidation:
    """Defensive validation: response-count + embedding-shape checks
    catch out-of-spec providers before mis-aligned rows poison
    downstream retrieval / index state."""

    @respx.mock
    async def test_embed_raises_on_response_count_mismatch(self) -> None:
        """Provider returns fewer rows than requested → fail loud."""

        import pytest

        respx.post(f"{BASE}/v1/embeddings").mock(
            return_value=Response(
                200,
                json={
                    "data": [
                        # Requested 2 inputs, only 1 row returned
                        {"embedding": [0.1, 0.2, 0.3, 0.4], "index": 0},
                    ],
                    "model": MODEL,
                    "object": "list",
                },
            )
        )
        a = _adapter()
        with pytest.raises(ValueError, match="response shape mismatch"):
            await a.embed(["foo", "bar"])

    @respx.mock
    async def test_embed_raises_on_wrong_dimensions(self) -> None:
        """Provider returns a row with dim != adapter.dimensions →
        operator misconfiguration; fail loud."""

        import pytest

        respx.post(f"{BASE}/v1/embeddings").mock(
            return_value=Response(
                200,
                json={
                    "data": [
                        # adapter dimensions=4 but provider returned 8
                        {
                            "embedding": [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8],
                            "index": 0,
                        },
                    ],
                    "model": MODEL,
                    "object": "list",
                },
            )
        )
        a = _adapter(dimensions=4)
        with pytest.raises(ValueError, match=r"dim=8.*dimensions=4"):
            await a.embed(["foo"])

    @respx.mock
    async def test_embed_raises_on_non_list_embedding(self) -> None:
        """Provider returns malformed row → fail loud rather than
        silently producing garbage."""

        import pytest

        respx.post(f"{BASE}/v1/embeddings").mock(
            return_value=Response(
                200,
                json={
                    "data": [{"embedding": "not-a-list", "index": 0}],
                    "model": MODEL,
                    "object": "list",
                },
            )
        )
        a = _adapter()
        with pytest.raises(ValueError, match="not a list"):
            await a.embed(["foo"])

    @respx.mock
    async def test_embed_raises_on_nan_value(self) -> None:
        """NaN values would poison Qdrant cosine-distance math (any vector
        containing NaN compares as NaN, breaking ANN ordering). Reject at
        the adapter boundary rather than letting it reach the index."""

        import pytest

        # JSON spec doesn't allow bare `NaN`, but Python's json module +
        # vLLM/SGLang both happily emit/consume it. Mock the parsed body
        # directly via a patched .json() call.
        body = {
            "data": [{"embedding": [0.1, float("nan"), 0.3, 0.4], "index": 0}],
            "model": MODEL,
            "object": "list",
        }
        # respx serializes via httpx Response; pass a Python dict that
        # round-trips through JSON. Use a custom content payload that
        # lets NaN through (httpx parses with ujson if installed; we
        # send raw bytes to be safe).
        import json as _json

        # Python's json.dumps emits 'NaN' (non-standard but readable);
        # httpx Response.json() parses it back via the stdlib parser
        # which DOES accept 'NaN'. That's the same path real providers
        # use when they emit NaN.
        raw = _json.dumps(body).encode("utf-8")
        respx.post(f"{BASE}/v1/embeddings").mock(
            return_value=Response(200, content=raw, headers={"content-type": "application/json"})
        )
        a = _adapter()
        with pytest.raises(ValueError, match="non-finite"):
            await a.embed(["foo"])

    @respx.mock
    async def test_embed_raises_on_inf_value(self) -> None:
        """Infinity values likewise corrupt downstream cosine-distance."""

        import json as _json

        import pytest

        body = {
            "data": [{"embedding": [0.1, 0.2, float("inf"), 0.4], "index": 0}],
            "model": MODEL,
            "object": "list",
        }
        raw = _json.dumps(body).encode("utf-8")
        respx.post(f"{BASE}/v1/embeddings").mock(
            return_value=Response(200, content=raw, headers={"content-type": "application/json"})
        )
        a = _adapter()
        with pytest.raises(ValueError, match="non-finite"):
            await a.embed(["foo"])

    @respx.mock
    async def test_embed_raises_on_non_numeric_value(self) -> None:
        """A string masquerading as a numeric in the embedding row would
        crash float(x) downstream of any silent coercion. Fail loud at
        the adapter."""

        import pytest

        respx.post(f"{BASE}/v1/embeddings").mock(
            return_value=Response(
                200,
                json={
                    "data": [{"embedding": [0.1, "oops", 0.3, 0.4], "index": 0}],
                    "model": MODEL,
                    "object": "list",
                },
            )
        )
        a = _adapter()
        with pytest.raises(ValueError, match="non-numeric"):
            await a.embed(["foo"])


class TestEmbedBearerAuth:
    """OpenAI / Cohere / vLLM-with-auth-token: ``Authorization: Bearer <key>``."""

    @respx.mock
    async def test_embed_sends_bearer_authorization(self) -> None:
        route = respx.post(f"{BASE}/v1/embeddings").mock(
            return_value=Response(
                200,
                json={
                    "data": [{"embedding": [0.1, 0.2, 0.3, 0.4], "index": 0}],
                    "model": MODEL,
                    "object": "list",
                },
            )
        )
        a = _adapter(api_key="sk-test-openai-key", api_key_header="Authorization")
        await a.embed(["foo"])

        sent = route.calls.last.request
        assert sent.headers["authorization"] == "Bearer sk-test-openai-key"


class TestEmbedAzureApiKeyAuth:
    """Azure-OpenAI proxy convention: ``api-key: <key>`` header (raw, no prefix)
    + custom api-version query/header carried via extra_headers."""

    @respx.mock
    async def test_embed_sends_api_key_header_raw(self) -> None:
        route = respx.post(f"{BASE}/v1/embeddings").mock(
            return_value=Response(
                200,
                json={
                    "data": [{"embedding": [0.1, 0.2, 0.3, 0.4], "index": 0}],
                    "model": MODEL,
                    "object": "list",
                },
            )
        )
        a = _adapter(
            api_key="azure-key-value",
            api_key_header="api-key",
            extra_headers={"api-version": "2024-02-15-preview"},
        )
        await a.embed(["foo"])

        sent = route.calls.last.request
        # Raw key value (no Bearer prefix)
        assert sent.headers["api-key"] == "azure-key-value"
        assert "authorization" not in {h.lower() for h in sent.headers}
        # extra_headers carried through
        assert sent.headers["api-version"] == "2024-02-15-preview"


class TestHealth:
    @respx.mock
    async def test_health_ok_via_v1_models(self) -> None:
        """Standard OpenAI-compat liveness path is GET /v1/models."""

        respx.get(f"{BASE}/v1/models").mock(
            return_value=Response(200, json={"object": "list", "data": [{"id": MODEL}]})
        )
        a = _adapter(dimensions=1024)
        h = await a.health_check()
        assert h.status == "ok"
        assert h.driver == "openai_compat"
        assert h.latency_ms is not None

    @respx.mock
    async def test_health_uses_same_auth_headers_as_embed(self) -> None:
        """The /v1/models probe must validate the same auth path that
        embed() uses, otherwise health_check could falsely report ``ok``
        on misconfigured tokens."""

        route = respx.get(f"{BASE}/v1/models").mock(
            return_value=Response(200, json={"object": "list", "data": []})
        )
        a = _adapter(api_key="sk-bearer", api_key_header="Authorization")
        await a.health_check()

        sent = route.calls.last.request
        assert sent.headers["authorization"] == "Bearer sk-bearer"

    @respx.mock
    async def test_health_unreachable_on_connect_error(self) -> None:
        respx.get(f"{BASE}/v1/models").mock(side_effect=ConnectError("nope"))
        a = _adapter()
        h = await a.health_check()
        assert h.status == "unreachable"

    @respx.mock
    async def test_health_unreachable_on_401(self) -> None:
        """Bad/expired API key → 401; surface as unreachable so operators
        see the auth failure in /readyz rather than getting silent embed
        failures later."""

        respx.get(f"{BASE}/v1/models").mock(return_value=Response(401))
        a = _adapter(api_key="sk-stale")
        h = await a.health_check()
        assert h.status == "unreachable"


class TestSatisfiesProtocol:
    def test_protocol_conformance(self) -> None:
        a = _adapter(dimensions=1024)
        assert isinstance(a, P.EmbeddingAdapter)
