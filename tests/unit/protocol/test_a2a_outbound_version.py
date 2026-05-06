"""Sprint-6 T14 — runtime canary for outbound A2A-Version header.

Per ADR-003 + A2A-CONFORMANCE.md §"Version negotiation": every
outbound A2A call AgentOS makes MUST advertise the pinned spec
version via the ``A2A-Version`` header. The spec instructs receivers
to interpret an absent header as A2A 0.3 (the legacy version), so
omitting the header silently drifts our outbound traffic to the
wrong wire contract on a 1.0-only target.

The Sprint-6 T14 prerequisite commit (34ebf32) added the header to
the two outbound ``_http.get`` sites in
:meth:`A2AAgentCardVerifier.fetch_and_verify_outbound_card`. This
runtime canary is the **drift-detector** that pins the contract:

  - Real :class:`A2AAgentCardVerifier` — instance-level mock on
    ``_http`` capturing every ``.get(...)`` call's kwargs.
  - Per-call-site assertion: every captured GET MUST carry
    ``A2A-Version: 1.0`` in its ``headers`` kwarg.
  - Pinned-version invariant — ``PINNED_VERSION == "1.0"`` so a
    future spec bump trips this canary alongside the inbound
    negotiator's pinned-version test.

If a future change drops the header (or the protocol's pinned
version moves without coordination), this canary is the runtime
half that catches it before it reaches a remote agent.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.protocol.a2a_agent_cards import A2AAgentCardVerifier
from cognic_agentos.protocol.a2a_version import PINNED_VERSION
from cognic_agentos.protocol.trust_gate import TrustGate

# ---------------------------------------------------------------------------
# Verifier fixture — instance-level mock on _http (per user's T14 lock)
# ---------------------------------------------------------------------------


def _make_verifier_with_mock_http() -> tuple[A2AAgentCardVerifier, MagicMock]:
    """Construct a real :class:`A2AAgentCardVerifier` whose ``_http``
    instance attribute is replaced with a :class:`MagicMock` that
    captures every ``.get(...)`` invocation.

    Returns ``(verifier, mock_http)``. The verifier is otherwise wired
    with a real :class:`TrustGate` + mocked secret/audit/dh adapters
    — the canary's subject is the call-site, not the trust path.
    """

    secret_adapter = MagicMock()
    secret_adapter.read = AsyncMock(return_value={"keys": []})
    audit_store = MagicMock()
    audit_store.append = AsyncMock(return_value=(None, b""))
    decision_history_store = MagicMock()
    decision_history_store.append = AsyncMock(return_value=(None, b""))
    settings = build_settings_without_env_file()

    # Real http_client at construction so the verifier accepts it
    # against its httpx.AsyncClient type contract; we then swap _http
    # for a capturing mock immediately after construction so the
    # canary observes every outbound .get() call's kwargs.
    real_http = MagicMock(spec=httpx.AsyncClient)
    verifier = A2AAgentCardVerifier(
        settings=settings,
        trust_gate=TrustGate(
            settings=settings,
            audit_store=audit_store,
            secret_adapter=secret_adapter,
        ),
        audit_store=audit_store,
        decision_history_store=decision_history_store,
        http_client=real_http,
    )
    # Instance-level swap (per the user's T14 lock — instance, not
    # module-import-boundary). The canary captures every .get() call
    # via this mock.
    mock_http = MagicMock()
    mock_http.get = AsyncMock(return_value=MagicMock(status_code=404, content=b""))
    verifier._http = mock_http
    return verifier, mock_http


# ---------------------------------------------------------------------------
# TestOutboundVersionHeaderAlwaysOneZero
# ---------------------------------------------------------------------------


class TestOutboundVersionHeaderAlwaysOneZero:
    """Every outbound A2A GET issued by
    :meth:`A2AAgentCardVerifier.fetch_and_verify_outbound_card` MUST
    carry ``A2A-Version: PINNED_VERSION`` in its ``headers`` kwarg.
    The fetch is allowed to fail downstream (we mock 404 so the
    verifier raises) — the canary's subject is the **call-site
    headers**, not the response handling."""

    async def test_card_get_sends_a2a_version_header(self) -> None:
        from cognic_agentos.protocol.a2a_agent_cards import A2AAgentCardError

        verifier, mock_http = _make_verifier_with_mock_http()
        with pytest.raises(A2AAgentCardError):
            # Mock returns 404 → verifier raises blob_unreadable;
            # the canary captures the GET call before the raise.
            await verifier.fetch_and_verify_outbound_card(
                target_origin="https://remote.example",
                tenant_id="bank_a",
                request_id="rid-outbound-version-canary-1",
            )
        # Both outbound GETs (card + JWS) ran — capture them.
        assert mock_http.get.await_count >= 1
        # First call is the card-fetch.
        first_call = mock_http.get.await_args_list[0]
        headers = first_call.kwargs.get("headers")
        assert headers is not None, (
            "outbound card-fetch GET must carry a `headers` kwarg (missing entirely)"
        )
        assert headers.get("A2A-Version") == PINNED_VERSION, (
            f"outbound card-fetch GET must send `A2A-Version: {PINNED_VERSION}`; "
            f"got headers={headers!r}"
        )

    async def test_jws_get_sends_a2a_version_header(self) -> None:
        from cognic_agentos.protocol.a2a_agent_cards import A2AAgentCardError

        verifier, mock_http = _make_verifier_with_mock_http()
        # First call returns 200 with empty card so the verifier
        # proceeds to the JWS fetch; second call returns 404 so the
        # verifier raises after both GETs landed.
        mock_http.get = AsyncMock(
            side_effect=[
                MagicMock(status_code=200, content=b"{}"),
                MagicMock(status_code=404, content=b""),
            ]
        )
        verifier._http = mock_http
        with pytest.raises(A2AAgentCardError):
            await verifier.fetch_and_verify_outbound_card(
                target_origin="https://remote.example",
                tenant_id="bank_a",
                request_id="rid-outbound-version-canary-2",
            )
        # The JWS-fetch is the second GET call.
        assert mock_http.get.await_count == 2, (
            f"expected 2 outbound GETs (card + JWS); got {mock_http.get.await_count}"
        )
        jws_call = mock_http.get.await_args_list[1]
        jws_headers = jws_call.kwargs.get("headers")
        assert jws_headers is not None, (
            "outbound JWS-fetch GET must carry a `headers` kwarg (missing entirely)"
        )
        assert jws_headers.get("A2A-Version") == PINNED_VERSION, (
            f"outbound JWS-fetch GET must send `A2A-Version: {PINNED_VERSION}`; "
            f"got headers={jws_headers!r}"
        )

    async def test_both_outbound_gets_share_pinned_version(self) -> None:
        """Belt-and-braces: both card and JWS GETs in a SINGLE
        ``fetch_and_verify_outbound_card`` invocation MUST share the
        same pinned version (no per-call drift). This guards against
        a future patch that adds the header to one call but not the
        other."""
        from cognic_agentos.protocol.a2a_agent_cards import A2AAgentCardError

        verifier, mock_http = _make_verifier_with_mock_http()
        mock_http.get = AsyncMock(
            side_effect=[
                MagicMock(status_code=200, content=b"{}"),
                MagicMock(status_code=404, content=b""),
            ]
        )
        verifier._http = mock_http
        with pytest.raises(A2AAgentCardError):
            await verifier.fetch_and_verify_outbound_card(
                target_origin="https://remote.example",
                tenant_id="bank_a",
                request_id="rid-outbound-version-canary-3",
            )
        assert mock_http.get.await_count == 2
        card_headers = mock_http.get.await_args_list[0].kwargs.get("headers", {})
        jws_headers = mock_http.get.await_args_list[1].kwargs.get("headers", {})
        assert card_headers.get("A2A-Version") == jws_headers.get("A2A-Version")
        assert card_headers.get("A2A-Version") == PINNED_VERSION

    def test_pinned_version_constant_is_one_zero(self) -> None:
        """Drift-detector: if the spec pin moves, the canary author
        MUST look here. ``PINNED_VERSION`` is the single source-of-
        truth for both the inbound version-negotiator and the
        outbound header — they MUST not disagree."""
        assert PINNED_VERSION == "1.0"
