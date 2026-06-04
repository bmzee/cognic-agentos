"""Request-ID middleware contract.

Sprint-7B.4 T6 amendment: portal traffic (`/api/v1/*`) now mints a
deterministic ``portal-req-<uuid4.hex>`` id at the portal request-id
middleware, OVERRIDING any X-Request-Id supplied by the caller. The
observability normalisation behavior (32-hex generation, UUID echo,
non-UUID replacement, overlong replacement) still applies for
non-portal paths — these tests now assert on `/openapi.json` (a
non-portal path that exists in every FastAPI app) so the observability
contract stays pinned in isolation from T6's override.

Portal paths' wire-shape (X-Request-Id = `portal-req-<hex>`) is
pinned by
`tests/unit/portal/rbac/test_rbac_denial_chain_emission.py::TestRequestIdMiddleware`.
"""

from __future__ import annotations

import re

from fastapi.testclient import TestClient

from cognic_agentos.observability.middleware import REQUEST_ID_HEADER
from cognic_agentos.portal.api.app import create_app
from tests.support.settings_fixtures import prod_settings

_HEX32 = re.compile(r"^[0-9a-f]{32}$")

#: Non-portal path used to exercise observability's request-id
#: normalisation behavior without the T6 portal override kicking in.
#: `/openapi.json` exists by default in every FastAPI app at
#: `{api_prefix}/openapi.json` — but `api_prefix` defaults to `/api/v1`
#: in this repo, so we use the root-mounted `/livez` route instead
#: (registered by the system router under api_prefix too — see below).
#:
#: Sprint-7B.4 T6: use a non-`/api/v1/*` path so the T6 middleware
#: skips the portal-req-* override. Verified the system router's
#: `/livez` is registered at the BARE root in addition to under the
#: api_prefix (FastAPI's default `/openapi.json` lives under api_prefix).
_NON_PORTAL_PATH = "/livez"


def _client() -> TestClient:
    return TestClient(create_app(prod_settings()))


def test_request_id_generated_when_absent() -> None:
    # The request-id middleware fires on every request regardless of
    # whether the route matches — the response has the X-Request-Id
    # header even if the path 404s. The non-portal `_NON_PORTAL_PATH`
    # returns 404 by design (no public non-portal routes in this app;
    # all real endpoints sit behind the `/api/v1/*` prefix where T6's
    # portal-req-* override applies); we only care about the header.
    response = _client().get(_NON_PORTAL_PATH)
    rid = response.headers.get(REQUEST_ID_HEADER)
    assert rid is not None
    assert _HEX32.match(rid), f"generated id should be 32-hex UUID, got {rid!r}"


def test_request_id_echoed_when_supplied_as_uuid() -> None:
    incoming = "12345678-1234-5678-1234-567812345678"
    response = _client().get(_NON_PORTAL_PATH, headers={REQUEST_ID_HEADER: incoming})
    # Echo is UUID hex (no hyphens) — guarantees the value was parsed.
    assert response.headers[REQUEST_ID_HEADER] == "12345678123456781234567812345678"


def test_request_id_replaces_non_uuid_input() -> None:
    """A non-UUID caller value must NOT poison logs; replace with fresh UUID."""

    response = _client().get(
        _NON_PORTAL_PATH, headers={REQUEST_ID_HEADER: "not-a-uuid; DROP TABLE users;--"}
    )
    rid = response.headers[REQUEST_ID_HEADER]
    assert _HEX32.match(rid)
    assert "DROP" not in rid


def test_request_id_replaces_overlong_input() -> None:
    response = _client().get(_NON_PORTAL_PATH, headers={REQUEST_ID_HEADER: "x" * 4096})
    rid = response.headers[REQUEST_ID_HEADER]
    assert _HEX32.match(rid)


def test_portal_path_overrides_request_id_with_portal_prefix() -> None:
    """Sprint-7B.4 T6 wire-shape: portal traffic (`/api/v1/*`) ALWAYS
    mints a deterministic ``portal-req-<uuid4.hex>`` id regardless of
    any X-Request-Id supplied by the caller. This is the inverse of the
    observability echo-when-uuid behavior tested above — portal traffic
    owns its request_id minting end-to-end (response header + access
    log + denial log + chain row all carry the SAME portal-prefixed id)."""
    incoming = "12345678-1234-5678-1234-567812345678"
    response = _client().get("/api/v1/healthz", headers={REQUEST_ID_HEADER: incoming})
    rid = response.headers[REQUEST_ID_HEADER]
    assert rid.startswith("portal-req-"), (
        f"portal path should mint portal-req-* regardless of supplied X-Request-Id; got {rid!r}"
    )
    # Caller's supplied id is NOT echoed on portal paths.
    assert rid != "12345678123456781234567812345678"
