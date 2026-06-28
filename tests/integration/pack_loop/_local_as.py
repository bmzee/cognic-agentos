# tests/integration/pack_loop/_local_as.py
"""A tiny localhost OAuth2 client-credentials authorization server.

Two modes (env COGNIC_PROOF_AS_SIGNING_MODE):
  * "unsigned" (default) — Proof 1a/1b-2 path. The access token is an alg:none
    JWT carrying only {aud=<resource>, scope}; the signature is decorative
    (AgentOS validates `aud`, trusts the AS via the per-tenant allow-list).
  * "rs256" — M3-E2c path. Mints an RS256-signed JWT
    {iss, aud=<resource>, exp, iat, nbf, scope} and serves a JWKS endpoint so a
    real resource-server verifier (the oracle pack's PyJWKClient) can verify it.
"""

from __future__ import annotations

import base64
import json
import os
import time
from typing import TYPE_CHECKING

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

_AS_ISSUER = os.environ.get("COGNIC_PROOF_AS_ISSUER", "http://127.0.0.1:9000")
_SIGNING_MODE = os.environ.get("COGNIC_PROOF_AS_SIGNING_MODE", "unsigned")
_KID = "proof-1b-2c-rs256"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _rsa_material() -> tuple[RSAPrivateKey, dict[str, str]]:
    # rs256 only. Process-lifetime keypair (the AS pod is single-replica + stable
    # for a run; a restart rotates the key, which is fine — the pack fetches JWKS
    # fresh and AgentOS re-acquires the token on a cold boot).
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk: dict[str, str] = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(priv.public_key()))
    jwk.update({"use": "sig", "alg": "RS256", "kid": _KID})
    return priv, jwk


_RSA_PRIV: RSAPrivateKey | None = None
_RSA_JWK: dict[str, str] | None = None
if _SIGNING_MODE == "rs256":
    _RSA_PRIV, _RSA_JWK = _rsa_material()


async def _metadata(_request: Request) -> JSONResponse:
    body = {"token_endpoint": f"{_AS_ISSUER}/token", "issuer": _AS_ISSUER}
    if _SIGNING_MODE == "rs256":
        body["jwks_uri"] = f"{_AS_ISSUER}/.well-known/jwks.json"
    return JSONResponse(body)


async def _jwks(_request: Request) -> JSONResponse:
    assert _RSA_JWK is not None, "jwks route is registered only in rs256 mode"
    return JSONResponse({"keys": [_RSA_JWK]})


async def _token(request: Request) -> JSONResponse:
    form = await request.form()
    requested_scope = str(form.get("scope", "mcp:tools"))
    resource = str(form.get("resource", ""))  # RFC 8707 resource indicator == server_url
    if _SIGNING_MODE == "rs256":
        import jwt

        assert _RSA_PRIV is not None, "rs256 keypair is minted at import in rs256 mode"
        now = int(time.time())
        access_token = jwt.encode(
            {
                "iss": _AS_ISSUER,
                "aud": resource,
                "scope": requested_scope,
                "iat": now,
                "nbf": now,
                "exp": now + 3600,
            },
            _RSA_PRIV,
            algorithm="RS256",
            headers={"kid": _KID},
        )
    else:
        header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode("utf-8"))
        payload = _b64url(json.dumps({"aud": resource, "scope": requested_scope}).encode("utf-8"))
        access_token = f"{header}.{payload}.sig"
    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": requested_scope,
        }
    )


def build_app() -> Starlette:
    routes = [
        Route("/.well-known/oauth-authorization-server", _metadata, methods=["GET"]),
        Route("/token", _token, methods=["POST"]),
    ]
    if _SIGNING_MODE == "rs256":
        routes.append(Route("/.well-known/jwks.json", _jwks, methods=["GET"]))
    return Starlette(routes=routes)


def run_local_as(*, port: int = 9000) -> None:
    uvicorn.run(
        build_app(),
        host=os.environ.get("COGNIC_PROOF_AS_HOST", "127.0.0.1"),
        port=port,
        log_level="warning",
    )


if __name__ == "__main__":
    run_local_as(port=int(os.environ.get("COGNIC_PROOF_AS_PORT", "9000")))
