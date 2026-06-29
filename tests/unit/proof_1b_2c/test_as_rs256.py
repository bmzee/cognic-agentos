"""RS256 mode for the proof AS fixture (M3-E2c Task 1). The unsigned path
(Proof 1b-2) MUST stay behaviorally unchanged (same alg:none token); the rs256
path mints a verifiable RS256 JWT and serves a JWKS the pack's PyJWKClient can
consume."""

from __future__ import annotations

import base64
import importlib
import json
from types import ModuleType

import jwt
import pytest
from starlette.testclient import TestClient


def _reload(monkeypatch: pytest.MonkeyPatch, **env: str) -> ModuleType:
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return importlib.reload(importlib.import_module("tests.integration.pack_loop._local_as"))


def test_unsigned_mode_is_unchanged(monkeypatch):
    monkeypatch.delenv("COGNIC_PROOF_AS_SIGNING_MODE", raising=False)
    mod = _reload(monkeypatch, COGNIC_PROOF_AS_ISSUER="http://as.test:9000")
    client = TestClient(mod.build_app())
    tok = client.post(
        "/token", data={"scope": "oracle_schema.read", "resource": "http://rs.test/mcp"}
    ).json()["access_token"]
    assert tok.endswith(".sig")  # decorative signature unchanged
    hdr = json.loads(base64.urlsafe_b64decode(tok.split(".")[0] + "=="))
    assert hdr["alg"] == "none"


def test_rs256_mode_mints_verifiable_jwt_and_serves_jwks(monkeypatch):
    mod = _reload(
        monkeypatch,
        COGNIC_PROOF_AS_SIGNING_MODE="rs256",
        COGNIC_PROOF_AS_ISSUER="http://as.test:9000",
    )
    client = TestClient(mod.build_app())

    meta = client.get("/.well-known/oauth-authorization-server").json()
    assert meta["issuer"] == "http://as.test:9000"
    assert meta["jwks_uri"] == "http://as.test:9000/.well-known/jwks.json"

    jwks = client.get("/.well-known/jwks.json").json()
    key = jwks["keys"][0]
    assert key["kty"] == "RSA" and key["use"] == "sig" and key["alg"] == "RS256"

    resource = "http://10.96.0.51:8765/mcp"
    tok = client.post("/token", data={"scope": "oracle_schema.read", "resource": resource}).json()[
        "access_token"
    ]
    assert jwt.get_unverified_header(tok)["kid"] == key["kid"]
    claims = jwt.decode(
        tok,
        jwt.PyJWK(key).key,
        algorithms=["RS256"],
        audience=resource,
        issuer="http://as.test:9000",
        options={"require": ["exp", "iat", "nbf"]},
    )
    assert claims["scope"] == "oracle_schema.read"
    assert claims["aud"] == resource and claims["iss"] == "http://as.test:9000"
