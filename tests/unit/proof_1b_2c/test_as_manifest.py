"""Structural pin — the RS256 AS image + manifest (M3-E2c Task 6)."""

from pathlib import Path

import yaml

DF = Path("infra/proof-1b-2c/Dockerfile.as").read_text()
DOCS = list(yaml.safe_load_all(Path("infra/proof-1b-2c/manifests/auth-server.yaml").read_text()))
ORACLE_DOCS = list(
    yaml.safe_load_all(Path("infra/proof-1b-2c/manifests/oracle-pack.yaml").read_text())
)
DEP = next(d for d in DOCS if d["kind"] == "Deployment")
SVC = next(d for d in DOCS if d["kind"] == "Service")
C = DEP["spec"]["template"]["spec"]["containers"][0]
ENV = {e["name"]: e.get("value") for e in C["env"]}
ORACLE_ENV = {
    e["name"]: e.get("value")
    for e in next(d for d in ORACLE_DOCS if d["kind"] == "Deployment")["spec"]["template"]["spec"][
        "containers"
    ][0]["env"]
}


def test_as_image_installs_pyjwt_crypto_and_vendors_fixture():
    assert "FROM python:3.12-slim" in DF
    for dep in (
        "uvicorn[standard]>=0.35",
        "starlette>=0.40",
        "python-multipart>=0.0.9",
        "PyJWT[crypto]>=2.10,<3",
    ):
        assert dep in DF
    assert "COPY _local_as.py /app/_local_as.py" in DF
    assert "WORKDIR /app" in DF
    assert "EXPOSE 9000" in DF
    assert 'CMD ["python", "_local_as.py"]' in DF


def test_as_deployment_identity_and_image():
    assert DEP["metadata"]["name"] == "proof-as"
    assert DEP["spec"]["selector"]["matchLabels"] == {"app": "proof-as"}
    assert DEP["spec"]["template"]["metadata"]["labels"] == {"app": "proof-as"}
    assert C["name"] == "as"
    assert C["image"] == "cognic-proof-as:1b2c"
    assert C["imagePullPolicy"] == "IfNotPresent"
    assert C["ports"] == [{"containerPort": 9000}]


def test_as_rs256_mode_and_issuer():
    assert ENV == {
        "COGNIC_PROOF_AS_HOST": "0.0.0.0",
        "COGNIC_PROOF_AS_ISSUER": "http://192.88.99.9:9000",
        "COGNIC_PROOF_AS_PORT": "9000",
        "COGNIC_PROOF_AS_SIGNING_MODE": "rs256",
    }


def test_as_issuer_matches_oracle_pack_jwks_wiring():
    issuer = ENV["COGNIC_PROOF_AS_ISSUER"]
    assert ORACLE_ENV["COGNIC_MCP_AS_ISSUER"] == issuer == ORACLE_ENV["COGNIC_OAUTH_ISSUER"]
    assert ORACLE_ENV["COGNIC_OAUTH_JWKS_URI"] == f"{issuer}/.well-known/jwks.json"


def test_as_service_externalip():
    assert SVC["metadata"]["name"] == "proof-as"
    assert SVC["spec"]["externalIPs"] == ["192.88.99.9"]
    assert SVC["spec"]["selector"] == {"app": "proof-as"}
    assert SVC["spec"]["ports"] == [{"port": 9000, "targetPort": 9000}]
