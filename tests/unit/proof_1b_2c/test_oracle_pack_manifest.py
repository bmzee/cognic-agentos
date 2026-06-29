"""Structural pin — the oracle-pack Deployment+Service manifest (M3-E2c Task 5).

Pins the static ClusterIP, the single-effective-URL invariant, the issuer
invariant, jwt-mode-never-dev_insecure, the Oracle connection + owner allow-list,
and the XE-wait initContainer.
"""

from pathlib import Path

import yaml

DOCS = list(yaml.safe_load_all(Path("infra/proof-1b-2c/manifests/oracle-pack.yaml").read_text()))
DEP = next(d for d in DOCS if d["kind"] == "Deployment")
SVC = next(d for d in DOCS if d["kind"] == "Service")
POD = DEP["spec"]["template"]["spec"]
CONTAINER = POD["containers"][0]
ENV = {e["name"]: e.get("value") for e in CONTAINER["env"]}
SERVER_URL = "http://10.96.0.51:8765/mcp"
AS_ISSUER = "http://192.88.99.9:9000"


def test_deployment_service_identity_and_image():
    assert DEP["metadata"]["name"] == "proof-oracle-pack"
    assert DEP["spec"]["selector"]["matchLabels"] == {"app": "proof-oracle-pack"}
    assert DEP["spec"]["template"]["metadata"]["labels"] == {"app": "proof-oracle-pack"}
    assert CONTAINER["name"] == "oracle-pack"
    assert CONTAINER["image"] == "cognic-proof-oracle-pack:1b2c"
    assert CONTAINER["imagePullPolicy"] == "IfNotPresent"
    assert CONTAINER["ports"] == [{"containerPort": 8765}]
    assert SVC["metadata"]["name"] == "proof-oracle-pack"
    assert SVC["spec"]["selector"] == {"app": "proof-oracle-pack"}
    assert SVC["spec"]["ports"] == [{"port": 8765, "targetPort": 8765}]


def test_static_clusterip():
    assert SVC["spec"]["clusterIP"] == "10.96.0.51"


def test_single_effective_url_invariant():
    assert ENV["COGNIC_MCP_SERVER_URL"] == SERVER_URL == ENV["COGNIC_OAUTH_AUDIENCE"]


def test_issuer_invariant():
    assert ENV["COGNIC_MCP_AS_ISSUER"] == AS_ISSUER == ENV["COGNIC_OAUTH_ISSUER"]
    assert ENV["COGNIC_OAUTH_JWKS_URI"] == f"{AS_ISSUER}/.well-known/jwks.json"


def test_real_jwt_never_dev_insecure():
    assert ENV["COGNIC_AUTH_MODE"] == "jwt"
    assert "COGNIC_ENV" not in ENV  # dev_insecure unreachable
    assert "dev_insecure" not in ENV.values()
    assert ENV["COGNIC_REQUIRED_SCOPES"] == "oracle_schema.read"


def test_oracle_connection_and_owner_allowlist():
    assert ENV["COGNIC_MCP_HOST"] == "0.0.0.0"
    assert ENV["COGNIC_MCP_PORT"] == "8765"
    assert ENV["COGNIC_ORACLE_DSN"] == "oracle-xe:1521/XEPDB1"
    assert ENV["COGNIC_ORACLE_USER"] == "cognic"
    assert ENV["COGNIC_ORACLE_PASSWORD"] == "cognic_dev_only"
    assert ENV["COGNIC_ORACLE_ALLOWED_OWNERS"] == "COGNIC"


def test_waits_for_xe():
    init = POD["initContainers"][0]
    assert init["name"] == "wait-for-xe"
    assert init["image"] == "busybox:1.36"
    assert init["command"] == [
        "sh",
        "-c",
        "until nc -z oracle-xe 1521; do echo waiting for oracle-xe; sleep 5; done",
    ]
