"""Structural gate (author-time): the Proof 1b-2 kind manifests pin the
load-bearing topology + the single-URL / AS-issuer invariants OFFLINE — without a
``kind`` cluster, ``kubectl``, or any live API server (the proof RUN is deferred
behind ``COGNIC_RUN_PROOF_1B2=1`` to the operator-run T9 stage).

Per the Proof 1b-2 plan (Task 7), the two manifests under
``infra/proof-1b-2/manifests/`` describe the in-cluster MCP tool Service + the
emulated-external OAuth AS. The deployed proof depends on four facts a malformed
or drifted manifest would silently regress (every value is byte-identical to the
plan's Global Constraints — the override / allow-list seed / RFC-8707 ``resource``
/ token ``aud`` alignment depends on it):

1. the MCP Service has the static **private** ClusterIP ``10.96.0.50`` (the
   PR-2b-1 override + exact-IP allow-list seed THIS exact IP; it is reachable only
   via that carve-out, never a guard-allowed address);
2. the AS Service has the genuine-global (RFC7526) **public-shaped** externalIP
   ``192.88.99.9`` (``is_global=True`` so the OAuth legs' hard-public-only guard
   allows it, yet kube-proxy-intercepted — NO real external egress);
3. the MCP container advertises EXACTLY the single effective URL
   ``http://10.96.0.50:8765/mcp`` (``COGNIC_PROOF_SERVER_URL`` → PRM
   ``resource_server_url`` + token ``resource``);
4. the AS issuer ``http://192.88.99.9:9000`` is byte-identical on BOTH the MCP
   container (``COGNIC_PROOF_AS_ISSUER`` → PRM ``authorization_servers``) AND the
   AS container (``COGNIC_PROOF_AS_ISSUER`` → ``token_endpoint`` + ``issuer``).

These tests parse the manifests with ``yaml.safe_load_all`` only — they never
contact a cluster.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[3]
_MANIFESTS = _REPO_ROOT / "infra" / "proof-1b-2" / "manifests"
_MCP_MANIFEST = _MANIFESTS / "mcp-server.yaml"
_AS_MANIFEST = _MANIFESTS / "auth-server.yaml"

# Global-Constraints invariant values — byte-identical across override row /
# allow-list seed / container env / RFC-8707 resource / token aud.
_MCP_CLUSTER_IP = "10.96.0.50"
_MCP_SERVER_URL = "http://10.96.0.50:8765/mcp"
_AS_EXTERNAL_IP = "192.88.99.9"
_AS_ISSUER = "http://192.88.99.9:9000"


def _load_docs(path: Path) -> list[dict[str, Any]]:
    """Parse a multi-doc manifest, dropping any empty (``None``) documents."""
    return [doc for doc in yaml.safe_load_all(path.read_text()) if doc is not None]


def _pick(docs: list[dict[str, Any]], *, kind: str, name: str) -> dict[str, Any]:
    """Select the doc matching ``kind`` + ``metadata.name`` (fail loud if absent)."""
    for doc in docs:
        if doc.get("kind") == kind and doc.get("metadata", {}).get("name") == name:
            return doc
    raise AssertionError(f"no {kind}/{name} document found in manifest")


def _container_env(deployment: dict[str, Any]) -> dict[str, str]:
    """Flatten the first container's ``env`` list into a ``{name: value}`` dict."""
    containers = deployment["spec"]["template"]["spec"]["containers"]
    return {entry["name"]: entry["value"] for entry in containers[0]["env"]}


def test_manifests_exist() -> None:
    assert _MCP_MANIFEST.is_file(), f"MCP manifest not found at {_MCP_MANIFEST}"
    assert _AS_MANIFEST.is_file(), f"AS manifest not found at {_AS_MANIFEST}"


def test_mcp_service_has_static_private_cluster_ip() -> None:
    # The override + exact-IP allow-list seed THIS exact private ClusterIP; the MCP
    # Service is reachable only via that carve-out, never a guard-allowed address.
    svc = _pick(_load_docs(_MCP_MANIFEST), kind="Service", name="proof-mcp")
    assert svc["spec"]["clusterIP"] == _MCP_CLUSTER_IP


def test_as_service_has_public_shaped_external_ip() -> None:
    # Genuine-global (RFC7526) so is_global=True (the OAuth legs' hard-public-only
    # guard allows it), yet kube-proxy-intercepted — NO real external egress.
    svc = _pick(_load_docs(_AS_MANIFEST), kind="Service", name="proof-as")
    assert svc["spec"]["externalIPs"] == [_AS_EXTERNAL_IP]


def test_mcp_container_advertises_the_single_effective_url() -> None:
    # COGNIC_PROOF_SERVER_URL → PRM resource_server_url + token resource. Must be
    # byte-identical to the override row + the AgentOS-sent RFC-8707 resource.
    env = _container_env(_pick(_load_docs(_MCP_MANIFEST), kind="Deployment", name="proof-mcp"))
    assert env["COGNIC_PROOF_SERVER_URL"] == _MCP_SERVER_URL
    assert env["COGNIC_PROOF_AS_ISSUER"] == _AS_ISSUER


def test_as_container_carries_the_as_issuer() -> None:
    # COGNIC_PROOF_AS_ISSUER → the AS token_endpoint + issuer.
    env = _container_env(_pick(_load_docs(_AS_MANIFEST), kind="Deployment", name="proof-as"))
    assert env["COGNIC_PROOF_AS_ISSUER"] == _AS_ISSUER


def test_as_issuer_is_byte_identical_across_mcp_and_as_containers() -> None:
    # HARD BAR #4: the override / seed / audience alignment depends on the AS issuer
    # being byte-identical on BOTH containers. Pin the cross-manifest equality.
    mcp_env = _container_env(_pick(_load_docs(_MCP_MANIFEST), kind="Deployment", name="proof-mcp"))
    as_env = _container_env(_pick(_load_docs(_AS_MANIFEST), kind="Deployment", name="proof-as"))
    assert mcp_env["COGNIC_PROOF_AS_ISSUER"] == as_env["COGNIC_PROOF_AS_ISSUER"] == _AS_ISSUER


def test_containers_bind_all_interfaces_for_in_cluster_reachability() -> None:
    # A 127.0.0.1 bind would make the in-cluster Service unable to reach either
    # container — pin the 0.0.0.0 bind hosts (load-bearing deployment values).
    mcp_env = _container_env(_pick(_load_docs(_MCP_MANIFEST), kind="Deployment", name="proof-mcp"))
    as_env = _container_env(_pick(_load_docs(_AS_MANIFEST), kind="Deployment", name="proof-as"))
    assert mcp_env["COGNIC_PROOF_HOST"] == "0.0.0.0"
    assert as_env["COGNIC_PROOF_AS_HOST"] == "0.0.0.0"
    assert as_env["COGNIC_PROOF_AS_PORT"] == "9000"
