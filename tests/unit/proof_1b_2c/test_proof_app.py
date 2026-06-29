"""Structural pin — the proof_1b_2c fixed-actor app + the proof AgentOS image
(M3-E2c Task 7)."""

from pathlib import Path

from tests.integration.proof_1b_2c.proof_app import PROOF_TENANT, ProofActorBinder

DF = Path("infra/proof-1b-2c/Dockerfile.agentos-proof").read_text()


def test_binds_proof_1b_2c_tenant():
    actor = ProofActorBinder().bind(request=None)
    assert PROOF_TENANT == "proof-1b-2c"
    assert actor.tenant_id == "proof-1b-2c"
    assert actor.subject == "proof-1b-2c-operator"
    assert {"mcp.tool.list", "mcp.tool.invoke"} <= set(actor.scopes)
    assert actor.actor_type == "service"


def test_image_uses_expected_base_and_root_then_cognic_ordering():
    assert "ARG BASE_IMAGE=cognic-agentos:proof1b2-base" in DF
    assert "FROM ${BASE_IMAGE}" in DF
    assert DF.index("USER root") < DF.index("RUN chmod -R a+rX")
    assert DF.index("RUN chmod -R a+rX") < DF.index("USER cognic")


def test_image_bakes_released_staging_tree():
    for line in (
        "COPY proof1b2c-staging/wheel/ /tmp/wheel/",
        "COPY proof1b2c-staging/pack-attestations/ /opt/cognic/pack-attestations/",
        "COPY proof1b2c-staging/trust-roots/ /opt/cognic/trust-roots/",
        "COPY proof1b2c-staging/policies/ /opt/cognic/policies/",
        "COPY proof1b2c-staging/alembic.ini /app/alembic.ini",
    ):
        assert line in DF, f"missing staging COPY: {line}"
    # no stale 1b-2 staging/app references
    assert "proof1b-staging" not in DF
    assert "proof_1b_2/" not in DF


def test_image_installs_released_wheel_without_dependencies():
    assert "/opt/venv/bin/python -m ensurepip --upgrade" in DF
    assert "/opt/venv/bin/python -m pip install --no-deps --no-cache-dir /tmp/wheel/*.whl" in DF
    assert "rm -rf /tmp/wheel" in DF


def test_image_vendors_proof_app_and_sets_trust_env_and_cmd():
    assert "COPY proof_1b_2c/ /app/proof_1b_2c/" in DF
    assert "RUN chmod -R a+rX /opt/cognic /app/alembic.ini /app/proof_1b_2c" in DF
    assert "COGNIC_PACK_ATTESTATION_ROOT_PATH=/opt/cognic/pack-attestations" in DF
    assert "COGNIC_TRUST_ROOT_PREFIX=/opt/cognic/trust-roots" in DF
    assert "COGNIC_PLUGIN_ALLOWLIST_PATH=/opt/cognic/policies/plugin_allowlist.json" in DF
    assert "ENV PYTHONPATH=/app" in DF
    assert (
        "uvicorn proof_1b_2c.proof_app:create_proof_app --factory --host 0.0.0.0 --port 8000" in DF
    )
