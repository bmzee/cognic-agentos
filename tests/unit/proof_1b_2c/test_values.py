"""Structural pin — the Helm values overlay + the non-hook migrate Job
(M3-E2c Task 9)."""

from pathlib import Path

import yaml

V = yaml.safe_load(Path("infra/proof-1b-2c/proof-1b-2c-values.yaml").read_text())
MJ = Path("infra/proof-1b-2c/migrate-job.yaml").read_text()
MJ_DOC = yaml.safe_load(MJ)
POD = MJ_DOC["spec"]["template"]["spec"]
CONTAINER = POD["containers"][0]


def test_values_prod_profile_migrations_off_proof_tag():
    assert V["image"]["repository"] == "cognic-agentos"
    assert V["image"]["tag"] == "proof1b2c"
    assert V["image"]["pullPolicy"] == "IfNotPresent"
    assert V["runtimeProfile"] == "prod"
    assert V["migrations"]["enabled"] is False
    assert V["cache"]["enabled"] is False


def test_values_backend_urls_and_database_secret():
    assert V["qdrant"]["url"] == "http://qdrant:6333"
    assert V["vault"]["addr"] == "http://vault:8200"
    assert V["embedding"] == {
        "driver": "ollama",
        "baseUrl": "http://ollama:11434",
        "model": "nomic-embed-text",
        "dimensions": 768,
    }
    assert V["langfuse"]["host"] == "http://langfuse:3000"
    assert V["litellm"]["baseUrl"] == "http://litellm:4000"
    assert V["secrets"]["databaseUrl"] == "postgresql+asyncpg://cognic:cognic@postgres:5432/cognic"


def test_values_vault_token_matches_seed_vault():
    # The chart-created Secret's vaultToken MUST equal seed-vault.sh's VAULT_TOKEN
    # (smoke-root-token == the reused backends.yaml Vault dev root) or `vault` 403s.
    assert V["secrets"]["create"] is True
    assert V["secrets"]["vaultToken"] == "smoke-root-token"
    assert "VAULT_TOKEN=smoke-root-token" in Path("infra/proof-1b-2c/seed-vault.sh").read_text()


def test_values_pod_security_context_numeric_uid():
    assert V["podSecurityContext"]["runAsUser"] == 10001
    assert V["podSecurityContext"]["fsGroup"] == 10001


def test_migrate_job_is_non_hook_with_image_slot_and_config_env():
    assert "__AGENTOS_IMAGE__" in MJ
    assert MJ_DOC["kind"] == "Job"
    assert "annotations" not in MJ_DOC["metadata"]  # NOT a helm hook (Gap 3 — runs post-install)
    assert MJ_DOC["metadata"]["name"] == "agentos-migrate"
    assert MJ_DOC["spec"]["backoffLimit"] == 1
    assert POD["restartPolicy"] == "Never"
    assert CONTAINER["envFrom"][0]["configMapRef"]["name"] == "rel-agentos-config"  # Gap 6
    assert CONTAINER["env"][0]["valueFrom"]["secretKeyRef"] == {
        "name": "rel-agentos-secrets",
        "key": "COGNIC_DATABASE_URL",
    }


def test_migrate_job_security_context_and_alembic_command():
    assert POD["securityContext"] == {"runAsNonRoot": True, "runAsUser": 10001}
    assert CONTAINER["securityContext"] == {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "capabilities": {"drop": ["ALL"]},
        "seccompProfile": {"type": "RuntimeDefault"},
    }
    assert CONTAINER["command"] == ["sh", "-c"]
    assert "COGNIC_DATABASE_URL is unset" in CONTAINER["args"][0]
    assert "exec alembic upgrade head" in CONTAINER["args"][0]
    assert CONTAINER["volumeMounts"] == [{"name": "tmp", "mountPath": "/tmp"}]
    assert POD["volumes"] == [{"name": "tmp", "emptyDir": {}}]
