"""In-session regressions for the operator-run AKS-smoke assets (Sprint 14B-Z1b-d-2).

These assets (Bicep + shell + static manifests) CANNOT run live in CI — no Azure creds, and
`az`/`bicep`/`shellcheck` are absent in the kernel authoring env. So the in-session proof is:
structural assertions (resource types / params present), `yaml.safe_load` parse + key checks on
the static manifests, and a `bash -n` syntax check on the smoke script. The live AKS deploy + the
`az bicep build` / `shellcheck` lint are operator-run (see the runbook).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[3]
_AKS = _REPO_ROOT / "infra" / "azure" / "aks-smoke"


def test_main_bicep_declares_required_resources_and_params() -> None:
    src = (_AKS / "main.bicep").read_text()
    for resource_type in (
        "Microsoft.ContainerService/managedClusters",
        "Microsoft.ManagedIdentity/userAssignedIdentities",
        "Microsoft.KeyVault/vaults",
        "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials",
        "Microsoft.Authorization/roleAssignments",
    ):
        assert resource_type in src, f"main.bicep missing resource {resource_type}"
    for param in (
        "param location",
        "param resourcePrefix",
        "param kubernetesVersion",
        "param nodeCount",
        "param nodeVmSize",
        "param agentosNamespace",
        "param agentosServiceAccountName",
        "param smokeRunnerObjectId",
    ):
        assert param in src, f"main.bicep missing {param}"
    # OIDC + workload identity must be enabled, and the KV must be RBAC-authorized + empty.
    assert "oidcIssuerProfile" in src and "workloadIdentity" in src
    assert "enableRbacAuthorization: true" in src
    # The federated subject must be namespace+SA scoped (the live-proof binding).
    assert "system:serviceaccount:${agentosNamespace}:${agentosServiceAccountName}" in src


def _load_yaml(name: str) -> dict[str, Any]:
    return cast("dict[str, Any]", yaml.safe_load((_AKS / name).read_text()))


def test_secretstore_is_workload_identity_azurekv() -> None:
    doc = _load_yaml("secretstore.yaml")
    assert doc["kind"] == "SecretStore"
    azurekv = doc["spec"]["provider"]["azurekv"]
    assert azurekv["authType"] == "WorkloadIdentity"
    assert azurekv["serviceAccountRef"]["name"] == "rel-agentos"


def test_aux_externalsecret_is_merge_single_key() -> None:
    doc = _load_yaml("externalsecret-otel-headers.yaml")
    assert doc["kind"] == "ExternalSecret"
    assert doc["spec"]["target"]["creationPolicy"] == "Merge"
    assert doc["spec"]["target"]["name"] == "rel-agentos-secrets"
    keys = [d["secretKey"] for d in doc["spec"]["data"]]
    assert keys == ["COGNIC_OTEL_EXPORTER_HEADERS"]


def test_migrate_job_is_plain_non_hook() -> None:
    doc = _load_yaml("migrate-job.yaml")
    assert doc["kind"] == "Job"
    annotations = doc["metadata"].get("annotations") or {}
    assert not any(k.startswith("helm.sh/hook") for k in annotations), (
        "migrate Job must NOT be a Helm hook"
    )
    container = doc["spec"]["template"]["spec"]["containers"][0]
    assert "alembic upgrade head" in " ".join(container["args"])
    env = {e["name"]: e for e in container["env"]}
    assert env["COGNIC_DATABASE_URL"]["valueFrom"]["secretKeyRef"]["name"] == "rel-agentos-secrets"


def test_aks_smoke_values_is_eso_mode_migrations_off_wi_otel() -> None:
    doc = _load_yaml("aks-smoke-values.yaml")
    assert doc["secrets"]["create"] is False
    assert doc["migrations"]["enabled"] is False
    assert doc["externalSecrets"]["enabled"] is True
    assert doc["podLabels"]["azure.workload.identity/use"] == "true"
    assert doc["otel"]["exporter"]["headersSecretKey"] == "COGNIC_OTEL_EXPORTER_HEADERS"


def test_smoke_script_syntax_valid() -> None:
    assert shutil.which("bash") is not None
    result = subprocess.run(
        ["bash", "-n", str(_AKS / "run-aks-smoke.sh")], capture_output=True, text=True
    )
    assert result.returncode == 0, f"bash -n failed:\n{result.stderr}"


def test_smoke_script_pins_namespace_image_migrations_and_otlp_toggle() -> None:
    src = (_AKS / "run-aks-smoke.sh").read_text()
    assert "set -euo pipefail" in src
    assert "AGENTOS_NAMESPACE" in src
    # every AgentOS-scoped kubectl/helm is namespace-pinned.
    assert '-n "$AGENTOS_NAMESPACE"' in src
    for key in ("COGNIC_DATABASE_URL", "COGNIC_VAULT_TOKEN", "COGNIC_OTEL_EXPORTER_HEADERS"):
        assert key in src
    # migrations off at install; the migration Job is applied AFTER the gate.
    assert "migrate-job.yaml" in src
    assert "rollout restart" in src
    # the Deployment image is the operator's (NOT smoke-values' hardcoded cognic-agentos:smoke).
    assert "--set-string image.repository" in src
    assert "--set-string image.tag" in src
    assert "image.pullPolicy=Always" in src
    assert "COGNIC_IMAGE_REPOSITORY" in src
    assert "COGNIC_IMAGE_TAG" in src
    # OTLP is a first-class toggle (ENABLE_OTLP) with a 2-key fallback gate.
    assert "ENABLE_OTLP" in src
    # the Helm args use an always-non-empty array (NOT the shell-fragile empty-array `+` idiom).
    assert 'helm "${helm_args[@]}"' in src
    assert "otlp_overrides" not in src
    # the migration Job is deleted before re-apply so the smoke is rerunnable (Jobs are immutable).
    assert "delete job/agentos-migrate" in src
    # ENABLE_OTLP=0 deletes a prior aux ExternalSecret (not just skips re-apply), so a retry
    # escapes an Owner/Merge conflict instead of leaving the old reconciler active.
    assert "delete externalsecret/agentos-otel-headers" in src
    # the cluster is NOT deleted by the smoke (the Bicep owns it).
    assert "az group delete" not in src
    assert "kind delete cluster" not in src
