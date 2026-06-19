"""In-session regressions for the operator-run AKS-smoke assets (Sprint 14B-Z1b-d-2).

These assets (Bicep + shell + static manifests) CANNOT run live in CI — no Azure creds, and
`az`/`bicep`/`shellcheck` are absent in the kernel authoring env. So the in-session proof is:
structural assertions (resource types / params present), `yaml.safe_load` parse + key checks on
the static manifests, and a `bash -n` syntax check on the smoke script. The live AKS deploy + the
`az bicep build` / `shellcheck` lint are operator-run (see the runbook).
"""

from __future__ import annotations

from pathlib import Path

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
