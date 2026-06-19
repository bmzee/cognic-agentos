// infra/azure/aks-smoke/main.bicep
// Sprint 14B-Z1b-d-2 — minimal REFERENCE IaC for the env-gated AKS live-cloud smoke.
// Operator/CI-run (az/bicep are absent in the kernel authoring env). Validate: `az bicep build --file main.bicep`.
// Provisions ONLY the cloud-managed surfaces the smoke needs: AKS (OIDC + workload identity), a UAMI,
// an EMPTY Key Vault, the federated credential (chart SA -> UAMI), and the KV read/write role assignments.
// Production hardening (private cluster, VNet, Log Analytics, policy) is bank-overlay — see the runbook.

@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('Short prefix for resource names.')
param resourcePrefix string = 'agentosz1bd2'

@description('Optional AKS Kubernetes version; empty string uses the AKS default.')
param kubernetesVersion string = ''

@description('AKS system node pool node count.')
@minValue(1)
param nodeCount int = 2

@description('AKS system node pool VM size.')
param nodeVmSize string = 'Standard_DS2_v2'

@description('Kubernetes namespace the AgentOS chart installs into (MUST equal the smoke AGENTOS_NAMESPACE).')
param agentosNamespace string = 'cognic-smoke'

@description('The chart ServiceAccount name (release name x chart name; default rel-agentos).')
param agentosServiceAccountName string = 'rel-agentos'

@description('Object ID of the principal that runs the smoke (granted Key Vault write to seed secrets).')
param smokeRunnerObjectId string

var suffix = uniqueString(resourceGroup().id)
var clusterName = '${resourcePrefix}-aks-${suffix}'
var uamiName = '${resourcePrefix}-uami-${suffix}'
var keyVaultName = take('${resourcePrefix}kv${suffix}', 24)
// Built-in role definition IDs (stable across Azure): Key Vault Secrets User (read) + Secrets Officer (write).
var kvSecretsUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6'
var kvSecretsOfficerRoleId = 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'

resource aks 'Microsoft.ContainerService/managedClusters@2024-09-01' = {
  name: clusterName
  location: location
  identity: { type: 'SystemAssigned' }
  properties: union({
    dnsPrefix: '${resourcePrefix}-${suffix}'
    enableRBAC: true
    oidcIssuerProfile: { enabled: true }
    securityProfile: { workloadIdentity: { enabled: true } }
    agentPoolProfiles: [
      {
        name: 'system'
        mode: 'System'
        count: nodeCount
        vmSize: nodeVmSize
        osType: 'Linux'
      }
    ]
  }, empty(kubernetesVersion) ? {} : { kubernetesVersion: kubernetesVersion })
}

resource uami 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: uamiName
  location: location
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    // EMPTY — the smoke seeds the 3 secrets via `az keyvault secret set`.
  }
}

resource fedCred 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2023-01-31' = {
  parent: uami
  name: 'agentos-chart-sa'
  properties: {
    issuer: aks.properties.oidcIssuerProfile.issuerURL
    subject: 'system:serviceaccount:${agentosNamespace}:${agentosServiceAccountName}'
    audiences: [ 'api://AzureADTokenExchange' ]
  }
}

resource uamiKvRead 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, uami.id, kvSecretsUserRoleId)
  scope: keyVault
  properties: {
    principalId: uami.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', kvSecretsUserRoleId)
  }
}

resource runnerKvWrite 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, smokeRunnerObjectId, kvSecretsOfficerRoleId)
  scope: keyVault
  properties: {
    principalId: smokeRunnerObjectId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', kvSecretsOfficerRoleId)
  }
}

output clusterName string = aks.name
output resourceGroupName string = resourceGroup().name
output keyVaultName string = keyVault.name
output uamiClientId string = uami.properties.clientId
output oidcIssuerUrl string = aks.properties.oidcIssuerProfile.issuerURL
