// Example params for main.bicep. Fill smokeRunnerObjectId with the object ID of the principal that
// runs run-aks-smoke.sh (`az ad signed-in-user show --query id -o tsv`). agentosNamespace MUST equal
// the smoke's AGENTOS_NAMESPACE. Deploy: `az deployment group create -g <rg> -f main.bicep -p main.bicepparam`.
using './main.bicep'

param location = 'eastus'
param resourcePrefix = 'agentosz1bd2'
param nodeCount = 2
param nodeVmSize = 'Standard_DS2_v2'
param agentosNamespace = 'cognic-smoke'
param agentosServiceAccountName = 'rel-agentos'
param smokeRunnerObjectId = '00000000-0000-0000-0000-000000000000'
