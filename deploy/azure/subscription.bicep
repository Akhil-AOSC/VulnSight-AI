// Subscription-scope wrapper: creates a resource group and deploys main.bicep into it.
// Its main purpose is a no-change preview: `az deployment sub what-if` works without the resource
// group existing, so nothing has to be created to review the plan.
targetScope = 'subscription'

param location string
param resourceGroupName string = 'rg-vulnsight-scratch'
param apiImage string
param workerImage string
@secure()
param masterKey string
param extraEgressHosts string = ''

resource rg 'Microsoft.Resources/resourceGroups@2023-07-01' = {
  name: resourceGroupName
  location: location
}

module platform 'main.bicep' = {
  name: 'vulnsight-platform'
  scope: rg
  params: {
    location: location
    apiImage: apiImage
    workerImage: workerImage
    masterKey: masterKey
    extraEgressHosts: extraEgressHosts
  }
}

output apiUrl string = platform.outputs.apiUrl
