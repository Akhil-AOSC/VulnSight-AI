// Azure reference deployment: API (Container App) + isolated scan jobs (Container Apps Job) with
// network-enforced egress control.
//
// Compiles with the Bicep CLI. NOT yet validated by Azure (run what-if) and NOT yet deployed.
// See docs/OPERATIONS.md and docs/STATUS.md.
//
//   scan jobs (subnet 'scan', NSG: deny all outbound except the proxy, our private endpoints, DNS, platform)
//        |  HTTPS_PROXY
//        v
//   egress proxy (subnet 'proxy'): CONNECT-only, hostname allowlist, port 443, refuses private addresses
//        |
//        v   internet (only allowlisted hosts)
//
// COST WARNING: Azure Container Registry Premium (needed for its private endpoint) and three Container
// Apps environments are not free. Review the what-if output and the pricing calculator first.
param location string = resourceGroup().location
param prefix string = 'vulnsight'
@description('Image of the API, e.g. <registry>.azurecr.io/vulnsight-api:1')
param apiImage string
@description('Image of the scan worker, e.g. <registry>.azurecr.io/vulnsight-worker:1')
param workerImage string
@secure()
param masterKey string
@description('Extra hostnames the egress proxy may reach, comma separated (the defaults cover git hosts, OSV, Semgrep, Trivy databases).')
param extraEgressHosts string = ''

var suffix = uniqueString(resourceGroup().id)
var resultsContainer = 'scan-results'
var proxyPort = 3128

// Address plan.
var vnetCidr = '10.40.0.0/16'
var scanSubnetCidr = '10.40.0.0/23'
var proxySubnetCidr = '10.40.2.0/23'
var endpointSubnetCidr = '10.40.4.0/24'

// Built-in role definition ids (Microsoft documentation).
var roleAcrPull = '7f951dda-4ed3-4680-a7ca-43fe172d538d'
var roleKeyVaultSecretsUser = '4633458b-17de-408a-b874-0445c86b69e6'
var roleBlobDataContributor = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
var roleJobsOperator = 'b9a307c4-5aa3-4b52-ba60-2b17c136cd7b' // Container Apps Jobs Operator: read, start, stop jobs

resource logs 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: '${prefix}-logs-${suffix}'
  location: location
  properties: { sku: { name: 'PerGB2018' }, retentionInDays: 90 }
}

resource insights 'Microsoft.Insights/components@2020-02-02' = {
  name: '${prefix}-ai-${suffix}'
  location: location
  kind: 'web'
  properties: { Application_Type: 'web', WorkspaceResourceId: logs.id }
}

// Premium: required for a private endpoint, which is how the isolated scan subnet pulls its image.
resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: '${prefix}acr${suffix}'
  location: location
  sku: { name: 'Premium' }
  properties: { adminUserEnabled: false }
}

// ---- identities: separate, each with only what it needs ----
resource apiIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${prefix}-api-id'
  location: location
}

resource jobIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${prefix}-job-id'
  location: location
}

resource proxyIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${prefix}-proxy-id'
  location: location
}

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: '${prefix}-kv-${suffix}'
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    enablePurgeProtection: true
  }
}

resource masterKeySecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: vault
  name: 'master-key'
  properties: { value: masterKey }
}

resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: '${prefix}st${suffix}'
  location: location
  sku: { name: 'Standard_GRS' }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false // identities only: no account keys or SAS
    supportsHttpsTrafficOnly: true
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {
  parent: storage
  name: 'default'
}

resource results 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: blobService
  name: resultsContainer
  properties: { publicAccess: 'None' }
}

// Results are read and deleted by the API straight away; this removes any that were orphaned.
resource lifecycle 'Microsoft.Storage/storageAccounts/managementPolicies@2023-01-01' = {
  parent: storage
  name: 'default'
  properties: {
    policy: {
      rules: [ {
        name: 'delete-old-scan-results'
        enabled: true
        type: 'Lifecycle'
        definition: {
          filters: { blobTypes: [ 'blockBlob' ], prefixMatch: [ '${resultsContainer}/' ] }
          actions: { baseBlob: { delete: { daysAfterModificationGreaterThan: 1 } } }
        }
      } ]
    }
  }
}

// ---- network ----
// Scan subnet: outbound is denied by default. The only exceptions are the egress proxy, the private
// endpoints of OUR storage account and registry, Azure DNS, and the platform services Container Apps
// needs to run. Everything else (including cloud metadata and other Azure customers' storage) is
// unreachable, whether or not a scanner honours the proxy settings.
resource scanNsg 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: '${prefix}-scan-nsg'
  location: location
  properties: {
    securityRules: [
      { name: 'allow-egress-proxy', properties: { priority: 100, direction: 'Outbound', access: 'Allow', protocol: 'Tcp', sourceAddressPrefix: '*', sourcePortRange: '*', destinationAddressPrefix: proxySubnetCidr, destinationPortRange: string(proxyPort) } }
      { name: 'allow-private-endpoints', properties: { priority: 110, direction: 'Outbound', access: 'Allow', protocol: 'Tcp', sourceAddressPrefix: '*', sourcePortRange: '*', destinationAddressPrefix: endpointSubnetCidr, destinationPortRange: '443' } }
      { name: 'allow-azure-dns', properties: { priority: 120, direction: 'Outbound', access: 'Allow', protocol: '*', sourceAddressPrefix: '*', sourcePortRange: '*', destinationAddressPrefix: '168.63.129.16/32', destinationPortRange: '53' } }
      { name: 'allow-aca-platform-mcr', properties: { priority: 130, direction: 'Outbound', access: 'Allow', protocol: 'Tcp', sourceAddressPrefix: '*', sourcePortRange: '*', destinationAddressPrefix: 'MicrosoftContainerRegistry', destinationPortRange: '443' } }
      { name: 'allow-aca-platform-frontdoor', properties: { priority: 140, direction: 'Outbound', access: 'Allow', protocol: 'Tcp', sourceAddressPrefix: '*', sourcePortRange: '*', destinationAddressPrefix: 'AzureFrontDoor.FirstParty', destinationPortRange: '443' } }
      { name: 'deny-all-outbound', properties: { priority: 4000, direction: 'Outbound', access: 'Deny', protocol: '*', sourceAddressPrefix: '*', sourcePortRange: '*', destinationAddressPrefix: '*', destinationPortRange: '*' } }
    ]
  }
}

// Proxy subnet: only the scan subnet may talk to the proxy.
resource proxyNsg 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: '${prefix}-proxy-nsg'
  location: location
  properties: {
    securityRules: [
      { name: 'allow-scan-subnet', properties: { priority: 100, direction: 'Inbound', access: 'Allow', protocol: 'Tcp', sourceAddressPrefix: scanSubnetCidr, sourcePortRange: '*', destinationAddressPrefix: '*', destinationPortRange: string(proxyPort) } }
      { name: 'deny-other-inbound', properties: { priority: 4000, direction: 'Inbound', access: 'Deny', protocol: '*', sourceAddressPrefix: '*', sourcePortRange: '*', destinationAddressPrefix: '*', destinationPortRange: '*' } }
    ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2023-09-01' = {
  name: '${prefix}-vnet'
  location: location
  properties: {
    addressSpace: { addressPrefixes: [ vnetCidr ] }
    subnets: [
      { name: 'scan', properties: { addressPrefix: scanSubnetCidr, networkSecurityGroup: { id: scanNsg.id }, delegations: [ { name: 'aca', properties: { serviceName: 'Microsoft.App/environments' } } ] } }
      { name: 'proxy', properties: { addressPrefix: proxySubnetCidr, networkSecurityGroup: { id: proxyNsg.id }, delegations: [ { name: 'aca', properties: { serviceName: 'Microsoft.App/environments' } } ] } }
      { name: 'endpoints', properties: { addressPrefix: endpointSubnetCidr, privateEndpointNetworkPolicies: 'Disabled' } }
    ]
  }
}

resource scanSubnet 'Microsoft.Network/virtualNetworks/subnets@2023-09-01' existing = { parent: vnet, name: 'scan' }
resource proxySubnet 'Microsoft.Network/virtualNetworks/subnets@2023-09-01' existing = { parent: vnet, name: 'proxy' }
resource endpointSubnet 'Microsoft.Network/virtualNetworks/subnets@2023-09-01' existing = { parent: vnet, name: 'endpoints' }

// Private endpoints so the scan subnet reaches only OUR storage account and registry.
resource blobZone 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink.blob.${environment().suffixes.storage}'
  location: 'global'
}
resource acrZone 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink.azurecr.io'
  location: 'global'
}
resource blobZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: blobZone
  name: 'vnet'
  location: 'global'
  properties: { registrationEnabled: false, virtualNetwork: { id: vnet.id } }
}
resource acrZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: acrZone
  name: 'vnet'
  location: 'global'
  properties: { registrationEnabled: false, virtualNetwork: { id: vnet.id } }
}

resource storagePe 'Microsoft.Network/privateEndpoints@2023-09-01' = {
  name: '${prefix}-storage-pe'
  location: location
  properties: {
    subnet: { id: endpointSubnet.id }
    privateLinkServiceConnections: [ { name: 'blob', properties: { privateLinkServiceId: storage.id, groupIds: [ 'blob' ] } } ]
  }
}
resource storagePeDns 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-09-01' = {
  parent: storagePe
  name: 'default'
  properties: { privateDnsZoneConfigs: [ { name: 'blob', properties: { privateDnsZoneId: blobZone.id } } ] }
}

resource acrPe 'Microsoft.Network/privateEndpoints@2023-09-01' = {
  name: '${prefix}-acr-pe'
  location: location
  properties: {
    subnet: { id: endpointSubnet.id }
    privateLinkServiceConnections: [ { name: 'registry', properties: { privateLinkServiceId: registry.id, groupIds: [ 'registry' ] } } ]
  }
}
resource acrPeDns 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-09-01' = {
  parent: acrPe
  name: 'default'
  properties: { privateDnsZoneConfigs: [ { name: 'registry', properties: { privateDnsZoneId: acrZone.id } } ] }
}

// ---- environments ----
resource apiEnv 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${prefix}-env-${suffix}'
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: { customerId: logs.properties.customerId, sharedKey: logs.listKeys().primarySharedKey }
    }
  }
}

resource proxyEnv 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${prefix}-proxy-env-${suffix}'
  location: location
  properties: {
    vnetConfiguration: { infrastructureSubnetId: proxySubnet.id, internal: true }
    workloadProfiles: [ { name: 'Consumption', workloadProfileType: 'Consumption' } ]
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: { customerId: logs.properties.customerId, sharedKey: logs.listKeys().primarySharedKey }
    }
  }
}

resource scanEnv 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${prefix}-scan-env-${suffix}'
  location: location
  properties: {
    vnetConfiguration: { infrastructureSubnetId: scanSubnet.id, internal: true }
    workloadProfiles: [ { name: 'Consumption', workloadProfileType: 'Consumption' } ]
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: { customerId: logs.properties.customerId, sharedKey: logs.listKeys().primarySharedKey }
    }
  }
}

var apiFqdn = '${prefix}-api.${apiEnv.properties.defaultDomain}'
var proxyUrl = 'http://${proxyEnv.properties.staticIp}:${proxyPort}'

// ---- egress proxy: the only way out of the scan subnet ----
resource proxyAcrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: registry
  name: guid(registry.id, proxyIdentity.id, roleAcrPull)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleAcrPull)
    principalId: proxyIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource egressProxy 'Microsoft.App/containerApps@2024-03-01' = {
  name: '${prefix}-egress-proxy'
  location: location
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${proxyIdentity.id}': {} } }
  properties: {
    managedEnvironmentId: proxyEnv.id
    workloadProfileName: 'Consumption'
    configuration: {
      // Internal TCP ingress: reachable only from inside the VNet, and the NSG narrows that to the scan subnet.
      ingress: { external: false, transport: 'tcp', targetPort: proxyPort, exposedPort: proxyPort }
      registries: [ { server: registry.properties.loginServer, identity: proxyIdentity.id } ]
    }
    template: {
      containers: [ {
        name: 'proxy'
        image: apiImage
        command: [ 'node', 'src/platform/egress-proxy.js' ]
        resources: { cpu: json('0.25'), memory: '0.5Gi' }
        env: [
          { name: 'PORT', value: string(proxyPort) }
          // Scan jobs need the API to redeem their one-time credential grant.
          { name: 'VULNSIGHT_EGRESS_ALLOW', value: empty(extraEgressHosts) ? apiFqdn : '${apiFqdn},${extraEgressHosts}' }
        ]
      } ]
      scale: { minReplicas: 1, maxReplicas: 2 }
    }
  }
  dependsOn: [ proxyAcrPull ]
}

// ---- scan job: one short-lived container per scan ----
resource scanJob 'Microsoft.App/jobs@2024-03-01' = {
  name: '${prefix}-scan'
  location: location
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${jobIdentity.id}': {} } }
  properties: {
    environmentId: scanEnv.id
    workloadProfileName: 'Consumption'
    configuration: {
      triggerType: 'Manual'
      replicaTimeout: 900
      replicaRetryLimit: 0
      manualTriggerConfig: { parallelism: 1, replicaCompletionCount: 1 }
      registries: [ { server: registry.properties.loginServer, identity: jobIdentity.id } ]
    }
    template: {
      containers: [ {
        name: 'scanner'
        image: workerImage
        resources: { cpu: json('1'), memory: '2Gi' }
        // The API supplies the per-scan settings (including the proxy) when it starts an execution.
        env: [ { name: 'AZURE_CLIENT_ID', value: jobIdentity.properties.clientId } ]
      } ]
    }
  }
  dependsOn: [ jobAcrPull, acrPeDns, storagePeDns ]
}

resource jobAcrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: registry
  name: guid(registry.id, jobIdentity.id, roleAcrPull)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleAcrPull)
    principalId: jobIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource jobBlobWrite 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: storage
  name: guid(storage.id, jobIdentity.id, roleBlobDataContributor)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleBlobDataContributor)
    principalId: jobIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// ---- API ----
resource apiAcrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: registry
  name: guid(registry.id, apiIdentity.id, roleAcrPull)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleAcrPull)
    principalId: apiIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource apiKeyVault 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: vault
  name: guid(vault.id, apiIdentity.id, roleKeyVaultSecretsUser)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleKeyVaultSecretsUser)
    principalId: apiIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// The API reads (and deletes) scan results.
resource apiBlob 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: storage
  name: guid(storage.id, apiIdentity.id, roleBlobDataContributor)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleBlobDataContributor)
    principalId: apiIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Least privilege: the built-in "Container Apps Jobs Operator" role (read, start, stop jobs), scoped to
// the one scan job. It cannot create, modify or delete jobs or any other resource.
resource apiStartJobs 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: scanJob
  name: guid(scanJob.id, apiIdentity.id, roleJobsOperator)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleJobsOperator)
    principalId: apiIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource api 'Microsoft.App/containerApps@2024-03-01' = {
  name: '${prefix}-api'
  location: location
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${apiIdentity.id}': {} } }
  properties: {
    managedEnvironmentId: apiEnv.id
    configuration: {
      ingress: { external: true, targetPort: 4400, transport: 'auto', allowInsecure: false }
      registries: [ { server: registry.properties.loginServer, identity: apiIdentity.id } ]
      secrets: [ { name: 'master-key', keyVaultUrl: masterKeySecret.properties.secretUri, identity: apiIdentity.id } ]
    }
    template: {
      containers: [ {
        name: 'api'
        image: apiImage
        resources: { cpu: json('0.5'), memory: '1Gi' }
        env: [
          { name: 'NODE_ENV', value: 'production' }
          { name: 'VULNSIGHT_MASTER_KEY', secretRef: 'master-key' }
          { name: 'VULNSIGHT_TRUST_PROXY', value: '1' }
          { name: 'VULNSIGHT_HSTS', value: '1' }
          { name: 'VULNSIGHT_SANDBOX', value: 'aca' }
          { name: 'VULNSIGHT_PUBLIC_URL', value: 'https://${apiFqdn}' }
          { name: 'VULNSIGHT_ACA_SUBSCRIPTION', value: subscription().subscriptionId }
          { name: 'VULNSIGHT_ACA_RESOURCE_GROUP', value: resourceGroup().name }
          { name: 'VULNSIGHT_ACA_JOB', value: scanJob.name }
          { name: 'VULNSIGHT_ACA_IMAGE', value: workerImage }
          { name: 'VULNSIGHT_ACA_STORAGE_ACCOUNT', value: storage.name }
          { name: 'VULNSIGHT_ACA_CONTAINER', value: resultsContainer }
          { name: 'VULNSIGHT_ACA_JOB_CLIENT_ID', value: jobIdentity.properties.clientId }
          { name: 'VULNSIGHT_ACA_API_CLIENT_ID', value: apiIdentity.properties.clientId }
          { name: 'VULNSIGHT_ACA_PROXY_URL', value: proxyUrl }
          { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: insights.properties.ConnectionString }
        ]
      } ]
      // The embedded database must not be scaled out: one replica until the PostgreSQL migration.
      scale: { minReplicas: 1, maxReplicas: 1 }
    }
  }
  dependsOn: [ apiKeyVault, apiAcrPull, apiBlob, apiStartJobs ]
}

output apiUrl string = 'https://${apiFqdn}'
output scanJobName string = scanJob.name
output proxyUrl string = proxyUrl
