# =============================================================================
# Compute Module — Converted from ARM Template
# Source: arm-templates/compute/azuredeploy.json
#
# ARM resources converted:
#   1. Microsoft.ManagedIdentity/userAssignedIdentities  -> azurerm_user_assigned_identity
#   2. Microsoft.ContainerRegistry/registries            -> azurerm_container_registry
#   3. Microsoft.ContainerService/managedClusters        -> azurerm_kubernetes_cluster
#   4. (implicit role assignment via ARM dependsOn)       -> azurerm_role_assignment
#
# Key ARM-to-Terraform conversion differences:
#   - ARM [concat()] and [format()] replaced with Terraform string interpolation
#   - ARM [resourceGroup().location] replaced with var.location
#   - ARM [parameters()] replaced with Terraform variables
#   - ARM [reference()] replaced with Terraform resource attribute references
#   - ARM [resourceId()] replaced with Terraform resource .id attributes
#   - ARM dependsOn replaced with implicit Terraform dependency graph
#   - ARM nested properties (e.g. properties.agentPoolProfiles) become nested
#     Terraform blocks (e.g. default_node_pool {})
#   - ARM apiVersion pinning is unnecessary; the azurerm provider handles API
#     version selection internally
#   - ARM copy loops for node pools become separate Terraform resource blocks
#     or dynamic blocks; here we use separate default_node_pool + user pool
#   - ARM identity.type "UserAssigned" with userAssignedIdentities map becomes
#     Terraform identity { type = "UserAssigned", identity_ids = [...] }
#   - ARM nested addonProfiles map becomes separate Terraform addon blocks
#     (oms_agent, azure_policy, key_vault_secrets_provider, etc.)
#   - ARM Microsoft.Authorization/roleAssignments nested/child resource becomes
#     a standalone azurerm_role_assignment resource in Terraform
# =============================================================================

# -----------------------------------------------------------------------------
# User-Assigned Managed Identity
# ARM: Microsoft.ManagedIdentity/userAssignedIdentities
#
# Conversion notes:
#   - ARM defines this as a standalone resource with just location and tags.
#   - Terraform equivalent is identical in simplicity.
#   - The identity is referenced by AKS via identity_ids and by the role
#     assignment for ACR pull access.
# -----------------------------------------------------------------------------
resource "azurerm_user_assigned_identity" "aks" {
  name                = "id-aks-${var.environment}"
  location            = var.location
  resource_group_name = var.resource_group_name

  tags = var.tags
}

# -----------------------------------------------------------------------------
# Azure Container Registry (ACR)
# ARM: Microsoft.ContainerRegistry/registries
#
# Conversion notes:
#   - ARM sku.name "Premium" -> Terraform sku = "Premium"
#   - ARM properties.adminUserEnabled -> Terraform admin_enabled
#   - ARM properties.publicNetworkAccess "Disabled" -> Terraform
#     public_network_access_enabled = false
#   - ARM properties.encryption with keyVaultProperties -> Terraform
#     encryption block (only available on Premium SKU)
#   - ARM properties.policies.retentionPolicy -> Terraform retention_policy block
#   - ARM properties.policies.trustPolicy -> Terraform trust_policy block
#   - ARM properties.networkRuleBypassOptions "AzureServices" -> Terraform
#     network_rule_bypass_option = "AzureServices"
#   - ARM properties.dataEndpointEnabled and properties.zoneRedundancy are
#     Premium-only features mapped to direct Terraform arguments
# -----------------------------------------------------------------------------
resource "azurerm_container_registry" "main" {
  name                = var.acr_name
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "Premium"

  # ARM: properties.adminUserEnabled = false
  admin_enabled = false

  # ARM: properties.publicNetworkAccess = "Disabled"
  public_network_access_enabled = false

  # ARM: properties.networkRuleBypassOptions = "AzureServices"
  # Allows trusted Azure services to access ACR even with public access disabled
  network_rule_bypass_option = "AzureServices"

  # ARM: properties.zoneRedundancy = "Enabled"
  zone_redundancy_enabled = true

  # ARM: properties.dataEndpointEnabled = true
  # Enables dedicated data endpoints for reduced latency in geo-replicated setups
  data_endpoint_enabled = true

  # ARM: properties.encryption
  # Note: In ARM, encryption is defined under properties.encryption with
  # keyVaultProperties.keyIdentifier and identity. In Terraform, the encryption
  # block mirrors this but references the user-assigned identity directly.
  encryption {
    key_vault_key_id   = var.acr_encryption_key_id
    identity_client_id = azurerm_user_assigned_identity.aks.client_id
  }

  # ARM: properties.policies.retentionPolicy
  # Retention policy for untagged manifests (Premium SKU only)
  retention_policy_in_days = var.acr_retention_days
  retention_policy_enabled = true

  # ARM: properties.policies.trustPolicy
  # Docker Content Trust for image signing verification (Premium SKU only)
  trust_policy_enabled = true

  # ARM: identity block with UserAssigned type
  # Required for CMK encryption — the identity must have Key Vault access
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.aks.id]
  }

  tags = var.tags
}

# -----------------------------------------------------------------------------
# Azure Kubernetes Service (AKS)
# ARM: Microsoft.ContainerService/managedClusters
#
# Conversion notes:
#   - ARM uses a single monolithic resource with deeply nested properties.
#     Terraform splits concerns into the main resource + separate blocks.
#   - ARM identity.type "UserAssigned" + userAssignedIdentities map ->
#     Terraform identity { type = "UserAssigned", identity_ids = [...] }
#   - ARM sku.name "Base" + sku.tier "Standard" -> Terraform sku_tier = "Standard"
#   - ARM properties.aadProfile with managed=true and enableAzureRBAC=true ->
#     Terraform azure_active_directory_role_based_access_control block
#   - ARM properties.networkProfile -> Terraform network_profile block
#     - ARM networkPlugin "azure" -> network_plugin = "azure"
#     - ARM networkPolicy "calico" -> network_policy = "calico"
#     - ARM serviceCidr/dnsServiceIP -> service_cidr/dns_service_ip
#   - ARM properties.apiServerAccessProfile.enablePrivateCluster ->
#     Terraform private_cluster_enabled = true
#   - ARM properties.agentPoolProfiles[0] (system pool) ->
#     Terraform default_node_pool block
#   - ARM properties.agentPoolProfiles[1] (user pool) ->
#     Separate azurerm_kubernetes_cluster_node_pool resource
#     Note: ARM allows multiple pools in one array; Terraform requires the
#     default pool inline and additional pools as separate resources.
#   - ARM properties.addonProfiles map -> Terraform individual addon blocks:
#     - omsagent -> oms_agent {}
#     - azurepolicy -> azure_policy_enabled = true
#     - azureKeyvaultSecretsProvider -> key_vault_secrets_provider {}
#   - ARM properties.securityProfile.workloadIdentity ->
#     Terraform workload_identity_enabled = true
#   - ARM properties.securityProfile.defender ->
#     Terraform microsoft_defender { log_analytics_workspace_id = ... }
#   - ARM properties.autoUpgradeProfile.upgradeChannel ->
#     Terraform automatic_upgrade_channel = "stable"
#   - ARM properties.agentPoolProfiles[].enableEncryptionAtHost ->
#     Terraform node pool enable_host_encryption = true
#   - ARM properties.agentPoolProfiles[].availabilityZones ->
#     Terraform node pool zones = [...]
#   - ARM properties.agentPoolProfiles[].enableAutoScaling +
#     minCount/maxCount -> Terraform auto_scaling_enabled + min_count/max_count
# -----------------------------------------------------------------------------
resource "azurerm_kubernetes_cluster" "main" {
  name                = "aks-${var.environment}"
  location            = var.location
  resource_group_name = var.resource_group_name

  # ARM: properties.dnsPrefix
  dns_prefix = "aks-${var.environment}"

  # ARM: properties.kubernetesVersion
  kubernetes_version = var.kubernetes_version

  # ARM: sku.name = "Base", sku.tier = "Standard"
  # Note: ARM has both sku.name and sku.tier. In Terraform, only sku_tier is
  # needed — "Standard" enables the uptime SLA (financially backed).
  sku_tier = "Standard"

  # ARM: identity block with type "UserAssigned"
  # Conversion note: ARM uses a map of { resourceId: {} } for userAssignedIdentities.
  # Terraform uses a list of identity IDs instead.
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.aks.id]
  }

  # ARM: properties.apiServerAccessProfile.enablePrivateCluster = true
  # This disables the public FQDN for the API server; access is via private endpoint only.
  private_cluster_enabled = true

  # ARM: properties.aadProfile
  # Conversion note: ARM has a flat aadProfile with managed=true, enableAzureRBAC=true,
  # and adminGroupObjectIDs. Terraform uses a dedicated nested block. The block name
  # changed from "role_based_access_control" in older provider versions.
  azure_active_directory_role_based_access_control {
    azure_rbac_enabled     = true
    admin_group_object_ids = var.aks_admin_group_object_ids
  }

  # ARM: properties.networkProfile
  # Conversion note: ARM networkProfile is a flat properties object. Terraform
  # nests it inside a network_profile block. The load_balancer_sku defaults to
  # "standard" for new clusters (matching ARM behavior).
  network_profile {
    network_plugin = "azure"
    network_policy = "calico"

    # ARM: properties.networkProfile.serviceCidr and dnsServiceIP
    # The DNS service IP must be within the service CIDR range.
    service_cidr   = "172.16.0.0/16"
    dns_service_ip = "172.16.0.10"

    # ARM: properties.networkProfile.loadBalancerSku
    load_balancer_sku = "standard"
  }

  # ARM: properties.autoUpgradeProfile.upgradeChannel = "stable"
  # Conversion note: ARM uses autoUpgradeProfile.upgradeChannel. Terraform
  # uses automatic_upgrade_channel. "stable" applies Kubernetes patches
  # automatically after they are validated in the "patch" channel.
  automatic_upgrade_channel = "stable"

  # ---------------------------------------------------------------------------
  # Default (System) Node Pool
  # ARM: properties.agentPoolProfiles[0] where mode = "System"
  #
  # Conversion note: ARM allows multiple agentPoolProfiles in a single array.
  # Terraform requires exactly one default_node_pool block inline within the
  # azurerm_kubernetes_cluster. Additional pools must be defined as separate
  # azurerm_kubernetes_cluster_node_pool resources.
  # ---------------------------------------------------------------------------
  default_node_pool {
    name = "system"

    # ARM: vmSize
    vm_size = var.system_node_pool_vm_size

    # ARM: enableAutoScaling, minCount, maxCount, count
    # Conversion note: ARM uses enableAutoScaling (bool) alongside minCount
    # and maxCount. In Terraform, auto_scaling_enabled replaces enableAutoScaling
    # and node_count serves as the initial count.
    auto_scaling_enabled = true
    min_count            = var.system_node_pool_min_count
    max_count            = var.system_node_pool_max_count
    node_count           = var.system_node_pool_min_count

    # ARM: availabilityZones = ["1","2","3"]
    # Conversion note: ARM uses string array, Terraform uses list of strings.
    zones = ["1", "2", "3"]

    # ARM: osDiskSizeGB and osDiskType
    os_disk_size_gb = 128
    os_disk_type    = "Managed"

    # ARM: vnetSubnetID (references the AKS subnet from networking module)
    vnet_subnet_id = var.aks_subnet_id

    # ARM: enableEncryptionAtHost = true
    # Encrypts the temp disk and OS/data disk caches at the host level.
    enable_host_encryption = true

    # ARM: nodeTaints for system pool
    # System pools often taint to prevent user workloads from scheduling here.
    only_critical_addons_enabled = true

    tags = var.tags
  }

  # ---------------------------------------------------------------------------
  # Addon: OMS Agent (Container Insights)
  # ARM: properties.addonProfiles.omsagent
  #
  # Conversion note: ARM defines addons as a map under addonProfiles with
  # enabled=true and config.logAnalyticsWorkspaceResourceID. Terraform uses
  # a dedicated oms_agent block.
  # ---------------------------------------------------------------------------
  oms_agent {
    log_analytics_workspace_id = var.log_analytics_workspace_id
  }

  # ---------------------------------------------------------------------------
  # Addon: Azure Policy
  # ARM: properties.addonProfiles.azurepolicy.enabled = true
  #
  # Conversion note: ARM uses addonProfiles.azurepolicy with enabled and
  # config. Terraform simplifies this to a single boolean flag.
  # ---------------------------------------------------------------------------
  azure_policy_enabled = true

  # ---------------------------------------------------------------------------
  # Addon: Key Vault Secrets Provider (CSI Driver)
  # ARM: properties.addonProfiles.azureKeyvaultSecretsProvider
  #
  # Conversion note: ARM uses addonProfiles.azureKeyvaultSecretsProvider with
  # enabled=true and config.enableSecretRotation. Terraform uses a dedicated
  # block with secret_rotation_enabled.
  # ---------------------------------------------------------------------------
  key_vault_secrets_provider {
    secret_rotation_enabled  = true
    secret_rotation_interval = "2m"
  }

  # ---------------------------------------------------------------------------
  # Workload Identity
  # ARM: properties.securityProfile.workloadIdentity.enabled = true
  # ARM: properties.oidcIssuerProfile.enabled = true
  #
  # Conversion note: In ARM, workload identity and OIDC issuer are separate
  # properties under securityProfile and oidcIssuerProfile. Terraform uses
  # two boolean flags at the top level. OIDC issuer must be enabled for
  # workload identity to function (Terraform enforces this).
  # ---------------------------------------------------------------------------
  workload_identity_enabled = true
  oidc_issuer_enabled       = true

  # ---------------------------------------------------------------------------
  # Microsoft Defender for Containers
  # ARM: properties.securityProfile.defender
  #
  # Conversion note: ARM has securityProfile.defender with
  # logAnalyticsWorkspaceResourceId and securityMonitoring.enabled. Terraform
  # uses a microsoft_defender block with log_analytics_workspace_id.
  # ---------------------------------------------------------------------------
  microsoft_defender {
    log_analytics_workspace_id = var.log_analytics_workspace_id
  }

  tags = var.tags

  # ---------------------------------------------------------------------------
  # Lifecycle management
  # Note: No ARM equivalent. Terraform-specific configuration to prevent
  # accidental destruction and to ignore node count changes made by the
  # autoscaler outside of Terraform.
  # ---------------------------------------------------------------------------
  lifecycle {
    ignore_changes = [
      default_node_pool[0].node_count,
    ]
  }
}

# -----------------------------------------------------------------------------
# User Node Pool
# ARM: properties.agentPoolProfiles[1] where mode = "User"
#
# Conversion notes:
#   - ARM defines all node pools in a single agentPoolProfiles array.
#   - Terraform only allows one default_node_pool inline; all others must be
#     separate azurerm_kubernetes_cluster_node_pool resources.
#   - This separation is a fundamental structural difference between ARM and
#     Terraform for AKS.
#   - The depends_on is implicit via kubernetes_cluster_id reference, unlike
#     ARM which uses explicit dependsOn for ordering.
# -----------------------------------------------------------------------------
resource "azurerm_kubernetes_cluster_node_pool" "user" {
  name                  = "user"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.main.id

  # ARM: vmSize
  vm_size = var.user_node_pool_vm_size

  # ARM: enableAutoScaling, minCount, maxCount, count
  auto_scaling_enabled = true
  min_count            = var.user_node_pool_min_count
  max_count            = var.user_node_pool_max_count
  node_count           = var.user_node_pool_min_count

  # ARM: availabilityZones = ["1","2","3"]
  zones = ["1", "2", "3"]

  # ARM: mode = "User"
  mode = "User"

  # ARM: osDiskSizeGB and osDiskType
  os_disk_size_gb = 256
  os_disk_type    = "Managed"

  # ARM: vnetSubnetID
  vnet_subnet_id = var.aks_subnet_id

  # ARM: enableEncryptionAtHost = true
  enable_host_encryption = true

  tags = var.tags

  # Terraform-specific: ignore autoscaler changes to node_count
  lifecycle {
    ignore_changes = [
      node_count,
    ]
  }
}

# -----------------------------------------------------------------------------
# Role Assignment: AKS -> ACR Pull
# ARM: Microsoft.Authorization/roleAssignments (nested or standalone)
#
# Conversion notes:
#   - ARM role assignments use a GUID as the resource name and reference the
#     role definition by its full resource ID:
#     /subscriptions/{sub}/providers/Microsoft.Authorization/roleDefinitions/{guid}
#   - Terraform uses the built-in role_definition_name which resolves the
#     display name to the correct GUID automatically.
#   - ARM references the kubelet identity via
#     reference(aksId).properties.identityProfile.kubeletidentity.objectId
#   - Terraform references it via
#     azurerm_kubernetes_cluster.main.kubelet_identity[0].object_id
#   - ARM scopes the assignment to the ACR resource ID; Terraform does the same
#     via the scope attribute.
#   - The "AcrPull" role (7f951dda-4ed3-4680-a7ca-43fe172d538d) allows the
#     kubelet identity to pull images from ACR without admin credentials.
# -----------------------------------------------------------------------------
resource "azurerm_role_assignment" "aks_acr_pull" {
  scope                = azurerm_container_registry.main.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_kubernetes_cluster.main.kubelet_identity[0].object_id

  # Terraform-specific: skip_service_principal_aad_check speeds up assignments
  # for managed identities (not needed for service principals).
  skip_service_principal_aad_check = true
}
