# =============================================================================
# Outputs for the Compute Module
# Source: arm-templates/compute/azuredeploy.json outputs section
#
# Conversion notes:
#   - ARM outputs use [resourceId('Microsoft.ContainerService/managedClusters', ...)]
#     Terraform uses the resource .id attribute directly.
#   - ARM outputs use [reference(resourceId(...)).properties.xxx]
#     Terraform uses direct resource attribute references.
#   - ARM outputs the kubelet identity via
#     reference(aksId).properties.identityProfile.kubeletidentity
#     Terraform uses azurerm_kubernetes_cluster.main.kubelet_identity[0]
#   - ARM outputs the ACR login server via
#     reference(acrId).properties.loginServer
#     Terraform uses azurerm_container_registry.main.login_server
# =============================================================================

output "aks_id" {
  description = "Resource ID of the AKS cluster"
  value       = azurerm_kubernetes_cluster.main.id
}

output "acr_id" {
  description = "Resource ID of the Azure Container Registry"
  value       = azurerm_container_registry.main.id
}

output "aks_identity_principal_id" {
  description = "Principal ID of the user-assigned managed identity for AKS"
  value       = azurerm_user_assigned_identity.aks.principal_id
}

output "aks_kubelet_identity" {
  description = "Kubelet identity object containing client_id, object_id, and user_assigned_identity_id"
  value = {
    client_id                 = azurerm_kubernetes_cluster.main.kubelet_identity[0].client_id
    object_id                 = azurerm_kubernetes_cluster.main.kubelet_identity[0].object_id
    user_assigned_identity_id = azurerm_kubernetes_cluster.main.kubelet_identity[0].user_assigned_identity_id
  }
}

output "acr_login_server" {
  description = "Login server URL of the Azure Container Registry"
  value       = azurerm_container_registry.main.login_server
}
