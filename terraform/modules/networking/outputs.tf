# Outputs mirror the ARM template outputs section for parity validation

output "vnet_id" {
  description = "Resource ID of the Virtual Network"
  value       = azurerm_virtual_network.main.id
}

output "vnet_name" {
  description = "Name of the Virtual Network"
  value       = azurerm_virtual_network.main.name
}

output "app_subnet_id" {
  description = "Resource ID of the application subnet"
  value       = azurerm_subnet.app.id
}

output "data_subnet_id" {
  description = "Resource ID of the data subnet"
  value       = azurerm_subnet.data.id
}

output "aks_subnet_id" {
  description = "Resource ID of the AKS subnet"
  value       = azurerm_subnet.aks.id
}

output "private_endpoint_subnet_id" {
  description = "Resource ID of the private endpoint subnet"
  value       = azurerm_subnet.private_endpoints.id
}

output "bastion_subnet_id" {
  description = "Resource ID of the Bastion subnet"
  value       = azurerm_subnet.bastion.id
}
