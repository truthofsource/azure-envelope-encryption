resource "azurerm_resource_group" "encryption" {
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}
resource "azurerm_key_vault" "records" {
  name                          = var.vault_name
  location                      = var.location
  resource_group_name           = azurerm_resource_group.encryption.name
  tenant_id                     = var.tenant_id
  sku_name                      = "standard"
  rbac_authorization_enabled    = true
  purge_protection_enabled      = true
  soft_delete_retention_days    = 90
  public_network_access_enabled = false
  network_acls {
    default_action = "Deny"
    bypass         = "None"
  }
  tags = var.tags
}
# Source pattern: RSA-3072, wrap/unwrap only, version rotation and prevent_destroy.
resource "azurerm_key_vault_key" "wrapping" {
  count        = var.enable_wrapping_key ? 1 : 0
  name         = var.wrapping_key_name
  key_vault_id = azurerm_key_vault.records.id
  key_type     = "RSA"
  key_size     = 3072
  key_opts     = ["unwrapKey", "wrapKey"]
  rotation_policy {
    automatic { time_before_expiry = "P30D" }
    expire_after         = "P180D"
    notify_before_expiry = "P30D"
  }
  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.key_operations_ready
      error_message = "Prove the private caller route/DNS and key-management identity before enabling key creation."
    }
  }
  tags = var.tags
}
resource "azurerm_role_assignment" "runtime_wrap_unwrap" {
  count                = var.grant_runtime_wrap_unwrap ? 1 : 0
  scope                = "${azurerm_key_vault.records.id}/keys/${var.wrapping_key_name}"
  principal_id         = var.runtime_principal_id
  principal_type       = "ServicePrincipal"
  role_definition_name = "Key Vault Crypto Service Encryption User"
  lifecycle {
    precondition {
      condition     = var.enable_wrapping_key && var.runtime_principal_id != ""
      error_message = "Provide an exact runtime identity and reviewed key before granting wrap/unwrap."
    }
  }
}
output "vault_id" { value = azurerm_key_vault.records.id }
output "wrapping_key_versionless_uri" { value = try(azurerm_key_vault_key.wrapping[0].versionless_id, null) }
