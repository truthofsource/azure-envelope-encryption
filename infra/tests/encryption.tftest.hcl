mock_provider "azurerm" {}
variables {
  subscription_id     = "00000000-0000-0000-0000-000000000001"
  tenant_id           = "00000000-0000-0000-0000-000000000002"
  resource_group_name = "rg-example-encryption"
  vault_name          = "kv-example-records"
}
run "private_rbac_vault_without_key_or_runtime_grant" {
  command = plan
  assert {
    condition     = azurerm_key_vault.records.rbac_authorization_enabled && azurerm_key_vault.records.purge_protection_enabled && !azurerm_key_vault.records.public_network_access_enabled
    error_message = "Retain private ingress, RBAC and recovery protection."
  }
  assert {
    condition     = length(azurerm_key_vault_key.wrapping) == 0 && length(azurerm_role_assignment.runtime_wrap_unwrap) == 0
    error_message = "Key operations and runtime grants stay opt-in."
  }
}
run "key_requires_caller_preflight" {
  command = plan
  variables { enable_wrapping_key = true }
  expect_failures = [azurerm_key_vault_key.wrapping[0]]
}
run "reviewed_key_is_wrap_only_rsa3072" {
  command = plan
  variables {
    enable_wrapping_key  = true
    key_operations_ready = true
  }
  assert {
    condition     = azurerm_key_vault_key.wrapping[0].key_size == 3072 && toset(azurerm_key_vault_key.wrapping[0].key_opts) == toset(["unwrapKey", "wrapKey"])
    error_message = "Do not expand the key's cryptographic operations."
  }
}
