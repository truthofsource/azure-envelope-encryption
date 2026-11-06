variable "subscription_id" { type = string }
variable "tenant_id" { type = string }
variable "resource_group_name" { type = string }
variable "vault_name" { type = string }
variable "location" {
  type    = string
  default = "eastus2"
}
variable "wrapping_key_name" {
  type    = string
  default = "record-wrapping-key"
}
variable "enable_wrapping_key" {
  type    = bool
  default = false
}
variable "key_operations_ready" {
  type        = bool
  default     = false
  description = "Operator assertion after actual DNS, route and deployment-key permissions are proved. Not an automated reachability test."
}
variable "grant_runtime_wrap_unwrap" {
  type    = bool
  default = false
}
variable "runtime_principal_id" {
  type    = string
  default = ""
}
variable "tags" {
  type    = map(string)
  default = { environment = "lab", owner = "engineering", managed_by = "terraform", purpose = "field-encryption" }
}
