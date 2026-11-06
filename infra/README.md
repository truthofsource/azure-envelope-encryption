# Envelope-encryption Terraform

| Resource / file | Purpose |
| --- | --- |
| Private Standard Key Vault | RBAC authorization, no public network ingress, purge protection and 90-day soft deletion |
| Optional key used to protect the data key | RSA-3072 with wrapKey/unwrapKey only and the source rotation/expiry pattern |
| Runtime grant | Key Vault Crypto Service Encryption User scoped to one key, not vault administration |
| Tests | Private/recovery defaults, key-creation readiness check and wrap-only key attributes |

```bash
terraform -chdir=infra init -backend=false -input=false
terraform -chdir=infra fmt -check -recursive
terraform -chdir=infra validate
terraform -chdir=infra test
```

The three mock plans do not authenticate to Azure or create a vault/key. `key_operations_ready` is an operator assertion after separate private DNS/route and deployment-key permission proof; it is not an automated probe. Key creation and runtime grants remain Off by default. The public root creates no private endpoint, does not open the vault and does not deploy an API.

The actual source uses its existing vault/runtime identity and separate deployment management permission. This standalone root makes the boundaries reviewable. An operator who separately applies it needs the correct subscription/tenant, globally unique name, protected backend, cost decision, private route and key-management authority. No key bytes or client secret belongs in input/state.

`prevent_destroy` on a created key and purge protection are intentional recovery controls. Do not disable them to clear a lab. Expiry, rotation and key-version retention are distinct; see [recovery](../docs/RECOVERY.md). Standard RSA keys here are software-protected service keys, not a claim of dedicated HSM deployment.
