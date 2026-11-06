# Sources and presentation credits

## Actual engineering source

The case study is based on application-level sensitive-field encryption in the author's Azure workforce platform. The actual Node field/bank core and Key Vault adapter are extracted with portable imports and neutral fixture/domain labels. Original deployment IDs, state, credentials and employee records are omitted. [Source map](SOURCE-MAP.md).

## Technical references

- [Microsoft Key Vault algorithms and key attributes](https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details) — RSA-OAEP-256, supported operations and expiry behavior.
- [Node.js crypto](https://nodejs.org/api/crypto.html) — AES-GCM, authentication tags and additional data.
- [Cryptography AESGCM](https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM) — local reference library.
- [AzureRM Key Vault key](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_key) — declarative key/rotation configuration.

## Presentation inspiration

- [Network Security and Traffic Analysis](https://github.com/fabrizio-mastrogiovanni/Network-Security---Traffic-Analysis) — business problem, solution, components and numbered proof.
- [Azure DevOps / AWS federation lab](https://github.com/Lia-Bing0/azure-devops-aws-federation-lab)
- [Multi-cloud IAM and NHI governance](https://github.com/JustinGallimore/multi-cloud-iam-nhi-governance)

Their source code and screenshots were not copied. This repository's code/evidence is its own work or extracted from the author's implementation.
