# Security boundary

The public project combines actual cryptographic source with a fictional local exercise. Established Node/cryptography library primitives are used; no new cipher is invented.

- Encryption is not authorization. The hosted API must authenticate and enforce record/role access before a sensitive read/write.
- Store only encrypted value plus required envelope metadata; keep plaintext DEKs and real sensitive records out of logs/Git.
- The runtime needs one key's wrap/unwrap permission, not key deletion/administration.
- Preserve authenticated context and historical key versions. Do not edit metadata to bypass a failed decrypt.
- The local keyring is temporary process memory, not an Azure credential, HSM or durable backup.
- Do not expose the loopback workbench as a public service; it uses test-only records and has no production authentication.
- Public AAD namespaces/formats are reference adaptations and not compatible migration instructions for existing stored data.

Envelope encryption helps protect database copies and detects authenticated-data changes. It does not protect plaintext already returned to an authorized caller, defeat a compromised authorized runtime, or replace TLS, storage encryption, monitoring and access review.

Report defects with fictional data only. Never attach keys, real payroll/onboarding values, tokens, protected backups or live envelope dumps.
