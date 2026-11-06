# Strengths, weaknesses and scaling tradeoffs

| Choice | Strength | Weakness / tradeoff |
| --- | --- | --- |
| Per-value AES-GCM DEK | Authenticated encryption and independent random key material | Adds nonce/tag/key metadata and strict format handling |
| RSA wrapping in Key Vault | Separates cloud key custody from database copies | Adds service permissions, latency, availability and request cost |
| Exact historical key version | Preserves deterministic key selection across rotation | Recovery needs old versions and correct metadata |
| AAD record/domain binding | Detects copying valid ciphertext to the wrong context | Changing identifiers/namespaces requires compatibility planning |
| Application-level field encryption | Adds a boundary beyond SQL/storage at-rest encryption | Authorized application memory still contains plaintext; some queries/searches need redesign |
| Buffer cleanup | Reduces lifetime of owned sensitive buffers | Does not guarantee managed-runtime memory erasure |

Measure record volume, wrap/unwrap latency, throttling, payload size and failure rate before increasing concurrency. Bound queues/retries and use idempotent business writes; a timeout is not permission to save plaintext. Protect backups and logs as volume grows.

Key caching and DEK reuse can reduce provider calls but change blast radius and revocation behavior. They are not implemented as shortcuts in this reference. Separate payroll/onboarding/form AAD domains and key scopes according to real data/access requirements, not merely to simplify a diagram.

Private routing, premium/HSM features and additional diagnostics have cost and integration tradeoffs. This root uses a Standard software-key vault and does not claim HSM validation, FIPS certification or universal compliance.
