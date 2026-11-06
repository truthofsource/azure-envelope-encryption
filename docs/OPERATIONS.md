# Encryption operations and troubleshooting

| Symptom | Inspect | Response |
| --- | --- | --- |
| Encryption cannot wrap a new key | Exact key URI, current key state, wrap permission and network route | Fail the write; do not store plaintext as a fallback |
| Historical decrypt fails | Stored key ID/version, retained version, runtime permission and route | Use the recorded version; do not try latest silently |
| Authentication fails | Ciphertext, nonce, tag and exact AAD context | Preserve the record and error stage; do not return partial plaintext |
| Wrong DEK length | Provider result/adapter contract | Reject it before AES processing |
| Leading zeroes disappear | Sensitive-field normalization and string handling | Keep the defined string contract; do not coerce identifiers to numbers |
| Rotation appears to affect old records | Latest-version lookup, changed metadata or different policy state | Check historical pinning and distinguish expiry from disable/delete |
| Backup restore cannot read data | Envelope/schema plus key-version/identity/network recovery chain | A database restore is only one part of acceptance |

## Observe without disclosing

Log operation type, correlation ID, safe error stage, latency and approved metadata references. Do not log plaintext, raw DEKs, unwrapped buffers or full sensitive envelopes. Retain real vault IDs privately when needed for investigation. A key-service success alone is not application authorization or record integrity proof.

Monitor wrap/unwrap failures, version distribution, key availability, permission changes and abnormal read patterns. Alert on failures that need an operator action rather than generating a plaintext-heavy debug trace.

## Memory and caching

The actual Node core clears buffers it owns in `finally`. JavaScript strings, library copies and garbage collection prevent a claim of guaranteed erasure. Python immutable bytes are not securely wiped by this reference. Do not add long-lived plaintext/DEK caches casually to reduce latency; scope, TTL, revocation and incident behavior need separate review.

## Operating commands

The [command guide](COMMANDS.md) separates local tests from optional Azure metadata reads. No production unwrap, key rotation, service start or network opening is needed to reproduce the local screenshots.
