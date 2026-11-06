# Step-by-step envelope encryption

**Terms used here:** A nonce is a value used once for a particular encryption key.

## 1. Authorize and resolve context

The application resolves the sensitive field and its trusted record identifiers. The wrapper is cryptography, not an access-control API. Do not accept arbitrary caller-supplied metadata as permission to decrypt.

## 2. Encrypt locally

Generate a fresh AES-256 key and 12-byte nonce. Supply the domain/record/field as authenticated additional data (AAD), then use AES-GCM to produce encrypted value and a 16-byte tag.

## 3. Wrap the DEK

The hosted adapter calls `wrapKey` using RSA-OAEP-256. The returned key identifier must match the configured key and contain a version. The Key Vault key is a cryptographic key, not an application secret holding a reusable AES password.

## 4. Persist the complete envelope

Store all fields in [the envelope schema](STORED-ENVELOPE.md). Do not omit the key version or assume the current configuration is enough to recover old rows.

## 5. Decrypt the recorded version

Resolve the exact configured key/version, unwrap the DEK and authenticate the same AAD. Return a value only after authentication and the expected payload contract succeed. Clean up owned temporary buffers on both successful and failed paths.

```bash
npm run test:source
python -B -m unittest discover -s tests -v
python -B -m lab demo
```

The Node source tests and Python real-RSA demonstration have different scopes; the [validation guide](VALIDATION.md) keeps those distinctions explicit.
