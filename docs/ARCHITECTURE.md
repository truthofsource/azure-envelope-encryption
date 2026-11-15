# Encryption-wrapper architecture

**Terms used here:** A fixture is test data or a test setup used instead of real business records. A nonce is a value used once for a particular encryption key.

1. **Authorized application request** → **Trusted record and field context**.
2. **Trusted record and field context** → **Fresh 32-byte data key**.
3. **Fresh 32-byte data key** → **AES-256-GCM encryption**.
4. **Sensitive value** → **AES-256-GCM encryption**.
5. **Trusted record and field context** → **AES-256-GCM encryption (Authenticated additional data)**.
6. **Fresh 32-byte data key** → **RSA-OAEP-256 wrap**.
7. **Managed identity: exact-key permission** → **Azure Key Vault key**.
8. **Azure Key Vault key** → **RSA-OAEP-256 wrap**.
9. **AES-256-GCM encryption** → **Stored envelope**.
10. **RSA-OAEP-256 wrap** → **Stored envelope**.
11. **Stored envelope** → **Read recorded key ID and version**.
12. **Read recorded key ID and version** → **Unwrap historical data key**.
13. **Azure Key Vault key** → **Unwrap historical data key**.
14. **Unwrap historical data key** → **Authenticate ciphertext and record context**.
15. **Authenticate ciphertext and record context** → **Authorized plaintext in application memory**.

[View the illustrated project overview](diagrams/architecture.svg).

## Two keys with different jobs

Each encryption starts with a fresh random 32-byte data key, called a DEK. AES-GCM uses that key to protect the value and create a tag that detects changes. A separate RSA key, held by Key Vault in the hosted design, protects the small data key using RSA-OAEP-256. It does not encrypt the whole payroll or form record.

The application saves the encrypted value, the protected data key and the information needed to check and read them later. This includes the nonce, tag and exact Key Vault key version. It also checks the record and field identifiers, so copying an encrypted value to the wrong record or field causes the read to fail.

## Trust boundaries

- API authorization happens before encryption/decryption; possession of an employee ID is not authorization.
- The database stores the envelope, not an unwrapped data key.
- The runtime identity can wrap/unwrap at one key; key administration is separate.
- The authorized application necessarily handles plaintext in memory. Envelope encryption does not defeat a compromised authorized runtime.
- Key backups, old versions, AAD/schema versions and database rows are a recovery dependency chain.

## Public implementation boundary

The Node field/bank encryption and Key Vault adapter are extracted from actual implementation source. Portable imports and public domain labels are documented in [the source map](SOURCE-MAP.md). Source AES tests inject wrapper fixtures. The Python demo additionally uses real in-memory RSA keys, but does not emulate managed identity, Key Vault control, HSM behavior or Azure policy.
