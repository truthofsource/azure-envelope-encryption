# What is stored with an encrypted value

| Field | Purpose | Sensitive? |
| --- | --- | --- |
| Ciphertext | Encrypted payload | Treat as protected record material |
| Nonce | Per-encryption AES-GCM input; 12 bytes | Not a password; preserve exactly |
| Authentication tag | Detects wrong key/context or modified data; 16 bytes | Preserve exactly |
| Wrapped DEK | Data key protected by RSA-OAEP-256 | Not the plaintext AES key; protect and retain |
| Key ID | Expected vault/key identity | Metadata, not a secret value; keep real IDs out of public evidence |
| Key version | Exact version needed for historical unwrap | Required for recovery |
| Domain and record identifiers | Reconstructed AAD context | Not necessarily stored in the same column; must remain stable |

The source field wrapper also returns a last-four display hint. That is intentionally separate from the encrypted value and needs its own disclosure/access policy. The local demo uses fictional values and does not imply that ciphertext hides every metadata field.

Binary values may be encoded as base64 in a JSON envelope. Base64 is encoding, not encryption. Do not replace encryption with base64 or hash a sensitive field and call it reversible protection.

The public Python format and neutral source AAD labels are reference formats. They are not byte-compatible migration instructions for existing stored rows. Never rename an authenticated namespace on live data without a deliberate compatible read/migration plan.
