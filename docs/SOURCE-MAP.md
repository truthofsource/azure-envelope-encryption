# Implementation source map

| Public module | Relationship to the actual platform |
| --- | --- |
| `reference/fieldEncryption.ts` | Actual AES-GCM field encrypt/decrypt core and types, separated from SDK imports |
| `reference/fieldEncryption.test.ts` | Actual source tests with portable imports and fictional fixture IDs |
| `reference/bankDetailsEncryption.ts` and test | Actual JSON/bank-details wrapper with a separate AAD domain |
| `reference/keyIdentifiers.ts` | Actual configured-key/version validation helpers, exported for public tests |
| `reference/keyVaultAdapter.ts` | Actual managed-identity CryptographyClient wrap/unwrap factory, split into a separate optional module |
| `reference/recordTypes.ts` | Type-only boundary replacing the private application contract import |
| `lab/envelope.py` | Standalone real-crypto reference with local ephemeral RSA version rotation/rewrap |
| `infra/` | Related RSA-3072, rotation, recovery protection and exact-key runtime permission pattern |

The source tests use injected key wrappers, including deliberately simple fixtures, to isolate AES behavior. Those fixtures are test doubles, not the production wrapping algorithm. The local Python reference uses actual RSA-OAEP-256 wrapping.

Public imports, fixture IDs and AAD product labels are neutral. Changing an AAD label changes authenticated bytes: this example is not a drop-in decoder or migration for real records. The hosted SQL/authorization/audit adapters and actual vault identifiers are not included. The Python format is independently versioned and does not claim wire compatibility with the Node envelope.
