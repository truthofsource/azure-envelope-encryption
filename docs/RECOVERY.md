# Rotation and recovery

**Terms used here:** The data key encrypts a value; the wrapping key protects that data key. DNS turns a service name into the network address used to reach it.

## Rotation creates a new version

New writes can use the current Key Vault key version. Existing envelopes retain their own key ID/version, so reads must select that historical version. Rotation does not automatically rewrite old encrypted value, rewrap every stored DEK or prove backup recovery.

The reference Terraform carries the implemented RSA-3072 wrap-only pattern with a 180-day expiry policy and rotation/notification settings 30 days before expiry. Those settings are a reference, not a fresh apply or a universal retention policy.

## Expired is not the same as disabled, deleted or purged

Azure Key Vault documents that decrypt/unwrap operations can work outside a key's expiration window. Expiration therefore must not be described as automatically making historical data unreadable. That behavior is different from key disable/delete/purge, a missing version, loss of identity permission or a blocked network path. Verify the actual policy and operation, not just a date. [Microsoft key attributes and operations](https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details).

## Recovery dependency chain

Retain the database envelope, original AAD/domain/schema context, matching wrapping-key versions, authorized identity and network/DNS path. A restored database alone does not establish recoverability. Key Vault protected backups also have service restoration constraints; validate the intended destination before relying on them.

1. Inventory the exact records and key versions without exposing plaintext.
2. Verify the protected backup and permitted restoration boundary.
3. Restore into an isolated environment with the matching metadata and keys.
4. Confirm allowed unwrap/read and wrong-context denial with approved fictional evidence.
5. Preserve failure-stage evidence, remove temporary access and restore the operating state.

No cloud key backup, restore, rotation or deletion is performed by the public demo.

## Local exercise

```bash
python -B -m lab demo
```

The in-memory keyring creates v1, creates v2 for new writes and confirms the v1 record still decrypts while v1 is retained. A local reference rewrap protects the same DEK with v2 without changing encrypted value. Removing only that temporary local v1 key shows why latest-key fallback is wrong. This does not model all Azure attribute/policy behavior.

## Before a real rewrap/migration

Require a separately reviewed, idempotent migration with exact record/version checks, transactional updates, failure accounting and recovery copies. Verify old and new reads before retiring any key version. Never replace an AAD namespace, algorithm or key reference by mass editing metadata.
