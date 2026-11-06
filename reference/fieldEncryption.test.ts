import assert from "node:assert/strict";
import test from "node:test";
import {
  createCipheriv,
  createDecipheriv,
} from "node:crypto";
import {
  buildStage2SsnAad,
  decryptStage2Ssn,
  encryptStage2Ssn,
  type Stage2SsnKeyUnwrapper,
  type Stage2SsnKeyWrapper,
  type StoredEncryptedStage2Ssn,
} from "./fieldEncryption.ts";

const packetId =
  "00000000-0000-4000-8000-000000000001";
const packetItemId =
  "00000000-0000-4000-8000-000000000002";

function decryptForTest(
  key: Buffer,
  encrypted: Awaited<
    ReturnType<
      typeof encryptStage2Ssn
    >
  >,
  aad: Buffer
) {
  const decipher =
    createDecipheriv(
      "aes-256-gcm",
      key,
      encrypted.encryptionNonce,
      {
        authTagLength: 16,
      }
    );

  decipher.setAAD(aad);
  decipher.setAuthTag(
    encrypted.authenticationTag
  );

  return Buffer.concat([
    decipher.update(
      encrypted.encryptedSsn
    ),
    decipher.final(),
  ]).toString("utf8");
}

test(
  "AES-GCM round trip preserves leading zeroes",
  async () => {
    let capturedKey =
      Buffer.alloc(0);

    const wrapper:
      Stage2SsnKeyWrapper =
      async dataKey => {
        capturedKey =
          Buffer.from(dataKey);

        return {
          wrappedDataKey:
            Buffer.from(
              dataKey
            ).reverse(),
          keyId:
            "https://example.vault.azure.net/keys/stage2-ssn-wrapping-key",
          keyVersion:
            "test-version",
        };
      };

    const encrypted =
      await encryptStage2Ssn(
        "001234567",
        packetId,
        packetItemId,
        wrapper
      );

    assert.equal(
      decryptForTest(
        capturedKey,
        encrypted,
        buildStage2SsnAad(
          packetId,
          packetItemId
        )
      ),
      "001234567"
    );
    assert.equal(
      encrypted.encryptionNonce.length,
      12
    );
    assert.equal(
      encrypted.authenticationTag.length,
      16
    );
    assert.equal(
      encrypted.ssnLastFour,
      "4567"
    );
  }
);

test(
  "AAD mismatch fails authentication",
  async () => {
    let capturedKey =
      Buffer.alloc(0);

    const encrypted =
      await encryptStage2Ssn(
        "001234567",
        packetId,
        packetItemId,
        async dataKey => {
          capturedKey =
            Buffer.from(dataKey);

          return {
            wrappedDataKey:
              Buffer.from(dataKey),
            keyId:
              "https://example.vault.azure.net/keys/stage2-ssn-wrapping-key",
            keyVersion:
              "test-version",
          };
        }
      );

    assert.throws(() =>
      decryptForTest(
        capturedKey,
        encrypted,
        buildStage2SsnAad(
          packetId,
          "00000000-0000-4000-8000-000000000003"
        )
      )
    );
  }
);

test(
  "each encryption uses a fresh nonce and DEK",
  async () => {
    const keys:
      Buffer[] = [];

    const wrapper:
      Stage2SsnKeyWrapper =
      async dataKey => {
        keys.push(
          Buffer.from(dataKey)
        );

        return {
          wrappedDataKey:
            Buffer.from(dataKey),
          keyId:
            "https://example.vault.azure.net/keys/stage2-ssn-wrapping-key",
          keyVersion:
            "test-version",
        };
      };

    const first =
      await encryptStage2Ssn(
        "001234567",
        packetId,
        packetItemId,
        wrapper
      );
    const second =
      await encryptStage2Ssn(
        "001234567",
        packetId,
        packetItemId,
        wrapper
      );

    assert.equal(
      first.encryptionNonce.equals(
        second.encryptionNonce
      ),
      false
    );
    assert.equal(
      keys[0].equals(keys[1]),
      false
    );
  }
);

function storedEncrypted(
  encrypted: Awaited<
    ReturnType<
      typeof encryptStage2Ssn
    >
  >
): StoredEncryptedStage2Ssn {
  return {
    encryptedSsn:
      Buffer.from(
        encrypted.encryptedSsn
      ),
    encryptionNonce:
      Buffer.from(
        encrypted.encryptionNonce
      ),
    authenticationTag:
      Buffer.from(
        encrypted.authenticationTag
      ),
    wrappedDataKey:
      Buffer.from(
        encrypted.wrappedDataKey
      ),
    keyId:
      encrypted.keyId,
    keyVersion:
      encrypted.keyVersion,
  };
}

test(
  "production decrypt round trip preserves leading zeroes",
  async () => {
    let capturedKey =
      Buffer.alloc(0);

    const encrypted =
      await encryptStage2Ssn(
        "001234567",
        packetId,
        packetItemId,
        async dataKey => {
          capturedKey =
            Buffer.from(dataKey);

          return {
            wrappedDataKey:
              Buffer.from(
                "synthetic-wrapped-key"
              ),
            keyId:
              "https://example.vault.azure.net/keys/stage2-ssn-wrapping-key",
            keyVersion:
              "test-version",
          };
        }
      );

    let returnedDataKey =
      Buffer.alloc(0);

    const unwrapper:
      Stage2SsnKeyUnwrapper =
      async () => {
        returnedDataKey =
          Buffer.from(capturedKey);
        return returnedDataKey;
      };

    assert.equal(
      await decryptStage2Ssn(
        storedEncrypted(
          encrypted
        ),
        packetId,
        packetItemId,
        unwrapper
      ),
      "001234567"
    );
    assert.equal(
      returnedDataKey.every(
        value => value === 0
      ),
      true
    );
  }
);

test(
  "production decrypt fails closed on AAD mismatch",
  async () => {
    let capturedKey =
      Buffer.alloc(0);
    let returnedDataKey =
      Buffer.alloc(0);

    const encrypted =
      await encryptStage2Ssn(
        "001234567",
        packetId,
        packetItemId,
        async dataKey => {
          capturedKey =
            Buffer.from(dataKey);

          return {
            wrappedDataKey:
              Buffer.from(dataKey),
            keyId:
              "https://example.vault.azure.net/keys/stage2-ssn-wrapping-key",
            keyVersion:
              "test-version",
          };
        }
      );

    await assert.rejects(
      () =>
        decryptStage2Ssn(
          storedEncrypted(
            encrypted
          ),
          packetId,
          "00000000-0000-4000-8000-000000000003",
          async () => {
            returnedDataKey =
              Buffer.from(
                capturedKey
              );
            return returnedDataKey;
          }
        )
    );
    assert.equal(
      returnedDataKey.every(
        value => value === 0
      ),
      true
    );
  }
);

test(
  "production decrypt rejects tampered authentication material",
  async () => {
    let capturedKey =
      Buffer.alloc(0);

    const encrypted =
      await encryptStage2Ssn(
        "001234567",
        packetId,
        packetItemId,
        async dataKey => {
          capturedKey =
            Buffer.from(dataKey);

          return {
            wrappedDataKey:
              Buffer.from(dataKey),
            keyId:
              "https://example.vault.azure.net/keys/stage2-ssn-wrapping-key",
            keyVersion:
              "test-version",
          };
        }
      );

    const tampered =
      storedEncrypted(
        encrypted
      );

    tampered.authenticationTag[0] ^=
      0xff;

    await assert.rejects(
      () =>
        decryptStage2Ssn(
          tampered,
          packetId,
          packetItemId,
          async () =>
            Buffer.from(
              capturedKey
            )
        )
    );
  }
);

test(
  "production decrypt rejects an invalid unwrapped DEK length",
  async () => {
    const encrypted =
      await encryptStage2Ssn(
        "001234567",
        packetId,
        packetItemId,
        async dataKey => ({
          wrappedDataKey:
            Buffer.from(dataKey),
          keyId:
            "https://example.vault.azure.net/keys/stage2-ssn-wrapping-key",
          keyVersion:
            "test-version",
        })
      );

    await assert.rejects(
      () =>
        decryptStage2Ssn(
          storedEncrypted(
            encrypted
          ),
          packetId,
          packetItemId,
          async () =>
            Buffer.alloc(31)
        ),
      /invalid length/
    );
  }
);

test(
  "production decrypt rejects plaintext outside the nine-digit contract",
  async () => {
    const key =
      Buffer.alloc(32, 7);
    const nonce =
      Buffer.alloc(12, 8);
    const cipher =
      createCipheriv(
        "aes-256-gcm",
        key,
        nonce,
        {
          authTagLength: 16,
        }
      );

    cipher.setAAD(
      buildStage2SsnAad(
        packetId,
        packetItemId
      )
    );

    const encryptedSsn =
      Buffer.concat([
        cipher.update(
          Buffer.from(
            "12345678X",
            "utf8"
          )
        ),
        cipher.final(),
      ]);

    const authenticationTag =
      cipher.getAuthTag();

    await assert.rejects(
      () =>
        decryptStage2Ssn(
          {
            encryptedSsn,
            encryptionNonce:
              nonce,
            authenticationTag,
            wrappedDataKey:
              Buffer.from(
                "synthetic"
              ),
            keyId:
              "https://example.vault.azure.net/keys/stage2-ssn-wrapping-key",
            keyVersion:
              "test-version",
          },
          packetId,
          packetItemId,
          async () =>
            Buffer.from(key)
        ),
      /Decrypted SSN is invalid/
    );
  }
);
