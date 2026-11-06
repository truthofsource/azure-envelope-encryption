import {createCipheriv,createDecipheriv,randomBytes} from "node:crypto";

export const stage2SsnKeyWrapAlgorithm =
  "RSA-OAEP-256";

export type Stage2SsnWrappedDataKey = {
  wrappedDataKey: Buffer;
  keyId: string;
  keyVersion: string;
};

export type Stage2SsnKeyWrapper = (
  dataKey: Buffer
) => Promise<Stage2SsnWrappedDataKey>;

export type Stage2SsnKeyUnwrapper = (
  wrappedDataKey: Buffer,
  keyId: string,
  keyVersion: string
) => Promise<Buffer>;

export type StoredEncryptedStage2Ssn = {
  encryptedSsn: Buffer;
  encryptionNonce: Buffer;
  authenticationTag: Buffer;
  wrappedDataKey: Buffer;
  keyId: string;
  keyVersion: string;
};

export type EncryptedStage2Ssn = {
  encryptedSsn: Buffer;
  encryptionNonce: Buffer;
  authenticationTag: Buffer;
  wrappedDataKey: Buffer;
  keyId: string;
  keyVersion: string;
  ssnLastFour: string;
};

export function buildStage2SsnAad(
  packetId: string,
  packetItemId: string
): Buffer {
  return Buffer.from(
    [
      "workforce-stage2-ssn:v1",
      packetId.toLowerCase(),
      packetItemId.toLowerCase(),
    ].join(":"),
    "utf8"
  );
}

function requireEncryptedBuffer(
  value: Buffer,
  fieldName: string,
  options: {
    exactLength?: number;
    maximumLength?: number;
  } = {}
): Buffer {
  if (!Buffer.isBuffer(value)) {
    throw new Error(
      `${fieldName} is invalid.`
    );
  }

  if (
    options.exactLength !== undefined &&
    value.length !== options.exactLength
  ) {
    throw new Error(
      `${fieldName} has an invalid length.`
    );
  }

  if (
    value.length === 0 ||
    (
      options.maximumLength !== undefined &&
      value.length > options.maximumLength
    )
  ) {
    throw new Error(
      `${fieldName} has an invalid length.`
    );
  }

  return value;
}

export async function decryptStage2Ssn(
  encrypted:
    StoredEncryptedStage2Ssn,
  packetId: string,
  packetItemId: string,
  unwrapDataKey:
    Stage2SsnKeyUnwrapper
): Promise<string> {
  const encryptedSsn =
    requireEncryptedBuffer(
      encrypted.encryptedSsn,
      "encrypted_ssn",
      {
        maximumLength: 64,
      }
    );
  const nonce =
    requireEncryptedBuffer(
      encrypted.encryptionNonce,
      "encryption_nonce",
      {
        exactLength: 12,
      }
    );
  const authenticationTag =
    requireEncryptedBuffer(
      encrypted.authenticationTag,
      "authentication_tag",
      {
        exactLength: 16,
      }
    );
  const wrappedDataKey =
    requireEncryptedBuffer(
      encrypted.wrappedDataKey,
      "wrapped_data_key",
      {
        maximumLength: 512,
      }
    );

  let dataKey: Buffer =
    Buffer.alloc(0);
  let plaintext =
    Buffer.alloc(0);

  try {
    dataKey =
      await unwrapDataKey(
        wrappedDataKey,
        encrypted.keyId,
        encrypted.keyVersion
      );

    if (dataKey.length !== 32) {
      throw new Error(
        "Unwrapped SSN data key has an invalid length."
      );
    }

    const decipher =
      createDecipheriv(
        "aes-256-gcm",
        dataKey,
        nonce,
        {
          authTagLength: 16,
        }
      );

    decipher.setAAD(
      buildStage2SsnAad(
        packetId,
        packetItemId
      )
    );
    decipher.setAuthTag(
      authenticationTag
    );

    plaintext =
      Buffer.concat([
        decipher.update(
          encryptedSsn
        ),
        decipher.final(),
      ]);

    const normalizedSsn =
      plaintext.toString("utf8");

    if (
      !/^[0-9]{9}$/.test(
        normalizedSsn
      )
    ) {
      throw new Error(
        "Decrypted SSN is invalid."
      );
    }

    return normalizedSsn;
  } finally {
    dataKey.fill(0);
    plaintext.fill(0);
  }
}

export async function encryptStage2Ssn(
  normalizedSsn: string,
  packetId: string,
  packetItemId: string,
  wrapDataKey:
    Stage2SsnKeyWrapper
): Promise<EncryptedStage2Ssn> {
  if (
    !/^[0-9]{9}$/.test(
      normalizedSsn
    )
  ) {
    throw new Error(
      "Normalized SSN is invalid."
    );
  }

  const dataKey =
    randomBytes(32);
  const nonce =
    randomBytes(12);
  const plaintext =
    Buffer.from(
      normalizedSsn,
      "utf8"
    );
  const aad =
    buildStage2SsnAad(
      packetId,
      packetItemId
    );

  try {
    const cipher =
      createCipheriv(
        "aes-256-gcm",
        dataKey,
        nonce,
        {
          authTagLength: 16,
        }
      );

    cipher.setAAD(aad);

    const encryptedSsn =
      Buffer.concat([
        cipher.update(plaintext),
        cipher.final(),
      ]);
    const authenticationTag =
      cipher.getAuthTag();

    const wrapped =
      await wrapDataKey(
        dataKey
      );

    return {
      encryptedSsn,
      encryptionNonce:
        Buffer.from(nonce),
      authenticationTag:
        Buffer.from(
          authenticationTag
        ),
      wrappedDataKey:
        Buffer.from(
          wrapped.wrappedDataKey
        ),
      keyId:
        wrapped.keyId,
      keyVersion:
        wrapped.keyVersion,
      ssnLastFour:
        normalizedSsn.slice(-4),
    };
  } finally {
    dataKey.fill(0);
    plaintext.fill(0);
  }
}
