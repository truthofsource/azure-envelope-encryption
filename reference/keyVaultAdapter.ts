import {DefaultAzureCredential} from "@azure/identity";
import {CryptographyClient} from "@azure/keyvault-keys";
import {stage2SsnKeyWrapAlgorithm,type Stage2SsnKeyWrapper,type Stage2SsnKeyUnwrapper} from "./fieldEncryption.ts";
import {requireVersionedKeyId,buildStage2SsnVersionedKeyId} from "./keyIdentifiers.ts";

export function createStage2SsnKeyVaultWrapper(
  env:
    NodeJS.ProcessEnv =
      process.env
): Stage2SsnKeyWrapper {
  const keyId =
    env.STAGE2_SSN_KEY_VAULT_KEY_ID
      ?.trim();

  if (!keyId) {
    throw new Error(
      "Missing required SSN wrapping-key configuration."
    );
  }

  const credential =
    new DefaultAzureCredential();
  const client =
    new CryptographyClient(
      keyId,
      credential
    );

  return async dataKey => {
    const wrapResult =
      await client.wrapKey(
        stage2SsnKeyWrapAlgorithm,
        dataKey
      );

    const keyVersion =
      requireVersionedKeyId(
        keyId,
        wrapResult.keyID
      );

    return {
      wrappedDataKey:
        Buffer.from(
          wrapResult.result
        ),
      keyId,
      keyVersion,
    };
  };
}

export function createStage2SsnKeyVaultUnwrapper(
  env:
    NodeJS.ProcessEnv =
      process.env
): Stage2SsnKeyUnwrapper {
  const configuredKeyId =
    env.STAGE2_SSN_KEY_VAULT_KEY_ID
      ?.trim();

  if (!configuredKeyId) {
    throw new Error(
      "Missing required SSN wrapping-key configuration."
    );
  }

  const credential =
    new DefaultAzureCredential();

  return async (
    wrappedDataKey,
    keyId,
    keyVersion
  ) => {
    const versionedKeyId =
      buildStage2SsnVersionedKeyId(
        configuredKeyId,
        keyId,
        keyVersion
      );

    const client =
      new CryptographyClient(
        versionedKeyId,
        credential
      );

    const unwrapResult =
      await client.unwrapKey(
        stage2SsnKeyWrapAlgorithm,
        wrappedDataKey
      );

    if (unwrapResult.keyID) {
      const actualVersion =
        requireVersionedKeyId(
          configuredKeyId,
          unwrapResult.keyID
        );

      if (
        actualVersion !==
          keyVersion.trim()
      ) {
        unwrapResult.result.fill(0);

        throw new Error(
          "Key Vault unwrap response used an unexpected key version."
        );
      }
    }

    const dataKey =
      Buffer.from(
        unwrapResult.result
      );

    unwrapResult.result.fill(0);

    return dataKey;
  };
}
