export function requireVersionedKeyId(
  configuredVersionlessKeyId: string,
  actualKeyId: string | undefined
): string {
  if (!actualKeyId) {
    throw new Error(
      "Key Vault wrap response did not identify the key version."
    );
  }

  const configured =
    new URL(
      configuredVersionlessKeyId
    );
  const actual =
    new URL(actualKeyId);

  const configuredSegments =
    configured.pathname
      .split("/")
      .filter(Boolean);
  const actualSegments =
    actual.pathname
      .split("/")
      .filter(Boolean);

  if (
    configured.protocol !==
      actual.protocol ||
    configured.host !==
      actual.host ||
    configuredSegments.length !== 2 ||
    configuredSegments[0] !==
      "keys" ||
    actualSegments.length !== 3 ||
    actualSegments[0] !==
      "keys" ||
    actualSegments[1] !==
      configuredSegments[1] ||
    !actualSegments[2]
  ) {
    throw new Error(
      "Key Vault wrap response used an unexpected key identifier."
    );
  }

  return actualSegments[2];
}

export function buildStage2SsnVersionedKeyId(
  configuredVersionlessKeyId: string,
  persistedKeyId: string,
  keyVersion: string
): string {
  const configuredKeyId =
    configuredVersionlessKeyId.trim();
  const storedKeyId =
    persistedKeyId.trim();
  const normalizedVersion =
    keyVersion.trim();

  if (
    configuredKeyId.length === 0 ||
    storedKeyId !== configuredKeyId
  ) {
    throw new Error(
      "Stored SSN key identifier does not match configuration."
    );
  }

  if (
    !/^[A-Za-z0-9-]{1,100}$/.test(
      normalizedVersion
    )
  ) {
    throw new Error(
      "Stored SSN key version is invalid."
    );
  }

  const configured =
    new URL(configuredKeyId);
  const segments =
    configured.pathname
      .split("/")
      .filter(Boolean);

  if (
    configured.protocol !== "https:" ||
    configured.search.length > 0 ||
    configured.hash.length > 0 ||
    segments.length !== 2 ||
    segments[0] !== "keys" ||
    segments[1].length === 0
  ) {
    throw new Error(
      "SSN wrapping-key configuration is invalid."
    );
  }

  return (
    `${configured.origin}/keys/` +
    `${segments[1]}/${normalizedVersion}`
  );
}
