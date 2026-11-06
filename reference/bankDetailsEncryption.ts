import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import type { Stage2SsnKeyWrapper, Stage2SsnKeyUnwrapper } from "./fieldEncryption.ts";
import type { Stage2BankDetails } from "./recordTypes.ts";

export type EncryptedStage2BankDetails = { ciphertext: Buffer; nonce: Buffer; tag: Buffer; wrappedKey: Buffer; keyId: string; keyVersion: string };
export type StoredStage2BankDetails = EncryptedStage2BankDetails;
const aad = (packet: string, item: string) => Buffer.from(`workforce-stage2-bank-details:v1:${packet.toLowerCase()}:${item.toLowerCase()}`);

export async function encryptStage2BankDetails(details: Stage2BankDetails, packet: string, item: string, wrap: Stage2SsnKeyWrapper): Promise<EncryptedStage2BankDetails> {
  const plain = Buffer.from(JSON.stringify(details), "utf8"), key = randomBytes(32), nonce = randomBytes(12);
  try {
    const cipher = createCipheriv("aes-256-gcm", key, nonce);
    cipher.setAAD(aad(packet, item));
    const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
    const wrapped = await wrap(key);
    return { ciphertext, nonce, tag: cipher.getAuthTag(), wrappedKey: Buffer.from(wrapped.wrappedDataKey), keyId: wrapped.keyId, keyVersion: wrapped.keyVersion };
  } finally { plain.fill(0); key.fill(0); }
}

export async function decryptStage2BankDetails(value: StoredStage2BankDetails, packet: string, item: string, unwrap: Stage2SsnKeyUnwrapper): Promise<Stage2BankDetails> {
  if (value.ciphertext.length < 2 || value.ciphertext.length > 4096 || value.nonce.length !== 12 || value.tag.length !== 16 || value.wrappedKey.length > 512) throw new Error("Encrypted direct-deposit record is invalid.");
  let key: Buffer = Buffer.alloc(0), plain: Buffer = Buffer.alloc(0);
  try {
    key = await unwrap(value.wrappedKey, value.keyId, value.keyVersion);
    if (key.length !== 32) throw new Error("Unwrapped direct-deposit key is invalid.");
    const decipher = createDecipheriv("aes-256-gcm", key, value.nonce);
    decipher.setAAD(aad(packet, item)); decipher.setAuthTag(value.tag);
    plain = Buffer.concat([decipher.update(value.ciphertext), decipher.final()]);
    const parsed = JSON.parse(plain.toString("utf8")) as Stage2BankDetails;
    if (!parsed || typeof parsed !== "object" || !/^\d{9}$/.test(parsed.routingNumber) || !/^\d{4,17}$/.test(parsed.accountNumber)) throw new Error("Decrypted direct-deposit record is invalid.");
    return parsed;
  } finally { key.fill(0); plain.fill(0); }
}
