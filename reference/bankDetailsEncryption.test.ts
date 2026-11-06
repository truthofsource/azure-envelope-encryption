import test from "node:test";
import assert from "node:assert/strict";
import { decryptStage2BankDetails, encryptStage2BankDetails } from "./bankDetailsEncryption.ts";
import type { Stage2SsnKeyWrapper, Stage2SsnKeyUnwrapper } from "./fieldEncryption.ts";

test("encrypts bank values and authenticates packet/item binding", async () => {
  const wrap: Stage2SsnKeyWrapper = async key => ({ wrappedDataKey: Buffer.from(key), keyId: "test-key", keyVersion: "v1" });
  const unwrap: Stage2SsnKeyUnwrapper = async wrapped => Buffer.from(wrapped);
  const details = { bankName: "Example Bank", accountHolder: "Test Person", accountType: "checking" as const, routingNumber: "021000021", accountNumber: "123456789" };
  const packet = "00000000-0000-4000-8000-000000000001", item = "00000000-0000-4000-8000-000000000002";
  const encrypted = await encryptStage2BankDetails(details, packet, item, wrap);
  assert.equal(encrypted.ciphertext.includes(Buffer.from(details.accountNumber)), false);
  assert.deepEqual(await decryptStage2BankDetails(encrypted, packet, item, unwrap), details);
  await assert.rejects(decryptStage2BankDetails(encrypted, "00000000-0000-4000-8000-000000000003", item, unwrap));
});
