import test from "node:test";
import assert from "node:assert/strict";
import {requireVersionedKeyId,buildStage2SsnVersionedKeyId} from "./keyIdentifiers.ts";
const key="https://example.vault.azure.net/keys/record-wrap-key";
test("key response must return the configured key and an explicit version",()=>{
  assert.equal(requireVersionedKeyId(key,key+"/version-one"),"version-one");
  assert.throws(()=>requireVersionedKeyId(key,undefined));
  assert.throws(()=>requireVersionedKeyId(key,"https://other.vault.azure.net/keys/record-wrap-key/v1"));
});
test("historical read constructs the stored version rather than latest",()=>{
  assert.equal(buildStage2SsnVersionedKeyId(key,key,"old-version"),key+"/old-version");
});
test("foreign stored key and path injection are rejected",()=>{
  assert.throws(()=>buildStage2SsnVersionedKeyId(key,key+"-other","v1"));
  assert.throws(()=>buildStage2SsnVersionedKeyId(key,key,"v1/other"));
});
test("unwrap configuration requires https and no query/fragment",()=>{
  for(const bad of ["http://example.vault.azure.net/keys/key",key+"?query=1",key+"#fragment"]){
    assert.throws(()=>buildStage2SsnVersionedKeyId(bad,bad,"v1"));
  }
});
