/**
 * crypto.test.ts — envelope encryption unit tests.
 *
 * Run: node --import tsx --test src/crypto.test.ts
 *
 * Coverage:
 *  - Round-trip: wrap then unwrap returns original token
 *  - Tamper detection: flipping a byte in ciphertext, IV, or tag causes failure
 *  - Independence: DEK from one call cannot decrypt another call's token
 *  - Key length validation: master key must be exactly 32 bytes
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { aeadEncrypt, aeadDecrypt, newDataKey, wrapToken, unwrapToken } from "./crypto.js";

function setMasterKey(): Buffer {
  const key = randomBytes(32);
  process.env.MASTER_KEY_B64 = key.toString("base64");
  return key;
}

test("aeadEncrypt / aeadDecrypt: round-trip preserves plaintext", () => {
  const key = randomBytes(32);
  const plaintext = Buffer.from("ghp_ABCdef1234567890xyz", "utf8");
  const blob = aeadEncrypt(key, plaintext);
  const decrypted = aeadDecrypt(key, blob);
  assert.deepEqual(decrypted, plaintext);
});

test("aeadDecrypt: fails when ciphertext bit is flipped", () => {
  const key = randomBytes(32);
  const plaintext = Buffer.from("sensitive-token-value", "utf8");
  const blob = aeadEncrypt(key, plaintext);
  // Flip a bit in the ciphertext region (after IV, before tag)
  blob[16] ^= 0x01;
  assert.throws(() => aeadDecrypt(key, blob));
});

test("aeadDecrypt: fails when auth tag is tampered", () => {
  const key = randomBytes(32);
  const plaintext = Buffer.from("token", "utf8");
  const blob = aeadEncrypt(key, plaintext);
  blob[blob.length - 1] ^= 0x01;
  assert.throws(() => aeadDecrypt(key, blob));
});

test("aeadDecrypt: fails when IV is tampered", () => {
  const key = randomBytes(32);
  const plaintext = Buffer.from("token", "utf8");
  const blob = aeadEncrypt(key, plaintext);
  blob[0] ^= 0x01;
  assert.throws(() => aeadDecrypt(key, blob));
});

test("aeadDecrypt: fails when decrypted with wrong key", () => {
  const keyA = randomBytes(32);
  const keyB = randomBytes(32);
  const blob = aeadEncrypt(keyA, Buffer.from("token", "utf8"));
  assert.throws(() => aeadDecrypt(keyB, blob));
});

test("newDataKey: returns 32 random bytes", () => {
  const k1 = newDataKey();
  const k2 = newDataKey();
  assert.equal(k1.length, 32);
  assert.equal(k2.length, 32);
  assert.notDeepEqual(k1, k2);
});

test("wrapToken / unwrapToken: full envelope round-trip", () => {
  setMasterKey();
  const token = "ghp_ABCdef1234567890xyz";
  const { encryptedDek, encryptedToken } = wrapToken(token);
  const recovered = unwrapToken(encryptedDek, encryptedToken);
  assert.equal(recovered, token);
});

test("wrapToken: each call produces distinct ciphertexts even for same token", () => {
  setMasterKey();
  const token = "same-token-two-users";
  const a = wrapToken(token);
  const b = wrapToken(token);
  assert.notDeepEqual(a.encryptedDek, b.encryptedDek);
  assert.notDeepEqual(a.encryptedToken, b.encryptedToken);
});

test("unwrapToken: DEK from one user cannot decrypt another user's token", () => {
  setMasterKey();
  const a = wrapToken("user-a-token");
  const b = wrapToken("user-b-token");
  // Attempt to unwrap b's token with a's DEK ciphertext — must fail
  assert.throws(() => unwrapToken(a.encryptedDek, b.encryptedToken));
});

test("wrapToken: throws when MASTER_KEY_B64 is not set", () => {
  delete process.env.MASTER_KEY_B64;
  assert.throws(() => wrapToken("any"), /MASTER_KEY_B64 is required/);
});

test("wrapToken: throws when MASTER_KEY_B64 decodes to wrong length", () => {
  process.env.MASTER_KEY_B64 = randomBytes(16).toString("base64");
  assert.throws(() => wrapToken("any"), /must decode to 32 bytes/);
});
