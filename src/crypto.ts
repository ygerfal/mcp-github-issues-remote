/**
 * crypto.ts — envelope encryption for per-user GitHub tokens.
 *
 * Threat model:
 *  - Attacker exfiltrates SQLite DB (backup theft, ops mistake, insider).
 *  - Without MASTER_KEY_B64 they get ciphertext only.
 *  - MASTER_KEY_B64 lives in Fly secrets (or equivalent), never on disk.
 *
 * Pattern (KMS-style envelope encryption without a cloud KMS):
 *  1. Per user, generate a 32-byte "data key" at signup.
 *  2. Encrypt the data key with MASTER_KEY → store `encrypted_dek` in DB.
 *  3. Encrypt the GitHub token with the data key → store `encrypted_token` in DB.
 *  4. To decrypt: read `encrypted_dek` → decrypt with MASTER_KEY → decrypt token.
 *
 * Why not just AES(MASTER_KEY, token) directly?
 *  - Key rotation. Rotating MASTER_KEY re-encrypts only N DEKs (fast), not N tokens.
 *  - Domain separation. A leaked DEK compromises one user, not all users.
 *  - Matches the AWS KMS / GCP KMS envelope pattern reviewers already know.
 *
 * Algorithm: AES-256-GCM. 12-byte IV, 16-byte auth tag, deterministic layout:
 *   [12-byte IV][ciphertext][16-byte tag]
 */

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;

function getMasterKey(): Buffer {
  const b64 = process.env.MASTER_KEY_B64;
  if (!b64) {
    throw new Error("MASTER_KEY_B64 is required");
  }
  const key = Buffer.from(b64, "base64");
  if (key.length !== KEY_LEN) {
    throw new Error(
      `MASTER_KEY_B64 must decode to ${KEY_LEN} bytes, got ${key.length}`
    );
  }
  return key;
}

/** Encrypt `plaintext` under `key` with AES-256-GCM. Returns [iv|ct|tag]. */
export function aeadEncrypt(key: Buffer, plaintext: Buffer): Buffer {
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, ct, tag]);
}

/** Decrypt `[iv|ct|tag]` under `key`. Throws on tag mismatch. */
export function aeadDecrypt(key: Buffer, blob: Buffer): Buffer {
  if (blob.length < IV_LEN + TAG_LEN) {
    throw new Error("ciphertext too short");
  }
  const iv = blob.subarray(0, IV_LEN);
  const tag = blob.subarray(blob.length - TAG_LEN);
  const ct = blob.subarray(IV_LEN, blob.length - TAG_LEN);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

/** Generate a fresh 32-byte data-encryption key. */
export function newDataKey(): Buffer {
  return randomBytes(KEY_LEN);
}

/**
 * Wrap a GitHub token for a new user. Returns the two ciphertexts to store.
 * The plaintext data key is discarded after wrapping — server never persists it.
 */
export function wrapToken(githubToken: string): {
  encryptedDek: Buffer;
  encryptedToken: Buffer;
} {
  const dek = newDataKey();
  const encryptedDek = aeadEncrypt(getMasterKey(), dek);
  const encryptedToken = aeadEncrypt(dek, Buffer.from(githubToken, "utf8"));
  return { encryptedDek, encryptedToken };
}

/**
 * Unwrap a GitHub token for a request. Read both ciphertexts from DB, get plaintext token.
 * The plaintext data key exists only for the duration of the call.
 */
export function unwrapToken(
  encryptedDek: Buffer,
  encryptedToken: Buffer
): string {
  const dek = aeadDecrypt(getMasterKey(), encryptedDek);
  const token = aeadDecrypt(dek, encryptedToken);
  return token.toString("utf8");
}
