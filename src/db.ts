/**
 * db.ts — SQLite persistence for envelope-encrypted per-user GitHub tokens.
 *
 * Schema is minimal on purpose. A production version would add:
 *  - key_version column on `users` for MASTER_KEY rotation tracking
 *  - audit_log table for every token access
 *  - refresh_token support if the OAuth provider issues one
 *  - session_revocations table for JWT deny-list
 *
 * For a demo the two-table shape (`users` + `oauth_flows`) covers the
 * end-to-end story: authenticate once, store encrypted, decrypt per-call.
 */

import Database from "better-sqlite3";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

let _db: Database.Database | null = null;

function getDb(): Database.Database {
  if (_db) return _db;
  const path = process.env.SQLITE_PATH || "./data/vault.db";
  mkdirSync(dirname(path), { recursive: true });
  _db = new Database(path);
  _db.pragma("journal_mode = WAL");
  _db.pragma("foreign_keys = ON");
  initSchema(_db);
  return _db;
}

function initSchema(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id                INTEGER PRIMARY KEY AUTOINCREMENT,
      github_user_id    INTEGER NOT NULL UNIQUE,
      github_login      TEXT NOT NULL,
      encrypted_dek     BLOB NOT NULL,
      encrypted_token   BLOB NOT NULL,
      created_at        TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS oauth_flows (
      state             TEXT PRIMARY KEY,
      code_verifier     TEXT NOT NULL,
      created_at        TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_users_github_user_id ON users(github_user_id);
  `);
}

// --- users table ---

export interface UserRow {
  id: number;
  github_user_id: number;
  github_login: string;
  encrypted_dek: Buffer;
  encrypted_token: Buffer;
}

export function upsertUser(row: {
  githubUserId: number;
  githubLogin: string;
  encryptedDek: Buffer;
  encryptedToken: Buffer;
}): number {
  const db = getDb();
  const stmt = db.prepare(`
    INSERT INTO users (github_user_id, github_login, encrypted_dek, encrypted_token)
    VALUES (@githubUserId, @githubLogin, @encryptedDek, @encryptedToken)
    ON CONFLICT (github_user_id) DO UPDATE SET
      github_login    = excluded.github_login,
      encrypted_dek   = excluded.encrypted_dek,
      encrypted_token = excluded.encrypted_token,
      updated_at      = datetime('now')
    RETURNING id
  `);
  const result = stmt.get(row) as { id: number };
  return result.id;
}

export function getUserById(id: number): UserRow | undefined {
  const db = getDb();
  return db.prepare("SELECT * FROM users WHERE id = ?").get(id) as UserRow | undefined;
}

// --- oauth_flows table (short-lived, PKCE state → verifier map) ---

export function storeOAuthFlow(state: string, codeVerifier: string): void {
  const db = getDb();
  db.prepare(
    "INSERT INTO oauth_flows (state, code_verifier) VALUES (?, ?)"
  ).run(state, codeVerifier);
}

export function popOAuthFlow(state: string): string | undefined {
  const db = getDb();
  const row = db
    .prepare("SELECT code_verifier FROM oauth_flows WHERE state = ?")
    .get(state) as { code_verifier: string } | undefined;
  if (row) {
    db.prepare("DELETE FROM oauth_flows WHERE state = ?").run(state);
    return row.code_verifier;
  }
  return undefined;
}

/** Delete OAuth flow rows older than 10 minutes. Call opportunistically. */
export function pruneStaleFlows(): void {
  const db = getDb();
  db.prepare(
    "DELETE FROM oauth_flows WHERE datetime(created_at) < datetime('now', '-10 minutes')"
  ).run();
}
