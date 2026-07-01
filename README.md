# mcp-github-issues-remote

A **remote Model Context Protocol (MCP)** server for GitHub Issues, with OAuth 2.1 + PKCE authorization and envelope-encrypted per-user token storage. Deploys to Fly.io.

Companion repo to [mcp-github-issues](https://github.com/ygerfal/mcp-github-issues) — same three tools, different transport, different identity model.

> **Status:** Active development this week. Day 1-3 complete: OAuth 2.1 + PKCE scaffold, envelope encryption, SQLite persistence, HTTP server, MCP handler over Streamable HTTP transport wired to per-user decrypted tokens. **16/16 tests passing** (11 crypto + 5 auth wall). Day 4-5: Fly.io deploy + expanded threat model.

---

## Why a second repo?

The [local stdio version](https://github.com/ygerfal/mcp-github-issues) runs inside the MCP host's process. The user's GitHub token comes from `process.env.GITHUB_TOKEN` — no auth flow, no persistence, no server-side risk. Simple, correct, but only usable for personal-scope tools running on the user's machine.

**This repo is the multi-tenant version.** Users authenticate once via GitHub OAuth 2.1 + PKCE, their access tokens are envelope-encrypted at rest, and MCP clients call the server over HTTP with a signed session JWT. Each tool call decrypts that user's token per-request, uses it to hit the GitHub API, and discards the plaintext.

Two versions, two identity models, two threat surfaces.

---

## Architecture

```
User Browser
    │  GET /oauth/start
    ▼
┌────────────────────────────────────────────────────┐
│  1. Generate code_verifier (32 bytes)              │
│  2. code_challenge = SHA256(code_verifier), b64url │
│  3. state = random 16 bytes                        │
│  4. Store (state → code_verifier) in SQLite        │
│  5. Redirect to GitHub authorize endpoint          │
└────────────────────────────────────────────────────┘
    │
    ▼
GitHub OAuth (user authorizes)
    │  callback: ?code=...&state=...
    ▼
┌────────────────────────────────────────────────────┐
│  6. Pop code_verifier by state (or fail)           │
│  7. POST to token endpoint with code + verifier    │
│  8. Fetch user identity (id, login)                │
│  9. Wrap token: envelope encryption                │
│     - Generate DEK (32 bytes random)               │
│     - encrypted_dek = AES-GCM(MASTER_KEY, DEK)     │
│     - encrypted_token = AES-GCM(DEK, gh_token)     │
│  10. Persist users(github_user_id, encrypted_dek,  │
│      encrypted_token)                              │
│  11. Issue session JWT (HS256, 30d, sub=user_id)   │
│  12. Return JWT to user                            │
└────────────────────────────────────────────────────┘
    │
    ▼
User configures MCP client with the JWT

MCP Client (Claude Desktop, Cursor, Claude Code)
    │  POST /mcp   Authorization: Bearer <JWT>
    ▼
┌────────────────────────────────────────────────────┐
│  13. Verify JWT signature + expiry + audience      │
│  14. Look up user by sub                           │
│  15. Unwrap token:                                 │
│      - DEK = AES-GCM-decrypt(MASTER_KEY, enc_dek)  │
│      - token = AES-GCM-decrypt(DEK, enc_token)     │
│  16. Octokit call with user's real token           │
│  17. Return result; plaintext token discarded      │
└────────────────────────────────────────────────────┘
    │
    ▼
GitHub REST API — sees the real user, audit log names them
```

---

## Envelope encryption

The pattern matches AWS KMS / GCP KMS envelope encryption, minus the cloud KMS. All primitives are Node's built-in `crypto` module.

- **MASTER_KEY_B64** — 32 random bytes, base64. Lives in Fly secrets. Never on disk.
- **DEK (Data Encryption Key)** — 32 random bytes, generated per user at signup. Never persisted in plaintext.
- **encrypted_dek** = `AES-256-GCM(MASTER_KEY, DEK)` — stored in `users.encrypted_dek`.
- **encrypted_token** = `AES-256-GCM(DEK, github_token)` — stored in `users.encrypted_token`.

**Why not just AES(MASTER_KEY, github_token) directly?**

1. **Key rotation.** Rotating MASTER_KEY re-encrypts N DEKs (fast), not N tokens.
2. **Domain separation.** A leaked DEK compromises one user, not all users.
3. **Interview-legibility.** Matches the AWS KMS pattern reviewers already know.

Wire layout of each ciphertext blob: `[12-byte IV][ciphertext][16-byte auth tag]`. Any tampering fails AEAD verification.

---

## Threat model (draft — expanded in Day 5)

| Threat | Mitigation |
|---|---|
| SQLite backup theft | Ciphertext-only exposure. Attacker needs MASTER_KEY to decrypt any DEK, DEK to decrypt any token. |
| MASTER_KEY leak | All DEKs compromised. Rotation re-wraps every DEK (fast); tokens themselves stay encrypted with their per-user DEKs. |
| Session JWT theft | Full access as that user until token expires (30d) or is revoked. Mitigation: shorter expiry + revocation list (backlog). |
| Auth-code interception between browser and server callback | PKCE `code_verifier` — attacker with the code but no verifier can't complete the exchange. |
| CSRF on `/oauth/callback` | `state` parameter is signed random, validated single-use. |
| Timing attack on token comparison | JWT verification via `jose` uses constant-time comparison. |
| Server memory dump | Plaintext token exists in memory only for the duration of a single tool call. Not stored, not logged. |

---

## Setup (local development)

```bash
git clone https://github.com/ygerfal/mcp-github-issues-remote.git
cd mcp-github-issues-remote
npm install
cp .env.example .env

# Generate keys
node -e "console.log('MASTER_KEY_B64=' + require('crypto').randomBytes(32).toString('base64'))"
node -e "console.log('SESSION_JWT_KEY_B64=' + require('crypto').randomBytes(32).toString('base64'))"
# Paste both into .env

# Register a GitHub OAuth App at https://github.com/settings/developers
# Homepage: http://localhost:8787
# Callback: http://localhost:8787/oauth/callback
# Paste GITHUB_CLIENT_ID + GITHUB_CLIENT_SECRET into .env

npm run build
npm start
# Open http://localhost:8787 and click "Connect GitHub"
```

---

## Deploy to Fly.io

```bash
fly launch --no-deploy
fly volumes create vault --size 1
fly secrets set MASTER_KEY_B64=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64'))")
fly secrets set SESSION_JWT_KEY_B64=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64'))")
fly secrets set GITHUB_CLIENT_ID=Iv1.xxxx GITHUB_CLIENT_SECRET=xxxx
fly deploy
```

Then update the GitHub OAuth App's callback to `https://<app>.fly.dev/oauth/callback`.

---

## Tests

11 unit tests for envelope encryption — round-trip, tamper detection (IV, ciphertext, auth tag), cross-user DEK isolation, key length validation.

```bash
node --import tsx --test src/crypto.test.ts
```

---

## What's shipping when

- **Day 1** ✅ — OAuth 2.1 + PKCE scaffold, envelope encryption, SQLite persistence, HTTP server
- **Day 2** ✅ — Crypto unit tests (11/11 pass)
- **Day 3** ✅ — MCP handler over Streamable HTTP transport, tools wired to per-user decrypted tokens, auth wall tests (5/5 pass)
- **Day 4** — Fly.io deployment, real GitHub OAuth App, end-to-end auth test in production
- **Day 5** — Expanded threat model, deployment guide, Loom demo

---

## License

MIT.

## Author

Yousef Gerfal — AI Automation Engineer @ Intuit Academy. Shipped six production MCP integrations to internal tool surfaces (Slack, Jira, Confluence, Google Suite, Zoom, FlowGrid); this repo is the multi-tenant version of that pattern with OAuth 2.1 + PKCE — the identity story security teams actually ask about.

linkedin.com/in/yousef-gerfal-b5b15446
