/**
 * oauth.ts — GitHub OAuth 2.1 flow with PKCE (RFC 7636).
 *
 * Flow:
 *   1. Client hits GET /oauth/start
 *   2. Server generates code_verifier + code_challenge (S256), stores in oauth_flows
 *   3. Server redirects to https://github.com/login/oauth/authorize with:
 *        response_type=code
 *        client_id=<GITHUB_CLIENT_ID>
 *        redirect_uri=<PUBLIC_BASE_URL>/oauth/callback
 *        scope=<GITHUB_OAUTH_SCOPES>
 *        state=<random>
 *        code_challenge=<hash>
 *        code_challenge_method=S256
 *   4. User authorizes on GitHub, GitHub redirects back with ?code=&state=
 *   5. Server pops flow row by state → gets code_verifier
 *   6. Server exchanges code + code_verifier for access_token at token endpoint
 *   7. Server fetches user identity, envelope-encrypts token, stores in users table
 *   8. Server issues session JWT to the user with user_id claim
 *
 * Why PKCE for a confidential client (server-side)?
 *  - Belt-and-suspenders. Even with client_secret, PKCE defends against auth-code
 *    interception between the browser and the server callback.
 *  - MCP 2025 spec explicitly calls for OAuth 2.1 + PKCE for remote MCP servers.
 *
 * Note: GitHub as of mid-2026 supports PKCE on OAuth Apps. Some earlier docs
 * suggested confidential clients skip it — we don't.
 */

import { createHash, randomBytes } from "node:crypto";
import { SignJWT } from "jose";
import { Octokit } from "@octokit/rest";
import { wrapToken } from "./crypto.js";
import { storeOAuthFlow, popOAuthFlow, upsertUser } from "./db.js";

function base64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required`);
  return v;
}

function baseUrl(): string {
  return requireEnv("PUBLIC_BASE_URL").replace(/\/$/, "");
}

/** Build the GitHub authorization URL for the start of the flow. */
export function buildAuthorizeUrl(): string {
  const codeVerifier = base64url(randomBytes(32));
  const codeChallenge = base64url(createHash("sha256").update(codeVerifier).digest());
  const state = base64url(randomBytes(16));

  storeOAuthFlow(state, codeVerifier);

  const params = new URLSearchParams({
    response_type: "code",
    client_id: requireEnv("GITHUB_CLIENT_ID"),
    redirect_uri: `${baseUrl()}/oauth/callback`,
    scope: process.env.GITHUB_OAUTH_SCOPES || "repo,read:user",
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });

  return `https://github.com/login/oauth/authorize?${params.toString()}`;
}

/**
 * Exchange authorization code for access token, verify PKCE, envelope-encrypt,
 * persist, and return the internal user_id.
 */
export async function handleCallback(
  code: string,
  state: string
): Promise<{ userId: number; login: string }> {
  const codeVerifier = popOAuthFlow(state);
  if (!codeVerifier) {
    throw new Error("Invalid or expired OAuth state");
  }

  const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({
      client_id: requireEnv("GITHUB_CLIENT_ID"),
      client_secret: requireEnv("GITHUB_CLIENT_SECRET"),
      code,
      redirect_uri: `${baseUrl()}/oauth/callback`,
      code_verifier: codeVerifier,
    }),
  });

  if (!tokenRes.ok) {
    throw new Error(`GitHub token exchange failed: ${tokenRes.status}`);
  }
  const tokenBody = (await tokenRes.json()) as {
    access_token?: string;
    error?: string;
    error_description?: string;
  };
  if (!tokenBody.access_token) {
    throw new Error(
      `GitHub token exchange rejected: ${tokenBody.error_description || tokenBody.error}`
    );
  }

  const githubToken = tokenBody.access_token;

  const octokit = new Octokit({ auth: githubToken });
  const { data: gh } = await octokit.users.getAuthenticated();

  const { encryptedDek, encryptedToken } = wrapToken(githubToken);
  const userId = upsertUser({
    githubUserId: gh.id,
    githubLogin: gh.login,
    encryptedDek,
    encryptedToken,
  });

  return { userId, login: gh.login };
}

/** Issue a session JWT to hand back to the user / MCP client. */
export async function issueSessionJwt(userId: number, login: string): Promise<string> {
  const keyB64 = requireEnv("SESSION_JWT_KEY_B64");
  const key = Buffer.from(keyB64, "base64");
  if (key.length !== 32) {
    throw new Error("SESSION_JWT_KEY_B64 must decode to 32 bytes");
  }
  return await new SignJWT({ sub: String(userId), login })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setIssuer(baseUrl())
    .setAudience("mcp-github-issues-remote")
    .setExpirationTime("30d")
    .sign(key);
}
