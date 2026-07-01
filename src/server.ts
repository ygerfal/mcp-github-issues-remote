/**
 * server.ts — HTTP entrypoint.
 *
 * Routes:
 *   GET  /healthz          liveness
 *   GET  /                 landing page (start OAuth)
 *   GET  /oauth/start      redirect to GitHub with PKCE challenge
 *   GET  /oauth/callback   handle GitHub redirect, mint session JWT
 *   POST /mcp              MCP protocol endpoint (Day 3)
 *
 * Day 1 status:
 *   - OAuth start + callback wired end-to-end
 *   - Session JWT minted and returned to browser
 *   - /mcp endpoint stubbed with JWT verification middleware
 *   - MCP protocol handlers land Day 3
 */

import express, { type Request, type Response, type NextFunction } from "express";
import { jwtVerify } from "jose";
import { buildAuthorizeUrl, handleCallback, issueSessionJwt } from "./oauth.js";
import { pruneStaleFlows } from "./db.js";

const app = express();
app.use(express.json({ limit: "1mb" }));

// ------------- Middleware -------------

interface AuthedRequest extends Request {
  userId?: number;
  login?: string;
}

async function requireSession(
  req: AuthedRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  const header = req.header("authorization") || "";
  const [scheme, token] = header.split(" ");
  if (scheme !== "Bearer" || !token) {
    res.status(401).json({ error: "missing bearer token" });
    return;
  }
  try {
    const keyB64 = process.env.SESSION_JWT_KEY_B64;
    if (!keyB64) throw new Error("SESSION_JWT_KEY_B64 not set");
    const key = Buffer.from(keyB64, "base64");
    const { payload } = await jwtVerify(token, key, {
      audience: "mcp-github-issues-remote",
    });
    req.userId = Number(payload.sub);
    req.login = String(payload.login || "");
    next();
  } catch (err) {
    res.status(401).json({ error: "invalid session token" });
  }
}

// ------------- Public routes -------------

app.get("/healthz", (_req, res) => {
  res.json({ ok: true, version: "0.1.0" });
});

app.get("/", (_req, res) => {
  res.type("html").send(`<!doctype html>
<html>
<head><meta charset="utf-8"><title>mcp-github-issues-remote</title>
<style>
  body { font-family: -apple-system, sans-serif; max-width: 640px; margin: 3em auto; padding: 0 1em; line-height: 1.5; color: #222; }
  a.btn { display: inline-block; background: #24292f; color: white; padding: 10px 18px; border-radius: 6px; text-decoration: none; }
  code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
</style>
</head>
<body>
  <h1>mcp-github-issues-remote</h1>
  <p>A remote Model Context Protocol server for GitHub Issues, using OAuth 2.1 + PKCE and envelope-encrypted per-user token storage.</p>
  <p><a class="btn" href="/oauth/start">Connect GitHub</a></p>
  <p>After connecting you get a session JWT to wire into your MCP client. See <a href="https://github.com/ygerfal/mcp-github-issues-remote">the README</a> for setup.</p>
</body>
</html>`);
});

// ------------- OAuth 2.1 + PKCE -------------

app.get("/oauth/start", (_req, res) => {
  pruneStaleFlows();
  const url = buildAuthorizeUrl();
  res.redirect(302, url);
});

app.get("/oauth/callback", async (req, res) => {
  const code = String(req.query.code || "");
  const state = String(req.query.state || "");
  const error = req.query.error;
  if (error) {
    res.status(400).type("text").send(`GitHub OAuth error: ${error}`);
    return;
  }
  if (!code || !state) {
    res.status(400).type("text").send("Missing code or state");
    return;
  }
  try {
    const { userId, login } = await handleCallback(code, state);
    const jwt = await issueSessionJwt(userId, login);
    res.type("html").send(`<!doctype html>
<html>
<head><meta charset="utf-8"><title>Connected</title>
<style>
  body { font-family: -apple-system, sans-serif; max-width: 640px; margin: 3em auto; padding: 0 1em; line-height: 1.5; color: #222; }
  pre { background: #f4f4f4; padding: 12px; border-radius: 6px; overflow-x: auto; word-break: break-all; white-space: pre-wrap; }
  code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
</style>
</head>
<body>
  <h1>Connected as @${login}</h1>
  <p>Your GitHub token has been envelope-encrypted and stored. Never in plaintext, never in logs.</p>
  <h2>Session token</h2>
  <p>Wire this into your MCP client's Authorization header as <code>Bearer &lt;token&gt;</code>:</p>
  <pre>${jwt}</pre>
  <p>Valid for 30 days. Rotate by revisiting <a href="/oauth/start">/oauth/start</a>.</p>
</body>
</html>`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    res.status(500).type("text").send(`OAuth callback failed: ${msg}`);
  }
});

// ------------- MCP endpoint (stub for Day 1) -------------

app.post("/mcp", requireSession, async (req: AuthedRequest, res) => {
  // Day 3 wires @modelcontextprotocol/sdk's Streamable HTTP transport here,
  // decrypting the user's GitHub token per-call via envelope encryption
  // and passing it to the Octokit client inside each tool handler.
  res.status(501).json({
    error: "not_yet_implemented",
    note: "MCP handler lands Day 3",
    session: { userId: req.userId, login: req.login },
  });
});

// ------------- Boot -------------

const port = Number(process.env.PORT || 8787);
app.listen(port, () => {
  console.log(`mcp-github-issues-remote listening on :${port}`);
  console.log(`Public base: ${process.env.PUBLIC_BASE_URL || `http://localhost:${port}`}`);
});
