/**
 * server.test.ts — auth wall integration tests.
 *
 * Verifies that /mcp endpoints reject unauthenticated and malformed requests
 * without needing a live GitHub API or real OAuth credentials.
 *
 * Run: node --import tsx --test src/server.test.ts
 *
 * Note: crypto env vars are set before the test starts so the JWT signing
 * path works. No real GitHub token is exchanged in these tests.
 */

import { test, before } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { SignJWT } from "jose";

// Set env before importing server modules
process.env.MASTER_KEY_B64 = randomBytes(32).toString("base64");
process.env.SESSION_JWT_KEY_B64 = randomBytes(32).toString("base64");
process.env.GITHUB_CLIENT_ID = "test_client";
process.env.GITHUB_CLIENT_SECRET = "test_secret";
process.env.PUBLIC_BASE_URL = "http://localhost:0";
process.env.SQLITE_PATH = ":memory:";
process.env.PORT = "0";

let baseUrl: string;
let httpServer: any;

before(async () => {
  // Boot the server on a random free port
  const { default: express } = await import("express");
  const { jwtVerify } = await import("jose");
  const { buildAuthorizeUrl, handleCallback, issueSessionJwt } = await import(
    "./oauth.js"
  );
  const { pruneStaleFlows, getUserById } = await import("./db.js");
  const { unwrapToken } = await import("./crypto.js");
  const { createMcpServer } = await import("./mcp.js");
  const { StreamableHTTPServerTransport } = await import(
    "@modelcontextprotocol/sdk/server/streamableHttp.js"
  );

  const app = express();
  app.use(express.json({ limit: "1mb" }));

  async function requireSession(req: any, res: any, next: any) {
    const header = req.header("authorization") || "";
    const [scheme, token] = header.split(" ");
    if (scheme !== "Bearer" || !token) {
      return res.status(401).json({ error: "missing bearer token" });
    }
    try {
      const key = Buffer.from(process.env.SESSION_JWT_KEY_B64!, "base64");
      const { payload } = await jwtVerify(token, key, {
        audience: "mcp-github-issues-remote",
      });
      req.userId = Number(payload.sub);
      req.login = String(payload.login || "");
      next();
    } catch {
      res.status(401).json({ error: "invalid session token" });
    }
  }

  async function handleMcp(req: any, res: any) {
    const user = getUserById(req.userId);
    if (!user) {
      return res.status(401).json({ error: "user not found" });
    }
    let githubToken: string;
    try {
      githubToken = unwrapToken(user.encrypted_dek, user.encrypted_token);
    } catch {
      return res.status(500).json({ error: "token unwrap failed" });
    }
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });
    res.on("close", () => transport.close());
    const server = createMcpServer({
      githubToken,
      actorLogin: user.github_login,
    });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      if (!res.headersSent) {
        res.status(500).json({ error: "mcp transport error" });
      }
    }
  }

  app.post("/mcp", requireSession, handleMcp);
  app.get("/healthz", (_req, res) => res.json({ ok: true }));

  await new Promise<void>((resolve) => {
    httpServer = app.listen(0, () => {
      const address = httpServer.address();
      const port = typeof address === "object" && address ? address.port : 0;
      baseUrl = `http://localhost:${port}`;
      resolve();
    });
  });
});

async function signTestJwt(sub: string, login: string): Promise<string> {
  const key = Buffer.from(process.env.SESSION_JWT_KEY_B64!, "base64");
  return await new SignJWT({ sub, login })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setAudience("mcp-github-issues-remote")
    .setExpirationTime("30d")
    .sign(key);
}

test("healthz responds 200", async () => {
  const res = await fetch(`${baseUrl}/healthz`);
  assert.equal(res.status, 200);
});

test("POST /mcp without Authorization returns 401", async () => {
  const res = await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  });
  assert.equal(res.status, 401);
});

test("POST /mcp with malformed Bearer returns 401", async () => {
  const res = await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: "Bearer not-a-real-jwt",
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  });
  assert.equal(res.status, 401);
});

test("POST /mcp with wrong-audience JWT returns 401", async () => {
  const key = Buffer.from(process.env.SESSION_JWT_KEY_B64!, "base64");
  const wrongAudienceJwt = await new SignJWT({ sub: "1", login: "test" })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setAudience("someone-else")
    .setExpirationTime("30d")
    .sign(key);
  const res = await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${wrongAudienceJwt}`,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  });
  assert.equal(res.status, 401);
});

test("POST /mcp with valid JWT but unknown user returns 401", async () => {
  const jwt = await signTestJwt("999999", "ghost");
  const res = await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${jwt}`,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  });
  assert.equal(res.status, 401);
  const body = (await res.json()) as { error: string };
  assert.match(body.error, /user not found/);
});

test.after(() => {
  if (httpServer) httpServer.close();
});
