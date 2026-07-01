# Deploy — Fly.io + GitHub OAuth App

Two things you set up: (1) a GitHub OAuth App so users can sign in, (2) the Fly.io machine that hosts the server. Do them in this order — the OAuth app's callback URL depends on the deploy URL.

## Step 1 — Install Fly CLI + authenticate

```bash
# macOS
curl -L https://fly.io/install.sh | sh

# Add to PATH if the installer didn't (check the installer's output)
export FLYCTL_INSTALL="$HOME/.fly"
export PATH="$FLYCTL_INSTALL/bin:$PATH"

fly version           # should print something like "flyctl v0.x.x"
fly auth signup       # or `fly auth login` if you already have an account
```

Fly free tier covers this deploy comfortably — one shared-cpu-1x machine + a 1GB volume.

## Step 2 — Provision the app (do NOT deploy yet)

From the repo root:

```bash
cd /Users/yg/claudecode/projects/mcp-github-issues-remote

# --no-deploy so we can set secrets before the first boot
fly launch --no-deploy --copy-config --name mcp-gh-issues-remote --region sea
```

If Fly complains the name is taken, pick another (e.g. `mcp-gh-issues-yousef`) and update `fly.toml` + `PUBLIC_BASE_URL` accordingly.

## Step 3 — Create the persistent volume

SQLite writes to `/data/vault.db` per the config. Volume must exist before boot.

```bash
fly volumes create vault --size 1 --region sea
```

## Step 4 — Generate + set the crypto secrets

```bash
fly secrets set \
  MASTER_KEY_B64=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64'))") \
  SESSION_JWT_KEY_B64=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64'))")
```

**Do not** commit these values anywhere. Fly stores them encrypted at rest and injects them as env vars only at boot. Losing them means every existing user has to re-authorize; **rotating** them (Day 5 topic) is a one-line re-wrap.

## Step 5 — Register the GitHub OAuth App

Go to https://github.com/settings/developers → **OAuth Apps** → **New OAuth App**.

Fill in exactly:

| Field | Value |
|---|---|
| Application name | `mcp-github-issues-remote` (or whatever you want) |
| Homepage URL | `https://mcp-gh-issues-remote.fly.dev` |
| Application description | `Remote MCP server for GitHub Issues with OAuth 2.1 + PKCE.` (optional) |
| Authorization callback URL | `https://mcp-gh-issues-remote.fly.dev/oauth/callback` |
| Enable Device Flow | leave unchecked |

Click **Register application**.

On the app page:
- Copy the **Client ID** — starts with `Iv1.` or `Ov23li.`
- Click **Generate a new client secret** → copy the secret (shown once)

Set both on Fly:

```bash
fly secrets set \
  GITHUB_CLIENT_ID=Iv1.xxxxxxxxxxxxxxxx \
  GITHUB_CLIENT_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

## Step 6 — Deploy

```bash
fly deploy
```

Fly builds the Dockerfile, pushes the image, mounts the volume, injects secrets, boots the container. First deploy takes 3-6 minutes (native `better-sqlite3` compile).

## Step 7 — Smoke test

```bash
# Health check
curl https://mcp-gh-issues-remote.fly.dev/healthz
# Expected: {"ok":true,"version":"0.1.0"}

# OAuth start — should 302 to github.com/login/oauth/authorize
curl -I https://mcp-gh-issues-remote.fly.dev/oauth/start
```

Then in a browser:

```
https://mcp-gh-issues-remote.fly.dev
```

Click **Connect GitHub** → authorize on GitHub → land on the connected-as-@you page with a session JWT displayed. Copy that JWT — you'll wire it into Claude Desktop / Cursor / Claude Code in Step 8.

## Step 8 — Wire an MCP client

Claude Desktop config (macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "github-issues-remote": {
      "url": "https://mcp-gh-issues-remote.fly.dev/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_SESSION_JWT_FROM_STEP_7"
      }
    }
  }
}
```

Claude Code CLI:

```bash
claude mcp add github-issues-remote --url https://mcp-gh-issues-remote.fly.dev/mcp \
  --header "Authorization: Bearer YOUR_SESSION_JWT_FROM_STEP_7"
```

Restart the host. Ask it: *"List the most recent 5 open issues in anthropics/anthropic-sdk-python"* — the model should call `list_issues` and stream the result back.

## Step 9 — Log the deployment

Commit + push the DEPLOY.md so the public repo history shows Day 4 landing:

```bash
git add DEPLOY.md Dockerfile fly.toml
git commit -m "Day 4: Fly.io deployment guide + Dockerfile"
git push
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `fly deploy` fails at `npm run build` | Wrong Node version in Dockerfile | Ensure Dockerfile uses `node:20-bookworm-slim`, not an older tag |
| Boot loop with `MASTER_KEY_B64 is required` | Secret not set | `fly secrets list` to confirm; re-run Step 4 |
| OAuth callback returns "Invalid or expired OAuth state" | `PUBLIC_BASE_URL` doesn't match the callback URL registered on GitHub | Verify both in Fly env and GitHub app settings |
| `fly logs` shows `SQLITE_CANTOPEN` | Volume not mounted | Confirm Step 3 ran and `fly.toml` `[[mounts]]` section is intact |
| Connect-GitHub button hangs | GitHub OAuth App secret wrong | Regenerate secret, `fly secrets set GITHUB_CLIENT_SECRET=...` |

## What's next (Day 5)

- Expanded threat model doc (`docs/threat-model.md`) covering key rotation, session revocation backlog, SQLite backup strategy
- Loom demo showing OAuth flow → Claude Desktop → issue creation live
- README polish: architecture diagram, deploy badge
