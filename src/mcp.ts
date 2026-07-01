/**
 * mcp.ts — factory for a per-request MCP server instance.
 *
 * Design:
 *  - Each incoming /mcp HTTP request creates a fresh MCP Server and transport.
 *  - The user's decrypted GitHub token is bound in closure to the tool handlers.
 *  - Plaintext token exists only for the lifetime of the request.
 *  - No server-wide singleton, no shared auth state — per-user isolation is
 *    enforced by the fact that each call is its own instance.
 *
 * This mirrors the KMS "decrypt-per-use" discipline: don't cache plaintext
 * secrets in long-lived memory. Cost is a small per-request setup overhead;
 * benefit is that a heap dump captures at most the currently-executing call's
 * token, not every active session's tokens.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ErrorCode,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { Octokit } from "@octokit/rest";

const TOOLS = [
  {
    name: "list_issues",
    description:
      "List issues in a GitHub repository. Use when the user wants to see open, closed, or all issues in a repo. Returns issue number, state, title, and author for each. Pull requests are filtered out so the result is true issues only.",
    inputSchema: {
      type: "object",
      properties: {
        repo: {
          type: "string",
          description:
            "Repository in 'owner/name' format, e.g. 'anthropics/anthropic-sdk-python'",
        },
        state: {
          type: "string",
          enum: ["open", "closed", "all"],
          description: "Issue state filter. Defaults to 'open'.",
        },
        limit: {
          type: "number",
          description: "Maximum issues to return (1-100). Defaults to 20.",
        },
      },
      required: ["repo"],
    },
  },
  {
    name: "create_issue",
    description:
      "Create a new issue in a GitHub repository. Use when the user wants to file a bug, request a feature, or track a task. Requires repo write permission. The created issue is attributed to the authenticated user in the GitHub audit log.",
    inputSchema: {
      type: "object",
      properties: {
        repo: { type: "string", description: "Repository in 'owner/name' format" },
        title: {
          type: "string",
          description: "Issue title — concise and action-oriented",
        },
        body: {
          type: "string",
          description: "Issue body in GitHub-flavored markdown",
        },
        labels: {
          type: "array",
          items: { type: "string" },
          description:
            "Optional list of label names to apply. Labels must already exist in the target repo.",
        },
      },
      required: ["repo", "title", "body"],
    },
  },
  {
    name: "add_comment",
    description:
      "Add a comment to an existing GitHub issue. Use when the user wants to reply to an issue thread. The comment is attributed to the authenticated user in the GitHub audit log.",
    inputSchema: {
      type: "object",
      properties: {
        repo: { type: "string", description: "Repository in 'owner/name' format" },
        issue_number: { type: "number", description: "Issue number to comment on" },
        body: {
          type: "string",
          description: "Comment body in GitHub-flavored markdown",
        },
      },
      required: ["repo", "issue_number", "body"],
    },
  },
];

function parseRepo(input: unknown): { owner: string; repo: string } {
  if (typeof input !== "string" || !input.includes("/")) {
    throw new McpError(
      ErrorCode.InvalidParams,
      "repo must be a string in 'owner/name' format"
    );
  }
  const [owner, repo] = input.split("/");
  if (!owner || !repo) {
    throw new McpError(
      ErrorCode.InvalidParams,
      "repo must be a non-empty 'owner/name' pair"
    );
  }
  return { owner, repo };
}

/**
 * Build a fully-wired MCP server for one request.
 * The GitHub token is captured in the closures below and is discarded when
 * the caller drops the returned Server.
 */
export function createMcpServer(params: {
  githubToken: string;
  actorLogin: string;
}): Server {
  const octokit = new Octokit({ auth: params.githubToken });

  const server = new Server(
    { name: "mcp-github-issues-remote", version: "0.1.0" },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: args = {} } = req.params;

    try {
      if (name === "list_issues") {
        const { owner, repo } = parseRepo(args.repo);
        const state = (args.state as "open" | "closed" | "all") ?? "open";
        const limit = Math.min(Math.max((args.limit as number) ?? 20, 1), 100);

        const { data } = await octokit.issues.listForRepo({
          owner,
          repo,
          state,
          per_page: limit,
        });
        const issues = data.filter((i) => !i.pull_request);
        const text =
          issues.length === 0
            ? `No ${state} issues found in ${owner}/${repo}.`
            : issues
                .map(
                  (i) =>
                    `#${i.number} [${i.state}] ${i.title}  (@${i.user?.login ?? "unknown"})`
                )
                .join("\n");
        return { content: [{ type: "text", text }] };
      }

      if (name === "create_issue") {
        const { owner, repo } = parseRepo(args.repo);
        const title = args.title as string;
        const body = args.body as string;
        const labels = (args.labels as string[]) ?? undefined;
        if (!title || !body) {
          throw new McpError(
            ErrorCode.InvalidParams,
            "title and body are required"
          );
        }
        const { data } = await octokit.issues.create({
          owner,
          repo,
          title,
          body,
          labels,
        });
        return {
          content: [
            {
              type: "text",
              text: `Created issue #${data.number} in ${owner}/${repo} as @${params.actorLogin}: ${data.html_url}`,
            },
          ],
        };
      }

      if (name === "add_comment") {
        const { owner, repo } = parseRepo(args.repo);
        const issue_number = args.issue_number as number;
        const body = args.body as string;
        if (typeof issue_number !== "number" || !body) {
          throw new McpError(
            ErrorCode.InvalidParams,
            "issue_number (number) and body (string) are required"
          );
        }
        const { data } = await octokit.issues.createComment({
          owner,
          repo,
          issue_number,
          body,
        });
        return {
          content: [
            {
              type: "text",
              text: `Added comment to ${owner}/${repo}#${issue_number} as @${params.actorLogin}: ${data.html_url}`,
            },
          ],
        };
      }

      throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
    } catch (err) {
      if (err instanceof McpError) throw err;
      const msg = err instanceof Error ? err.message : String(err);
      throw new McpError(ErrorCode.InternalError, `GitHub API error: ${msg}`);
    }
  });

  return server;
}
