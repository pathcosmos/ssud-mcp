# SSUD MCP

A local stdio MCP client for browsing, searching, and transferring files through an existing
SSUD server. Codex, Claude Code, and other stdio MCP hosts can install it without cloning
the SSUD server repository. You need a reachable SSUD server with agent approval enabled and a
web account that has access to the files you want to use.

## Install and connect

Install [uv](https://docs.astral.sh/uv/) and create a local transfer directory on the machine
that runs your agent. Replace the example URL and paths in the configuration below. The published
wheel is pinned to version 0.1.0. To update, replace the URL with the wheel URL for a newer
[release](https://github.com/pathcosmos/ssud-mcp/releases) and restart your MCP host.

### Codex

Add this entry to the host's Codex MCP configuration:

```toml
[mcp_servers.ssud]
command = "uvx"
args = ["--from", "https://github.com/pathcosmos/ssud-mcp/releases/download/v0.1.0/ssud_mcp-0.1.0-py3-none-any.whl", "ssud-mcp"]
tool_timeout_sec = 3600

[mcp_servers.ssud.env]
SSUD_AGENT_URL = "https://files.example.org"
SSUD_AGENT_LOCAL_ROOT = "/absolute/path/to/ssud-transfers"
SSUD_AGENT_OPEN_ON_START = "true"
```

### Claude Code

Merge the entry into the project's `.mcp.json`:

```json
{
  "mcpServers": {
    "ssud": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "https://github.com/pathcosmos/ssud-mcp/releases/download/v0.1.0/ssud_mcp-0.1.0-py3-none-any.whl", "ssud-mcp"],
      "env": {
        "SSUD_AGENT_URL": "https://files.example.org",
        "SSUD_AGENT_LOCAL_ROOT": "/absolute/path/to/ssud-transfers",
        "SSUD_AGENT_OPEN_ON_START": "true"
      }
    }
  }
}
```

1. Restart the agent and ask it to run `connect_files`. The link may open automatically.
2. Open the latest approval link, sign in to SSUD in the browser, and select your share
   and Home folder. Approve the connection in the browser.
3. Ask the agent to run `browse_files(path="")` to verify access. If a code expires, ask
   it to run `connect_files` again and open the newest link.

Browser approval is the default. Your password stays in the website's login flow, and the
client keeps its access token in memory. The approved Home folder and the website's access
rules apply to each tool call. Use HTTPS for remote access. For an operator-approved HTTP-only
installation, explicitly set `SSUD_AGENT_ALLOW_HTTP=true` in the MCP environment. The server
must also allow HTTP pairing, and HTTP does not encrypt traffic.

## Use

- Browse or search from the approved Home folder.
- Upload from, or download to, the configured local transfer directory. Transfers do not
  overwrite existing files.
- Create or rename folders and files, and delete one file or empty folder after user
  confirmation. Availability depends on the installed server version and your permissions.
- Inspect workspace and index status, adjust supported preferences, or disconnect.

## Develop

```bash
uv sync --locked
uv run pytest
uv run ruff check .
uv build
```

Licensed under MIT.
