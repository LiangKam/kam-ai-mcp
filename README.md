# kam-ai-mcp

`kam-ai-mcp` is a Cocos Creator 3.8+ local AI bridge optimized for Codex.

It is designed as a safer, more portable evolution of the original `cocos-mcp-server` idea:

- a **Cocos Creator extension** runs inside the editor and talks to `Editor.Message` / `asset-db` / `scene`;
- a local **HTTP MCP server** exposes stable tools to Codex, Cursor, Claude, or other MCP clients;
- a **Codex Skill** stores the Cocos-specific operating rules so the model uses query-before-write, UUID-first operations, and safe prefab workflows.

## Key changes

- Project/plugin name is unified as `kam-ai-mcp`.
- Default bind host is `127.0.0.1`, not `0.0.0.0`.
- Default CORS origins are local only, not `*`.
- Optional Bearer token is supported.
- Workspace guard prevents Codex from editing the wrong open Cocos project.
- Dangerous actions require `confirm: true`.
- Prefab edits use dry-run, backups, validation, and reimport instead of guessed private APIs.
- Codex-facing workflow knowledge is extracted into `.agents/skills/kam-ai-mcp`.

## Install

```bash
npm install
npm run build
```

Install globally for all Cocos projects:

```bash
node scripts/install-cocos-extension.js --global
```

Install into one Cocos project:

```bash
node scripts/install-cocos-extension.js --project /path/to/cocos-project
```

Install the Codex skill:

```bash
node scripts/install-codex-skill.js
```

## MCP endpoint

Default endpoint:

```text
http://127.0.0.1:3000/mcp
```

MCP client config:

```json
{
  "mcpServers": {
    "kam-ai-mcp": {
      "type": "http",
      "url": "http://127.0.0.1:3000/mcp"
    }
  }
}
```

With auth token:

```json
{
  "mcpServers": {
    "kam-ai-mcp": {
      "type": "http",
      "url": "http://127.0.0.1:3000/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_TOKEN"
      }
    }
  }
}
```

## Repository layout

```text
source/                         Cocos extension and MCP server source
source/tools/                   Core tool implementations
.agents/skills/kam-ai-mcp/      Codex Skill extracted from MCP behavior
scripts/                        Install helpers
docs/                           Architecture, API, security, prefab policy
.github/workflows/build.yml     TypeScript build check
```

## Current scope

This first version provides a safe core bridge:

- server info and health
- scene query/save/hierarchy
- node query/create/delete/transform
- component query/add/remove/set property
- asset query/path/uuid/info
- prefab list/info/validate/instantiate/backup/json patch/uuid replacement

High-risk functions are intentionally gated. This project favors safe reproducible editor automation over broad but fragile private-API guesses.
