# DevContainer OpenCode Testing

This repo includes an isolated DevContainer workflow for testing OpenCode in two clean modes:

- `zerokit`: clean container-local OpenCode plus this repo's `.opencode`
- `vanilla`: clean container-local OpenCode with no repo-local `.opencode`

## Why this exists

- Avoid using your host OpenCode install and host OpenCode state.
- Keep `vanilla` truly vanilla.
- Let `zerokit` add only ZeroKit's repo-local OpenCode integration.

## Included commands

- `opencode-vanilla`
- `opencode-zerokit`
- `opencode-sync vanilla`
- `opencode-sync zerokit`
- `opencode-reset vanilla`
- `opencode-reset zerokit`
- Compatibility aliases: `opencode-a` = `opencode-zerokit`, `opencode-b` = `opencode-vanilla`

## Important behavior

OpenCode automatically loads project-level `.opencode` directories.

Because this repo already has a `.opencode/`, launching OpenCode directly in the repo root is **not** vanilla.

To avoid that, the wrappers create a clean shadow copy of the repo outside the git tree:

- Source repo: `/workspaces/zerokit-dev`
- Shadow `zerokit`: `/tmp/zerokit-opencode/projects/zerokit`
- Shadow `vanilla`: `/tmp/zerokit-opencode/projects/vanilla`

The shadow copy excludes:

- `.opencode`
- `.claude`
- `.agents`
- `.devcontainer`
- `.git`
- `.mcp.json`
- `AGENTS.md`
- `CLAUDE.md`
- `CONTEXT.md`
- local caches and build artifacts

## Runtime behavior

### `opencode-zerokit`

- Rebuilds the clean `zerokit` shadow project
- Uses isolated state under `.devcontainer/state/zerokit/`
- Injects this repo's `.opencode` through `OPENCODE_CONFIG_DIR`
- Disables external Claude-style skills and prompt loading via env flags

This is the "ZeroKit enabled" run.

### `opencode-vanilla`

- Rebuilds the clean `vanilla` shadow project
- Uses isolated state under `.devcontainer/state/vanilla/`
- Does **not** inject this repo's `.opencode`
- Disables external Claude-style skills and prompt loading via env flags

This is the "vanilla OpenCode" run.

## Typical usage

1. Start the ZeroKit-enabled side:
   - `opencode-zerokit`
2. Start the vanilla side:
   - `opencode-vanilla`
3. If you changed files in the source repo and want a fresh shadow copy:
   - `opencode-sync zerokit`
   - `opencode-sync vanilla`
4. If you want to wipe OpenCode state and rebuild from scratch:
   - `opencode-reset zerokit`
   - `opencode-reset vanilla`

## Verification

Inside the container:

- `opencode --version`
- `uv --version`
- `bun --version`

For wrapper behavior:

- `opencode-zerokit`
- `opencode-vanilla`

## Troubleshooting

### `vanilla` still looks customized

Reset and rerun the vanilla runtime:

- `opencode-reset vanilla`
- `opencode-vanilla`

### `zerokit` does not include ZeroKit behavior

Confirm the repo still has `.opencode/`:

- `find .opencode -maxdepth 3 -print`

The `zerokit` runtime injects that directory directly.
