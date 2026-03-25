# DevContainer OpenCode Testing

This repo includes an isolated DevContainer workflow for testing OpenCode in two clean modes:

- Profile `A`: clean container-local OpenCode plus this repo's `.opencode`
- Profile `B`: clean container-local OpenCode with no repo-local `.opencode`

## Why this exists

- Avoid using your host OpenCode install and host OpenCode state.
- Keep profile `B` truly vanilla.
- Let profile `A` add only ZeroKit's repo-local OpenCode integration.

## Included commands

- `opencode-a`
- `opencode-b`
- `opencode-sync a`
- `opencode-sync b`
- `opencode-reset a`
- `opencode-reset b`

## Important behavior

OpenCode automatically loads project-level `.opencode` directories.

Because this repo already has a `.opencode/`, launching OpenCode directly in the repo root is **not** vanilla.

To avoid that, the wrappers create a clean shadow copy of the repo outside the git tree:

- Source repo: `/workspaces/zerokit-dev`
- Shadow A: `/tmp/zerokit-opencode/projects/a`
- Shadow B: `/tmp/zerokit-opencode/projects/b`

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

## Profile behavior

### `opencode-a`

- Rebuilds profile A's clean shadow project
- Uses isolated state under `.devcontainer/state/a/`
- Injects this repo's `.opencode` through `OPENCODE_CONFIG_DIR`
- Disables external Claude-style skills and prompt loading via env flags

This is the "ZeroKit enabled" run.

### `opencode-b`

- Rebuilds profile B's clean shadow project
- Uses isolated state under `.devcontainer/state/b/`
- Does **not** inject this repo's `.opencode`
- Disables external Claude-style skills and prompt loading via env flags

This is the "vanilla OpenCode" run.

## Typical usage

1. Start the ZeroKit-enabled side:
   - `opencode-a`
2. Start the vanilla side:
   - `opencode-b`
3. If you changed files in the source repo and want a fresh shadow copy:
   - `opencode-sync a`
   - `opencode-sync b`
4. If you want to wipe OpenCode state and rebuild from scratch:
   - `opencode-reset a`
   - `opencode-reset b`

## Verification

Inside the container:

- `opencode --version`
- `uv --version`
- `bun --version`

For wrapper behavior:

- `opencode-a`
- `opencode-b`

## Troubleshooting

### B still looks customized

Reset and rerun profile B:

- `opencode-reset b`
- `opencode-b`

### A does not include ZeroKit behavior

Confirm the repo still has `.opencode/`:

- `find .opencode -maxdepth 3 -print`

Profile A injects that directory directly.
