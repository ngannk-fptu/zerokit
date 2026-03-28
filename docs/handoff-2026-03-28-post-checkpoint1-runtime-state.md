---
date: 2026-03-28
author: codex
skills_used: [documentation-reporting]
agents_used: []
tags: [meeting-notes, zerokit, documentation, workflows, completed, medium-risk, with-diff, manual-review]
---

# Post-Checkpoint 1 Handoff: Runtime And Devcontainer Changes

## Context

This handoff summarizes changes made after the previous Claude handoff document:

- `docs/dev/checkpoint-1-usage-guide-2026-03-27.md`

Timeline anchor used for this report:

- Filesystem modify time: `2026-03-27 15:25:03 +0700`

Important note:

- No git commits were found after that timestamp.
- The changes below are based on the current working tree state and runtime verification, not a post-handoff commit history.
- The checkpoint guide itself is currently untracked in the working tree.

## Actions Taken

### 1. Renamed the A/B runtime model to explicit names

The OpenCode runtime naming was shifted from ambiguous profile letters to explicit intent:

- `opencode-vanilla` = clean OpenCode baseline
- `opencode-zerokit` = ZeroKit-enabled runtime
- Compatibility aliases were kept:
  - `opencode-b` = `opencode-vanilla`
  - `opencode-a` = `opencode-zerokit`

Files reflecting this shift:

- `README.md`
- `docs/dev/devcontainer-testing.md`
- `.devcontainer/postCreate.sh`

### 2. Removed the old tracked profile config stubs

The previous tracked placeholders under `.devcontainer/opencode/profiles/a` and `b` were deleted:

- `.devcontainer/opencode/profiles/a/opencode.jsonc`
- `.devcontainer/opencode/profiles/a/plugins/.gitkeep`
- `.devcontainer/opencode/profiles/b/opencode.jsonc`
- `.devcontainer/opencode/profiles/b/plugins/.gitkeep`

Related ignore cleanup:

- `.gitignore` now ignores `.devcontainer/opencode/profiles/`

### 3. Added a parallel ZeroKit runtime bundle

A new bundle was created at:

- `opencode-zerokit-test/`

Purpose:

- Keep the live ZeroKit runtime wiring isolated from the baseline runtime
- Avoid mutating the existing repo-local `.opencode` layout directly
- Make the new OpenCode-facing configuration easy to version as a separate unit

Bundle contents include:

- `opencode-zerokit-test/opencode.json`
- `opencode-zerokit-test/AGENTS.md`
- `opencode-zerokit-test/.opencode/agents/*.md`
- `opencode-zerokit-test/.opencode/plugins/zerokit-wiring-debug.js`
- `opencode-zerokit-test/bin/opencode.sh`
- `opencode-zerokit-test/bin/sync-shadow.sh`
- `opencode-zerokit-test/bin/reset.sh`

### 4. Wired ZeroKit instructions, agents, and skills into OpenCode

The new bundle does the following:

- Sets `default_agent` to `pentest-lead`
- Loads project instructions from:
  - `AGENTS.md`
  - `.agent/agent.md`
  - `.agent/HARNESS_SCOPE.md`
  - `.agent/methodology/master-harness.md`
  - `.agent/methodology/phases/*.md`
- Exposes OpenCode custom agents:
  - `pentest-lead`
  - `recon`
  - `scanner`
  - `exploiter`
  - `analyst`
- Exposes ZeroKit skills through a symlink:
  - `opencode-zerokit-test/.opencode/skills -> ../../.agent/skills`
- Adds a debug plugin that writes:
  - `.zerokit-debug/wiring.json`

### 5. Rewired the existing zerokit wrapper path

The existing runtime command path was updated so the standard zerokit wrapper now uses the new bundle.

Operational behavior now:

- `opencode-vanilla` still uses the old clean wrapper flow
- `opencode-zerokit` now routes into `opencode-zerokit-test/`
- `opencode-sync zerokit` and `opencode-reset zerokit` route into the same bundle

Implementation detail:

- This wrapper rewiring currently lives in `.devcontainer/bin/`
- Those scripts are present locally but are not tracked by git at the time of this handoff

Affected local launcher scripts:

- `.devcontainer/bin/opencode-profile`
- `.devcontainer/bin/opencode-sync`
- `.devcontainer/bin/opencode-reset`
- `.devcontainer/bin/opencode-vanilla`
- `.devcontainer/bin/opencode-zerokit`
- `.devcontainer/bin/opencode-a`
- `.devcontainer/bin/opencode-b`

### 6. Added explicit Docker support to the devcontainer

To support fixture startup and PoC verification from inside the devcontainer, the official Dev Container Docker feature was added:

- `.devcontainer/devcontainer.json`

Added feature:

- `ghcr.io/devcontainers/features/docker-outside-of-docker:1.8.0`

This change requires a devcontainer rebuild before `docker` and `docker compose` can be relied on inside the container.

### 7. Reduced CI/runtime noise

The stale reference checker was updated to ignore runtime-generated paths:

- `opencode-zerokit-test`
- `test-results`

File:

- `tools/ci/check_stale_references.py`

## Results

### Current runtime model

Current intended behavior:

- `opencode-vanilla`
  - clean baseline
  - isolated state under `.devcontainer/state/vanilla`
  - shadow worktree under `/tmp/zerokit-opencode/projects/vanilla`

- `opencode-zerokit`
  - uses `opencode-zerokit-test/`
  - isolated state under `.devcontainer/state/zerokit`
  - shadow worktree under `/tmp/zerokit-opencode/projects/zerokit`

### Verified runtime behavior

The following behaviors were manually verified during this session:

- `opencode-sync zerokit` resolved to `/tmp/zerokit-opencode/projects/zerokit`
- `opencode-sync vanilla` resolved to `/tmp/zerokit-opencode/projects/vanilla`
- `opencode-profile zerokit agent list` exposed the custom agents:
  - `pentest-lead`
  - `recon`
  - `scanner`
  - `exploiter`
  - `analyst`
- `opencode-profile zerokit debug skill` exposed the ZeroKit skill packs
- `opencode-profile zerokit run hello` launched with `pentest-lead`
- The debug plugin wrote:
  - `/tmp/zerokit-opencode/projects/zerokit/.zerokit-debug/wiring.json`

### Guide validity after these changes

The Checkpoint 1 usage guide is still broadly valid for user flow, but one implementation statement is now stale:

- The guide still describes `opencode-zerokit` as loading the repo-local `.opencode` directly
- The live runtime now loads through `opencode-zerokit-test/`, which then injects the instructions, agents, skills, and debug plugin

## Decisions

- Keep explicit runtime names instead of relying on A/B semantics
- Preserve backward-compatible aliases for continuity
- Use a separate `opencode-zerokit-test/` bundle instead of mutating the original repo-local `.opencode` structure directly
- Use a symlink for skills instead of copying the skill tree
- Route the zerokit wrapper through the new bundle rather than replacing the vanilla baseline behavior
- Add explicit Docker support to the devcontainer instead of assuming host tooling will appear inside the container

## Next Steps

- Rebuild and reopen the devcontainer so the new Docker feature is applied
- Re-run `bash .devcontainer/postCreate.sh` or open a fresh shell if wrapper symlinks appear stale
- Update `docs/dev/checkpoint-1-usage-guide-2026-03-27.md` so it reflects the `opencode-zerokit-test/`-backed runtime
- Decide whether the `.devcontainer/bin/*` launcher scripts should be promoted into tracked source
- Clean or ignore any remaining runtime artifacts under:
  - `opencode-zerokit-test/.runtime`
  - `test-results/`
- After rebuild, verify Docker inside the devcontainer with:
  - `docker version`
  - `docker compose version`
  - `docker compose up --build` in `tests/fixtures/vuln-flask-app`
