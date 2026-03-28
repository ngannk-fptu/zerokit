# OpenCode Zerokit Test Bundle

This folder is a parallel, non-destructive OpenCode wiring bundle for
ZeroKit. It does not modify the existing `opencode-zerokit` or
`opencode-vanilla` wrappers.

## What It Does

- Builds a disposable shadow project at
  `/tmp/zerokit-opencode/projects/zerokit-test`
- Injects a project-level `opencode.json` and `AGENTS.md` into that shadow
  project
- Exposes OpenCode custom agents from `opencode-zerokit-test/.opencode/agents/`
- Exposes ZeroKit skill packs by creating `.agents/skills -> .agent/skills`
  inside the shadow project
- Loads a debug plugin that writes
  `.zerokit-debug/wiring.json` inside the shadow project when the plugin loads

## Use

Start the wired test runtime:

```bash
./opencode-zerokit-test/bin/opencode.sh
```

Inspect resolved config:

```bash
./opencode-zerokit-test/bin/opencode.sh debug config
```

List custom agents:

```bash
./opencode-zerokit-test/bin/opencode.sh agent list
```

List discovered skills:

```bash
./opencode-zerokit-test/bin/opencode.sh debug skill
```

Reset the isolated runtime state:

```bash
./opencode-zerokit-test/bin/reset.sh
```

## Important

The existing `opencode-zerokit` command is unchanged. If you want that command
to use this bundle, the existing devcontainer wrapper scripts must be edited.
