# ZeroKit Test Runtime

This shadow project is the ZeroKit-enabled OpenCode test runtime.

Project instructions are loaded through `opencode.json`.

Use the `pentest-lead` agent as the primary entrypoint for whitebox security
assessments. The supporting specialist agents are:

- `recon`
- `scanner`
- `exploiter`
- `analyst`

Use the `skill` tool for the ZeroKit skill packs when they are relevant.
The canonical methodology and harness content still lives under `.agent/`.
