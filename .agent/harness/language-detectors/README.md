# Language Detector Contract

Language detectors are repository profiling modules, not IDE/LSP integrations.

Responsibilities:
- detect language and framework presence from filesystem/build metadata
- identify build/test entry commands for health checks
- extract attack-surface candidates (HTTP, RPC, queue, CLI, parser boundaries)
- provide trust boundaries and high-risk sink categories

Non-goals:
- no editor protocol integration
- no compiler replacement
- no autonomous exploitation logic

Output contract is defined in `detector_contract.json`.
