# Agent Harness Scope Lock

## Mission
Turn any capable AI agent into a professional whitebox pentester via
plug-and-play skills, methodology, tool connectors, and evidence contracts.

## Core Model
The agent runtime (OpenCode first, Claude Code/Codex/Copilot second)
provides reasoning. ZeroKit provides the pentest methodology and tools.
Agent decides; scripts execute.

## Primary Language Targets
- .NET / C#
- TypeScript / JavaScript
- Java
- Go
- Python

## Secondary Language Targets
- PHP
- C/C++
- Other languages only when directly needed for reachable findings

## Canonical Workflow Surface
- `methodology/master-harness.md`
- `methodology/phases/phase-01-intake-plan.md` ... `phase-06-report-regression.md`

## Hard Rules
1. No proof, no vulnerability.
2. Every reported issue must include reproducible evidence.
3. Every confirmed issue must include root cause and remediation guidance.
4. Prefer source-code reachability and exploitability over scanner noise.
5. Agent decides what to investigate and when. No autonomous scan chains.

## In Scope
- Attack surface mapping
- Threat modeling
- Static detection and finding normalization
- Verification gate (PoC/runtime evidence)
- Variant analysis
- Patch verification
- Reporting and regression guidance

## Out of Scope
- Autonomous pipeline execution without agent judgment
- Separate LLM gateway or API client (agent runtime handles reasoning)
- Generic productivity or design workflows
- Unrelated blockchain/mobile scanners for this harness baseline
