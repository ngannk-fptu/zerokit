# Orchestrator Shim Scope and Roadmap

This document defines what the current orchestration shim does, and
what the harness expansion path looks like.

## Core Principle

ZeroKit is agent-driven, not pipeline-driven. The shim scaffolds run
directories and validates artifacts. The agent runtime (Claude Code,
Codex, Copilot, etc.) provides the reasoning and decision-making.

There is no "full orchestrator" that replaces the agent. Expansion
means better tool connectors and richer skill packs, not more
autonomous execution.

## Current Shim Responsibilities

Implemented as agent-driven methodology plus harness scripts; no standalone master workflow runner is required.

- Enforces canonical phase order from `.agent/methodology/master-harness.md`.
- Initializes run directory structure under `.agent/artifacts/runs/<run_id>/`.
- Emits deterministic placeholder artifacts aligned to artifact contract.
- Captures phase-level status and diagnostics in `run_state.json`.
- Marks all shim output with `"source": "orchestration-shim"` and `"simulated": true`.
- Fails fast on phase exceptions and persists failure context.

## What the Shim Is Not

- Not a scanner orchestrator. The agent decides which tools to run.
- Not an LLM gateway. The agent runtime is the reasoning engine.
- Not an autonomous executor. The agent follows the workflow, the shim scaffolds.

## Expansion Path (Agent-First)

Better tool connectors:
- Semgrep subprocess wrapper with JSON normalization
- Gitleaks subprocess wrapper with finding normalization
- Joern HTTP client for CPG queries and taint analysis
- Docker sandbox wrapper for PoC execution in Phase 04

Better skill packs:
- Richer language-specific security patterns
- More PoC templates per CWE
- Variant search rule generators

Better artifact validation:
- Real-time schema validation during phase execution
- Cross-phase artifact consistency checks

## What Does NOT Change

- Agent decides, scripts execute.
- No proof, no vulnerability.
- Phase handoff is artifact-driven and schema-validated.
- Deterministic fallback paths remain for CI/smoke stability.
- Portable across agent runtimes by contract-first design.
