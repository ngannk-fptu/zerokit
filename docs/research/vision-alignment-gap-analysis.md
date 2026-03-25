# Vision Alignment Gap Analysis: ZeroKit V3

## Executive Summary

ZeroKit V3 is a well-structured whitebox pentesting harness with solid artifact contracts and methodology. However, **significant gaps exist** between the current implementation and the user's vision for human-agent collaboration, transparency, selectable options UI, and OpenCode-first platform support.

---

## Vision Pillar 1: Human-Agent Collaboration

### User's Vision
> "A human reviewer can easily intervene to guide/steer/collab with the agent OR to takeover from one point then continue to handoff to the agent later."

### Current State: ❌ NOT IMPLEMENTED

**Findings:**
- No intervention points defined in the 6-phase workflow
- No pause/checkpoint mechanism between phases
- No handoff protocol documented
- Workflow is designed for autonomous completion: "Run these phases in order... Do not skip phases"
- Only implicit intervention: grep found zero mentions of "human", "intervention", "checkpoint", or "pause" in workflow docs
- The word "handoff" appears only in artifact contracts context (phase handoff = artifact exchange), not human↔agent handoff

**Evidence:**
- `.agent/methodology/master-harness.md`: Linear flow with no intervention hooks
- `.agent/methodology/phases/phase-04-verification-gate.md`: No human approval gate before promoting findings
- No `.agent/hooks/` directory exists

### Gap Score: **CRITICAL** — Core vision missing

---

## Vision Pillar 2: Transparency & Explainability

### User's Vision
> "The agent should be transparent as much as possible... explainable work, with documented actions so that a human reviewer can verify and replicate results."

### Current State: ⚠️ PARTIALLY IMPLEMENTED

**What Exists:**
- Structured JSON artifacts at each phase (good for traceability)
- Evidence capture requirements in Phase 04 (command, output, exit code, log path)
- Artifact contracts enforce schema validation
- Run directories preserve all phase outputs

**What's Missing:**
- No **decision log** — why agent chose certain hypotheses over others
- No **action trace** — what commands were run, in what order, with what parameters
- No **reasoning capture** — the "thinking" behind exploitability assessments
- No **timestamped audit trail** — when each action occurred
- Artifacts capture *results*, not *process*

**Evidence:**
- `artifact_contract.json`: Defines output schemas only, no decision/reasoning fields
- No `agent_actions.json` or `decision_log.json` in contracts
- `HARNESS_SCOPE.md`: No mention of transparency requirements

### Gap Score: **MEDIUM** — Foundation exists, but process transparency missing

---

## Vision Pillar 3: Selectable Options UI

### User's Vision
> "The way OpenCode asks + presents the user with selectable option paths are very much appreciated and intuitive. I would like to add this functionality to ZeroKit."

### Current State: ❌ NOT IMPLEMENTED

**Findings:**
- No decision points defined where agent should present options
- No schema for structured choices
- Workflow assumes autonomous agent decision-making
- No concept of "user picks the path" — agent picks internally

**Where Selectable Options Would Add Value:**
1. **Phase 01 (Intake)**: Assessment depth: quick-triage vs deep-audit
2. **Phase 03 (Static)**: Which rulesets to enable (security-audit, owasp-top-ten, language-specific)
3. **Phase 04 (Verify)**: Which findings to attempt PoC for (when list is large)
4. **Phase 05 (RCA)**: How deep to search for variants
5. **Any phase**: Agent should ask when it encounters ambiguity

### Gap Score: **CRITICAL** — Feature completely absent

---

## Vision Pillar 4: OpenCode-First Platform

### User's Vision
> "The main platform for ZeroKit to be ran on is now OpenCode (Claude Code, Antigravity, GitHub Copilot are all secondary)."

### Current State: ❌ NOT IMPLEMENTED

**Findings:**
- README lists all platforms equally: "Claude Code, Codex, GitHub Copilot, Antigravity"
- No OpenCode-specific configuration or hooks
- No `.opencode/` directory or OpenCode hooks
- Zero mentions of "OpenCode" in any ZeroKit documentation
- Architecture is intentionally "runtime-agnostic" — this conflicts with OpenCode-first

**Evidence:**
- `README.md`: Platform messaging needed to reflect OpenCode-first positioning
- `HARNESS_SCOPE.md`: Lists "Codex compatibility" as in-scope, no OpenCode mention
- No OpenCode hooks structure (would be `.opencode/hooks/`)

### Gap Score: **HIGH** — Platform priority not reflected in codebase

---

## Actionable Suggestions for Next Development Plan

### Category 1: Quick Wins (Documentation/Config — 1-2 days each)

| # | Suggestion | Effort | Impact |
|---|------------|--------|--------|
| Q1 | Update README to declare OpenCode as primary platform, others as secondary | 1 hr | Aligns docs with vision |
| Q2 | Add OpenCode hooks directory structure (`.opencode/hooks/`) with placeholder files | 2 hrs | Enables future hook development |
| Q3 | Document decision points in each phase where human input is valid | 4 hrs | Makes intervention opportunities explicit |
| Q4 | Add "Human Collaboration Guide" to `.agent/knowledge_base/` | 4 hrs | Teaches users how to intervene |

### Category 2: Medium Effort (New Features — 1-2 weeks each)

| # | Suggestion | Effort | Impact |
|---|------------|--------|--------|
| M1 | **Decision Log Artifact** — Add `decision_log.json` to artifact contracts capturing agent reasoning at each phase | 3 days | Transparency: why agent made choices |
| M2 | **Action Trace Artifact** — Add `action_trace.json` capturing timestamped commands/tool calls | 3 days | Transparency: what agent did |
| M3 | **Checkpoint System** — Add `CHECKPOINT.md` protocol allowing agent to pause and request human review | 5 days | Intervention: explicit pause points |
| M4 | **Selectable Options Schema** — Define JSON schema for presenting choices, integrate with OpenCode's `question` tool pattern | 5 days | Enables UI-driven collaboration |
| M5 | **Phase Gate Hooks** — Add pre/post hooks for each phase that can trigger human approval | 5 days | Intervention: automatic pause points |

### Category 3: Large Effort (Architectural — 2-4 weeks each)

| # | Suggestion | Effort | Impact |
|---|------------|--------|--------|
| L1 | **Human-Agent Handoff Protocol** — Full system for agent to serialize state, human to modify, agent to resume | 2 weeks | Complete vision pillar 1 |
| L2 | **OpenCode Hooks Integration** — Implement PreToolUse/PostToolUse hooks for ZeroKit tools, leverage OpenCode's native hook system | 2 weeks | OpenCode-first with full feature utilization |
| L3 | **Selectable Options Engine** — Full implementation of choice presentation at decision points, state management for selected paths | 3 weeks | Complete vision pillar 3 |
| L4 | **Audit Trail System** — Comprehensive logging system that captures all agent actions, decisions, and reasoning in human-readable + machine-parseable format | 3 weeks | Complete vision pillar 2 |

---

## Recommended Priority Order

Based on vision alignment impact:

1. **Q1-Q4** (Quick wins) — Immediate, low cost, signals direction change
2. **M4** (Selectable Options Schema) — High user-experience impact
3. **M3** (Checkpoint System) — Enables intervention pattern
4. **L1** (Handoff Protocol) — Core vision enabler
5. **M1-M2** (Decision/Action logs) — Transparency foundation
6. **L2** (OpenCode Hooks) — Platform-first commitment
7. **L3-L4** (Full engines) — Complete vision realization

---

## Summary Table

| Vision Pillar | Current State | Gap | Priority |
|---------------|---------------|-----|----------|
| Human-Agent Collaboration | ❌ Not implemented | CRITICAL | 1 |
| Transparency/Explainability | ⚠️ Partial (artifacts only) | MEDIUM | 3 |
| Selectable Options UI | ❌ Not implemented | CRITICAL | 2 |
| OpenCode-First Platform | ❌ Not implemented | HIGH | 4 |

---

## Next Steps

### Option A: Full Vision Implementation
**Scope**: All 4 pillars  
**Timeline**: 8-12 weeks  
**Deliverables**: Complete human-agent collaboration system, full transparency/audit trail, selectable options UI, OpenCode-first platform with hooks

### Option B: Core Collaboration Features First
**Scope**: Pillars 1 & 3 (Collaboration + Selectable Options)  
**Timeline**: 4-6 weeks  
**Deliverables**: Checkpoint system, handoff protocol, selectable options engine, basic OpenCode integration

### Option C: Quick Wins + Foundation
**Scope**: All Q1-Q4 + selected medium features  
**Timeline**: 1-2 weeks  
**Deliverables**: Documentation updates, OpenCode directory structure, decision/action logs, checkpoint protocol

---

## Analysis Date
Generated: 2026-03-19  
Analyzed Files:
- `.agent/agent.md`
- `.agent/methodology/master-harness.md`
- `.agent/methodology/phases/*`
- `.agent/artifacts/contracts/artifact_contract.json`
- `README.md`
- `.agent/HARNESS_SCOPE.md`
- `.agent/knowledge_base/ARCHITECTURE.md`
