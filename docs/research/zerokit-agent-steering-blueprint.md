# ZeroKit Agent Steering Blueprint

Generated: 2026-03-20

## Executive Thesis

ZeroKit already has two important foundations:

1. A strong **professional pentest methodology**
2. A growing **tool execution layer**

What it does **not** yet have is a mature **steering layer**.

That steering layer is the missing system that makes an agent behave less like a script runner and more like a disciplined, human-like professional pentester.

The next phase of ZeroKit should therefore prioritize:

- checkpointed orchestration
- human intervention and handoff
- explicit decision policy
- action and reasoning traceability
- OpenCode-native steering primitives

The goal is not "more automation" by itself. The goal is **controlled, reviewable, high-signal autonomy**.

---

## First-Principles Framing

### What people often assume

- If the tool wrappers are good enough, the agent will naturally behave well.
- If the methodology docs are detailed enough, the agent will follow them consistently.
- If artifacts exist, transparency is solved.
- If a system is "agent-first," it should minimize human interruption.

### Bedrock truths

- A model does not reliably follow a long methodology unless the execution environment reinforces it.
- Tool wrappers only control execution at the leaf level; they do not control judgment, escalation, sequencing, or restraint.
- Final artifacts capture outcomes, not the path that produced them.
- Human intervention is not a failure mode in security work; it is part of the operating model.
- A professional pentester does not just use tools. They choose what to do next, explain why, pause when risk rises, and adapt when evidence changes.

### Fundamental conclusion

ZeroKit's novelty should not be "many security wrappers." It should be a **security-specific agent steering system** that reliably keeps an autonomous model inside a professional pentester operating pattern.

---

## Core Problem Statement

Current ZeroKit is strongest at:

- methodology definition
- tool invocation
- artifact contracts
- verification of outputs

Current ZeroKit is weakest at:

- steering the model through the methodology in a stable way
- making reasoning and decisions reviewable
- letting a human intervene without derailing the session
- making important decisions explicit and selectable
- enforcing phase-specific behavior beyond documentation alone

This creates a structural imbalance:

> ZeroKit can increasingly execute pentest tasks, but it cannot yet reliably govern how the model decides, pauses, escalates, hands off, and resumes.

---

## What ZeroKit Should Learn From OMO and OpenCode

### From OMO

Borrow these ideas:

- **Intent gate before action**: determine the real task before acting
- **Persistent task state**: work survives session boundaries
- **Explicit progress enforcement**: incomplete work is pushed forward until resolved
- **Specialized agent roles**: different cognitive jobs, different execution constraints
- **Verification loops**: completion requires checks, not self-report
- **Hook-driven orchestration**: steering logic lives in lifecycle events, not just prompts

Do not copy blindly:

- OMO is a general-purpose orchestration framework; ZeroKit is a security harness
- ZeroKit should not import broad complexity that does not improve pentest quality
- ZeroKit should avoid generic orchestration sprawl and keep the system security-task-centered

### From OpenCode

Borrow these primitives:

- selectable questions/options for branching decisions
- approvals for sensitive or destructive actions
- background tasks for parallel exploration
- hooks as steering enforcement points
- task graphs and resumable work units

This matters because these primitives are not just UX conveniences. They are the control surfaces that make autonomy steerable.

---

## The ZeroKit Steering Model

ZeroKit should be structured as five layers.

### Layer 1: Methodology Layer

This already exists in substantial form.

Purpose:

- define what a professional whitebox pentester should do
- define phase order
- define evidence thresholds
- define promotion criteria between phases

Current assets:

- `.agent/methodology/`
- `.agent/knowledge_base/`

### Layer 2: Steering Policy Layer

This is the most important missing layer.

Purpose:

- define what the agent is allowed to decide alone
- define when it must ask
- define when it must pause
- define what evidence is required before escalation
- define what counts as enough confidence to continue

This should become the policy engine for the whole system.

### Layer 3: Execution Layer

This is where the existing wrappers live.

Purpose:

- execute narrow, deterministic tool actions
- normalize outputs
- keep tool behavior stable and testable

Examples:

- Semgrep wrapper
- Gitleaks wrapper
- Joern wrapper
- PoC runner

### Layer 4: Oversight Layer

Purpose:

- record what happened
- expose why it happened
- allow interruption, approval, denial, and resume

This is the missing bridge between autonomy and trust.

### Layer 5: Runtime Integration Layer

Purpose:

- translate ZeroKit steering into OpenCode-native primitives
- enforce hooks, approvals, checkpoint prompts, and task persistence

This is where OpenCode-first support becomes real.

---

## The Key Design Shift

### Old center of gravity

"How do we make tools work well under agent control?"

### New center of gravity

"How do we make the agent behave like a disciplined pentester while using tools?"

That means ZeroKit should now optimize for:

- sequencing discipline
- escalation discipline
- hypothesis discipline
- evidence discipline
- review discipline

Not just for successful CLI wrapping.

---

## Required Steering Primitives

These are the minimum primitives ZeroKit should implement next.

### 1. Checkpoints

Every phase should have explicit pause candidates.

Examples:

- after intake scope is defined
- after attack surface is mapped
- after hypotheses are prioritized
- before risky verification or exploitation
- before final report publication

Checkpoint output should include:

- what was done
- what was learned
- what choices are available next
- what the recommended next step is
- what risks exist if continuing automatically

### 2. Selectable Options

The system should present structured options instead of asking vague open-ended questions.

Examples:

- which hypothesis cluster to pursue next
- whether to continue autonomous verification or request approval
- whether to deepen RCA or move to reporting
- whether to run a high-risk PoC

The rule should be:

> Ask with options whenever the choice materially changes scope, risk, cost, or direction.

### 3. Decision Log

ZeroKit needs a machine-readable record of why the agent made important decisions.

Minimal fields:

- timestamp
- phase
- decision id
- context summary
- options considered
- choice made
- confidence level
- rationale
- evidence references

This is essential if the system is meant to be reviewable and reproducible.

### 4. Action Trace

ZeroKit needs an append-only action trace for tool usage and orchestration state transitions.

Minimal fields:

- timestamp
- actor (main agent / subagent / human)
- action type
- command or tool name
- inputs summary
- outputs summary
- resulting artifact path
- success/failure

Decision log explains judgment. Action trace explains behavior.

### 5. Approval Gates

Some actions should never be on the same autonomy level as harmless analysis.

Require explicit approval for:

- destructive PoCs
- credential access attempts
- lateral movement simulations
- high-noise actions
- anything violating declared scope constraints

### 6. Handoff / Resume Protocol

ZeroKit needs a formal transfer format so a human can interrupt, inspect, modify direction, and hand work back.

The handoff object should capture:

- current phase
- active hypotheses
- pending tasks
- open risks
- recommended next actions
- blocked items
- state needed for resumption

### 7. Specialized Pentest Agent Roles

Not all subagents should be generic workers.

ZeroKit should eventually support role-based delegation such as:

- `surface-mapper`
- `hypothesis-builder`
- `static-triager`
- `verification-runner`
- `variant-hunter`
- `report-drafter`
- `oversight-agent`

The important part is not the labels; it is that each role has different constraints and success conditions.

---

## What "Human-Like Professional Pentester" Should Mean

This phrase needs operationalization.

It should not mean:

- imitating personality
- sounding clever
- producing long reasoning dumps

It should mean the system reliably exhibits these behaviors:

1. **Scoping discipline**
   - clarifies boundaries before action

2. **Hypothesis-driven work**
   - does not just scan blindly
   - forms and prioritizes hypotheses

3. **Evidence-based promotion**
   - does not escalate weak findings into reports

4. **Risk-sensitive restraint**
   - slows down or asks when actions become dangerous

5. **Adaptive iteration**
   - revises the plan as evidence changes

6. **Explainable choices**
   - can justify why path A was chosen over B

7. **Collaboration readiness**
   - can pause, summarize, accept direction changes, and resume coherently

ZeroKit should steer for these behaviors directly.

---

## Concrete Blueprint for the Next Build Phase

### A. New Artifacts

Add orchestration artifacts alongside existing pentest artifacts.

Recommended additions:

- `decision_log.json`
- `action_trace.json`
- `checkpoint_state.json`
- `handoff_state.json`
- `approval_events.json`

These should live per run, not as global logs.

### B. New Steering Documents

Add explicit steering policy docs.

Recommended additions:

- `.agent/methodology/steering-policy.md`
- `.agent/methodology/checkpoints.md`
- `.agent/methodology/approval-policy.md`
- `.agent/methodology/handoff-protocol.md`

These should define behavior, not just describe aspirations.

### C. OpenCode Runtime Integration

Use `.opencode/hooks/` as the integration surface.

Recommended hook responsibilities:

- inject phase-specific steering context
- enforce approval prompts for risky actions
- create checkpoint reminders at phase transitions
- validate that required logs were emitted
- block unsafe continuation when required human review is missing

### D. Agent Role System

Define a small initial set of ZeroKit-specific roles with clear boundaries.

Recommended MVP roles:

- `planner-analyst`
- `surface-analyst`
- `verification-specialist`
- `report-specialist`
- `oversight-controller`

### E. Phase-Specific Steering Contracts

For each phase, specify:

- entry conditions
- required questions
- optional questions
- mandatory artifacts
- allowed tool classes
- escalation thresholds
- checkpoint conditions
- human-approval conditions
- exit conditions

This is the actual steering contract.

---

## A Better Pentest Orchestration Loop

ZeroKit should move toward this loop:

1. **Establish scope and risk posture**
2. **Map surface and generate hypotheses**
3. **Prioritize what is worth spending verification budget on**
4. **Ask or auto-continue depending on policy and risk**
5. **Execute narrow tools only where justified**
6. **Log decisions and actions continuously**
7. **Checkpoint at meaningful transitions**
8. **Require evidence before promotion**
9. **Allow human override and resume at any checkpoint**
10. **Converge to confirmed, rejected, or explicitly deferred findings**

This keeps the model in a professional operating posture.

---

## Recommended Implementation Order

### Phase 1: Steering Foundations

Build first:

- decision log artifact
- action trace artifact
- checkpoint state artifact
- steering-policy docs

Reason:

- these improve transparency and control without requiring full agent-role architecture first

### Phase 2: Human Intervention Surface

Build next:

- selectable options schema
- approval-gate policy
- handoff/resume protocol
- OpenCode hook enforcement for risky actions and checkpoints

Reason:

- this closes the biggest gap between autonomous execution and practical oversight

### Phase 3: Specialized Role Orchestration

Build after that:

- pentest-specific subagent roles
- phase-specific delegation rules
- background exploration with structured return points

Reason:

- once control surfaces exist, specialization becomes safe and useful

### Phase 4: Adaptive Strategy Layer

Build later:

- confidence-based branching
- automatic checkpoint recommendations
- policy-driven escalation rules
- persistent session continuation across long investigations

Reason:

- this is where ZeroKit becomes a genuinely strong agent harness rather than a secure tool bundle

---

## What ZeroKit Should Avoid

### 1. Avoid turning into a generic orchestration framework

ZeroKit wins by being pentest-specific.

### 2. Avoid adding more wrappers before steering is strengthened

More tools without stronger orchestration deepens the imbalance.

### 3. Avoid hiding decisions in prose-only outputs

Important decisions must be structured and inspectable.

### 4. Avoid human review only at the very end

Professional workflows need mid-flight intervention points.

### 5. Avoid replacing policy with prompt verbosity

Longer prompts are not the same as stronger steering.

---

## Debate / Challenge to Current Direction

### Challenge 1: Tool quality is necessary but no longer the bottleneck

The project spent justified effort on wrappers, troubleshooting, and test stabilization. That work was necessary.

But from here on, additional wrapper work has sharply diminishing returns unless the steering layer improves.

### Challenge 2: Methodology docs are not enough

If the methodology is only descriptive, the runtime will drift.

ZeroKit now needs **enforcement mechanisms**, not just well-written guidance.

### Challenge 3: OpenCode-first should change behavior, not only folder names

OpenCode-first is not complete when `.opencode/` exists.

It becomes real when ZeroKit uses OpenCode-native:

- hooks
- questions/options
- approvals
- background tasks
- resumable execution

### Challenge 4: The real novelty is not "security tools for agents"

That is useful, but not enough.

The real novelty should be:

> a harness that makes a frontier model operate like a disciplined whitebox pentester under human-steerable governance.

---

## Success Criteria for the Next Milestone

The next steering-focused milestone should be considered successful if ZeroKit can do all of the following:

- pause at phase checkpoints with a structured status summary
- present selectable next-step options
- log decisions and actions in machine-readable form
- require approval for risky actions
- support human handoff and coherent resume
- keep tool wrappers as narrow executors under policy control
- show, in artifacts, not just what was found, but why the agent chose the path it took

If those are true, ZeroKit will have moved from "tool-capable" toward "professionally steerable."

---

## Final Recommendation

The next phase of ZeroKit should be framed internally as:

**Steering Before More Wrappers**

That means:

1. Build the steering artifacts
2. Build the checkpoint/approval/handoff protocol
3. Bind those controls into OpenCode hooks and selectable interactions
4. Only then broaden the specialized agent and tool ecosystem further

This is the path most likely to produce the "ultimate goal":

an autonomous but governable agent that actually behaves like a human-quality professional pentester.
