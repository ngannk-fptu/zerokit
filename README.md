# ZeroKit: Agentic Security Research Harness 🛡️

> **Map. Hypothesize. Detect. Verify. Patch. Report.**
> *A specialized capability provider for autonomous security research agents.*

ZeroKit is not a standalone application, but an **Agent Harness** — a comprehensive suite of security research workflows, specialized skills, and knowledge items designed to be orchestrated by an Agentic AI (e.g., Antigravity).

---

## 🏗️ The 6-Phase Pipeline (Master Harness)

The harness implements a canonical 6-phase whitebox pentest workflow defined in `.agent/workflows/master-harness.md`:

| Phase | Description | Key Workflow |
|-------|-------------|--------------|
| **1. Intake & Plan** | Environment setup, scope definition, and tech stack detection. | `phases/phase-01-intake-plan.md` |
| **2. Profile & Surface** | Mapping the attack surface and entry points (Routes, Middleware). | `phases/phase-02-profile-surface.md` |
| **3. Threat & Static** | Hypothesis generation and hybrid SAST detection. | `phases/phase-03-threat-and-static.md` |
| **4. Verification Gate** | Autonomous PoC generation and execution in Docker Sandbox. | `phases/phase-04-verification-gate.md` |
| **5. RCA & Patch** | Root cause analysis, variant discovery, and remediation. | `phases/phase-05-rca-variant-patch.md` |
| **6. Report** | Final security packaging and regression guidance. | `phases/phase-06-report-regression.md` |

---

## 🧠 Specialized Skills

The harness provides the following capabilities within the `.agent/skills/` directory:

- **Static Analysis**: `hunt-semgrep`, `sast-semgrep`, `semgrep-rule-authoring`.
- **Dynamic Verification**: `docker-sandbox-verifier` (Ephemeral Docker isolation).
- **Mapping**: `architecture-mapper`, `entry-point-discovery`.
- **Fuzzing**: `atheris-python-fuzzing`, `aflpp-testing`, `fuzzing-orchestrator`.
- **Analysis**: `differential-analysis`, `variant-analysis`, `patch-verification`.

---

## � Hard Rules (Protocol v5.1)

1.  **No proof, no vulnerability**: Every reported issue must include reproducible evidence (exit code 0).
2.  **No generic workflows**: The harness is strictly for source-code security assessments.
3.  **Stability First**: Prefer reachable findings over automated scanner noise.

---

## � Project Structure

- **[.agent/](.agent/)**: The core of the harness.
    - **[workflows/](.agent/workflows/)**: Step-by-step instructions for the Orchestrator.
    - **[skills/](.agent/skills/)**: Tool-specific logic and security patterns.
    - **[knowledge_base/](.agent/knowledge_base/)**: Distilled security research and CVE patterns.
- **[README.md](README.md)**: Current documentation.

---

## 🚀 Execution

To initiate the harness, invoke the canonical master workflow within your agentic environment:

```
/master-harness
```

Or trigger specialized subflows:
- `/hunt-diff`: Differential analysis.
- `/hunt-deps`: Supply chain inventory.
- `/hunt-fuzz`: Parser and protocol fuzzing.

---
*Developed for Advanced Agentic Coding and Autonomous Security Research.*
