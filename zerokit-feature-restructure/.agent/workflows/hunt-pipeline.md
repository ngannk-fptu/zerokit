---
description: Run the Antigravity 9-Phase Agentic Hunt Protocol (Manual Brain)
---

> **Note**: This workflow now uses **Antigravity (YOU)** as the **Intelligent Worker API/WordAPI** invoked by the Orchestrator, instead of an external API script.

1. Notify the user that Antigravity is starting the **10-Phase Agentic Hunt Protocol** as the **Intelligent Worker API/WordAPI**.
2. **Phase 1: Baseline Setup**: Verify the build environment and run tests using **Adapter Layers**.
3. **Phase 2: Surface Mapping**: Identify entry points and sinks using `list_dir` and `grep_search`.
4. **Phase 3: Threat Modeling & CWE Mapping**: Formulate hypotheses and map them to **CWE categories**.
5. **Phase 4: Hybrid Scanning**: Execute multi-tool scans (Semgrep, CodeQL, Joern).
6. **Phase 5: Intelligent Triage**: Antigravity (WordAPI) filters and classifies findings.
7. **Phase 6: PoC Verification**: Generate and run `repro.py` scripts to prove exploitability (Stage 5 in learn.md).
8. **Phase 7: Root Cause Analysis (RCA)**: Use sandbox data to pinpoint the exact failure point (Stage 6 in learn.md).
9. **Phase 8: Variant Analysis**: Following the **Trail of Bits** methodology to find similar patterns across the project.
10. **Phase 9: Remediation**: Analyze the root cause and generate an optimized `patch.diff`.
11. **Phase 10: Final Reporting**: Compile a comprehensive report with evidence, logs, and variant findings.
12. Ask the user for the `<target>` directory if not provided at the start.
