---
description: Patch-Diff Hunting Workflow. Finds silent security fixes and generates PoCs for the pre-fix version.
---

1. Analyze the project's git history to identify "Silent Fixes" (commits that look like bug fixes but might be security-related).
2. For each suspicious commit, perform a **Differential Review** of the code changes.
3. Use the `variant-analysis` skill to extract the underlying vulnerability pattern.
4. Attempt to generate a Proof-of-Concept (PoC) that triggers the vulnerability in the **pre-patch** version of the code.
5. Verify if similar patterns exist in other parts of the current codebase that remain unpatched.
6. Report findings as "Silent Patch Regressions" or "Unpatched Variants".
