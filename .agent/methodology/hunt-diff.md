---
description: Specialized subflow for patch-diff and silent-fix analysis.
---

1. Start from `methodology/master-harness.md` and complete Phase 01 first.
2. Identify security-relevant historical diffs and suspicious silent fixes.
3. Extract vulnerable pattern from pre-fix and post-fix deltas.
4. Validate exploitability of pre-fix behavior where feasible.
5. Run variant search against current codebase for unfixed sibling patterns.
6. Route validated findings through master Phase 04-06 gates.
