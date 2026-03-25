---
description: Root-cause analysis, variant discovery, and patch generation.
---

1. Perform root-cause analysis for each `confirmed` finding:
- exact vulnerable logic
- missing guard/validation
- exploit preconditions
2. Derive generalized vulnerable pattern from the confirmed case.
3. Scan for variants across the codebase using the generalized pattern.
4. Draft minimal patch proposals with explicit security rationale.
5. Verify patch candidates against original PoC and likely variant cases.
6. Reject patches that hide symptoms without fixing root cause.
