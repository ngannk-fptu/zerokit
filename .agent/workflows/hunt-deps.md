---
description: Specialized subflow for dependency risk and reachability analysis.
---

1. Start from `workflows/master-harness.md` and complete Phase 01-02 first.
2. Inventory direct and transitive dependencies from lock/manifests.
3. Match dependencies against known vulnerability intelligence (CVE/CWE advisories).
4. Perform reachability analysis from exposed attack surface to vulnerable package code paths.
5. Promote only reachable, exploitable candidates into Phase 03 findings.
6. Continue through verification and reporting using master workflow phases.
