---
description: Generate hypotheses and run static detection.
---

1. Turn attack-surface nodes into prioritized security hypotheses (CWE-oriented).
2. For each hypothesis, define concrete checks:
- source
- sink
- propagation path
- expected impact
3. Execute static analysis stack per language (Semgrep, CodeQL, and other available detectors).
4. Normalize findings into a single schema with unique IDs and source evidence.
5. Deduplicate findings across tools and remove low-confidence noise.
6. Send only high-confidence candidates to verification.
