---
description: Verification gate phase. Confirm exploitability with runnable evidence.
---

1. For each candidate finding, generate a minimal PoC strategy tied to the exact code location.
2. Execute verification in isolated context when possible.
3. Capture evidence:
- command used
- runtime output
- exit code
- artifact/log path
4. Mark finding status using strict outcomes:
- `confirmed`: reproducible exploit evidence exists
- `rejected`: evidence disproves exploitability
- `inconclusive`: retry required with adjusted strategy
5. For inconclusive results, iterate with alternative payload/path assumptions.
6. Enforce hard rule: do not promote to final vulnerability list without `confirmed` evidence.
