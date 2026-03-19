---
version: "1.0"
agent: "verifier"
method: "evaluate_poc"
phase: 6
description: "Zero-shot LLM judge for non-crash logic bug verification (IDOR, Race Condition, AuthZ, Crypto)"
last_updated: "2026-03-19"
pipeline_input_from: "Phase 6 (Verifier): PoC stdout from Docker sandbox, exit_code == 0 but CWE in LOGIC_CWES"
pipeline_output_to: "Phase 6 (Verifier): YES/NO verdict to classify CONFIRMED vs REJECTED"

default_model: "antigravity"
temperature: 0.0
max_tokens: 16

required_vars:
  - cwe_id            # Numeric CWE ID e.g. "639"
  - description       # Human-readable vulnerability description
  - poc_script        # The executed PoC source code (truncated if needed)
  - stdout            # The tail of the sandbox stdout (max 4000 chars)
optional_vars:
  - target_data       # What sensitive data/behavior would prove success (e.g. "user_b@email.com", "admin panel HTML")
---
You are a security analysis oracle. Your ONLY job is to judge whether a Proof-of-Concept exploit actually succeeded based on the sandbox output.

**DO NOT** explain your reasoning. **DO NOT** add any text. **Output ONLY**: `YES` or `NO`.

---
## Vulnerability Under Test

**CWE**: CWE-{{ cwe_id }}
**Description**: {{ description }}
{% if target_data %}**Success Indicator**: The stdout should contain or demonstrate: `{{ target_data }}`{% endif %}

---
## PoC Script Executed

```python
{{ poc_script[:2000] }}
```

---
## Sandbox Stdout (last 4000 chars)

```
{{ stdout }}
```

---
## Few-Shot Examples

**Example 1 — IDOR (CWE-639), Output: `user_b@example.com retrieved successfully`**
→ `YES` (sensitive data from another user was leaked)

**Example 2 — IDOR (CWE-639), Output: `403 Forbidden. Access denied for user_b resource.`**
→ `NO` (authorization check blocked the access)

**Example 3 — Race Condition (CWE-362), Output: `Balance: $0 after 10 parallel withdrawals`**
→ `NO` (bank correctly processed all requests from balance)

**Example 4 — Race Condition (CWE-362), Output: `Balance: $-50 detected in thread 7`**
→ `YES` (race won, negative balance = TOCTOU confirmed)

**Example 5 — Missing AuthZ (CWE-862), Output: `HTTP 200 OK — Admin Dashboard loaded`**
→ `YES` (unauthenticated access to protected resource confirmed)

**Example 6 — Missing AuthZ (CWE-862), Output: `HTTP 302 Found — Redirect to /login`**
→ `NO` (server correctly redirected unauthenticated request)

---

Based solely on the stdout above, did the exploit SUCCEED?

Output ONLY `YES` or `NO`:
