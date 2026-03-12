---
name: hunt-threat-modeler
description: >
  Phase 03 threat modeling skill for the harness. Converts mapped attack surface
  signals into prioritized, CWE-oriented hypotheses that can be tested by static
  detectors and later verification. Focuses on practical exploit paths and
  contract-aligned hypothesis output.
allowed-tools: Read, Grep, Bash
---

# Hunt-Threat-Modeler - Phase 03

## Role in Phase 03
This skill turns phase-02 surface data into structured hypotheses for static
analysis and verification planning.

Primary artifact flow:
- Input: `.agent/artifacts/runs/<run_id>/02-surface/attack_surface.json`
- Output: `.agent/artifacts/runs/<run_id>/03-static/hypotheses.json`

## Method
For each entry point, reason from controllable input to security-sensitive sink.

### HTTP Entry Points
Check:
- input channels (query, body, headers, cookies)
- authz/authn enforcement before sensitive actions
- output rendering paths and data-store access
- state changes lacking anti-CSRF controls

### File and Parser Entry Points
Check:
- upload validation and type enforcement
- path construction from user input
- unsafe parsing (XML, YAML, deserialization)

### CLI and Job Entry Points
Check:
- command construction from arguments/env vars
- privileged execution context misuse
- unsafe filesystem and process operations

## Hypothesis Contract
Each hypothesis should align with artifact requirements:
- `id`
- `title`
- `cwe`
- `source`
- `sink`
- `priority`
- `rationale`

Example:

```json
{
  "id": "hyp-021",
  "title": "Potential command injection in backup task",
  "cwe": "CWE-78",
  "source": "CLI argument: --path",
  "sink": "shell command execution",
  "priority": "high",
  "rationale": "User-controlled path is concatenated into command string without strict quoting or allowlist validation."
}
```

## Priority Assignment Rules

| Condition | Priority |
|---|---|
| Public input + dangerous sink + no sanitizer | `critical` |
| HTTP endpoint + auth bypass risk | `critical` |
| Admin functions with weak access control | `high` |
| File operations with user-controlled paths | `high` |
| Serialization/deserialization of user data | `high` |
| Business logic flaws (IDOR, race conditions) | `high` |
| Missing input validation (not yet exploitable) | `medium` |
| Information disclosure, verbose errors | `low` |

## Logic-Flaw Focus Areas
Static tools miss many logic issues. Explicitly model:
- missing authorization checks on sensitive actions
- state-machine bypasses (step skipping)
- time-of-check/time-of-use races
- trust boundary violations between components

### Logic Bug Patterns

```
PATTERN: "A then B" assumption violated
  What if attacker does B without A?
  Example: Add to cart without checking stock
  Example: Submit payment without completing previous step

PATTERN: Trust Boundary Crossing
  Data from untrusted zone used in trusted computation
  Example: User-editable metadata used in privilege check
  Example: Client-side value used server-side without re-validation

PATTERN: TOCTOU (Time of Check vs Time of Use)
  State changes between check and use
  Example: File permission checked, then file replaced
  Example: Token validated, then token reused

PATTERN: Integer Overflow / Underflow
  Large inputs causing unexpected behavior
  Example: Quantity * Price with 32-bit int overflow
  Example: Array index from user input

PATTERN: Missing Negative Case
  Code only handles success path
  Example: Auth check returns null but code continues
  Example: Signature verified but empty sig treated as valid
```

When logic flaws are suspected, define concrete verification ideas in rationale
so Phase 04 can test feasibility.

## CWE Priority Cheat Sheet

### Top CWEs for Web/Plugin Hunting

| CWE | Name | OWASP | Priority |
|-----|------|-------|----------|
| CWE-79 | Cross-site Scripting (XSS) | A03 | critical if unauth input |
| CWE-89 | SQL Injection | A03 | critical |
| CWE-78 | OS Command Injection | A03 | critical |
| CWE-22 | Path Traversal | A01 | high |
| CWE-352 | CSRF | A01 | high |
| CWE-434 | Unrestricted File Upload | A01 | critical |
| CWE-502 | Unsafe Deserialization | A08 | high |
| CWE-639 | IDOR (Auth Bypass via User Key) | A01 | high |
| CWE-798 | Hard-coded Credentials | A07 | critical |
| CWE-918 | SSRF | A10 | high |
| CWE-862 | Missing Authorization | A01 | critical if admin func |
| CWE-863 | Incorrect Authorization | A01 | high |

## Keyword Heuristic Fallback

When LLM-based reasoning is unavailable, map keywords to hypotheses:

| Keyword in location/description | Suggested Hypothesis |
|---|---|
| `upload`, `file`, `attach` | CWE-434 Unrestricted Upload |
| `auth`, `login`, `nonce`, `token` | CWE-352 CSRF / CWE-287 Auth Bypass |
| `admin`, `role`, `capability` | CWE-862 Missing Authorization |
| `query`, `sql`, `db`, `where` | CWE-89 SQL Injection |
| `echo`, `print`, `render`, `html` | CWE-79 XSS |
| `exec`, `shell`, `cmd`, `eval` | CWE-78 Command Injection |
| `include`, `require`, `path` | CWE-22 Path Traversal |
| `serial`, `unserialize`, `pickle` | CWE-502 Deserialization |

## Handoff to Static Detection
For every hypothesis, include enough detail for rule/query design:
- exact source signal
- expected sink pattern
- likely sanitizer or guard that should exist
- target files/functions to prioritize

This reduces low-signal scans and improves verification success rate.

## References
- `references/cwe_top25.md`
- `references/owasp_attack_patterns.md`
- `references/logic_flaw_catalog.md`
