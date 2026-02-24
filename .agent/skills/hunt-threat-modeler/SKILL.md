---
name: hunt-threat-modeler
description: >
  AI-driven threat modeling and hypothesis generation for the ZeroKit2 hunt-pipeline
  (Phase 3: Deep Logic & CWE Mapping). Analyzes AttackSurface entry points, generates
  security Hypotheses ranked by priority, maps to CWE/OWASP, and builds SecurityProfile
  for the Detector agent. Acts as the "intelligence layer" between surface mapping and
  static scanning.
  Use when: (1) Generating security hypotheses from Phase 2 surface map results,
  (2) Mapping entry points to CWE categories and OWASP Top 10,
  (3) Building a SecurityProfile (sources/sinks/sanitizers) for the target language,
  (4) Reasoning about logic flaws that SAST tools cannot detect,
  (5) Prioritizing which hypotheses the Detector should focus on first.
allowed-tools: Read, Grep, Bash
---

# Hunt-Threat-Modeler — Phase 3: Deep Logic & CWE Mapping

> **Pipeline Role**: Phase 3 (Threat Modeling & CWE Mapping)
> **Code Interface**: `core/agents/threat_modeler.py` → `ThreatModeler`
> **LLM Method**: `llm_gateway.generate_hypotheses(filename, signature, route)`
> **Output**: `List[Hypothesis]` → fed directly to Phase 4 `Detector.scan()`

---

## Architecture Context

```
Orchestrator.run_stage_hypothesis()
  └── ThreatModeler.generate_hypotheses(context.surface)
        ├── For each EntryPoint in AttackSurface:
        │     ├── llm_gateway.generate_hypotheses(filename, sig, route)
        │     │     └── prompt: threat_modeler/analyze_risk
        │     │     └── returns: JSON [{risk, severity, reasoning, suggested_check}]
        │     └── Fallback heuristic (keyword-based) if LLM fails
        ├── Sort by priority: CRITICAL > HIGH > MEDIUM > LOW > INFO
        └── context.hypotheses = List[Hypothesis]
```

**Key insight**: Antigravity (YOU) IS the ThreatModeler at the "Manual Brain" level.
When `/hunt-pipeline` is running, your threat modeling reasoning fills the `analyze_risk` prompt.

---

## Workflow 1: Analyzing Entry Points → Generating Hypotheses

For each entry point from Phase 2, reason through these **Attack Vector Questions**:

### HTTP Entry Points (`EntryPointType.HTTP`)
Ask yourself:
- Does this endpoint accept **user-controlled input** (GET/POST params, headers, cookies)?
- Is there **authentication/authorization** enforced before reaching business logic?
- Does the handler touch **database queries**, **file system**, **OS commands**, or **HTML output**?
- Are there **multiple roles** that could escalate privileges (IDOR, BOLA)?
- Is there **state mutation** without CSRF protection?

### File Entry Points (`EntryPointType.FILE`)
Ask yourself:
- Does this file handle **uploads**? What type checks exist?
- Does it **parse user-supplied data** (XML, JSON, YAML, serialized objects)?
- Are **path components** from user input used to construct file paths?

### CLI Entry Points (`EntryPointType.CLI`)
Ask yourself:
- Are arguments passed to **OS commands** without sanitization?
- Is there **privilege escalation** risk (setuid, sudo wrappers)?
- Are **environment variables** used in security decisions?

---

## Workflow 2: Hypothesis Construction

Each Hypothesis MUST follow this structure:

```python
from core.models import Hypothesis
import uuid

h = Hypothesis(
    id=str(uuid.uuid4()),
    description="{vuln_type}: {specific_reasoning_about_this_endpoint}",
    target_code="{file_path}:{function_or_line}",
    verification_plan="{what_semgrep_rule_or_PoC_will_prove_this}",
    metadata={
        "priority": "CRITICAL|HIGH|MEDIUM|LOW",
        "cwe": "CWE-{id}",
        "owasp": "A0{X}:2021",
        "vuln_category": "XSS|SQL_INJECTION|...",  # VulnerabilityCategory enum
        "attack_vector": "network|local|physical",
        "requires_auth": True | False,
        "llm_reasoning": "{brief rationale}"
    }
)
```

### Priority Assignment Rules

| Condition | Priority |
|---|---|
| Public input + dangerous sink + no sanitizer | `CRITICAL` |
| HTTP endpoint + auth bypass risk | `CRITICAL` |
| Admin functions with weak access control | `HIGH` |
| File operations with user-controlled paths | `HIGH` |
| Serialization/deserialization of user data | `HIGH` |
| Business logic flaws (IDOR, race conditions) | `HIGH` |
| Missing input validation (but not exploitable yet) | `MEDIUM` |
| Information disclosure, verbose errors | `LOW` |

---

## Workflow 3: Building SecurityProfile (for Detector)

After generating hypotheses, build a `SecurityProfile` for the Detector agent.
Group all identified sources, sinks, and sanitizers:

```python
from core.models import SecurityProfile, SecurityPattern, VulnerabilityCategory, FindingSeverity

profile = SecurityProfile(
    language="PHP",          # Detected from Phase 2
    framework="WordPress",   # Detected from Phase 2
    sources=[
        SecurityPattern(
            pattern=r"\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_FILES",
            category=VulnerabilityCategory.XSS,
            severity=FindingSeverity.HIGH,
            description="WordPress user-controlled HTTP input"
        ),
    ],
    sinks=[
        SecurityPattern(
            pattern=r"echo|print|wp_die|\$wpdb->query",
            category=VulnerabilityCategory.XSS,
            severity=FindingSeverity.CRITICAL,
            description="Output / DB query sink"
        ),
    ],
    sanitizers=[
        SecurityPattern(
            pattern=r"esc_html|esc_attr|sanitize_text_field|wpdb->prepare",
            category=VulnerabilityCategory.XSS,
            severity=FindingSeverity.INFO,
            description="WordPress output escaping functions"
        ),
    ]
)
# → assigned to context.security_profile for Detector.scan()
```

---

## CWE Priority Cheat Sheet

Use `CweManager` for detailed lookups: `cwe_manager.get_cwe("89")`, `cwe_manager.search_cwe("injection")`

### Top CWEs for Web/Plugin Hunting

| CWE | Name | OWASP | Priority |
|-----|------|-------|----------|
| **CWE-79** | Cross-site Scripting (XSS) | A03 | CRITICAL if unauth input |
| **CWE-89** | SQL Injection | A03 | CRITICAL |
| **CWE-78** | OS Command Injection | A03 | CRITICAL |
| **CWE-22** | Path Traversal | A01 | HIGH |
| **CWE-352** | CSRF | A01 | HIGH |
| **CWE-434** | Unrestricted File Upload | A01 | CRITICAL |
| **CWE-502** | Unsafe Deserialization | A08 | HIGH |
| **CWE-639** | IDOR (Auth Bypass via User Key) | A01 | HIGH |
| **CWE-798** | Hard-coded Credentials | A07 | CRITICAL |
| **CWE-918** | SSRF | A10 | HIGH |
| **CWE-862** | Missing Authorization | A01 | CRITICAL if admin func |
| **CWE-863** | Incorrect Authorization | A01 | HIGH |

---

## Workflow 4: Logic Flaw Hypothesis Generation

SAST tools miss these — YOU must generate them manually:

### Logic Bug Patterns

```
PATTERN: "A then B" assumption violated
→ What if attacker does B without A?
  Example: Add to cart without checking stock
  Example: Submit payment without completing previous step

PATTERN: Trust Boundary Crossing
→ Data from untrusted zone used in trusted computation
  Example: User-editable metadata used in privilege check
  Example: Client-side value used server-side without re-validation

PATTERN: TOCTOU (Time of Check vs Time of Use)
→ State changes between check and use
  Example: File permission checked, then file replaced
  Example: Token validated, then token reused

PATTERN: Integer Overflow / Underflow
→ Large inputs causing unexpected behavior
  Example: Quantity * Price with 32-bit int overflow
  Example: Array index from user input

PATTERN: Missing Negative Case
→ Code only handles success path
  Example: Auth check returns null but code continues
  Example: Signature verified but empty sig treated as valid
```

**For each pattern found**: generate a Hypothesis with `metadata.vuln_category = "LOGIC_ERROR"` and `verification_plan = "Manual PoC required — no static rule can detect this"`.

---

## LLM Response Format

`llm_gateway.generate_hypotheses()` expects the LLM to return **JSON array**:

```json
[
  {
    "risk": "Stored XSS via comment body",
    "severity": "CRITICAL",
    "reasoning": "Comment body is inserted into DOM without esc_html(), allowing script injection by unauthenticated users.",
    "suggested_check": "Semgrep rule: echo/print without esc_html on $comment_content | CWE-79"
  },
  {
    "risk": "Missing nonce verification in settings handler",
    "severity": "HIGH",
    "reasoning": "wp_ajax_update_settings() calls update_option() without check_ajax_referer(), enabling CSRF.",
    "suggested_check": "Grep for wp_ajax_ handlers without check_ajax_referer | CWE-352"
  }
]
```

**If LLM fails**, `_fallback_heuristic()` runs — keywords like `admin`, `auth`, `upload`, `token` → elevate to CRITICAL.

---

## Fallback Heuristic Enhancement

The existing `_fallback_heuristic()` is very basic. Enhance it mentally:

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

---

## References

- `references/cwe_top25.md` — SANS/MITRE Top 25 CWE quick reference
- `references/owasp_attack_patterns.md` — OWASP A01–A10 attack patterns for hypothesis generation
- `references/logic_flaw_catalog.md` — Common business logic vulnerability catalog
- `core/agents/threat_modeler.py` — Agent implementation
- `core/tools/cwe_manager.py` — CWE lookup/search/hierarchy tool
- `core/models.py` — `Hypothesis`, `SecurityProfile`, `VulnerabilityCategory` definitions
- `core/llm_gateway.py` → `generate_hypotheses()` — LLM prompt interface
