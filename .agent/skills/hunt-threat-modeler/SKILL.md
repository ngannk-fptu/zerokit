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

## Workflow 5: DoS / Availability Hypothesis Generation

> **Critical Rule — Volumetric Payload Attacks are PROHIBITED for Modern Frameworks.**
>
> All modern HTTP servers (Kestrel/ASP.NET, Spring Boot, Express/Node, Django, FastAPI)
> enforce **protocol-level body/frame size limits** in their lowest middleware layer:
> - Kestrel: `MaxRequestBodySize` (default ~28.6 MB) + HTTP/2 `MaxFrameSize` (default 16 KB)
> - Spring Boot: `server.tomcat.max-http-form-post-size` (default 2 MB)
> - Express: `express.json({ limit: '100kb' })` (default 100 KB)
>
> Sending a payload ≥ the server's limit causes an **immediate TCP Reset / HTTP 413** before
> the application code even runs. The server stays healthy. This is NOT a DoS — it is the
> server working correctly. An Agent that concludes "server rejected 16MB → server is safe"
> has proven NOTHING about the actual vulnerability.

### Approved DoS Hypothesis Types (Use these ONLY)

| Attack Type | What it exploits | Example payload |
|---|---|---|
| **ReDoS (Regex DoS)** | Catastrophic backtracking in regex engine | `"a" * 50000 + "!"` sent to any field that applies server-side regex |
| **Algorithmic Complexity** | Pathological parsing of deeply nested structures | JSON/YAML with 10,000+ nested levels, or hash-collision keys |
| **Connection Exhaustion (Slowloris)** | Holding many half-open TCP connections | Open 500 sockets, send headers byte-by-byte with 1s delay |
| **Pagination Abuse** | Unbounded DB query via user-supplied `limit` | `GET /items?page=1&size=999999` |
| **Amplification Loop** | Logic that calls expensive sub-operations per item | POST with 10,000 items each triggering a DB INSERT |

### Prohibited DoS Hypothesis Types (Never generate these)

| Pattern | Why it fails | Correct alternative |
|---|---|---|
| Send body > 1MB | Rejected by protocol middleware, never reaches app code | Use algorithmic complexity payload < 50 KB |
| Flood with valid requests (volumetric HTTP flood) | Requires botnet-scale infra, unverifiable in sandbox | Use Slowloris (one machine, low bandwidth) |
| Large file upload to non-upload endpoint | HTTP 413 from server config, not a code bug | Use deeply nested multipart body |

### DoS PoC Template Selection

| Hypothesis type | Template to use |
|---|---|
| ReDoS or Algorithmic Complexity | `knowledge_base/templates/poc/http_dos_algorithmic.py` |
| Connection Exhaustion / Slowloris | `knowledge_base/templates/poc/http_dos_timeout.py` with threading |
| Pagination / Query Abuse | General HTTP template with `timeout=30`, treat Timeout as success |

### Payload Size Budget

> **HARD LIMIT: DoS PoC payloads MUST NOT exceed 50 KB total.**
> Anything larger will be silently dropped by the server's protocol layer before reaching your target code.
> Effectiveness comes from **computational complexity**, not **raw size**.

---

## Workflow 6: Algorithmic Degeneracy Hunting

> **Root Cause of DoS False Negatives:**
> The Agent checks whether *static security guards* are in place (middleware body limits, auth headers,
> rate limiting, input length checks). If those guards exist, it concludes "protected" and moves on.
> **This is wrong.** Static guards only block the guard's own threat model (oversized bodies, unauth requests).
> They say NOTHING about what happens at the algorithmic level INSIDE the handler when
> attacker-controlled input is accepted.
>
> **"Algorithmic Degeneracy"** = A code path whose runtime complexity (CPU/memory) is not O(n) linear
> but instead blows up to O(n²), O(n³), O(2ⁿ), or unbounded for specially crafted inputs,
> even when the input passes all static guards.

### Step-by-Step: How to Hunt Algorithmic Degeneracy

#### Step 1 — Read the handler, not the middleware
Middleware passing = code execution begins. Now trace the actual code:
```
Did static guards pass? → YES
→ Now look INSIDE the handler function body.
   Do NOT stop at the framework/middleware layer.
```

#### Step 2 — Ask the Degeneracy Question for each code construct

For every loop, recursion, sort, regex, or parser you see, ask:

| Code Construct | Degeneracy Question |
|---|---|
| `foreach (var item in input) { foreach (var sub in item.children) ... }` | Is `input` size user-controlled? → O(n²) nested loop |
| `Regex.Match(...)`, `Regex.Replace(...)` | Does `pattern` have `(a+)+$` style groups? Is input user-controlled? → .NET ReDoS |
| `JsonSerializer.Deserialize(body)` | Does the parser have a max-depth limit configured? → Nested JSON collapse |
| `GeneratePdf(ids)`, `ExportCsv(data)` | Is input size unbounded? → Logic-based Amplification (Resource exhaustion) |
| `System.IO.File.WriteAllBytes`, `MemoryCache.Set` | Is there a rate limit or size cap per user/IP? → Stateful Resource Exhaustion |
| `ComputeHash(input)` | Is a deprecated non-crypto hash used (murmur, CRC32)? → Hash collision flooding |
| `Sort(items)` | Is sort comparator stable? Is sort input user-controlled? → Quicksort worst-case O(n²) |
| `while (node != null) { node = node.next; }` | Can an attacker construct a circular structure? → Infinite loop |
| `Expand(template, input)` | Does template engine resolve recursive references? → Billion Laughs pattern |

#### Step 3 — Classify the degeneracy type

| Type | Symptom | CWE |
|---|---|---|
| **Logic-based Amplification** | Payload < 50KB triggers heavy backend processing (DB queries, PDF render) without limits/pagination | CWE-400 |
| **ReDoS (Regex)** | CPU spikes on .NET Kestrel due to catastrophic backtracking (e.g. `(a+)+$`) | CWE-1333 |
| **Stateful Resource Exhaustion** | RAM/Disk/Cache fills up due to millions of small (<50KB) valid requests missing cleanup/limits | CWE-400 |
| **Nested loop amplification** | CPU spikes linearly with attacker-chosen nesting depth | CWE-407 |
| **Parser depth bomb** | Stack overflow or OOM on deeply nested JSON/XML/YAML | CWE-674 |
| **Hash collision** | HashMap degraded to O(n) lookup due to colliding keys | CWE-407 |
| **Unbounded recursion** | Stack overflow when input graph has cycles | CWE-674 |
| **Sort complexity collapse** | O(n²) sort triggered by adversarial input ordering | CWE-407 |

#### Step 4 — Generate a targeted PoC, NOT a random large payload

The PoC payload must be constructed to specifically **trigger the degenerate code path**:

```
❌ Wrong: Send 16 MB of random bytes → Kestrel drops it, code never runs
❌ Wrong: Send valid JSON that is 5 MB → Middleware drops it

✅ Right: Send 8 KB of valid JSON with 2000 nested levels → Parser recurses 2000 times
✅ Right: Send 2 KB string "(a)*5000!" to a regex endpoint → ReDoS triggers
✅ Right: Send a list of 500 items where each item references all others → O(n²) graph traversal
```

#### Step 5 — Measure, don't assume

The PoC must **measure response time** against a baseline. A vulnerability is confirmed if:
- **Attacker-crafted input** → response time > baseline × 10 (or Timeout)
- **Benign input of same size** → response time ≈ baseline

This eliminates false negatives from one-off timeouts and proves the degeneracy is input-driven.

```python
# Pattern: Time-ratio confirmation
baseline_time = measure(benign_payload)      # e.g., 0.05s
attack_time   = measure(degenerate_payload) # e.g., Timeout (10s)

if attack_time > baseline_time * 10:
    print("[+] CONFIRMED: Algorithmic degeneracy — attacker controls runtime cost")
    sys.exit(0)
```

### Pre-REJECTED Checklist — Run BEFORE concluding "Not Vulnerable"

> **CRITICAL:** Never mark a DoS hypothesis `rejected` based on a single vector or a single response code.\
> Complete ALL steps below first.

#### A. Vector Diversification
If the attack payload was blocked at one vector, **try all alternative delivery vectors** before concluding safe:

| Blocked at | Must also try |
|---|---|
| URL query param (HTTP 414 URI Too Long) | Request Body (JSON/Form POST), Custom Headers |
| Request Body (HTTP 413) | URL fragment, nested JSON key names, Base64-encoded body |
| Custom Header | Cookie, Multipart form field, User-Agent |

> **Rule:** URL limits are the tightest (typically 8KB). Body and Header limits are much more permissive.\
> A ReDoS payload rejected at `?q=...` may succeed without issue in `{"q":"..."}`.

#### B. Safety-Off Switch Scan (Source Code Audit — .NET)
Before testing, grep the codebase for these "protection disabled" signals. If found, upgrade the hypothesis to **CRITICAL** immediately:

```
# Regex — infinite timeout = ReDoS unmitigated
Regex.Match(...) without  RegexOptions.None + Regex(..., timeout: ...)  → CRITICAL
options.MatchTimeout = Timeout.InfiniteTimeSpan  → CRITICAL
new Regex(pattern)  (no timeout argument at all)  → HIGH

# JSON — unbounded depth = parser bomb
JsonSerializerOptions { MaxDepth = 0 }  → maps to 64 (safe)
JsonSerializerOptions { MaxDepth = null }  → CRITICAL
options.MaxDepth = <value > 200>  → HIGH

# Kestrel — unbounded body
options.Limits.MaxRequestBodySize = null  → CRITICAL (no body limit)
options.Limits.MaxRequestBodySize = <value > 100_000_000>  → HIGH
```

#### C. Time-based Oracle (Soft Confirmation)
A request that returns `200 OK` but takes `100×` longer than baseline IS a vulnerability signal — even if the server doesn't crash. Report as `MEDIUM/HIGH` risk immediately and escalate to full PoC:

```python
# Threshold rules:
if attack_time > baseline_time * 100:   → CRITICAL (report + full PoC)
if attack_time > baseline_time * 10:    → HIGH     (confirmed degeneracy)
if attack_time > baseline_time * 3:     → MEDIUM   (investigate further)
# Server crash / Timeout                → CRITICAL (always)
```

> **Why 200 OK still matters:** A server grinding at 100% CPU for 10s while returning 200 is still a DoS vector.\
> An attacker with 50 connections can render the server completely unavailable to legitimate users.

### Algorithmic Degeneracy Checklist (run for every DoS hypothesis)

Before generating a PoC, complete this checklist:

- [ ] Did I read the actual handler code, not just the middleware config?
- [ ] Is there a loop, sort, regex, or parser operating on attacker-controlled input?
- [ ] Is the complexity bounded (constant/linear) or unbounded (quadratic/exponential)?
- [ ] Have I scanned for Safety-Off Switches (`MatchTimeout`, `MaxDepth`, `MaxRequestBodySize = null`)?
- [ ] Have I tried all delivery vectors (URL → Body → Header → Cookie) before marking rejected?
- [ ] Is my payload < 50 KB (to pass protocol-layer guards and reach application code)?
- [ ] Does my PoC measure time-ratio vs a benign baseline payload of equal size?
- [ ] If attack_time > baseline × 3 (even 200 OK), did I report as MEDIUM/HIGH risk?

---

## References

- `references/cwe_top25.md` — SANS/MITRE Top 25 CWE quick reference
- `references/owasp_attack_patterns.md` — OWASP A01–A10 attack patterns for hypothesis generation
- `references/logic_flaw_catalog.md` — Common business logic vulnerability catalog
- `core/agents/threat_modeler.py` — Agent implementation
- `core/tools/cwe_manager.py` — CWE lookup/search/hierarchy tool
- `core/models.py` — `Hypothesis`, `SecurityProfile`, `VulnerabilityCategory` definitions
- `core/llm_gateway.py` → `generate_hypotheses()` — LLM prompt interface
