---
name: hunt-nuclei
description: >
  Nuclei-based DAST and PoC verification for the ZeroKit2 hunt-pipeline (Phase 6: Verify).
  Generates and selects Nuclei templates matching Hypothesis findings, executes them
  against target URLs, and maps results to VerifiedVuln model (CONFIRMED/REJECTED/INCONCLUSIVE).
  Integrates with Verifier agent's template-driven feedback loop and Docker sandbox.
  Use when: (1) Running Phase 6 PoC Verification against a live target URL,
  (2) Selecting the correct Nuclei template for a specific finding type (XSS, SQLi, SSRF...),
  (3) Writing custom Nuclei templates from hypothesis descriptions,
  (4) Interpreting Nuclei output and mapping to ConfirmedStatus,
  (5) Escalating INCONCLUSIVE findings to Python PoC sandbox execution.
allowed-tools: Bash, Read, Grep
---

# Hunt-Nuclei — Phase 6: PoC Verification

> **Pipeline Role**: Phase 6 (PoC Verify) — proves or disproves Hypotheses with live traffic
> **Code Interfaces**:
> - `core/agents/verifier.py` → `Verifier.verify_finding(finding, target_url)`
> - `core/tools/sandbox_executor.py` → `SandboxExecutor.run_project_poc()`
> **Exit Code Mandate**: Exit 0 = CONFIRMED. Anything else = continue retrying (max 3x) → REJECTED.

---

## Architecture Context

```
Orchestrator.run_stage_verify()
  └── Verifier.verify_finding(finding: StaticFinding, target_url: str)
        ├── _select_template(finding)       ← keyword → template mapping
        ├── _generate_poc(template, finding, target_url)  ← LLM fills template
        ├── Loop (max 3 retries):
        │     └── _run_sandbox(poc_script)  ← Docker: --network none, --memory 256m
        │           ├── exit_code == 0 → ConfirmedStatus.CONFIRMED → VerifiedVuln ✅
        │           └── exit_code != 0 → log error → retry with LLM feedback
        └── All retries fail → ConfirmedStatus.REJECTED
```

**Two verification paths:**
1. **Python PoC in Docker** → `Verifier._run_sandbox()` (isolated, --network none)
2. **Nuclei scan against live URL** → external HTTP requests to `target_url`

> ⚠️ Nuclei sends **real HTTP requests**. Only use on authorized targets.

---

## Workflow 1: Template Selection by Finding Type

`Verifier._select_template()` currently only handles SQLi and XSS. Use this expanded mapping:

| Finding Description Keywords | Template Path / Config | PoC Type |
|---|---|---|
| `xss`, `cross-site scripting` | `http/vulnerabilities/generic/generic-xss.yaml` | Nuclei HTTP |
| `sql injection`, `sqli` | `http/vulnerabilities/generic/sqli-time-based.yaml` | Python PoC (time-based) |
| `ssrf` | `http/vulnerabilities/generic/ssrf-via-redirect.yaml` | Nuclei HTTP |
| `command injection`, `rce` | `http/vulnerabilities/generic/command-injection.yaml` | Python PoC |
| `path traversal`, `lfi` | `http/vulnerabilities/generic/directory-traversal.yaml` | Nuclei HTTP |
| `csrf` | Custom Python PoC (no server-side request check) | Python PoC |
| `file upload` | `http/vulnerabilities/generic/file-upload.yaml` | Python PoC |
| `idor` | Custom Python PoC (param change + response diff) | Python PoC |
| `hardcoded secret` | **Auto-CONFIRMED** from gitleaks (no template needed) | None |

---

## Workflow 2: Nuclei Quick Scan (Broad Sweep)

Run Nuclei against target URL to catch known CVEs and misconfigs before custom PoC:

```bash
# Phase 6 standard scan — WordPress targets
nuclei -u http://{target_url} \
  -tags wordpress,cve \
  -severity critical,high \
  -rate-limit 30 \
  -concurrency 10 \
  -json -jsonl-export nuclei_results.jsonl \
  -timeout 15

# Technology fingerprint first (always run this)
nuclei -u http://{target_url} -tags tech -o tech_detected.txt

# Auth-required areas (supply session cookie from test account)
nuclei -u http://{target_url}/wp-admin/ \
  -header "Cookie: wordpress_logged_in_{hash}={cookie_value}" \
  -tags wp-plugin,auth,misconfig \
  -severity critical,high
```

**Normalize Nuclei JSONL → VerifiedVuln:**

```python
import json
from core.models import VerifiedVuln, ConfirmedStatus, FindingSeverity

def nuclei_to_verified(line: str, finding_id: str) -> VerifiedVuln:
    data = json.loads(line)
    sev_map = {
        "critical": FindingSeverity.CRITICAL,
        "high": FindingSeverity.HIGH,
        "medium": FindingSeverity.MEDIUM,
        "low": FindingSeverity.LOW,
    }
    return VerifiedVuln(
        finding_id=finding_id,
        status=ConfirmedStatus.CONFIRMED,
        poc={"type": "nuclei", "template_id": data.get("template-id")},
        runtime_output=json.dumps(data.get("matched-at", {})),
        evidence=f"Nuclei confirmed at {data.get('matched-at')} | {data.get('info', {}).get('name')}",
        severity_adjustment=sev_map.get(data.get("info", {}).get("severity", "high"))
    )
```

---

## Workflow 3: Custom Template for Hypothesis

When no public template matches, generate a custom Nuclei template from a Hypothesis:

### Template Skeleton

```yaml
id: zerokit-{hypothesis-slug}
info:
  name: "[ZeroKit] {hypothesis.description[:60]}"
  author: zerokit-hunter
  severity: {critical|high|medium}
  description: |
    {hypothesis.description}
  tags: zerokit,custom,{vuln-type}
  metadata:
    cwe-id: CWE-{id}
    owasp-part: {A0X:2021}

http:
  - method: {GET|POST}
    path:
      - "{{BaseURL}}/{endpoint}"
    
    # For POST requests
    headers:
      Content-Type: application/x-www-form-urlencoded
    body: "{param}={payload}&nonce={nonce_value}"

    matchers-condition: or
    matchers:
      # Option A: Response body contains payload (XSS/injection echo)
      - type: word
        part: body
        words:
          - "{payload_marker}"  # e.g., "ZEROKIT_XSS_PROBE"
      
      # Option B: Time-based (SQLi blind)
      - type: dsl
        dsl:
          - "duration >= 5"

      # Option C: HTTP status indicates success
      - type: status
        status:
          - 200
```

### XSS Template Example

```yaml
id: zerokit-xss-{endpoint-slug}
info:
  name: "[ZeroKit] Stored XSS via {parameter}"
  severity: critical
  tags: zerokit,xss,wordpress

http:
  - method: POST
    path:
      - "{{BaseURL}}/wp-comments-post.php"
    body: "comment=<script>window.ZEROKIT_XSS='confirmed'</script>&author=test&email=t@t.com&url=&submit=Post+Comment&comment_post_ID=1&comment_parent=0"
    headers:
      Content-Type: application/x-www-form-urlencoded
    
    matchers:
      - type: word
        part: body
        words:
          - "ZEROKIT_XSS='confirmed'"
```

---

## Workflow 4: Python PoC for Logic Flaws

For CSRF, IDOR, and logic flaws that Nuclei templates can't cover — use Python PoC through `SandboxExecutor.run_project_poc()`:

### CSRF PoC Template

```python
# templates/poc/http_csrf_check.py
import requests
import sys

TARGET = "{{TARGET}}"
ENDPOINT = "{{ENDPOINT}}"
DATA = {{PAYLOAD_DICT}}

# Attempt state-changing request WITHOUT CSRF token
resp = requests.post(f"{TARGET}{ENDPOINT}", data=DATA, allow_redirects=True)

# SUCCESS condition: request succeeds (no CSRF protection)
if resp.status_code in [200, 302] and "error" not in resp.text.lower():
    print(f"[CONFIRMED] CSRF possible — status={resp.status_code}")
    sys.exit(0)  # Exit 0 = CONFIRMED

print(f"[REJECTED] CSRF token validation blocks request — status={resp.status_code}")
sys.exit(1)  # Exit 1 = REJECTED
```

### IDOR PoC Template

```python
# templates/poc/http_idor_check.py
import requests
import sys

TARGET = "{{TARGET}}"
OWN_ID = "{{OWN_ID}}"
OTHER_ID = "{{OTHER_ID}}"
COOKIE = "{{SESSION_COOKIE}}"

headers = {"Cookie": COOKIE}

# Try to access another user's resource
resp = requests.get(f"{TARGET}?id={OTHER_ID}", headers=headers)

# Check if we got the other user's data (not an error)
if resp.status_code == 200 and "access denied" not in resp.text.lower():
    print(f"[CONFIRMED] IDOR — accessed resource of ID={OTHER_ID}")
    sys.exit(0)

print("[REJECTED] Access control enforced")
sys.exit(1)
```

> **Note**: Sandbox Docker runs with `--network none`. For PoCs requiring real HTTP,
> use Nuclei (workflow 2) or pass `network=host` via `sandbox.run_project_poc()` with explicit approval.

---

## VerifiedVuln Status Decision Tree

```
Finding received from Phase 4:
  │
  ├── Type: Secret (from gitleaks)     → CONFIRMED immediately (no PoC needed)
  │
  ├── Template match found?
  │     ├── YES → Run Nuclei template (-u target_url)
  │     │         ├── Match found → CONFIRMED ✅
  │     │         └── No match → try Python PoC
  │     └── NO  → Ask LLM to generate_poc() → Python PoC in sandbox
  │
  ├── PoC exit_code == 0?             → CONFIRMED ✅
  │
  ├── PoC exit_code != 0 (3x fail)?  → REJECTED ❌
  │
  └── Template exists but uncertain?  → INCONCLUSIVE 🔶
        └── Escalate to HarnessAgent (Phase 5 fuzzing)
```

---

## Severity Adjustment on Confirmation

When `ConfirmedStatus.CONFIRMED`, always set `severity_adjustment = FindingSeverity.CRITICAL`.
This overrides Phase 4 severity — a confirmed exploit is always critical regardless of original scan rating.

```python
# verifier.py line 68 — correct behavior
severity_adjustment=FindingSeverity.CRITICAL  # Confirmed exploits are critical
```

---

## WordPress-Specific Nuclei Commands

```bash
# All WordPress CVEs (plugin vulnerabilities)
nuclei -u http://{target}/ \
  -tags wp-plugin,cve -severity critical,high \
  -concurrency 5 -rate-limit 20

# Unauthenticated XSS (most common finding type)
nuclei -u http://{target}/ \
  -tags xss,reflected,stored -severity critical,high

# WordPress admin access
nuclei -u http://{target}/wp-admin/ \
  -tags admin-panel,login,default-logins

# Exposure scan (wp-config, debug log, backup files)
nuclei -u http://{target}/ \
  -tags exposure,config,backup,wp-config
```

---

## Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| Nuclei finds nothing | WAF/rate limiting | Lower `-rate-limit 10 -concurrency 3 -timeout 20` |
| False positive | Template too broad | Verify manually with curl, add `-verify` flag |
| Sandbox network error | `--network none` blocks requests | Use Nuclei for HTTP PoCs, sandbox only for logic |
| PoC template not found | `templates_dir` path mismatch | Check `templates/poc/` directory relative to project root |
| 3 retries all fail | Wrong template or patched vuln | Mark REJECTED, log `hypothesis.verification_plan` for manual review |

---

## References

- `references/owasp_mapping.md` — OWASP Top 10 → Nuclei template tags
- `references/template_development.md` — Custom Nuclei template authoring guide
- `references/authentication_patterns.md` — Authenticated scanning scenarios
- `references/false_positive_guide.md` — Nuclei result validation + FP identification
- `core/agents/verifier.py` — Verifier agent (template selection + sandbox execution)
- `core/tools/sandbox_executor.py` — Docker sandbox (execute_php/python/go/java + run_project_poc)
- `core/llm_gateway.py` → `generate_poc()` — LLM fills PoC templates
- `templates/poc/` — PoC template files (http_sqli_time_based.py, http_xss_reflected.py)
