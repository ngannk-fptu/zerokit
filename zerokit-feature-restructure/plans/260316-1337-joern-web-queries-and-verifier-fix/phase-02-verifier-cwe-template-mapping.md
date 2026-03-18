---
phase: 2
priority: critical
status: pending
---

# Phase 2: Verifier CWE→Template Mapping

## Context
`core/agents/verifier.py` → `_select_template()` chỉ match 2 loại:
```python
if "sql" in desc: return "http_sqli_time_based.py"
if "xss" in desc: return "http_xss_reflected.py"
return "generic_check.py"
```

Command injection, path traversal, SSRF, deserialization, IDOR → tất cả dùng `generic_check.py` → verify kém → miss confirmed findings.

## Requirements
- Map CWE ID → PoC template (structured, không dùng string matching)
- Thêm PoC templates cho top CWE categories
- Dùng `cwe_id` từ `StaticFinding.cwe_details` thay vì match description text
- Fallback chain: `cwe_id` → `trust_boundary` → `description` → generic

## Implementation Steps

### 1. Tạo CWE→Template mapping
```python
# Trong verifier.py hoặc file riêng
CWE_TEMPLATE_MAP = {
    # Injection
    89:  "http_sqli_time_based.py",    # SQL Injection
    78:  "command_injection.py",        # OS Command Injection
    77:  "command_injection.py",        # Command Injection
    94:  "code_injection.py",           # Code Injection (eval/SSTI)

    # XSS
    79:  "http_xss_reflected.py",       # Cross-site Scripting

    # File/Path
    22:  "path_traversal.py",           # Path Traversal
    434: "file_upload.py",              # Unrestricted Upload

    # Auth/Access
    639: "idor_check.py",              # IDOR
    862: "missing_authz_check.py",     # Missing Authorization
    287: "auth_bypass_check.py",       # Improper Authentication

    # Deserialization/XXE
    502: "deserialization.py",          # Deserialization of Untrusted Data
    611: "xxe.py",                      # XXE

    # SSRF
    918: "ssrf_check.py",              # SSRF

    # Misc
    352: "csrf_check.py",              # CSRF
    1321: "prototype_pollution.py",    # Prototype Pollution
}

# Fallback by trust boundary
BOUNDARY_TEMPLATE_MAP = {
    "HTTP→Database":   "http_sqli_time_based.py",
    "HTTP→OS":         "command_injection.py",
    "HTTP→File":       "path_traversal.py",
    "HTTP→Template":   "code_injection.py",
    "HTTP→URL":        "ssrf_check.py",
    "HTTP→Deserialize":"deserialization.py",
}
```

### 2. Rewrite `_select_template()`
```python
def _select_template(self, finding: StaticFinding) -> Optional[str]:
    # Priority 1: CWE ID (most precise)
    if finding.cwe_details:
        cwe_id = finding.cwe_details.get("id")
        if isinstance(cwe_id, str):
            cwe_id = int(cwe_id) if cwe_id.isdigit() else None
        if cwe_id and cwe_id in CWE_TEMPLATE_MAP:
            return CWE_TEMPLATE_MAP[cwe_id]

    # Priority 2: Trust boundary
    boundary = finding.metadata.get("trust_boundary", "")
    if boundary in BOUNDARY_TEMPLATE_MAP:
        return BOUNDARY_TEMPLATE_MAP[boundary]

    # Priority 3: Description keyword (legacy fallback)
    desc = finding.description.lower()
    for keyword, template in [("sql", "http_sqli_time_based.py"), ("xss", "http_xss_reflected.py"), ("command", "command_injection.py"), ("path", "path_traversal.py"), ("ssrf", "ssrf_check.py")]:
        if keyword in desc:
            return template

    return "generic_check.py"
```

### 3. Tạo missing PoC templates
Templates cần tạo trong `templates/poc/`:

| Template | CWE | Strategy |
|----------|-----|----------|
| `command_injection.py` | 78 | Inject `; echo MARKER` vào subprocess call |
| `path_traversal.py` | 22 | Inject `../../../etc/passwd`, check `root:` |
| `code_injection.py` | 94 | Inject `7*7`, check `49` (SSTI) hoặc `eval()` |
| `ssrf_check.py` | 918 | Inject internal URL, check response |
| `idor_check.py` | 639 | Request resource as user A → check user B access |
| `deserialization.py` | 502 | Craft malicious serialized object |
| `missing_authz_check.py` | 862 | Call endpoint without auth token |
| `auth_bypass_check.py` | 287 | Test default creds / token forgery |

Mỗi template phải tuân thủ:
- `print("VULNERABLE"); sys.exit(0)` khi confirm
- `print("NOT_VULNERABLE"); sys.exit(1)` khi reject
- Standalone, minimal deps

### 4. Update `_generate_poc()` truyền thêm context
Hiện tại `_generate_poc()` truyền `finding_description` + template content cho LLM.
Thêm: `cwe_id`, `trust_boundary`, `source`, `sink` → LLM tạo PoC chính xác hơn.

## Related Files
- Modify: `core/agents/verifier.py`
- Create: `templates/poc/command_injection.py`
- Create: `templates/poc/path_traversal.py`
- Create: `templates/poc/code_injection.py`
- Create: `templates/poc/ssrf_check.py`
- Create: `templates/poc/idor_check.py`
- Create: `templates/poc/deserialization.py`
- Create: `templates/poc/missing_authz_check.py`
- Create: `templates/poc/auth_bypass_check.py`

## Todo
- [ ] Tạo `CWE_TEMPLATE_MAP` + `BOUNDARY_TEMPLATE_MAP`
- [ ] Rewrite `_select_template()` với 3-tier fallback
- [ ] Tạo 8 PoC template files
- [ ] Update `_generate_poc()` truyền thêm context
- [ ] Test: SQLi finding → đúng template, CMDi finding → đúng template
- [ ] Test: finding không có cwe_id → fallback trust_boundary → fallback description

## Success Criteria
- `_select_template()` map đúng ≥12 CWE IDs
- Không còn case nào SQLi/CMDi/SSRF/Path Traversal rơi vào `generic_check.py`
- Mỗi template mới chạy được standalone (exit 0 hoặc 1)

## Risk
- Template cho IDOR/auth bypass cần multi-step logic → LLM phải fill nhiều hơn → quality có thể thấp
- Mitigation: template IDOR/auth cung cấp skeleton chi tiết hơn, giảm phần LLM phải tự viết
