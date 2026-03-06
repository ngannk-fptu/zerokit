# SANS/MITRE CWE Top 25 — Hunt-Pipeline Reference

Quick reference for the 25 most dangerous CWEs. Use with `CweManager.get_cwe()` and
`CweManager.search_cwe()` during Phase 3 hypothesis generation.

## Top 10 (Highest Priority)

| Rank | CWE | Name | OWASP | Hunt Priority |
|------|-----|------|-------|---------------|
| 1 | **CWE-787** | Out-of-bounds Write | - | HIGH (C/C++ targets) |
| 2 | **CWE-79** | Cross-site Scripting (XSS) | A03 | **CRITICAL** |
| 3 | **CWE-89** | SQL Injection | A03 | **CRITICAL** |
| 4 | **CWE-416** | Use After Free | - | HIGH (C/C++ targets) |
| 5 | **CWE-78** | OS Command Injection | A03 | **CRITICAL** |
| 6 | **CWE-20** | Improper Input Validation | A03 | HIGH |
| 7 | **CWE-125** | Out-of-bounds Read | - | MEDIUM (C/C++) |
| 8 | **CWE-22** | Path Traversal | A01 | HIGH |
| 9 | **CWE-352** | Cross-Site Request Forgery (CSRF) | A01 | HIGH |
| 10 | **CWE-434** | Unrestricted Upload of Dangerous File | A01 | **CRITICAL** |

## Top 11–25

| Rank | CWE | Name | Hunt Priority |
|------|-----|------|---------------|
| 11 | **CWE-502** | Deserialization of Untrusted Data | HIGH |
| 12 | **CWE-476** | NULL Pointer Dereference | LOW (DoS) |
| 13 | **CWE-287** | Improper Authentication | **CRITICAL** |
| 14 | **CWE-190** | Integer Overflow or Wraparound | MEDIUM |
| 15 | **CWE-798** | Hard-coded Credentials | **CRITICAL** |
| 16 | **CWE-862** | Missing Authorization | **CRITICAL** |
| 17 | **CWE-77** | Command Injection (general) | **CRITICAL** |
| 18 | **CWE-119** | Buffer Errors | HIGH (C/C++) |
| 19 | **CWE-276** | Incorrect Default Permissions | MEDIUM |
| 20 | **CWE-918** | Server-Side Request Forgery (SSRF) | HIGH |
| 21 | **CWE-362** | Race Condition | HIGH |
| 22 | **CWE-400** | Uncontrolled Resource Consumption | MEDIUM (DoS) |
| 23 | **CWE-611** | XML External Entity (XXE) | HIGH |
| 24 | **CWE-94** | Code Injection | **CRITICAL** |
| 25 | **CWE-863** | Incorrect Authorization | HIGH |

## Additional High-Value CWEs for Web/Plugin Hunting

| CWE | Name | Notes |
|-----|------|-------|
| **CWE-639** | Auth Bypass Through User-Controlled Key | IDOR pattern |
| **CWE-521** | Weak Password Requirements | Auth design flaw |
| **CWE-915** | Improperly Controlled Object Modification | Mass assignment |
| **CWE-384** | Session Fixation | Auth bypass |
| **CWE-601** | URL Redirection to Untrusted Site | Open redirect |
| **CWE-209** | Info Exposure Through Error Messages | Info leakage |
| **CWE-614** | Missing Secure Flag on Cookie | Session security |

## CWE Hierarchy Quick Reference

```
CWE-664 (Improper Control of Resource)
  └── CWE-400 Resource Consumption
  └── CWE-362 Race Condition

CWE-707 (Improper Neutralization)
  └── CWE-20 Input Validation
        └── CWE-79 XSS
        └── CWE-89 SQL Injection
        └── CWE-78 Command Injection
        └── CWE-22 Path Traversal
        └── CWE-611 XXE

CWE-284 (Improper Access Control)
  └── CWE-285 Improper Authorization
        └── CWE-862 Missing Authorization
        └── CWE-863 Incorrect Authorization
        └── CWE-639 IDOR
  └── CWE-287 Improper Authentication
        └── CWE-798 Hard-coded Credentials
```

## Usage with CweManager

```python
from core.tools.cwe_manager import CweManager

mgr = CweManager()

# Lookup by ID
cwe89 = mgr.get_cwe("89")
print(cwe89.get("attr", {}).get("@_Name"))  # → "Improper Neutralization of Special Elements..."

# Search by keyword
results = mgr.search_cwe("injection")  # Returns all injection CWEs

# Check hierarchy
mgr.is_child_of("89", "707", indirect=True)  # True — SQL Injection is under Neutralization

# Get OWASP membership
memberships = mgr.get_memberships("79")  # → [{"view": "OWASP Top 10 2021", "category": "A03"}]
```
