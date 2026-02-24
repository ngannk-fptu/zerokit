---
name: dependency-analysis
description: Supply Chain Security. Analyzes dependencies for Known CVEs and "Reachable Vulnerabilities".
tools: Read, Grep, Glob, Bash
---

# Dependency Analysis

> "Your code is 10% yours. 90% is dependencies."

## 1. Scanner Tools
- **Node**: `npm audit` / `yarn audit`
- **Python**: `pip-audit`
- **Go**: `govulncheck`
- **General**: `trivy fs .`

## 2. Reachability Analysis (The "Gold" Standard)
A vulnerability in `lodash` is only a risk if you *use* the vulnerable function.

1. **Identify**: CVE-202X-YYYY in `lib-A`.
2. **Trace**: Where do we `import lib-A`?
3. **Verify**: Do we call `vulnerable_func()`?

## 3. Lockfile Audits
Check `package-lock.json`, `requirements.txt`, `go.sum`.
- Look for *transitive* dependencies that are outdated.
- Check for "Typosquatting" (unusual package names).

## 4. Remediation
- **Update**: `npm update` / `pip install --upgrade`.
- **Patch**: If update is breaking, apply patches via `patch-package`.
- **Replace**: If unmaintained, find alternative.
