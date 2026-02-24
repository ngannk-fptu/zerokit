---
name: hunt-gitleaks
description: >
  Hardcoded secret detection for the ZeroKit2 hunt-pipeline (Phase 1: Baseline Setup).
  Scans repositories for exposed API keys, passwords, tokens, and credentials.
  Integrates with GitleaksRunner and maps findings to StaticFinding model.
  Use when: (1) Running Phase 1 Baseline on a target repository,
  (2) Checking if hardcoded secrets are present before deeper analysis,
  (3) Triaging secrets found as HIGH/CRITICAL StaticFindings for verification,
  (4) Reducing attack surface by identifying credential leakage at scan start,
  (5) Auditing git history for secrets that may already be compromised.
allowed-tools: Bash, Read, Grep
---

# Hunt-Gitleaks — Secret Detection for ZeroKit2 Hunt-Pipeline

> **Pipeline Role**: Phase 1 (Baseline Setup) — runs before any other scan
> **Code Interface**: `core/tools/gitleaks_runner.py` → `GitleaksRunner`
> **Priority**: 🔴 CRITICAL — exposed secrets = immediate CONFIRMED finding

---

## Architecture Context

```
Orchestrator.run_stage_baseline()
  └── GitleaksRunner.scan_repo(repo_path)
        ├── gitleaks detect --source <path> --no-git --report-format json
        ├── exit code 0 → clean (no secrets)
        ├── exit code 1 → secrets found → normalize to StaticFinding[]
        └── save to StateManager (DETECTED status)
```

**Exit code logic** (critical to understand):
- `0` = **No secrets detected** — repo is clean
- `1` = **Secrets detected** — findings written to JSON report
- `>1` = **Scan error** — stderr contains details

---

## Workflow 1: Phase 1 Baseline Scan

Called by `Orchestrator.run_stage_baseline()`. Steps:

1. Check `GitleaksRunner.available` — if `False`, log `PARTIAL_CONTEXT` and skip
2. Call `runner.scan_repo(context.repo_path)` → returns `List[Dict]`
3. Normalize each finding to `StaticFinding` (see mapping below)
4. Immediately flag `severity=CRITICAL` for any confirmed secret
5. Add to `context.static_findings` for the main pipeline to process

### Finding Normalization (gitleaks dict → StaticFinding)

```python
from core.models import StaticFinding, FindingSeverity

def normalize_gitleaks(finding: dict, repo_path: str) -> StaticFinding:
    return StaticFinding(
        id=f"gitleaks-{finding.get('RuleID', 'unknown')}-{finding.get('StartLine', 0)}",
        description=f"[SECRET] {finding.get('Description', 'Hardcoded Secret')} | Rule: {finding.get('RuleID')}",
        location=f"{finding.get('File', 'unknown')}:{finding.get('StartLine', 0)}",
        severity=FindingSeverity.CRITICAL,   # Secrets are always CRITICAL
        evidence=f"Match: {finding.get('Match', '[REDACTED]')} | Secret: [REDACTED]",
        tool_name="gitleaks",
        metadata={
            "rule_id": finding.get("RuleID"),
            "commit": finding.get("Commit", "HEAD"),
            "author": finding.get("Author", ""),
            "cwe": "CWE-798",   # Use of Hard-coded Credentials
            "owasp": "A07:2021"
        }
    )
```

---

## Workflow 2: Scan with Git History (Deep Baseline)

Use when target is a git repo and history should be checked:

```bash
# Scan with full git history (finds secrets in old commits too)
gitleaks detect --source /path/to/repo \
  --report-format json --report-path gitleaks_report.json -v

# Limit history for performance (last 6 months)
gitleaks detect --source /path/to/repo \
  --log-opts="--since=2024-01-01" \
  --report-format json --report-path gitleaks_report.json
```

**ZeroKit2 usage** (via GitleaksRunner without `--no-git`):
```python
# Currently scan_repo() uses --no-git for speed
# For deep history scan, call gitleaks directly:
runner = GitleaksRunner()
findings = runner.scan_repo(repo_path)  # --no-git mode (fast)
```

---

## Workflow 3: Incremental/Diff Scan

For variant analysis or scanning new files only:

```python
# scan_diff() uses gitleaks protect --source <path>
runner = GitleaksRunner()
diff_findings = runner.scan_diff(repo_path, base_ref="HEAD~1")
```

Use this when:
- Re-scanning after a patching phase (Phase 9) to check if new secrets were introduced
- Running quick checks on specific changed files

---

## CWE & OWASP Mapping

All gitleaks findings map to:

| CWE | Description | Gitleaks Rule Examples |
|-----|-------------|----------------------|
| **CWE-798** | Use of Hard-coded Credentials | `generic-api-key`, `aws-access-token` |
| **CWE-259** | Use of Hard-coded Password | `generic-password` |
| **CWE-321** | Use of Hard-coded Crypto Key | `private-key`, `rsa-private-key` |
| **CWE-312** | Cleartext Storage of Sensitive Info | `slack-token`, `github-token` |

**OWASP**: A07:2021 — Identification and Authentication Failures

---

## Severity Decision

Unlike other findings, **all secrets are CRITICAL**. However, refine based on context:

| Finding Type | Severity | Reason |
|---|---|---|
| Cloud keys (AWS, GCP, Azure) | `CRITICAL` | Direct infrastructure access |
| Auth tokens (GitHub, Slack, JWT) | `CRITICAL` | Credential theft vector |
| Database passwords | `CRITICAL` | Data breach potential |
| API keys (generic) | `HIGH` | Service abuse |
| Private keys (RSA/SSH) | `CRITICAL` | Full account compromise |

---

## Custom Rule Patterns for PHP/WordPress Targets

When scanning WordPress plugins or PHP apps, add these to `.gitleaks.toml`:

```toml
[[rules]]
id = "wp-db-credentials"
description = "WordPress database credentials in wp-config"
regex = '''define\s*\(\s*'DB_PASSWORD'\s*,\s*'([^']{8,})'\s*\)'''
secretGroup = 1
tags = ["wordpress", "database"]

[[rules]]
id = "php-hardcoded-token"
description = "PHP hardcoded API token or secret"
regex = '''(?i)(api_key|secret_key|auth_token|access_token)\s*[=:]\s*['"]([a-zA-Z0-9_\-]{20,})['"]'''
secretGroup = 2
tags = ["php", "api-key"]
```

---

## False Positive Handling

Common false positives in vulnerability research repos:

```toml
# Add to target repo's .gitleaks.toml (or use --baseline-path)
[allowlist]
description = "Hunt pipeline test fixtures"
paths = [
  '''test[_/]''',         # Test directories
  '''fixture[_/]''',      # Test fixtures
  '''repro_.*\.py''',     # PoC repro scripts (contain dummy payloads)
  '''\.md$''',            # Markdown documentation
]
stopwords = [
  "EXAMPLE", "PLACEHOLDER", "YOUR_KEY_HERE",
  "CHANGEME", "TODO", "FIXME", "DUMMY"
]
```

See `references/false_positives.md` for comprehensive allowlist patterns.

---

## Immediate Response Protocol

When secrets are found during Phase 1:

1. **Log CRITICAL alert** → `logger.critical("🔴 SECRET DETECTED: ...")`
2. **Classify as StaticFinding** with `severity=CRITICAL`
3. **Skip to PoC Verification (Phase 6)** immediately for secret findings
   - PoC = verify the secret is live/valid (e.g., test API key against endpoint)
4. **Add to pipeline context** as high-priority verification target
5. **Do NOT skip** — secrets are auto-CONFIRMED, no static analysis triage needed

---

## References

- `references/detection_rules.md` — Built-in Gitleaks rules with CWE mappings
- `references/remediation_guide.md` — Git history cleanup, credential rotation steps
- `references/false_positives.md` — Common FP patterns and allowlist config
- `references/compliance_mapping.md` — PCI-DSS, SOC2, GDPR compliance context
- `core/tools/gitleaks_runner.py` — Execution engine (scan_repo + scan_diff)
- `core/state_manager.py` — Persistence layer for tracking DETECTED/REJECTED findings
