---
name: hunt-gitleaks
description: >
  Harness-compatible Gitleaks secret detection for Phase 03 (Static Detection).
  Use when scanning repositories for hardcoded credentials, tokens, and private
  keys, then normalizing confirmed matches into contract-aligned static findings
  under 03-static artifacts.
allowed-tools: Bash, Read, Grep
---

# Hunt-Gitleaks - Phase 03 Secret Detection

## Role in Phase 03
Use this skill during Static Detection to find exposed secrets and create
high-confidence `static_findings` entries.

Artifact targets:
- `.agent/artifacts/runs/<run_id>/03-static/gitleaks_report.json` (raw tool output)
- `.agent/artifacts/runs/<run_id>/03-static/static_findings.json` (normalized findings)

## How Gitleaks Works
Core command pattern:

```bash
gitleaks detect \
  --source <target_repo> \
  --report-format json \
  --report-path <run_root>/03-static/gitleaks_report.json
```

Common exit behavior:
- `0`: no leaks detected
- `1`: leaks detected
- `>1`: tool/runtime error

## What It Detects
Gitleaks uses regex-based rules to detect:
- cloud credentials (AWS, GCP, Azure)
- API tokens (GitHub, Slack, Stripe, etc.)
- database passwords and private keys
- generic secret-like assignments in code and config files

Typical mapping:
- `CWE-798` hardcoded credentials
- `CWE-259` hardcoded password
- `CWE-321` hardcoded cryptographic key

## Phase 03 Workflow
1. Run Gitleaks against the target repository.
2. Save raw JSON output to `03-static/` for traceability.
3. Normalize each hit into the artifact contract fields:
- `id`
- `tool` (`gitleaks`)
- `severity`
- `path`
- `line`
- `evidence`
- `hypothesis_id`
4. Write normalized records into `03-static/static_findings.json`.

Example normalized item:

```json
{
  "id": "sf-gitleaks-001",
  "tool": "gitleaks",
  "severity": "critical",
  "path": "src/config/settings.py",
  "line": 42,
  "evidence": "Rule aws-access-token matched high-entropy token",
  "hypothesis_id": "hyp-secret-001"
}
```

## Rule Configuration
Prefer repository-local `.gitleaks.toml` when target-specific patterns are needed.

Example custom rule:

```toml
[[rules]]
id = "generic-api-token"
description = "Generic API token assignment"
regex = '''(?i)(api[_-]?key|token|secret)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]'''
secretGroup = 2
tags = ["api", "credentials"]
```

## False Positive Controls
Use allowlists for fixtures or known placeholders.

```toml
[allowlist]
description = "Known non-production strings"
paths = [
  '''(^|/)tests?/''',
  '''(^|/)fixtures?/'''
]
stopwords = [
  "EXAMPLE",
  "PLACEHOLDER",
  "DUMMY",
  "CHANGEME"
]
```

## Severity Decision Table

| Finding Type | Severity | Reason |
|---|---|---|
| Cloud keys (AWS, GCP, Azure) | `critical` | Direct infrastructure access |
| Auth tokens (GitHub, Slack, JWT) | `critical` | Credential theft vector |
| Database passwords | `critical` | Data breach potential |
| Private keys (RSA/SSH) | `critical` | Full account compromise |
| API keys (generic, non-privileged) | `high` | Service abuse |

Lower only when evidence clearly indicates non-production or invalid material.

## CWE and OWASP Mapping

All gitleaks findings map to:

| CWE | Description | Gitleaks Rule Examples |
|-----|-------------|----------------------|
| CWE-798 | Use of Hard-coded Credentials | `generic-api-key`, `aws-access-token` |
| CWE-259 | Use of Hard-coded Password | `generic-password` |
| CWE-321 | Use of Hard-coded Crypto Key | `private-key`, `rsa-private-key` |
| CWE-312 | Cleartext Storage of Sensitive Info | `slack-token`, `github-token` |

OWASP: A07:2021 -- Identification and Authentication Failures

## Git History Scanning

Scan with full git history (finds secrets in old commits):

```bash
gitleaks detect --source <target_repo> \
  --report-format json --report-path <run_root>/03-static/gitleaks_report.json -v
```

Limit history for performance (last 6 months):

```bash
gitleaks detect --source <target_repo> \
  --log-opts="--since=2024-01-01" \
  --report-format json --report-path <run_root>/03-static/gitleaks_report.json
```

No-git mode (current working tree only, faster):

```bash
gitleaks detect --source <target_repo> --no-git \
  --report-format json --report-path <run_root>/03-static/gitleaks_report.json
```

## Custom Rule Patterns for PHP/WordPress Targets

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

## Immediate Response Protocol

When secrets are found during Phase 03:

1. Classify as `static_findings` entry with `severity: critical`
2. Secrets are high-confidence -- prioritize for Phase 04 verification
3. PoC for secrets = verify the secret is live/valid (test API key against endpoint)
4. Do NOT skip -- secrets are near-auto-confirmed, minimal static triage needed

## References
- `references/detection_rules.md`
- `references/false_positives.md`
- `references/remediation_guide.md`
- `references/compliance_mapping.md`
