---
name: hunt-semgrep
description: >
  Harness-compatible Semgrep SAST skill for Phase 03 (Static Detection).
  Use when turning hypotheses into executable rules, running Semgrep scans,
  and normalizing findings into the 03-static artifact set under the shared
  artifact contract.
allowed-tools: Bash, Read, Grep
---

# Hunt-Semgrep - Phase 03 SAST

## Role in Phase 03
Semgrep provides fast pattern and taint scanning to test hypotheses produced in
threat modeling.

Artifact targets:
- `.agent/artifacts/runs/<run_id>/03-static/semgrep_report.json`
- `.agent/artifacts/runs/<run_id>/03-static/static_findings.json`

## Scan Modes
Registry scan (broad baseline):

```bash
semgrep scan --config p/security-audit --json --output <run_root>/03-static/semgrep_report.json <target_repo>
```

Custom rule scan (hypothesis-driven):

```bash
semgrep scan --config <rule_file.yml> --json --output <run_root>/03-static/semgrep_report.json <target_repo>
```

## Rule Writing Guidance
Use hypothesis fields (`source`, `sink`, `cwe`, `priority`) to build focused rules.

Basic rule template:

```yaml
rules:
  - id: phase03-cwe-89-inline-sql
    message: Untrusted input reaches SQL execution
    severity: ERROR
    languages: [python]
    metadata:
      cwe: CWE-89
      category: security
    patterns:
      - pattern: cursor.execute($Q + $INPUT)
      - pattern-not: cursor.execute("...", ...)
```

Taint rule template:

```yaml
rules:
  - id: phase03-taint-user-input-to-sink
    mode: taint
    message: Tainted data reaches dangerous sink
    severity: ERROR
    languages: [javascript]
    pattern-sources:
      - pattern: req.$ANY
    pattern-sinks:
      - pattern: eval(...)
    pattern-sanitizers:
      - pattern: sanitize(...)
```

## Auto-Repair Concepts for Failing Rules
When custom rules fail, use a bounded repair loop:
1. Validate syntax first (`semgrep --validate --config <rule_file.yml>`).
2. Run scan and capture parser/runtime errors.
3. Apply minimal edits (indentation, keys, language list, pattern syntax).
4. Re-run validation and scan.
5. After repeated failure, fall back to a stable registry ruleset and record the fallback.

Keep a short error log in `03-static/` so rule evolution is auditable.

## Normalization to Artifact Contract
Normalize Semgrep results into `static_findings` entries with required fields:
- `id`
- `tool` (`semgrep`)
- `severity`
- `path`
- `line`
- `evidence`
- `hypothesis_id`

Example normalized item:

```json
{
  "id": "sf-semgrep-004",
  "tool": "semgrep",
  "severity": "high",
  "path": "api/orders.ts",
  "line": 118,
  "evidence": "Rule phase03-taint-user-input-to-sink matched req.body -> eval",
  "hypothesis_id": "hyp-017"
}
```

## Deduplication and Triage
Before handoff to verification:
- deduplicate by `(path, line, sink pattern, cwe)`
- keep strongest severity when duplicates collide
- retain raw result IDs in evidence text for traceability

## OWASP to CWE Quick Reference

See `references/owasp_cwe_mapping.md` for full mapping with Semgrep rules.

| OWASP A0X | CWEs | Semgrep Config |
|-----------|------|----------------|
| A01 - Broken Access Control | CWE-22, CWE-352, CWE-639 | `p/owasp-top-ten` |
| A02 - Crypto Failures | CWE-259, CWE-327, CWE-330 | `p/crypto`, `p/secrets` |
| A03 - Injection | CWE-79, CWE-89, CWE-95 | `p/security-audit` |
| A05 - Misconfiguration | CWE-16, CWE-611, CWE-614 | `p/security-audit` |
| A07 - Auth Failures | CWE-287, CWE-798, CWE-916 | `p/jwt` |
| A08 - Integrity Failures | CWE-502, CWE-829 | `p/security-audit` |
| A10 - SSRF | CWE-918 | `r/{lang}.requests.security.*` |

## Severity Mapping

Map Semgrep output severity to artifact contract:

| Semgrep | Artifact severity | Action |
|---------|-------------------|--------|
| `ERROR` | `critical` / `high` | Verify immediately in Phase 04 |
| `WARNING` | `medium` | Verify in batch |
| `INFO` | `low` | Review, skip verification |

## Variant Analysis (Phase 05)

After a confirmed finding, create an abstract pattern and scan for variants:

1. Extract the abstract pattern from the confirmed finding's code
2. Generate a new Semgrep rule that generalizes the sink/source
3. Scan the full codebase with the generalized rule
4. Filter out locations already in `static_findings`

Pattern abstraction example:
- Confirmed: `mysql_query($_GET['id'])` -> Abstract: `{db_func}({user_controllable})`
- Generated rule targets all similar calls across the repo

## Performance Tips

```bash
# Large repos: parallel jobs + exclude noise
semgrep scan --config auto --jobs 4 \
  --exclude "vendor/" --exclude "node_modules/" --exclude "test/" \
  --json <target_repo>

# Differential scan (changed files only)
git diff --name-only HEAD~1 | xargs semgrep scan --config auto --json
```

## References
- `references/owasp_cwe_mapping.md`
- `references/rule_library.md`
- `references/remediation_guide.md`
