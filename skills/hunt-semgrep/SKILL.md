---
name: hunt-semgrep
description: >
  Semgrep SAST skill adapted for the ZeroKit2 hunt-pipeline (Phase 4: Hybrid Scan).
  Provides hypothesis-driven rule generation, OWASP/CWE mapping, and integration
  with the SemgrepRunner's auto-repair loop.
  Use when: (1) Running Phase 4 Hybrid Scan against a target repo,
  (2) Generating custom Semgrep rules from hypotheses produced in Phase 3,
  (3) Triaging and mapping static findings to CWE/OWASP categories,
  (4) Debugging Semgrep rule failures using the auto-repair loop,
  (5) Performing variant analysis (Phase 8) by scanning for cloned patterns.
allowed-tools: Bash, Read, Grep
---

# Hunt-Semgrep — Semgrep for ZeroKit2 Hunt-Pipeline

> **Pipeline Role**: Phase 4 (Hybrid Scan) · Phase 8 (Variant Analysis)
> **Code Interface**: `core/tools/semgrep_runner.py` → `SemgrepRunner`

---

## Architecture Context

```
Orchestrator
  └── Detector.scan(hypotheses, repo_path, security_profile)
        └── SemgrepRunner.run_scan_async(rule_config, target_path)
              ├── RuleValidator.validate()      ← pre-scan gate
              ├── RuleRepairer.repair()         ← auto-repair loop (3x)
              └── semgrep scan --json --config  ← execution
```

**Key constraint**: `SemgrepRunner` already handles validation + auto-repair.
Your job as AI is to generate *correct hypotheses → rules* so repair is rarely needed.

---

## Workflow 1: Hypothesis → Rule Generation (Phase 4)

Given a `Hypothesis` object from Phase 3, generate a targeted Semgrep rule:

1. Extract `hypothesis.target_code` and `hypothesis.description`
2. Identify the **sink** (dangerous function) and **source** (user-controlled input)
3. Map to OWASP/CWE using `references/owasp_cwe_mapping.md`
4. Write a taint-aware Semgrep rule (see Rule Template below)
5. Pass rule path to `SemgrepRunner.run_scan_async()`

### Rule Template

```yaml
rules:
  - id: zerokit-{cwe-id}-{slug}
    message: "[ZeroKit] {description} | CWE-{id} | OWASP {category}"
    severity: ERROR  # ERROR=CRITICAL, WARNING=HIGH, INFO=MEDIUM
    languages: [{language}]
    metadata:
      cwe: "CWE-{id}"
      owasp: "{A0X:2021}"
      confidence: HIGH
      category: security
    patterns:
      - pattern: {dangerous_sink}($INPUT)
      - pattern-not: {sanitizer}($INPUT)
```

**Taint rule template** (for source → sink flows):
```yaml
rules:
  - id: zerokit-taint-{slug}
    mode: taint
    message: "Tainted data from {source} reaches {sink}"
    languages: [{language}]
    severity: ERROR
    pattern-sources:
      - pattern: {user_input_source}
    pattern-sinks:
      - pattern: {dangerous_sink}
    pattern-sanitizers:
      - pattern: {sanitizer_function}
```

---

## Workflow 2: Quick Scan with Registry Rules (Phase 4 Fast Path)

Use when there are no custom hypotheses or for a broad sweep:

```bash
# OWASP Top 10 comprehensive scan
semgrep scan --config "p/owasp-top-ten" --json --no-git-ignore <target_path>

# Language-aware security audit
semgrep scan --config "p/security-audit" --json <target_path>

# Secrets detection (always run in Phase 1 Baseline too)
semgrep scan --config "p/secrets" --json <target_path>
```

**ZeroKit2 orchestration** (preferred — uses auto-repair):
```python
from core.tools.semgrep_runner import SemgrepRunner

runner = SemgrepRunner()
result = await runner.run_scan_async(
    rule_config="p/owasp-top-ten",
    target_path=repo_path,
    jobs=4
)
# result.findings → List[Dict] → normalize to StaticFinding
```

---

## Workflow 3: Variant Analysis (Phase 8)

After a `ConfirmedStatus.CONFIRMED` vuln, create an abstract pattern and scan:

1. Extract the **abstract pattern** from the confirmed finding's code
2. Generate a new `Hypothesis` with `metadata.type = "variant"`
3. Run `Detector.scan([variant_hypothesis], repo_path)` — this calls SemgrepRunner internally
4. Filter out locations already in `context.static_findings`

**Pattern abstraction example**:
- Confirmed: `mysql_query($_GET['id'])` → Abstract: `{db_func}({user_controllable})`
- Generated rule targets all similar calls across the repo

---

## OWASP → CWE Quick Reference

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

---

## Auto-Repair Loop Integration

`SemgrepRunner` has a built-in 3-attempt repair loop. When writing rules:

- **If repair triggers**: Check `state_manager.get_rule_error(rule_content)` for last error
- **If rule blacklisted** (>80% failure in ≥3 runs): `state_manager.is_rule_blacklisted()` → skip and try registry rule instead
- **Fallback**: Use `"p/security-audit"` as the universal fallback config

---

## Severity Mapping

Map Semgrep output severity to `FindingSeverity` model:

| Semgrep | ZeroKit `FindingSeverity` | Priority |
|---------|--------------------------|----------|
| `ERROR` | `CRITICAL` / `HIGH` | Verify immediately |
| `WARNING` | `MEDIUM` | Verify in batch |
| `INFO` | `LOW` / `INFO` | Review, skip verification |

---

## Performance Tips

```bash
# Large repos: parallel jobs + exclude noise
semgrep scan --config auto --jobs 4 \
  --exclude "vendor/" --exclude "node_modules/" --exclude "test/"

# Differential scan (changed files only for variant analysis)
git diff --name-only HEAD~1 | xargs semgrep scan --config auto
```

---

## References

- `references/owasp_cwe_mapping.md` — Full OWASP A01–A10 → CWE → Semgrep rules
- `references/remediation_guide.md` — Fix patterns by vulnerability category
- `references/rule_library.md` — Curated Semgrep rulesets for common stacks
- `core/tools/semgrep_runner.py` — Execution engine (async + auto-repair)
- `core/tools/rule_generator.py` — AI-driven rule synthesis from hypotheses
- `core/agents/detector.py` — Orchestration layer that calls this skill
