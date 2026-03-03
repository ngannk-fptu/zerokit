# Skills Scope (Harness Baseline)

This folder is intentionally constrained to whitebox source-code pentest capabilities.

## Kept Skill Families
- Static detection and rule authoring: `sast-semgrep`, `semgrep-rule-authoring`, `sarif-processing`
- Threat and reachability: `hunt-threat-modeler`, `dependency-analysis`, `cve-pattern-mining`, `differential-analysis`
- Verification and fuzzing: `fuzzing-orchestrator`, `aflpp-testing`, `atheris-python-fuzzing`, `libfuzzer-patterns`, `oss-fuzz-integration`, `patch-verification`
- Language security patterns: `csharp-security-patterns`, `node-security-patterns`, `java-security-patterns`, `go-security-patterns`, `python-security-patterns`, `php-security-patterns`, `api-patterns`
- Discovery and orchestration support: `target-acquisition`, `architecture-mapper`, `entry-point-discovery`, `variant-analysis`, `vulnerability-scanner`, `hunt-semgrep`, `hunt-gitleaks`, `insecure-defaults-audit`

## Removal Policy
Anything not directly supporting the harness mission in `../HARNESS_SCOPE.md` should stay out of this folder.
