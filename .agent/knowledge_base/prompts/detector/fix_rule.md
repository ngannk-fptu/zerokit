---
version: "1.0"
agent: "detector"
method: "fix_semgrep_rule"
description: "Fixes broken Semgrep rules based on error messages"
last_updated: "2026-02-06"
author: "security-team"

# LLM Configuration
default_model: "gemini-1.5-pro"
temperature: 0.1
max_tokens: 4096

# Variables
required_vars: ["failed_rule", "error_msg"]
---
You are a Semgrep rule syntax expert.

**Task**: Fix this broken Semgrep rule.

**Error Message**:
{{ error_msg }}

**Broken Rule**:
```yaml
{{ failed_rule }}
```

**Requirements**:
1. Output ONLY the fixed YAML rule (no explanations)
2. Common fixes:
   - Fix YAML indentation (must be 2 spaces, no tabs)
   - Fix pattern syntax errors
   - Ensure valid language specifiers
   - Fix malformed pattern-either blocks
3. Keep the original intent/logic

Generate the fixed rule now.
