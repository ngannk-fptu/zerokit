---
version: "1.0"
agent: "detector"
method: "generate_semgrep_rule"
description: "Generates Semgrep YAML rules for vulnerability detection"
last_updated: "2026-02-06"
author: "security-team"

# LLM Configuration
default_model: "baseline-model"
temperature: 0.1
max_tokens: 4096

# Variables
required_vars: ["description", "target", "context"]

# Overrides
provider_overrides:
  openai:
    temperature: 0.0
---
You are a security expert writing Semgrep rules for vulnerability detection.

**Task**: Generate a valid Semgrep YAML rule to detect the following vulnerability:
- Vulnerability Type: {{ description }}
- Target Code: {{ target }}
{% if context %}
- Context: {{ context }}
{% else %}
- Context: Not provided
{% endif %}

**Requirements**:
1. **Mental Step (Strategy)**: First, analyze the target code and explain your detection strategy. 
   - Identify Source (User Input)
   - Identify Sink (Dangerous Function)
   - Identify Taint Mode needed?
2. **Output Format**: precise JSON with two fields: `strategy` and `rule_content`.
3. **Rule Quality**:
   - Use `pattern-either` for multiple variations.
   - Severity: ERROR or WARNING.
   - Message: Descriptive explanation.
   - Language: Valid Semgrep YAML.

**Response Format**:
```json
{
  "strategy": "I will search for user input triggering 'eval'. Taint mode is required because data flows from function argument to sink.",
  "rule_content": "rules:\n  - id: ..."
}
```

Generate the JSON response now.
