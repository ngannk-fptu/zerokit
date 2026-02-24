# Antigravity Integration - Quick Start Demo

This guide demonstrates the Antigravity integration in action.

## Prerequisites

```bash
pip install -r requirements.txt
pip install watchdog
```

## Demo Scenario

We'll hunt a simple PHP application to demonstrate the workflow.

### Step 1: Create Test Target

```bash
mkdir -p targets/demo-php-app
```

Create `targets/demo-php-app/index.php`:

```php
<?php
// Demo vulnerable PHP app
$user_id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $user_id;
$result = mysqli_query($conn, $query);
?>
```

### Step 2: Start Monitor

**Terminal 1:**
```bash
cd d:\WLD\SSI\research\1\trilm\ZeroKit2
python .agent\scripts\antigravity_monitor.py
```

Expected output:
```
================================================================================
🚀 ANTIGRAVITY MONITOR STARTED
================================================================================
Queue Directory: D:\WLD\SSI\research\1\trilm\ZeroKit2\.agent\prompts\queue
Response Directory: D:\WLD\SSI\research\1\trilm\ZeroKit2\.agent\prompts\responses
Auto-Execute All: False
Auto-Execute Methods: fix_semgrep_rule, fix_rule
Manual Review Methods: generate_hypotheses, analyze_risk, generate_patch, generate_poc
================================================================================

⏳ Watching for new prompts... (Press Ctrl+C to stop)
```

### Step 3: Run Pipeline

**Terminal 2:**
```bash
cd d:\WLD\SSI\research\1\trilm\ZeroKit2
python hunt_pipeline.py targets\demo-php-app
```

### Step 4: Respond to Prompts

**Monitor Terminal will show:**

```
================================================================================
📥 NEW PROMPT REQUEST
================================================================================
ID: a1b2c3d4-e5f6-...
Agent: threat_modeler
Method: analyze_risk
Prompt Length: 1234 characters
--------------------------------------------------------------------------------
🔍 MANUAL REVIEW MODE (method 'analyze_risk' requires confirmation)

--------------------------------------------------------------------------------
PROMPT CONTENT:
--------------------------------------------------------------------------------
Analyze the security risks for this PHP file...
[full prompt content]
--------------------------------------------------------------------------------

================================================================================
AWAITING YOUR RESPONSE (Antigravity)
================================================================================
Instructions:
  1. Process the prompt above using your expertise
  2. Type or paste your response below
  3. End with '---END---' on a new line
================================================================================
```

**Your Response:**
```json
[
  {
    "risk": "SQL Injection via Direct Parameter Interpolation",
    "severity": "CRITICAL",
    "reasoning": "User input $_GET['id'] is directly concatenated into SQL query without sanitization",
    "suggested_check": "Verify with taint analysis from $_GET to mysqli_query"
  }
]
---END---
```

### Step 5: Observe Pipeline Continue

The pipeline will:
1. Generate Semgrep rules based on your hypotheses
2. Scan the code
3. Ask you to generate PoC
4. Verify vulnerability
5. Generate patch
6. Create final report

### Expected Full Workflow

**Prompt 1: Threat Modeling (Manual)**
- Agent: `threat_modeler`
- Method: `analyze_risk`
- Your task: Identify potential vulnerabilities

**Prompt 2: Rule Generation (Auto, if fix needed)**
- Agent: `detector`
- Method: `fix_semgrep_rule`
- Executes automatically if syntax error

**Prompt 3: PoC Generation (Manual)**
- Agent: `verifier`
- Method: `generate_poc`
- Your task: Create Python exploit script

**Prompt 4: Patch Generation (Manual)**
- Agent: `patcher`
- Method: `generate_patch`
- Your task: Provide secure code fix

## Verification

Check archived conversations:

```bash
ls .agent\prompts\archive\
```

Each `.json` file contains:
- Original request (prompt, agent, method)
- Your response
- Token usage

## Troubleshooting

**Problem**: Monitor not detecting prompts

**Solution**:
```bash
# Check queue directory exists
ls .agent\prompts\queue\

# Restart monitor with debug
python .agent\scripts\antigravity_monitor.py --auto-all
```

**Problem**: Pipeline timeout

**Solution**:
- Ensure you ended response with `---END---`
- Check response file was created
- Increase timeout in `.env`:
  ```
  ANTIGRAVITY_TIMEOUT=120
  ```

## Success Criteria

✅ Monitor detects queue files
✅ Prompts display correctly
✅ Your responses are parsed
✅ Pipeline continues after each response
✅ Final report.md is generated
✅ No external API calls made

## Next Steps

- Try with real WordPress plugin
- Experiment with `--auto-all` flag
- Analyze archived dataset
- Fine-tune auto-execute rules
