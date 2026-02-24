---
name: variant-analysis
description: Methodology for finding variants of known vulnerabilities using Abstraction and Pattern Matching.
tools: Read, Grep, Glob, Bash, Edit, Write
---

# Variant Analysis (Abstraction Engine)

> "One bug is a mistake. Two bugs is a pattern."

## The Abstraction Process

To find variants, you must stop thinking about *specific* code and start thinking about *abstract* patterns.

### Level 1: The Instance (Too Specific)
> "The function `getUser` lines 45-50 has a SQL injection because `req.query.id` is concatenated."
- **Search**: `grep "getUser"` -> Finds nothing else.

### Level 2: The Pattern (Just Right)
> "A Controller Action takes User Input and passes it to a Database Query without Parameterization."
- **Semgrep**: `db.query("..." + $INPUT)`
- **Finds**: 50 other injections in `getProduct`, `searchItems`, etc.

### Level 3: The Class (Too Broad)
> "Input goes to Database."
- **Finds**: Every database query in the app. Too noisy.

---

## How to Abstract a Bug

1. **Identify the Sink**: What dangerous function was called? (`eval`, `query`, `render`)
2. **Identify the Source**: Where did the data come from? (`req.body`, `argv`, `file`)
3. **Identify the Missing Barrier**: What validation was missing? (`sanitize`, `authorize`)
4. **Construct the Query**: "Find Source -> Sink AND NOT Barrier".

## Workflows by Language

| Language | Typical Abstraction |
|----------|---------------------|
| **JavaScript** | Find `dangerouslySetInnerHTML` with non-literal strings. |
| **Python** | Find `pickle.loads` with any argument. |
| **Java** | Find classes implementing `Serializable` with `readObject`. |
| **Go** | Find `go func()` inside a loop using loop variables (closure capture). |
| **PHP** | Find `unserialize()` on user input. |
