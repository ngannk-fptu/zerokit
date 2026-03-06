---
name: go-security-patterns
description: Advanced Go security patterns. Goroutine Leaks, Unsafe Pointers, Gin/Echo binding issues, SSRF.
tools: Read, Grep, Glob
---

# Go Security Patterns

## 1. Goroutine Leaks (DoS)
- **Pattern**: Starting a goroutine that waits on a channel which is never written to.
- **Impact**: Memory exhaustion.

## 2. Unsafe Pointers
- **Pattern**: `unsafe.Pointer(...)`
- **Impact**: Memory corruption, bypassing type safety.

## 3. Directory Traversal (`path/filepath`)
- **Pattern**: `filepath.Join("/app/data", userInput)`
- **Issue**: `Join` cleans paths but does NOT sandox them. User can pass `../`.
- **Fix**: Check `strings.HasPrefix(finalPath, "/app/data")`.

## 4. SSTI (text/template)
- **Pattern**: `template.New("x").Parse(userInput)`
- **Impact**: RCE (method execution on passed data objects).

## 5. Gin/Echo Binding
- **Pattern**: Binding JSON to a struct with fields that shouldn't be modifiable (Mass Assignment).
- **Fix**: Use specific DTO structs for input.
