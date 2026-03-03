# ZeroKit2 Tool Setup Checklist

> **Reference**: Based on `learn.md` methodology and adapter specifications (lines 296-641, 948-1082)

## Core Static Analysis Tools

### ✅ Must-Have (Priority 1)

- [ ] **Semgrep** (v1.x latest)
  - Purpose: Fast pattern matching, taint analysis
  - Languages: Python, Java, JavaScript, Go, PHP, C/C++
  - Installation: `pip install semgrep` or Docker
  - Rules: Clone `semgrep-rules` repo for community rulesets
  - **Status in ZeroKit2**: ✅ Integrated (`SemgrepRunner` exists)

- [ ] **CodeQL CLI** (v2.x latest)
  - Purpose: Deep dataflow, interprocedural taint tracking
  - Languages: Java, JavaScript/TypeScript, Python, Go, C/C++, Ruby, C#
  - Installation: Download from GitHub, add to PATH
  - Requires: CodeQL standard libraries (auto-downloaded)
  - **Status in ZeroKit2**: ❌ No wrapper (needs `CodeQLRunner` tool)

- [ ] **Joern** (v2.x latest)
  - Purpose: Code Property Graph (CPG) analysis for C/C++
  - Installation: Download binary from joernio/joern releases
  - Use cases: Buffer overflow patterns, unsafe pointer ops
  - **Status in ZeroKit2**: ❌ No integration

---

## Dynamic Analysis & Fuzzing

### Fuzzers (Language-Specific)

- [ ] **AFL++** (latest)
  - Purpose: Coverage-guided fuzzing for C/C++
  - Installation: `git clone && make install`
  - **Status**: ❌ Not integrated

- [ ] **libFuzzer** (via Clang)
  - Purpose: In-process fuzzing for C/C++
  - Installation: Comes with Clang/LLVM (ensure `-fsanitize=fuzzer`)
  - **Status**: ❌ Not configured

- [ ] **Jazzer** (v0.x latest)
  - Purpose: JVM fuzzing (Java/Kotlin)
  - Installation: Download JAR from GitHub releases
  - **Status**: ❌ Not integrated

- [ ] **Atheris** (Python fuzzing)
  - Purpose: libFuzzer for Python
  - Installation: `pip install atheris`
  - **Status**: ❌ Not integrated

- [ ] **Go native fuzzing** (Go 1.18+)
  - Purpose: Built-in fuzz testing
  - Installation: Ensure Go 1.18+ (`go version`)
  - **Status**: ⚠️ Depends on Go adapter (not implemented)

---

## Sanitizers (Runtime Detection)

> **Critical**: Must compile with sanitizer flags for `Verifier` agent

- [ ] **AddressSanitizer (ASan)**
  - Purpose: Heap/stack buffer overflow, use-after-free
  - Flags: `-fsanitize=address` (GCC/Clang)
  - **Status**: ⚠️ `Verifier` has **mock logic** to parse ASan output, but no build integration

- [ ] **UndefinedBehaviorSanitizer (UBSan)**
  - Purpose: Integer overflow, null dereference, etc.
  - Flags: `-fsanitize=undefined`
  - **Status**: ❌ Not configured

- [ ] **MemorySanitizer (MSan)**
  - Purpose: Uninitialized memory reads
  - Flags: `-fsanitize=memory` (Clang only)
  - **Status**: ❌ Not configured

- [ ] **ThreadSanitizer (TSan)**
  - Purpose: Data races in concurrent code
  - Flags: `-fsanitize=thread`
  - **Status**: ❌ Not configured

---

## Build System Detection & Integration

> **Adapter Layer Requirement** (learn.md lines 310-447)

### Java
- [ ] **Maven** (`mvn` command available)
- [ ] **Gradle** (`gradle` or `./gradlew`)
- **Adapter Status**: ❌ No `JavaAdapter` (only `PythonAdapter` exists)

### JavaScript/TypeScript
- [ ] **npm** (`package.json` detection)
- [ ] **Yarn** (alternative package manager)
- **Adapter Status**: ❌ No `NodeAdapter`

### Python
- [ ] **pip** (`requirements.txt`)
- [ ] **Poetry** (`pyproject.toml`)
- **Adapter Status**: ✅ `PythonAdapter` implemented

### C/C++
- [ ] **CMake** (`CMakeLists.txt`)
- [ ] **Make** (`Makefile`)
- **Adapter Status**: ❌ No `CAdapter`

### Go
- [ ] **Go Modules** (`go.mod`)
- **Adapter Status**: ❌ No `GoAdapter`

---

## Supply Chain & Secret Scanning

> **Optional but Recommended** (learn.md mentions SCA/Secrets)

- [ ] **Trivy**
  - Purpose: Container/dependency vulnerability scanning
  - Installation: Download binary or Docker image
  - **Status**: ❌ Not integrated

- [ ] **Gitleaks**
  - Purpose: Detect hardcoded secrets in repos
  - Installation: `brew install gitleaks` or download binary
  - **Status**: ❌ Not integrated

---

## Debugging & Inspection

- [ ] **GDB** (GNU Debugger)
  - Purpose: Manual exploit development, crash analysis
  - Installation: `sudo apt install gdb` (Linux) or built-in (macOS)
  - **Status**: ❌ No integration (manual use only)

- [ ] **Valgrind** (optional, slower alternative to ASan)
  - Purpose: Memory leak/error detection
  - **Status**: ❌ Not integrated

---

## Language-Specific Linters & Analyzers

### Python
- [x] **Bandit** (security linter)
  - Install: `pip install bandit`
  - **Status**: ❌ Not integrated (but easy to add)

### Java
- [ ] **SpotBugs** + FindSecBugs plugin
  - **Status**: ❌ Not integrated

### Go
- [ ] **Gosec** (security scanner)
  - Install: `go install github.com/securego/gosec/v2/cmd/gosec@latest`
  - **Status**: ❌ Not integrated

### PHP
- [ ] **Psalm** or **Phan** (static analysis)
  - **Status**: ❌ Not integrated

---

## Infrastructure & Orchestration

- [ ] **Docker** (for sandboxed verification)
  - Purpose: Isolate PoC execution
  - **Status**: ⚠️ Not explicitly used yet

- [ ] **Fuzz Introspector** (Google OSS-Fuzz)
  - Purpose: Identify low-coverage functions for targeted fuzzing
  - **Status**: ❌ Not integrated

---

## Summary by Priority

| Priority | Tool Category | Status | Action Required |
|----------|---------------|--------|-----------------|
| **P0** | Semgrep | ✅ Done | None |
| **P0** | CodeQL CLI | ❌ Missing | Implement `CodeQLRunner` |
| **P0** | ASan Integration | ⚠️ Partial | Add build flag injection to adapters |
| **P1** | Joern | ❌ Missing | Implement `JoernRunner` |
| **P1** | AFL++/libFuzzer | ❌ Missing | Implement `FuzzerRunner` |
| **P1** | Jazzer (Java) | ❌ Missing | Add to `JavaAdapter` (when created) |
| **P2** | Language Adapters | ⚠️ 1/5 done | Implement Java, JS, C++, Go adapters |
| **P2** | Trivy/Gitleaks | ❌ Missing | Optional SCA/Secrets integration |
| **P3** | Atheris, UBSan, TSan | ❌ Missing | Future enhancements |

---

## Next Steps

1. **Install Core Tools**: CodeQL, Joern, AFL++
2. **Create Wrappers**: `CodeQLRunner`, `JoernRunner`, `FuzzerRunner` as reusable skill scripts under `.agent/skills/<tool-skill>/scripts/`
3. **Implement Adapters**: Java (Maven/Gradle), JavaScript (npm), C++ (CMake)
4. **Sanitizer Integration**: Update `Verifier` to compile targets with `-fsanitize=address,undefined`
5. **Testing**: Validate on OWASP Benchmark or deliberately vulnerable apps
