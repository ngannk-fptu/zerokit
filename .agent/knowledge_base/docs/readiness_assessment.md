# ZeroKit2 Readiness Assessment

> **Date**: 2026-02-04  
> **Pipeline Version**: Phase 6 Complete (Reporting & Feedback)

---

## Executive Summary

**ZeroKit2 is ARCHITECTURALLY READY but TOOLING INCOMPLETE.**

- ✅ **Core Framework**: 9-phase pipeline with Verification Gate implemented
- ✅ **Agents**: Profiler, Threat Modeler, Detector, Verifier, Reporter all exist
- ⚠️ **Tool Integration**: Only Semgrep wrapper exists (1/10+ tools needed)
- ❌ **Language Coverage**: Only Python adapter implemented (1/6+ languages)
- ⚠️ **Verification**: ASan logic **simulated**, not actually compiling with sanitizers

**Readiness Score**: **35%** (Architecture: 90%, Tooling: 10%)

---

## Detailed Gap Analysis

### Phase 1-2: Profiling & Attack Surface ✅ (70% Ready)

| Component | Status | Gap |
|-----------|--------|-----|
| **Orchestrator** | ✅ Complete | None |
| **PipelineContext** (Pydantic models) | ✅ Complete | None |
| **PythonAdapter** | ✅ Implemented | Smart detection works, entry point parsing (AST) works |
| **JavaAdapter** | ❌ Missing | Need Maven/Gradle detection + Spring route parsing |
| **NodeAdapter** | ❌ Missing | Need npm detection + Express/Nest route parsing |
| **CAdapter** | ❌ Missing | Need CMake/Make detection + function signature extraction |
| **GoAdapter** | ❌ Missing | Need go.mod detection + net/http handler parsing |
| **Health Check Execution** | ⚠️ Stubbed | `_run_health_check` doesn't actually validate build success |

**What's Missing**:
- 4 additional language adapters (templates available in `learn.md` lines 310-447)
- Build system auto-detection needs actual subprocess execution validation
- Entry point identification needs framework-specific parsers (e.g., Spring annotations, Flask decorators)

---

### Phase 3: Threat Modeling ✅ (80% Ready)

| Component | Status | Gap |
|-----------|--------|-----|
| **ThreatModeler** | ✅ Implemented | Prioritization logic works |
| **Hypothesis Generation** | ✅ Working | Keyword-based ranking (CRITICAL/HIGH/MEDIUM/LOW) |
| **CWE Mapping** | ❌ Not implemented | `learn.md` suggests CWE matcher (lines 193-196) |
| **Adapter Integration** | ⚠️ Partial | Only uses generic entry points, not framework-specific threats |

**What's Missing**:
- CWE database integration (e.g., map "file upload" → CWE-434)
- Framework-specific threat patterns (e.g., Spring deserialization, Django CSRF bypass)

---

### Phase 4: Static Detection ⚠️ (40% Ready)

| Component | Status | Gap |
|-----------|--------|-----|
| **SemgrepRunner** | ✅ Implemented | Can execute Semgrep, parse JSON output |
| **CodeQLRunner** | ❌ Missing | No wrapper for CodeQL CLI |
| **JoernRunner** | ❌ Missing | No CPG query execution |
| **Query Synthesis** | ⚠️ Stubbed | Architecture exists, but no LLM integration |
| **Repair Loop** | ⚠️ Stubbed | Hook exists, but no error handling logic |
| **Detector Agent** | ✅ Implemented | Normalizes findings into `StaticFinding` models |

**What's Missing**:
- **CodeQL Integration**: Need `CodeQLRunner` (similar to `SemgrepRunner`) to:
  - Execute `codeql database create`
  - Run `.ql` queries via `codeql query run`
  - Parse SARIF output
- **Joern Integration**: Need `JoernRunner` to:
  - Generate CPG via `joern-parse`
  - Execute Scala/Gremlin queries
  - Return code locations
- **Query Synthesis**: LLM-based rule generation (QLPro approach from `learn.md` lines 198-206)

**Resource Mapping** (from `learn.md`):
- **CodeQL Examples**: `learn.md` lines 762-791 (query skeleton)
- **Semgrep Examples**: `learn.md` lines 793-817 (YAML template)
- **Joern Examples**: `learn.md` lines 819-848 (Scala/Gremlin snippets)

---

### Phase 5: Dynamic Verification ⚠️ (30% Ready)

| Component | Status | Gap |
|-----------|--------|-----|
| **Verifier Agent** | ✅ Implemented | Orchestration logic exists |
| **Directed Fuzzing** | ⚠️ **SIMULATED** | Keyword-based mock, no actual fuzzer execution |
| **Sanitizer Integration** | ⚠️ **SIMULATED** | Checks for "AddressSanitizer" string, doesn't compile with ASan |
| **FuzzerRunner** (AFL++/libFuzzer) | ❌ Missing | No subprocess execution of fuzzers |
| **Harness Generation** | ❌ Missing | Templates exist in `learn.md` (lines 850-937) but not implemented |
| **PoC Execution Sandbox** | ❌ Missing | No Docker/VM isolation |

**What's Missing**:
1. **Fuzzer Integration**:
   - `AFL++Runner`: Execute `afl-fuzz -i input -o output -- ./target`
   - `libFuzzerRunner`: Compile with `-fsanitize=fuzzer`, execute harness
   - `JazzerRunner`: Java fuzzing via `jazzer --cp=...`
   - `AtherisRunner`: Python fuzzing

2. **Sanitizer Compilation**:
   - Modify adapters to inject `-fsanitize=address,undefined` into build commands
   - Parse actual ASan output (heap-buffer-overflow, use-after-free patterns)

3. **Harness Templates** (from `learn.md`):
   - **C/C++ libFuzzer**: `learn.md` lines 854-863
   - **Jazzer (Java)**: `learn.md` lines 866-877
   - **Go Fuzz**: `learn.md` lines 879-886
   - **Atheris (Python)**: `learn.md` lines 899-909

**Current Limitation**: `Verifier.verify()` uses **keyword matching** (e.g., if "buffer" in finding, assume ASan would detect it). This is **NOT** actual verification.

---

### Phase 6: Reporting & Feedback ✅ (90% Ready)

| Component | Status | Gap |
|-----------|--------|-----|
| **Reporter Agent** | ✅ Implemented | Evidence packaging works |
| **Variant Analysis Loop** | ✅ Implemented | `run_stage_feedback()` triggers re-scan |
| **Markdown Report** | ✅ Working | Includes PoC, runtime logs, traces |
| **JSON Export** | ✅ Working | `generate_json_report()` |
| **Regression Test Generation** | ❌ Missing | Should auto-create test from PoC (lines 925-936 in `learn.md`) |

**What's Missing**:
- Auto-generate JUnit/pytest tests from `VerifiedVuln` PoC
- CVSS scoring (mentioned in `learn.md` line 219)

---

## Tool Inventory vs. Requirements

| Tool Category | Required (from `learn.md`) | Implemented | Gap |
|---------------|---------------------------|-------------|-----|
| **Static Analysis** | Semgrep, CodeQL, Joern | Semgrep ✅ | CodeQL ❌, Joern ❌ |
| **Fuzzers** | AFL++, libFuzzer, Jazzer, Atheris | None | All missing ❌ |
| **Sanitizers** | ASan, UBSan, MSan, TSan | Mock logic ⚠️ | No build integration ❌ |
| **Build Systems** | Maven, Gradle, npm, pip, CMake, go mod | pip ✅ | Others ❌ |
| **SCA/Secrets** | Trivy, Gitleaks | None | Both missing ❌ |
| **Debuggers** | GDB | N/A | Manual use only |

---

## What You Need to Provide/Configure

### 1. Tool Installation

Run these commands to install missing tools:

```bash
# CodeQL
wget https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-win64.zip
unzip codeql-win64.zip
# Add to PATH

# Joern
wget https://github.com/joernio/joern/releases/latest/download/joern-cli.zip
unzip joern-cli.zip

# AFL++ (requires WSL or Linux VM on Windows)
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus && make install

# Jazzer
wget https://github.com/CodeIntelligenceTesting/jazzer/releases/latest/download/jazzer-linux.tar.gz

# Atheris
pip install atheris

# Trivy
wget https://github.com/aquasecurity/trivy/releases/latest/download/trivy_Windows-64bit.zip

# Gitleaks
wget https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_windows_x64.zip
```

### 2. Configuration Files

#### Option A: Provide Tool Paths
Create a local harness config module (for example `.agent/knowledge_base/local_config_example.py`) or use environment variables:

```python
TOOL_PATHS = {
    "semgrep": "semgrep",  # Assumes in PATH
    "codeql": "C:/tools/codeql/codeql.exe",
    "joern": "C:/tools/joern/joern",
    "afl-fuzz": "C:/wsl/afl-fuzz",  # Via WSL
    "jazzer": "java -jar C:/tools/jazzer.jar",
    "trivy": "C:/tools/trivy.exe",
    "gitleaks": "C:/tools/gitleaks.exe",
}
```

#### Option B: I Can Auto-Detect
I can implement auto-detection (search common paths, check `which`/`where` commands).

### 3. Adapter Templates (from `learn.md`)

Do you want me to:
- **Implement remaining adapters** (Java, JS, C++, Go) using templates from `learn.md` lines 310-447?
- **Create tool wrappers** (`CodeQLRunner`, `JoernRunner`, `FuzzerRunner`) based on examples in `learn.md`?

### 4. Harness Templates

Should I:
- Copy harness templates from `learn.md` (lines 850-937) into `.agent/knowledge_base/templates/`?
- Implement `Verifier._generate_harness()` to use these templates?

---

## Recommended Action Plan

### Immediate (Next 1-2 hours)
1. ✅ **You provide**: Tool installation paths or confirm auto-install preference
2. ✅ **I implement**: `CodeQLRunner` and `JoernRunner` tools
3. ✅ **I implement**: Java, JavaScript, C++ adapters with build detection

### Short-term (Next 1-2 days)
4. ✅ **I implement**: `FuzzerRunner` with AFL++/libFuzzer integration
5. ✅ **I upgrade**: `Verifier` to actually compile with ASan and parse real crash logs
6. ✅ **I create**: Harness generation logic using templates

### Medium-term (Next week)
7. ✅ **I add**: Trivy/Gitleaks for SCA/Secrets scanning
8. ✅ **I test**: Full pipeline on OWASP Benchmark or WebGoat
9. ✅ **I tune**: Rules and adapters based on false positive rate

---

## Resources from `learn.md` to Leverage

### Query/Rule Templates
- **CodeQL Skeleton**: `learn.md` lines 762-791
- **Semgrep YAML**: `learn.md` lines 793-817
- **Joern CPG Queries**: `learn.md` lines 819-848

### Harness Templates
- **C/C++ libFuzzer**: `learn.md` lines 854-863
- **Jazzer (Java)**: `learn.md` lines 866-877
- **Go Fuzz**: `learn.md` lines 879-886
- **Python Hypothesis**: `learn.md` lines 887-898
- **Atheris**: `learn.md` lines 899-909
- **Rust cargo-fuzz**: `learn.md` lines 911-920

### Adapter Specs
- **Java/Spring**: `learn.md` lines 310-329
- **JavaScript/Node**: `learn.md` lines 331-361
- **Python/Django**: `learn.md` lines 363-398
- **Go**: `learn.md` lines 400-446
- **PHP**: `learn.md` lines 448-487
- **C/C++**: `learn.md` lines 489-540
- **Rust**: `learn.md` lines 542-580

### Key Research Papers (Referenced in `learn.md`)
- **HarnessAgent** (arXiv 2512.03420): Auto-generate fuzz harnesses with LLMs
- **QLPro** (arXiv 2506.23644): Auto-generate CodeQL queries with repair loop
- **Lyso** (USENIX 2025): Directed fuzzing from static analysis
- **Aardvark** (OpenAI 2025): Multi-stage AI security agent

---

## Conclusion

**You have an EXCELLENT foundation** - the 9-phase architecture is sound and matches industry best practices (Aardvark, QLPro, HarnessAgent methodologies).

**Critical Gap**: Tool wrappers and adapters. With `learn.md` as reference, I can implement these **in 2-4 hours** if you confirm:
1. Tool installation strategy (manual or auto-detect)
2. Priority order (CodeQL > Joern > Fuzzers, or all at once)
3. Whether you want LLM-based query/harness generation (requires API key)

**Ready to proceed when you confirm!** 🚀
