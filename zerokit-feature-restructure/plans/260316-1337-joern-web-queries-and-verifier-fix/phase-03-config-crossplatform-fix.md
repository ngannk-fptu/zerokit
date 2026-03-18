---
phase: 3
priority: high
status: pending
---

# Phase 3: Config Cross-Platform Fix

## Context
`core/config.py` hardcode Windows paths:
```python
self.CODEQL_BIN = r"storage\tools\codeql-win64\codeql\codeql.cmd"
self.JOERN_HOME = os.path.abspath(r"storage\tools\joern")
```
User trên macOS → paths sai, `.bat`/`.cmd` extensions không tồn tại.

## Requirements
- Config detect OS, dùng đúng path separator + binary extension
- Bỏ CodeQL config (theo quyết định chỉ dùng Joern)
- Giữ JOERN_HOME configurable qua env var

## Implementation Steps

### 1. Fix `core/config.py`
```python
import platform

class PipelineConfig:
    def __init__(self):
        is_windows = platform.system() == "Windows"
        ext = ".bat" if is_windows else ""

        # Joern
        default_joern = os.path.join("storage", "tools", "joern")
        self.JOERN_HOME = os.getenv("JOERN_HOME", os.path.abspath(default_joern))
        self.JOERN_PARSE = os.path.join(self.JOERN_HOME, f"joern-parse{ext}")
        self.JOERN_SCAN = os.path.join(self.JOERN_HOME, f"joern-scan{ext}")
        self.JOERN_EXPORT = os.path.join(self.JOERN_HOME, f"joern-export{ext}")
        self.JOERN_WORKSPACE = os.getenv("JOERN_WORKSPACE",
            os.path.join("storage", "workspaces", "joern_workspace"))

        # Semgrep (usually in PATH)
        self.SEMGREP_RULES_PATH = os.getenv("SEMGREP_RULES_PATH",
            os.path.join("skills", "rules", "semgrep"))

        # SCA & Secrets
        self.GITLEAKS_PATH = os.getenv("GITLEAKS_PATH", "gitleaks")
        self.TRIVY_PATH = os.getenv("TRIVY_PATH", "trivy")

        # General
        self.LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
        self.VERIFY_TIMEOUT = int(os.getenv("VERIFY_TIMEOUT", "30"))
```

### 2. Remove CodeQL references
- Remove `self.CODEQL_BIN`, `self.CODEQL_DB_PATH`
- Remove `from ..tools.codeql_runner import CodeQLRunner` trong `detector.py`
- Remove `self.codeql_runner` initialization
- Keep `generate_codeql.md` prompt (useful cho MRVA export, nhưng không chạy local)

### 3. Remove fuzzer configs (chưa cần)
Jazzer, AFL, Atheris configs → remove khỏi default config. Thêm lại khi implement fuzzer phase.
Theo YAGNI — không config tool chưa dùng.

## Related Files
- Modify: `core/config.py`
- Modify: `core/agents/detector.py` (remove CodeQL runner)
- Modify: `core/tools/joern_runner.py` (verify dùng config paths đúng)

## Todo
- [ ] Rewrite `config.py` với `platform.system()` detection
- [ ] Remove CodeQL config + runner references
- [ ] Remove unused fuzzer configs
- [ ] Test: import config trên macOS không lỗi
- [ ] Test: `JOERN_HOME` env var override hoạt động

## Success Criteria
- `config.py` chạy clean trên macOS + Linux + Windows
- Không còn hardcode backslash paths
- Không còn reference đến tools chưa implement
