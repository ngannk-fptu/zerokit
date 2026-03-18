---
status: complete
branch: feature/restructure
created: 2026-03-16
slug: joern-web-queries-and-verifier-fix
---

# Plan: Joern Web Language Queries + Verifier Template Fix

## Context
Review nhánh `feature/restructure` phát hiện 2 thiếu sót lớn:
1. Joern queries chỉ cover C/C++ — vô dụng cho web targets
2. Verifier template mapping chỉ match SQLi + XSS — miss phần lớn CWE

## Phases

| # | Phase | Status | File |
|---|-------|--------|------|
| 1 | Joern web taint queries (PHP, Java, JS, Python) | ✅ done | phase-01 |
| 2 | Verifier CWE→template mapping | ✅ done | phase-02 |
| 3 | Config cross-platform fix | ✅ done | phase-03 |

## Dependencies
- Nhánh `feature/restructure` đã checkout
- Joern installed (hỗ trợ jssrc, javasrc, pythonsrc, php)

## Key Files
- `core/tools/joern_queries.py` — thêm web queries
- `core/agents/verifier.py` — fix `_select_template()`
- `core/config.py` — fix hardcode Windows paths
- `core/profiles.py` — reference source/sink patterns
