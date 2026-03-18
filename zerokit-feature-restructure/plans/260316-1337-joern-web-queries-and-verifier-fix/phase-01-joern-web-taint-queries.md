---
phase: 1
priority: critical
status: pending
---

# Phase 1: Joern Web Language Taint Queries

## Context
- `core/tools/joern_queries.py` hiện chỉ có 8 templates cho C/C++ (strcpy, sprintf, use-after-free...)
- Web targets (PHP, Java, JS, Python) = 90%+ use case → Joern gần như vô dụng
- SecurityProfile trong `core/profiles.py` đã define source/sink cho 5 languages → dùng làm reference

## Requirements
- Thêm taint query templates cho: PHP, Java, JavaScript, Python
- Mỗi language cần cover ít nhất: SQLi, XSS, CMDi, Path Traversal
- Query dùng Joern `reachableByFlows()` cho interprocedural taint
- Tổ chức theo language + vuln type

## Architecture

```
joern_queries.py
├── C/C++ queries (giữ nguyên 8 existing)
├── PHP queries (NEW)
│   ├── php_sqli_taint
│   ├── php_xss_taint
│   ├── php_cmdi_taint
│   └── php_path_traversal
├── Java queries (NEW)
│   ├── java_sqli_taint
│   ├── java_cmdi_taint
│   ├── java_deserialization
│   └── java_xxe
├── JavaScript queries (NEW)
│   ├── js_sqli_taint
│   ├── js_xss_dom
│   ├── js_cmdi_taint
│   ├── js_prototype_pollution
│   └── js_ssrf
└── Python queries (NEW)
    ├── py_sqli_taint
    ├── py_cmdi_taint
    ├── py_ssti
    └── py_path_traversal
```

## Implementation Steps

### 1. PHP Taint Queries
Source patterns (from profiles.py): `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`
Sink patterns: `wpdb->query(`, `echo`, `system(`, `exec(`, `eval(`

```scala
// PHP SQLi: $_GET/$_POST → query/execute
def source = cpg.call.name(".*\\$_(GET|POST|REQUEST|COOKIE).*")
def sink = cpg.call.name(".*query.*|.*execute.*|.*prepare.*").filterNot(_.code.contains("prepare("))
sink.reachableByFlows(source).p
```

### 2. Java Taint Queries
Source: `getParameter(`, `getHeader(`, `getInputStream(`
Sink: `Statement.execute(`, `Runtime.exec(`, `ObjectInputStream(`, `DocumentBuilder.parse(`

### 3. JavaScript Taint Queries
Source: `req.query`, `req.body`, `req.params`
Sink: `eval(`, `child_process.exec`, `db.query(`, `innerHTML`

### 4. Python Taint Queries
Source: `request.args`, `request.form`, `request.GET`, `request.POST`
Sink: `cursor.execute(`, `os.system(`, `subprocess.call(`, `eval(`, `render_template_string(`

### 5. Update Registry
Thêm vào `QUERY_TEMPLATES`, tạo category maps:
```python
WEB_SQLI_QUERIES = ["php_sqli_taint", "java_sqli_taint", "js_sqli_taint", "py_sqli_taint"]
WEB_XSS_QUERIES = ["php_xss_taint", "js_xss_dom"]
WEB_CMDI_QUERIES = ["php_cmdi_taint", "java_cmdi_taint", "js_cmdi_taint", "py_cmdi_taint"]
```

### 6. Update Detector agent
`core/agents/detector.py` cần chọn query set dựa trên `security_profile.language`:
```python
if profile.language in ("php", "java", "typescript", "python"):
    queries = get_queries_for_language(profile.language)
elif profile.language in ("c", "cpp"):
    queries = MEMORY_SAFETY_QUERIES + INJECTION_QUERIES
```

## Related Files
- Modify: `core/tools/joern_queries.py`
- Modify: `core/agents/detector.py` (query selection logic)
- Reference: `core/profiles.py` (source/sink patterns)

## Todo
- [ ] Thêm PHP taint queries (4 queries)
- [ ] Thêm Java taint queries (4 queries)
- [ ] Thêm JS taint queries (5 queries)
- [ ] Thêm Python taint queries (4 queries)
- [ ] Update QUERY_TEMPLATES registry + language category maps
- [ ] Update Detector.scan() để chọn queries theo language
- [ ] Test với fixture files: `tests/fixtures/sqli.php`, `tests/fixtures/xss.py`

## Success Criteria
- `joern_queries.py` có ≥20 query templates (8 existing + 17 new)
- Detector chọn đúng query set theo detected language
- Test fixtures phát hiện được SQLi trong `sqli.php` và XSS trong `xss.py`

## Risk
- Joern PHP/Python/JS parser chất lượng khác nhau → một số query có thể cần adjust syntax
- `reachableByFlows()` trên Joern cho non-C languages có thể chậm hoặc incomplete
- Mitigation: test từng language riêng, fallback Semgrep nếu Joern parser fail
