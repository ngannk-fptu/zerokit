"""
Joern Query Templates for Vulnerability Detection

Organized by language:
- C/C++: Memory safety (strcpy, sprintf, UAF, format string, etc.)
- PHP: Taint analysis (SQLi, XSS, CMDi, path traversal)
- Java: Taint analysis (SQLi, CMDi, deserialization, XXE)
- JavaScript: Taint analysis (SQLi, XSS DOM, CMDi, SSRF, prototype pollution)
- Python: Taint analysis (SQLi, CMDi, SSTI, path traversal)

Each query outputs JSON with: vulnerability_type, file, line, code, function, severity, description
"""

# =============================================================================
# Helper: standard output format for taint queries
# IMPORTANT: vulnType and severity are injected via Python .format() BEFORE
# passing to Joern, so Scala never sees undefined variables.
# =============================================================================
_TAINT_OUTPUT_TEMPLATE = """
flows.map {{ flow =>
  val src = flow.elements.head
  val snk = flow.elements.last
  Map(
    "vulnerability_type" -> "{vuln_type}",
    "file" -> snk.file.name.headOption.getOrElse("unknown"),
    "line" -> snk.lineNumber.getOrElse(-1),
    "code" -> snk.code,
    "function" -> snk.method.name,
    "source_code" -> src.code,
    "source_line" -> src.lineNumber.getOrElse(-1),
    "severity" -> "{severity}",
    "description" -> s"Taint flow: ${{src.code}} \u2192 ${{snk.code}}"
  )
}}.toJson
"""

# =============================================================================
# C/C++ QUERIES (existing — memory safety)
# =============================================================================

BUFFER_OVERFLOW_STRCPY = """
val strcpyCalls = cpg.call("strcpy").l
val vulnerableCalls = strcpyCalls.filterNot { call =>
  call.cfgPrev.isCall.name("strlen").nonEmpty ||
  call.cfgPrev.isCall.name("strnlen").nonEmpty ||
  call.cfgPrev.isCall.name("sizeof").nonEmpty
}
vulnerableCalls.map { call =>
  Map(
    "vulnerability_type" -> "Buffer Overflow (strcpy)",
    "file" -> call.file.name.headOption.getOrElse("unknown"),
    "line" -> call.lineNumber.getOrElse(-1),
    "code" -> call.code,
    "function" -> call.method.name,
    "severity" -> "HIGH",
    "description" -> "strcpy called without size validation"
  )
}.toJson
"""

BUFFER_OVERFLOW_SPRINTF = """
val sprintfCalls = cpg.call.name("sprintf|vsprintf").l
sprintfCalls.map { call =>
  Map(
    "vulnerability_type" -> "Buffer Overflow (sprintf)",
    "file" -> call.file.name.headOption.getOrElse("unknown"),
    "line" -> call.lineNumber.getOrElse(-1),
    "code" -> call.code,
    "function" -> call.method.name,
    "severity" -> "CRITICAL",
    "description" -> "Unsafe sprintf/vsprintf - use snprintf instead"
  )
}.toJson
"""

USE_AFTER_FREE = """
val freeCalls = cpg.call("free").l
val vulnerableUses = freeCalls.flatMap { freeCall =>
  val freedVar = freeCall.argument(1).code.headOption.getOrElse("")
  val laterUses = freeCall.cfgNext.ast.isIdentifier
    .filter(_.code == freedVar)
    .whereNot(_.inCall.name("free"))
  laterUses.map { use =>
    Map(
      "vulnerability_type" -> "Use-After-Free",
      "file" -> use.file.name.headOption.getOrElse("unknown"),
      "line" -> use.lineNumber.getOrElse(-1),
      "code" -> use.code,
      "freed_at" -> freeCall.lineNumber.getOrElse(-1),
      "function" -> use.method.name,
      "severity" -> "CRITICAL",
      "description" -> s"Variable '$freedVar' used after free()"
    )
  }
}.toJson
"""

FORMAT_STRING_VULN = """
val printfCalls = cpg.call.name("printf|fprintf|sprintf|snprintf").l
val vulnerableCalls = printfCalls.filter { call =>
  val formatArg = call.argument(1)
  !formatArg.isLiteral.nonEmpty
}
vulnerableCalls.map { call =>
  Map(
    "vulnerability_type" -> "Format String",
    "file" -> call.file.name.headOption.getOrElse("unknown"),
    "line" -> call.lineNumber.getOrElse(-1),
    "code" -> call.code,
    "function" -> call.method.name,
    "severity" -> "HIGH",
    "description" -> "Format string from untrusted input"
  )
}.toJson
"""

INTEGER_OVERFLOW_ALLOC = """
val allocCalls = cpg.call.name("malloc|calloc").l
val riskyAllocs = allocCalls.filter { call =>
  val sizeArg = call.argument(1)
  sizeArg.ast.isCall.name("operator\\\\*|operator\\\\+").nonEmpty
}
riskyAllocs.map { call =>
  Map(
    "vulnerability_type" -> "Integer Overflow (Allocation)",
    "file" -> call.file.name.headOption.getOrElse("unknown"),
    "line" -> call.lineNumber.getOrElse(-1),
    "code" -> call.code,
    "function" -> call.method.name,
    "severity" -> "MEDIUM",
    "description" -> "Allocation size via arithmetic - potential integer overflow"
  )
}.toJson
"""

NULL_DEREF = """
val pointerParams = cpg.method.parameter.evalType(".*\\\\*.*").l
val riskyDerefs = pointerParams.flatMap { param =>
  val paramName = param.name
  val method = param.method
  val derefs = method.ast.isCall.argument.code(paramName)
  derefs.filterNot { deref =>
    deref.cfgPrev.ast.isCall.name("operator==|operator!=")
      .argument.code(paramName).nonEmpty
  }.map { deref =>
    Map(
      "vulnerability_type" -> "NULL Pointer Dereference",
      "file" -> deref.file.name.headOption.getOrElse("unknown"),
      "line" -> deref.lineNumber.getOrElse(-1),
      "code" -> deref.code,
      "function" -> method.name,
      "severity" -> "MEDIUM",
      "description" -> s"Pointer '$paramName' dereferenced without NULL check"
    )
  }
}.toJson
"""

COMMAND_INJECTION_C = """
val execCalls = cpg.call.name("system|exec.*|popen").l
val vulnerableCalls = execCalls.filter { call =>
  val cmdArg = call.argument(1)
  !cmdArg.isLiteral.nonEmpty
}
vulnerableCalls.map { call =>
  Map(
    "vulnerability_type" -> "Command Injection",
    "file" -> call.file.name.headOption.getOrElse("unknown"),
    "line" -> call.lineNumber.getOrElse(-1),
    "code" -> call.code,
    "function" -> call.method.name,
    "severity" -> "CRITICAL",
    "description" -> "Shell command constructed from untrusted input"
  )
}.toJson
"""

DOUBLE_FREE = """
val freeCalls = cpg.call("free").l
val doubleFreeCandidates = freeCalls.groupBy { call =>
  call.argument(1).code.headOption.getOrElse("")
}.filter(_._2.size > 1)
doubleFreeCandidates.flatMap { case (varName, calls) =>
  calls.zipWithIndex.drop(1).map { case (call, idx) =>
    Map(
      "vulnerability_type" -> "Double Free",
      "file" -> call.file.name.headOption.getOrElse("unknown"),
      "line" -> call.lineNumber.getOrElse(-1),
      "code" -> call.code,
      "variable" -> varName,
      "function" -> call.method.name,
      "severity" -> "HIGH",
      "description" -> s"Variable '$varName' freed multiple times"
    )
  }
}.toJson
"""

# ---------------------------------------------------------------------------
# FIX: PHP superglobals ($_ GET, $_POST, etc.) are IDENTIFIERS in Joern's CPG,
# NOT function calls. Using cpg.call.name would return 0 results.
# FIX: Use raw strings (r""") to prevent Python interpreter from consuming
# backslashes before passing the regex to Scala/Joern.
# ---------------------------------------------------------------------------

PHP_SQLI_TAINT = r"""
// PHP SQL Injection: $_GET/$_POST/$_REQUEST/$_COOKIE → query/execute (no prepare)
val source = cpg.identifier.name("_GET|_POST|_REQUEST|_COOKIE").l
val sink = cpg.call.name("query|execute|db_query|mysql_query").filterNot(_.code.matches(".*prepare.*|.*PDO.*prepare.*")).l
val flows = sink.reachableByFlows(source).l
""" + _TAINT_OUTPUT_TEMPLATE.format(vuln_type="SQL Injection (PHP)", severity="CRITICAL")

PHP_XSS_TAINT = r"""
// PHP XSS: $_GET/$_POST → echo/print without esc_html/htmlspecialchars
val source = cpg.identifier.name("_GET|_POST|_REQUEST").l
val sink = cpg.call.name("echo|print|print_r").filterNot { call =>
  call.argument.code.exists(c =>
    c.contains("esc_html") || c.contains("esc_attr") ||
    c.contains("htmlspecialchars") || c.contains("htmlentities")
  )
}.l
val flows = sink.reachableByFlows(source).l
""" + _TAINT_OUTPUT_TEMPLATE.format(vuln_type="Cross-Site Scripting (PHP)", severity="HIGH")

PHP_CMDI_TAINT = r"""
// PHP Command Injection: $_GET/$_POST → system/exec/passthru/shell_exec
val source = cpg.identifier.name("_GET|_POST|_REQUEST").l
val sink = cpg.call.name("system|exec|passthru|shell_exec|popen|proc_open").l
val flows = sink.reachableByFlows(source).l
""" + _TAINT_OUTPUT_TEMPLATE.format(vuln_type="Command Injection (PHP)", severity="CRITICAL")

PHP_PATH_TRAVERSAL = r"""
// PHP Path Traversal: $_GET/$_POST → file_get_contents/include/require/fopen
val source = cpg.identifier.name("_GET|_POST|_REQUEST").l
val sink = cpg.call.name("file_get_contents|file_put_contents|include|require|include_once|require_once|fopen|readfile|unlink").l
val flows = sink.reachableByFlows(source).l
""" + _TAINT_OUTPUT_TEMPLATE.format(vuln_type="Path Traversal (PHP)", severity="HIGH")

# =============================================================================
# JAVA QUERIES (taint analysis)
# FIX: Use raw strings to prevent Python from mangling backslash-heavy patterns.
# FIX: ProcessBuilder uses "<init>" which needs proper raw-string preservation.
# =============================================================================

JAVA_SQLI_TAINT = r"""
// Java SQLi: getParameter → Statement.execute/executeQuery/executeUpdate
val source = cpg.call.name("getParameter|getHeader|getQueryString").l
val sink = cpg.call.name("execute|executeQuery|executeUpdate").where(_.receiver.code(".*Statement.*")).l
val flows = sink.reachableByFlows(source).l
""" + _TAINT_OUTPUT_TEMPLATE.format(vuln_type="SQL Injection (Java)", severity="CRITICAL")

JAVA_CMDI_TAINT = r"""
// Java CMDi: getParameter → Runtime.exec / ProcessBuilder
val source = cpg.call.name("getParameter|getHeader").l
val runtimeSinks = cpg.call.name("exec").where(_.receiver.code(".*Runtime.*")).l
val processSinks = cpg.call.name("start").where(_.receiver.typeFullName(".*ProcessBuilder.*")).l
val sink = runtimeSinks ++ processSinks
val flows = sink.reachableByFlows(source).l
""" + _TAINT_OUTPUT_TEMPLATE.format(vuln_type="Command Injection (Java)", severity="CRITICAL")

JAVA_DESERIALIZATION = r"""
// Java Insecure Deserialization: input stream → ObjectInputStream.readObject
val source = cpg.call.name("getInputStream|getReader").l
val sink = cpg.call.name("readObject|readUnshared").l
val flows = sink.reachableByFlows(source).l
""" + _TAINT_OUTPUT_TEMPLATE.format(vuln_type="Insecure Deserialization (Java)", severity="CRITICAL")

JAVA_XXE = r"""
// Java XXE: input → DocumentBuilder.parse / SAXParser.parse without secure features
val source = cpg.call.name("getInputStream|getReader|getParameter").l
val sink = cpg.call.name("parse").where(_.receiver.code(".*DocumentBuilder.*|.*SAXParser.*|.*XMLReader.*")).l
val flows = sink.reachableByFlows(source).l
""" + _TAINT_OUTPUT_TEMPLATE.format(vuln_type="XML External Entity (Java)", severity="HIGH")

# =============================================================================
# JAVASCRIPT QUERIES (taint analysis — uses jssrc frontend)
# FIX: cpg.fieldAccess was removed in Joern 1.x. Use cpg.call.code for innerHTML.
# FIX: Use raw strings to avoid Python double-escaping the dot-access patterns.
# =============================================================================

JS_SQLI_TAINT = r"""
// JS SQLi: req.query/req.body/req.params → db.query/execute/raw
val source = cpg.call.code(".*req\.(query|body|params|cookies).*").l
val sink = cpg.call.name("query|execute|raw").l
val flows = sink.reachableByFlows(source).l
""" + _TAINT_OUTPUT_TEMPLATE.format(vuln_type="SQL Injection (JavaScript)", severity="CRITICAL")

JS_XSS_DOM = r"""
// JS DOM XSS: user input → innerHTML assignment / document.write / eval
// FIX: Use cpg.call.code for innerHTML sink — old API was removed in Joern 1.x
val source = cpg.call.code(".*req\.(query|body|params).*").l ++ cpg.call.code(".*location\.(hash|search|href).*").l
val sink = cpg.call.name("eval").l ++
           cpg.call.name("write").where(_.receiver.code(".*document.*")).l ++
           cpg.call.code(".*\.innerHTML.*=.*").l
val flows = sink.reachableByFlows(source).l
""" + _TAINT_OUTPUT_TEMPLATE.format(vuln_type="DOM Cross-Site Scripting (JavaScript)", severity="HIGH")

JS_CMDI_TAINT = r"""
// JS CMDi: req.query/body → child_process.exec/execSync/spawn
val source = cpg.call.code(".*req\.(query|body|params).*").l
val sink = cpg.call.name("exec|execSync|spawn|spawnSync").l
val flows = sink.reachableByFlows(source).l
""" + _TAINT_OUTPUT_TEMPLATE.format(vuln_type="Command Injection (JavaScript)", severity="CRITICAL")

JS_SSRF = r"""
// JS SSRF: req input → fetch/axios/http.request with user-controlled URL
val source = cpg.call.code(".*req\.(query|body|params).*").l
val sink = cpg.call.name("fetch|get|post|request").l
val flows = sink.reachableByFlows(source).l
""" + _TAINT_OUTPUT_TEMPLATE.format(vuln_type="Server-Side Request Forgery (JavaScript)", severity="HIGH")

JS_PROTOTYPE_POLLUTION = r"""
// JS Prototype Pollution: dynamic property assignment from user input
val source = cpg.call.code(".*req\.(query|body).*").l
val sink = cpg.call.name("assign|merge|extend|defaultsDeep").l
val flows = sink.reachableByFlows(source).l
""" + _TAINT_OUTPUT_TEMPLATE.format(vuln_type="Prototype Pollution (JavaScript)", severity="HIGH")

# =============================================================================
# PYTHON QUERIES (taint analysis)
# FIX: Use raw strings to avoid \\\\. becoming garbled regex in Scala.
# =============================================================================

PY_SQLI_TAINT = r"""
// Python SQLi: request.args/form/GET/POST → cursor.execute (no parameterized)
val source = cpg.call.code(".*request\.(args|form|GET|POST|values|json).*").l
val sink = cpg.call.name("execute|executemany|raw").l
val flows = sink.reachableByFlows(source).l
""" + _TAINT_OUTPUT_TEMPLATE.format(vuln_type="SQL Injection (Python)", severity="CRITICAL")

PY_CMDI_TAINT = r"""
// Python CMDi: request input → os.system/subprocess.call/Popen
val source = cpg.call.code(".*request\.(args|form|GET|POST).*").l
val sink = cpg.call.name("system|popen").l ++ cpg.call.code(".*subprocess\.(call|run|Popen|check_output).*").l
val flows = sink.reachableByFlows(source).l
""" + _TAINT_OUTPUT_TEMPLATE.format(vuln_type="Command Injection (Python)", severity="CRITICAL")

PY_SSTI = r"""
// Python SSTI: request input → render_template_string/Template/eval/exec
val source = cpg.call.code(".*request\.(args|form|GET|POST).*").l
val sink = cpg.call.name("render_template_string|eval|exec").l ++ cpg.call.code(".*Template\(.*").l
val flows = sink.reachableByFlows(source).l
""" + _TAINT_OUTPUT_TEMPLATE.format(vuln_type="Server-Side Template Injection (Python)", severity="CRITICAL")

PY_PATH_TRAVERSAL = r"""
// Python Path Traversal: request input → open/read/send_file without sanitization
val source = cpg.call.code(".*request\.(args|form|GET|POST).*").l
val sink = cpg.call.name("open|send_file|send_from_directory").l
val flows = sink.reachableByFlows(source).l
""" + _TAINT_OUTPUT_TEMPLATE.format(vuln_type="Path Traversal (Python)", severity="HIGH")


# =============================================================================
# QUERY REGISTRY
# =============================================================================

QUERY_TEMPLATES = {
    # C/C++ memory safety
    "buffer_overflow_strcpy": BUFFER_OVERFLOW_STRCPY,
    "buffer_overflow_sprintf": BUFFER_OVERFLOW_SPRINTF,
    "use_after_free": USE_AFTER_FREE,
    "format_string": FORMAT_STRING_VULN,
    "integer_overflow": INTEGER_OVERFLOW_ALLOC,
    "null_deref": NULL_DEREF,
    "command_injection_c": COMMAND_INJECTION_C,
    "double_free": DOUBLE_FREE,
    # PHP
    "php_sqli_taint": PHP_SQLI_TAINT,
    "php_xss_taint": PHP_XSS_TAINT,
    "php_cmdi_taint": PHP_CMDI_TAINT,
    "php_path_traversal": PHP_PATH_TRAVERSAL,
    # Java
    "java_sqli_taint": JAVA_SQLI_TAINT,
    "java_cmdi_taint": JAVA_CMDI_TAINT,
    "java_deserialization": JAVA_DESERIALIZATION,
    "java_xxe": JAVA_XXE,
    # JavaScript
    "js_sqli_taint": JS_SQLI_TAINT,
    "js_xss_dom": JS_XSS_DOM,
    "js_cmdi_taint": JS_CMDI_TAINT,
    "js_ssrf": JS_SSRF,
    "js_prototype_pollution": JS_PROTOTYPE_POLLUTION,
    # Python
    "py_sqli_taint": PY_SQLI_TAINT,
    "py_cmdi_taint": PY_CMDI_TAINT,
    "py_ssti": PY_SSTI,
    "py_path_traversal": PY_PATH_TRAVERSAL,
}

# =============================================================================
# CATEGORY MAPS
# =============================================================================

# C/C++ categories
MEMORY_SAFETY_QUERIES = [
    "buffer_overflow_strcpy", "buffer_overflow_sprintf",
    "use_after_free", "null_deref", "double_free",
]

INJECTION_QUERIES = [
    "command_injection_c", "format_string",
]

# Web language categories
WEB_SQLI_QUERIES = [
    "php_sqli_taint", "java_sqli_taint", "js_sqli_taint", "py_sqli_taint",
]

WEB_XSS_QUERIES = ["php_xss_taint", "js_xss_dom"]

WEB_CMDI_QUERIES = [
    "php_cmdi_taint", "java_cmdi_taint", "js_cmdi_taint", "py_cmdi_taint",
]

WEB_PATH_TRAVERSAL_QUERIES = ["php_path_traversal", "py_path_traversal"]

WEB_DESER_QUERIES = ["java_deserialization"]

WEB_SSRF_QUERIES = ["js_ssrf"]

# Per-language query sets
_LANGUAGE_QUERIES = {
    "c": MEMORY_SAFETY_QUERIES + INJECTION_QUERIES,
    "cpp": MEMORY_SAFETY_QUERIES + INJECTION_QUERIES,
    "php": ["php_sqli_taint", "php_xss_taint", "php_cmdi_taint", "php_path_traversal"],
    "java": ["java_sqli_taint", "java_cmdi_taint", "java_deserialization", "java_xxe"],
    "typescript": ["js_sqli_taint", "js_xss_dom", "js_cmdi_taint", "js_ssrf", "js_prototype_pollution"],
    "javascript": ["js_sqli_taint", "js_xss_dom", "js_cmdi_taint", "js_ssrf", "js_prototype_pollution"],
    "python": ["py_sqli_taint", "py_cmdi_taint", "py_ssti", "py_path_traversal"],
}

ALL_QUERIES = list(QUERY_TEMPLATES.keys())


def get_queries_for_language(language: str) -> list:
    """Return appropriate Joern query names for a given language."""
    return _LANGUAGE_QUERIES.get(language.lower(), [])
