"""
Joern Query Templates for Common Vulnerability Patterns

Based on learn.md lines 819-848 and Praetorian research.
These templates target C/C++ memory safety issues.
"""

# Template 1: Buffer Overflow - strcpy without bounds check
BUFFER_OVERFLOW_STRCPY = """
// Find strcpy calls without preceding length validation
val strcpyCalls = cpg.call("strcpy").l

val vulnerableCalls = strcpyCalls.filterNot { call =>
  // Check if there's a strlen or size check in control flow predecessors
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
    "description" -> "strcpy called without size validation - potential buffer overflow"
  )
}.toJson
"""

# Template 2: Buffer Overflow - sprintf/vsprintf
BUFFER_OVERFLOW_SPRINTF = """
// Find sprintf/vsprintf (always dangerous)
val sprintfCalls = cpg.call.name("sprintf|vsprintf").l

sprintfCalls.map { call =>
  Map(
    "vulnerability_type" -> "Buffer Overflow (sprintf)",
    "file" -> call.file.name.headOption.getOrElse("unknown"),
    "line" -> call.lineNumber.getOrElse(-1),
    "code" -> call.code,
    "function" -> call.method.name,
    "severity" -> "CRITICAL",
    "description" -> "Unsafe sprintf/vsprintf detected - use snprintf instead"
  )
}.toJson
"""

# Template 3: Use-After-Free
USE_AFTER_FREE = """
// Find free() followed by potential use of same variable
val freeCalls = cpg.call("free").l

val vulnerableUses = freeCalls.flatMap { freeCall =>
  val freedVar = freeCall.argument(1).code.headOption.getOrElse("")
  
  // Look for uses of the same variable after free in CFG
  val laterUses = freeCall.cfgNext.ast.isIdentifier
    .filter(_.code == freedVar)
    .whereNot(_.inCall.name("free"))  // Ignore double-free checks
  
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

# Template 4: Format String Vulnerabilities
FORMAT_STRING_VULN = """
// Find printf-family calls with non-literal format strings
val printfCalls = cpg.call.name("printf|fprintf|sprintf|snprintf").l

val vulnerableCalls = printfCalls.filter { call =>
  // Check if first argument (format string) is NOT a literal
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
    "description" -> "Format string from untrusted input - potential info leak/code execution"
  )
}.toJson
"""

# Template 5: Integer Overflow (Allocation)
INTEGER_OVERFLOW_ALLOC = """
// Find malloc/calloc with arithmetic expressions
val allocCalls = cpg.call.name("malloc|calloc").l

val riskyAllocs = allocCalls.filter { call =>
  val sizeArg = call.argument(1)
  // Check if size argument contains multiplication/addition
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
    "description" -> "Allocation size computed via arithmetic - potential integer overflow"
  )
}.toJson
"""

# Template 6: NULL Pointer Dereference
NULL_DEREF = """
// Find pointer uses without NULL checks
val pointerParams = cpg.method.parameter.evalType(".*\\\\*.*").l

val riskyDerefs = pointerParams.flatMap { param =>
  val paramName = param.name
  val method = param.method
  
  // Find dereferences of this pointer without preceding NULL check
  val derefs = method.ast.isCall.argument.code(paramName)
  
  derefs.filterNot { deref =>
    // Check if there's a NULL check in control flow
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

# Template 7: Command Injection (system/exec calls)
COMMAND_INJECTION = """
// Find system/exec calls with non-literal arguments
val execCalls = cpg.call.name("system|exec.*|popen").l

val vulnerableCalls = execCalls.filter { call =>
  // Check if command argument is NOT a string literal
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

# Template 8: Double Free
DOUBLE_FREE = """
// Find multiple free() calls on same variable
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

# Query Registry
QUERY_TEMPLATES = {
    "buffer_overflow_strcpy": BUFFER_OVERFLOW_STRCPY,
    "buffer_overflow_sprintf": BUFFER_OVERFLOW_SPRINTF,
    "use_after_free": USE_AFTER_FREE,
    "format_string": FORMAT_STRING_VULN,
    "integer_overflow": INTEGER_OVERFLOW_ALLOC,
    "null_deref": NULL_DEREF,
    "command_injection": COMMAND_INJECTION,
    "double_free": DOUBLE_FREE,
}

# Query categories for selective scanning
MEMORY_SAFETY_QUERIES = [
    "buffer_overflow_strcpy",
    "buffer_overflow_sprintf",
    "use_after_free",
    "null_deref",
    "double_free",
]

INJECTION_QUERIES = [
    "command_injection",
    "format_string",
]

ALL_QUERIES = list(QUERY_TEMPLATES.keys())
