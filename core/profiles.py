"""
core/profiles.py — Multi-Language SecurityProfile Factory

Priority: .NET/C# → TypeScript/Node → Java → PHP → Python → Go
Auto-detects language from repo file extensions.
"""
import os
import logging
from collections import Counter
from pathlib import Path
from typing import Optional, Tuple

from .models import (
    SecurityProfile, SecurityPattern,
    VulnerabilityCategory, FindingSeverity
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Extension → (language, framework) map
# Priority determines which language wins in mixed repos
# ---------------------------------------------------------------------------
_EXT_MAP = {
    # .NET / C#
    ".cs":      ("csharp", "dotnet"),
    ".csproj":  ("csharp", "dotnet"),
    ".vbproj":  ("csharp", "dotnet"),
    # TypeScript / JavaScript
    ".ts":      ("typescript", "node"),
    ".tsx":     ("typescript", "react"),
    # Java / Kotlin
    ".java":    ("java", "spring"),
    ".kt":      ("java", "kotlin"),
    # PHP
    ".php":     ("php", "wordpress"),
    # Python
    ".py":      ("python", None),
    # Go
    ".go":      ("go", None),
}

_PRIORITY = ["csharp", "typescript", "java", "php", "python", "go"]


def detect_language(repo_path: str) -> Tuple[str, Optional[str]]:
    """
    Walk repo and count file extensions to determine dominant language.
    Returns (language, framework) tuple.
    Defaults to ("php", "wordpress") if nothing detected.
    """
    counts: Counter = Counter()

    try:
        for root, dirs, files in os.walk(repo_path):
            # Skip noise
            dirs[:] = [d for d in dirs if d not in {
                ".git", "node_modules", "__pycache__", "vendor",
                "bin", "obj", ".vs", "dist", "build"
            }]
            for f in files:
                ext = Path(f).suffix.lower()
                if ext in _EXT_MAP:
                    lang, _ = _EXT_MAP[ext]
                    counts[lang] += 1
    except Exception as e:
        logger.warning(f"Language detection failed: {e}")
        return ("php", "wordpress")

    if not counts:
        logger.info("No source files detected — defaulting to php/wordpress")
        return ("php", "wordpress")

    # Pick highest priority language with at least 1 file
    for lang in _PRIORITY:
        if counts.get(lang, 0) > 0:
            # Find framework for this language
            framework = next(
                (fw for ext, (l, fw) in _EXT_MAP.items() if l == lang and fw),
                None
            )
            logger.info(f"Detected language: {lang} ({framework}) — {counts[lang]} files")
            return (lang, framework)

    return ("php", "wordpress")


# ---------------------------------------------------------------------------
# Helper builder
# ---------------------------------------------------------------------------
def _sp(pattern: str, category: VulnerabilityCategory,
         severity: FindingSeverity = FindingSeverity.HIGH,
         description: str = "") -> SecurityPattern:
    return SecurityPattern(
        pattern=pattern,
        category=category,
        severity=severity,
        description=description
    )


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------

def _build_dotnet() -> SecurityProfile:
    sqli = VulnerabilityCategory.SQL_INJECTION
    xss  = VulnerabilityCategory.XSS
    rce  = VulnerabilityCategory.COMMAND_INJECTION
    pt   = VulnerabilityCategory.PATH_TRAVERSAL
    hi   = FindingSeverity.HIGH
    cr   = FindingSeverity.CRITICAL

    return SecurityProfile(
        language="csharp",
        framework="dotnet",
        sources=[
            _sp("Request.QueryString",           sqli, hi, "HTTP query param"),
            _sp("HttpContext.Request.Query",      sqli, hi, "ASP.NET Core query"),
            _sp("Request.Form",                  sqli, hi, "Form POST data"),
            _sp("HttpContext.Request.Headers",    xss,  hi, "Custom headers"),
            _sp("Request.Cookies",               sqli, hi, "Cookie values"),
        ],
        sinks=[
            _sp("SqlCommand",                    sqli, cr, "Raw SQL execution"),
            _sp("SqlCommand.ExecuteNonQuery",    sqli, cr, "SQL mutation"),
            _sp("SqlCommand.ExecuteReader",      sqli, cr, "SQL query"),
            _sp("Response.Write",                xss,  cr, "Direct HTML output"),
            _sp("HttpContext.Response.WriteAsync",xss,  cr, "Async HTML output"),
            _sp("Process.Start",                 rce,  cr, "OS process spawn"),
            _sp("Directory.Delete",              pt,   hi, "Filesystem delete"),
            _sp("File.ReadAllText",              pt,   hi, "Arbitrary file read"),
        ],
        sanitizers=[
            _sp("HtmlEncoder.Default.Encode",    xss,  hi, "HTML encoding"),
            _sp("SqlParameter",                  sqli, hi, "Parameterized query"),
            _sp("System.Web.HttpUtility.HtmlEncode", xss, hi, "Legacy HTML encode"),
            _sp("Microsoft.Data.SqlClient.SqlParameter", sqli, hi, "Modern SQL param"),
        ],
        metadata={
            "semgrep_configs": ["p/csharp", "p/owasp-top-ten"],
            "codeql_language": "csharp",
            "framework_specific": {"dotnet": True},
        }
    )


def _build_typescript() -> SecurityProfile:
    sqli = VulnerabilityCategory.SQL_INJECTION
    xss  = VulnerabilityCategory.XSS
    rce  = VulnerabilityCategory.COMMAND_INJECTION
    ssrf = VulnerabilityCategory.SSRF
    pp   = VulnerabilityCategory.PROTOTYPE_POLLUTION
    hi   = FindingSeverity.HIGH
    cr   = FindingSeverity.CRITICAL

    return SecurityProfile(
        language="typescript",
        framework="node",
        sources=[
            _sp("req.query",       sqli, hi, "URL query params"),
            _sp("req.body",        sqli, hi, "POST body"),
            _sp("req.params",      sqli, hi, "Route params"),
            _sp("req.headers",     xss,  hi, "HTTP headers"),
            _sp("process.env",     ssrf, FindingSeverity.MEDIUM, "Env var injection"),
        ],
        sinks=[
            _sp("eval(",           rce,  cr, "Dynamic code evaluation"),
            _sp("element.innerHTML",xss,  cr, "DOM XSS sink"),
            _sp("document.write(", xss,  cr, "Document write XSS"),
            _sp("child_process.exec", rce, cr, "OS command injection"),
            _sp("child_process.execSync", rce, cr, "Sync command injection"),
            _sp("db.query(",       sqli, cr, "Raw DB query"),
            _sp("sequelize.query(", sqli, cr, "Sequelize raw query"),
        ],
        sanitizers=[
            _sp("DOMPurify.sanitize", xss, hi, "DOM sanitizer"),
            _sp("helmet(",         xss,  hi, "Helmet security headers"),
            _sp("validator.escape(", xss, hi, "Validator escape"),
            _sp("parameterized(",  sqli, hi, "Parameterized query helper"),
            _sp("escape(",         sqli, hi, "SQL escape function"),
        ],
        metadata={
            "semgrep_configs": ["p/nodejs", "p/typescript", "p/owasp-top-ten"],
            "codeql_language": "javascript",
            "framework_specific": {"node": True},
        }
    )


def _build_java() -> SecurityProfile:
    sqli = VulnerabilityCategory.SQL_INJECTION
    xss  = VulnerabilityCategory.XSS
    rce  = VulnerabilityCategory.COMMAND_INJECTION
    deser= VulnerabilityCategory.DESERIALIZATION
    xxe  = VulnerabilityCategory.XXE
    hi   = FindingSeverity.HIGH
    cr   = FindingSeverity.CRITICAL

    return SecurityProfile(
        language="java",
        framework="spring",
        sources=[
            _sp("request.getParameter(",     sqli, hi, "Servlet input"),
            _sp("ServletRequest.getPart(",   sqli, hi, "Multipart input"),
            _sp("HttpServletRequest.getHeader(", xss, hi, "Header input"),
            _sp("request.getInputStream(",   deser,hi, "Raw body stream"),
        ],
        sinks=[
            _sp("Statement.execute(",        sqli, cr, "Raw SQL Statement"),
            _sp("Statement.executeQuery(",   sqli, cr, "SQL query"),
            _sp("Statement.executeUpdate(",  sqli, cr, "SQL update"),
            _sp("Runtime.getRuntime().exec(", rce, cr, "OS command exec"),
            _sp("ProcessBuilder(",           rce,  cr, "Process builder"),
            _sp("PrintWriter.write(",        xss,  cr, "Servlet output write"),
            _sp("ObjectInputStream(",        deser,cr, "Java deserialization"),
            _sp("DocumentBuilder.parse(",    xxe,  cr, "XML parsing"),
        ],
        sanitizers=[
            _sp("PreparedStatement",         sqli, hi, "Parameterized SQL"),
            _sp("HtmlUtils.htmlEscape(",     xss,  hi, "Spring HTML escape"),
            _sp("ESAPI.encoder().",          xss,  hi, "OWASP ESAPI"),
            _sp("StringEscapeUtils.escapeHtml", xss, hi, "Apache escape"),
        ],
        metadata={
            "semgrep_configs": ["p/java", "p/spring", "p/owasp-top-ten"],
            "codeql_language": "java",
            "framework_specific": {"spring": True},
        }
    )


def _build_php_wordpress() -> SecurityProfile:
    sqli = VulnerabilityCategory.SQL_INJECTION
    xss  = VulnerabilityCategory.XSS
    rce  = VulnerabilityCategory.COMMAND_INJECTION
    hi   = FindingSeverity.HIGH
    cr   = FindingSeverity.CRITICAL

    return SecurityProfile(
        language="php",
        framework="wordpress",
        sources=[
            _sp("$_GET",           sqli, hi, "GET params"),
            _sp("$_POST",          sqli, hi, "POST params"),
            _sp("$_REQUEST",       sqli, hi, "Request superglobal"),
            _sp("$_COOKIE",        sqli, hi, "Cookie values"),
        ],
        sinks=[
            _sp("wpdb->query(",    sqli, cr, "Raw WP SQL"),
            _sp("wpdb->get_results(", sqli, cr, "WP SQL query"),
            _sp("echo ",           xss,  hi, "Direct echo"),
            _sp("print ",          xss,  hi, "Direct print"),
            _sp("eval(",           rce,  cr, "PHP eval"),
            _sp("system(",         rce,  cr, "System command"),
            _sp("exec(",           rce,  cr, "Exec command"),
        ],
        sanitizers=[
            _sp("esc_html(",       xss,  hi, "WP HTML escape"),
            _sp("esc_attr(",       xss,  hi, "WP attribute escape"),
            _sp("wpdb->prepare(",  sqli, hi, "WP prepared query"),
            _sp("sanitize_text_field(", xss, hi, "WP sanitize"),
            _sp("intval(",         sqli, hi, "Integer cast"),
        ],
        metadata={
            "semgrep_configs": ["p/php", "p/wordpress"],
            "codeql_language": "php",
            "framework_specific": {"wordpress-core": True},
        }
    )


def _build_python() -> SecurityProfile:
    sqli = VulnerabilityCategory.SQL_INJECTION
    xss  = VulnerabilityCategory.XSS
    rce  = VulnerabilityCategory.COMMAND_INJECTION
    hi   = FindingSeverity.HIGH
    cr   = FindingSeverity.CRITICAL

    return SecurityProfile(
        language="python",
        framework=None,
        sources=[
            _sp("request.args",     sqli, hi, "Flask GET params"),
            _sp("request.form",     sqli, hi, "Flask POST params"),
            _sp("request.GET",      sqli, hi, "Django GET params"),
            _sp("request.POST",     sqli, hi, "Django POST params"),
        ],
        sinks=[
            _sp("cursor.execute(",  sqli, cr, "Raw SQL cursor"),
            _sp("os.system(",       rce,  cr, "OS system call"),
            _sp("subprocess.call(", rce,  cr, "Subprocess"),
            _sp("eval(",            rce,  cr, "Python eval"),
            _sp("exec(",            rce,  cr, "Python exec"),
            _sp("render_template_string(", xss, cr, "Jinja2 SSTI"),
        ],
        sanitizers=[
            _sp("escape(",          xss,  hi, "Markupsafe escape"),
            _sp("parameterize(",    sqli, hi, "SQL param"),
            _sp("bleach.clean(",    xss,  hi, "Bleach sanitizer"),
        ],
        metadata={
            "semgrep_configs": ["p/python", "p/django", "p/flask", "p/owasp-top-ten"],
            "codeql_language": "python",
            "framework_specific": {},
        }
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_PROFILE_BUILDERS = {
    "csharp":     _build_dotnet,
    "typescript": _build_typescript,
    "java":       _build_java,
    "php":        _build_php_wordpress,
    "python":     _build_python,
}


def build_security_profile(language: str, framework: Optional[str] = None) -> SecurityProfile:
    """
    Build and return a SecurityProfile for the given language.
    Falls back to PHP/WordPress profile if language unknown.
    """
    builder = _PROFILE_BUILDERS.get(language, _build_php_wordpress)
    profile = builder()
    logger.info(
        f"Built SecurityProfile: {profile.language}/{profile.framework} "
        f"— {len(profile.sources)} sources, {len(profile.sinks)} sinks, "
        f"{len(profile.sanitizers)} sanitizers"
    )
    return profile


def get_profile_for_repo(repo_path: str) -> SecurityProfile:
    """
    Convenience: detect language + build profile in one call.
    """
    lang, framework = detect_language(repo_path)
    return build_security_profile(lang, framework)
