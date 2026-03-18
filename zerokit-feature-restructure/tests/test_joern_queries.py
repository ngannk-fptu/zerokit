"""Tests for Joern query templates and language routing."""
import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.tools.joern_queries import (
    QUERY_TEMPLATES,
    MEMORY_SAFETY_QUERIES,
    INJECTION_QUERIES,
    get_queries_for_language,
    ALL_QUERIES,
)


class TestQueryRegistry(unittest.TestCase):
    """Verify query registry completeness and consistency."""

    def test_total_query_count(self):
        """Must have at least 25 templates (8 C/C++ + 17 web)."""
        self.assertGreaterEqual(len(QUERY_TEMPLATES), 25)

    def test_all_queries_list_matches_registry(self):
        self.assertEqual(set(ALL_QUERIES), set(QUERY_TEMPLATES.keys()))

    def test_no_empty_queries(self):
        for name, query in QUERY_TEMPLATES.items():
            self.assertTrue(len(query.strip()) > 50, f"Query '{name}' is too short")

    def test_memory_safety_queries_exist(self):
        for q in MEMORY_SAFETY_QUERIES:
            self.assertIn(q, QUERY_TEMPLATES, f"Missing memory safety query: {q}")

    def test_injection_queries_exist(self):
        for q in INJECTION_QUERIES:
            self.assertIn(q, QUERY_TEMPLATES, f"Missing injection query: {q}")


class TestLanguageRouting(unittest.TestCase):
    """Verify get_queries_for_language returns correct sets."""

    def test_php_queries(self):
        queries = get_queries_for_language("php")
        self.assertEqual(len(queries), 4)
        self.assertIn("php_sqli_taint", queries)
        self.assertIn("php_xss_taint", queries)
        self.assertIn("php_cmdi_taint", queries)
        self.assertIn("php_path_traversal", queries)

    def test_java_queries(self):
        queries = get_queries_for_language("java")
        self.assertEqual(len(queries), 4)
        self.assertIn("java_sqli_taint", queries)
        self.assertIn("java_deserialization", queries)
        self.assertIn("java_xxe", queries)

    def test_javascript_queries(self):
        queries = get_queries_for_language("javascript")
        self.assertEqual(len(queries), 5)
        self.assertIn("js_sqli_taint", queries)
        self.assertIn("js_ssrf", queries)
        self.assertIn("js_prototype_pollution", queries)

    def test_typescript_same_as_javascript(self):
        self.assertEqual(
            get_queries_for_language("typescript"),
            get_queries_for_language("javascript"),
        )

    def test_python_queries(self):
        queries = get_queries_for_language("python")
        self.assertEqual(len(queries), 4)
        self.assertIn("py_sqli_taint", queries)
        self.assertIn("py_ssti", queries)

    def test_c_queries(self):
        queries = get_queries_for_language("c")
        self.assertGreaterEqual(len(queries), 7)
        self.assertIn("buffer_overflow_strcpy", queries)
        self.assertIn("use_after_free", queries)

    def test_cpp_same_as_c(self):
        self.assertEqual(
            get_queries_for_language("c"),
            get_queries_for_language("cpp"),
        )

    def test_unknown_language_returns_empty(self):
        self.assertEqual(get_queries_for_language("rust"), [])
        self.assertEqual(get_queries_for_language(""), [])

    def test_case_insensitive(self):
        self.assertEqual(
            get_queries_for_language("PHP"),
            get_queries_for_language("php"),
        )


class TestQueryContent(unittest.TestCase):
    """Verify query templates contain expected Joern patterns."""

    def test_php_sqli_has_taint_flow(self):
        q = QUERY_TEMPLATES["php_sqli_taint"]
        self.assertIn("reachableByFlows", q)
        self.assertIn("$_(GET|POST|REQUEST|COOKIE)", q)
        self.assertIn("query", q)

    def test_java_deserialization_targets_readobject(self):
        q = QUERY_TEMPLATES["java_deserialization"]
        self.assertIn("readObject", q)
        self.assertIn("getInputStream", q)

    def test_js_ssrf_targets_fetch(self):
        q = QUERY_TEMPLATES["js_ssrf"]
        self.assertIn("fetch", q)
        self.assertIn("req", q)

    def test_python_ssti_targets_template(self):
        q = QUERY_TEMPLATES["py_ssti"]
        self.assertIn("render_template_string", q)
        self.assertIn("eval", q)

    def test_all_web_queries_have_taint_output(self):
        """All web taint queries must produce JSON output."""
        web_queries = [k for k in QUERY_TEMPLATES if k.startswith(("php_", "java_", "js_", "py_"))]
        for name in web_queries:
            q = QUERY_TEMPLATES[name]
            self.assertIn("toJson", q, f"Query '{name}' missing toJson output")
            self.assertIn("reachableByFlows", q, f"Query '{name}' missing taint flow")


if __name__ == "__main__":
    unittest.main()
