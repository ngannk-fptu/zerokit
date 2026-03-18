"""Tests for Verifier CWE→template selection logic."""
import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.agents.verifier import (
    Verifier,
    CWE_TEMPLATE_MAP,
    BOUNDARY_TEMPLATE_MAP,
    _KEYWORD_FALLBACKS,
)
from core.models import StaticFinding, FindingSeverity


def _make_finding(
    desc="test",
    cwe_id=None,
    boundary=None,
    **kwargs,
) -> StaticFinding:
    """Helper to create a StaticFinding with minimal boilerplate."""
    metadata = kwargs.pop("metadata", {})
    if boundary:
        metadata["trust_boundary"] = boundary
    cwe = {"id": cwe_id} if cwe_id is not None else None
    return StaticFinding(
        id="test-1",
        description=desc,
        location="a.py:1",
        severity=FindingSeverity.HIGH,
        evidence="test",
        tool_name="semgrep",
        cwe_details=cwe,
        metadata=metadata,
        **kwargs,
    )


class TestCWEMapping(unittest.TestCase):
    """Tier 1: CWE ID → template (most precise)."""

    def setUp(self):
        self.v = Verifier.__new__(Verifier)

    def test_sqli_cwe89(self):
        f = _make_finding(cwe_id=89)
        self.assertEqual(self.v._select_template(f), "http_sqli_time_based.py")

    def test_cmdi_cwe78(self):
        f = _make_finding(cwe_id=78)
        self.assertEqual(self.v._select_template(f), "command_injection.py")

    def test_xss_cwe79(self):
        f = _make_finding(cwe_id=79)
        self.assertEqual(self.v._select_template(f), "http_xss_reflected.py")

    def test_path_traversal_cwe22(self):
        f = _make_finding(cwe_id=22)
        self.assertEqual(self.v._select_template(f), "path_traversal.py")

    def test_ssrf_cwe918(self):
        f = _make_finding(cwe_id=918)
        self.assertEqual(self.v._select_template(f), "ssrf_check.py")

    def test_idor_cwe639(self):
        f = _make_finding(cwe_id=639)
        self.assertEqual(self.v._select_template(f), "idor_check.py")

    def test_deserialization_cwe502(self):
        f = _make_finding(cwe_id=502)
        self.assertEqual(self.v._select_template(f), "deserialization.py")

    def test_xxe_cwe611(self):
        f = _make_finding(cwe_id=611)
        self.assertEqual(self.v._select_template(f), "xxe.py")

    def test_code_injection_cwe94(self):
        f = _make_finding(cwe_id=94)
        self.assertEqual(self.v._select_template(f), "code_injection.py")

    def test_prototype_pollution_cwe1321(self):
        f = _make_finding(cwe_id=1321)
        self.assertEqual(self.v._select_template(f), "prototype_pollution.py")

    def test_all_cwe_map_entries_covered(self):
        """Every CWE in the map must select the correct template."""
        for cwe_id, expected in CWE_TEMPLATE_MAP.items():
            f = _make_finding(cwe_id=cwe_id)
            result = self.v._select_template(f)
            self.assertEqual(result, expected, f"CWE-{cwe_id} mismatch")


class TestCWEStringFormats(unittest.TestCase):
    """Test that _extract_cwe_id handles various formats."""

    def setUp(self):
        self.v = Verifier.__new__(Verifier)

    def test_integer_cwe(self):
        f = _make_finding(cwe_id=89)
        self.assertEqual(self.v._extract_cwe_id(f), 89)

    def test_string_cwe(self):
        f = _make_finding()
        f.cwe_details = {"id": "89"}
        self.assertEqual(self.v._extract_cwe_id(f), 89)

    def test_prefixed_cwe(self):
        f = _make_finding()
        f.cwe_details = {"id": "CWE-78"}
        self.assertEqual(self.v._extract_cwe_id(f), 78)

    def test_lowercase_prefix(self):
        f = _make_finding()
        f.cwe_details = {"id": "cwe-22"}
        self.assertEqual(self.v._extract_cwe_id(f), 22)

    def test_none_cwe_details(self):
        f = _make_finding()
        f.cwe_details = None
        self.assertIsNone(self.v._extract_cwe_id(f))

    def test_missing_id_key(self):
        f = _make_finding()
        f.cwe_details = {"name": "SQL Injection"}
        self.assertIsNone(self.v._extract_cwe_id(f))

    def test_invalid_string(self):
        f = _make_finding()
        f.cwe_details = {"id": "not-a-number"}
        self.assertIsNone(self.v._extract_cwe_id(f))


class TestBoundaryFallback(unittest.TestCase):
    """Tier 2: trust boundary → template."""

    def setUp(self):
        self.v = Verifier.__new__(Verifier)

    def test_http_to_database(self):
        f = _make_finding(boundary="HTTP→Database")
        self.assertEqual(self.v._select_template(f), "http_sqli_time_based.py")

    def test_http_to_os(self):
        f = _make_finding(boundary="HTTP→OS")
        self.assertEqual(self.v._select_template(f), "command_injection.py")

    def test_http_to_file(self):
        f = _make_finding(boundary="HTTP→File")
        self.assertEqual(self.v._select_template(f), "path_traversal.py")

    def test_http_to_template(self):
        f = _make_finding(boundary="HTTP→Template")
        self.assertEqual(self.v._select_template(f), "code_injection.py")

    def test_http_to_url(self):
        f = _make_finding(boundary="HTTP→URL")
        self.assertEqual(self.v._select_template(f), "ssrf_check.py")

    def test_boundary_only_used_when_no_cwe(self):
        """CWE takes priority over boundary."""
        f = _make_finding(cwe_id=79, boundary="HTTP→Database")
        # CWE-79 (XSS) wins over HTTP→Database (SQLi)
        self.assertEqual(self.v._select_template(f), "http_xss_reflected.py")


class TestKeywordFallback(unittest.TestCase):
    """Tier 3: description keyword → template."""

    def setUp(self):
        self.v = Verifier.__new__(Verifier)

    def test_sql_keyword(self):
        f = _make_finding(desc="Possible SQL injection in query")
        self.assertEqual(self.v._select_template(f), "http_sqli_time_based.py")

    def test_xss_keyword(self):
        f = _make_finding(desc="Reflected XSS via parameter")
        self.assertEqual(self.v._select_template(f), "http_xss_reflected.py")

    def test_command_keyword(self):
        f = _make_finding(desc="OS command injection risk")
        self.assertEqual(self.v._select_template(f), "command_injection.py")

    def test_rce_keyword(self):
        f = _make_finding(desc="Remote Code Execution (RCE)")
        self.assertEqual(self.v._select_template(f), "command_injection.py")

    def test_ssrf_keyword(self):
        f = _make_finding(desc="SSRF via user-controlled URL")
        self.assertEqual(self.v._select_template(f), "ssrf_check.py")

    def test_ssti_keyword(self):
        f = _make_finding(desc="Server-Side Template Injection (SSTI)")
        self.assertEqual(self.v._select_template(f), "code_injection.py")

    def test_path_traversal_keyword(self):
        f = _make_finding(desc="Path traversal in file download")
        self.assertEqual(self.v._select_template(f), "path_traversal.py")

    def test_deserialization_keyword(self):
        f = _make_finding(desc="Insecure deserialization of user data")
        self.assertEqual(self.v._select_template(f), "deserialization.py")

    def test_xxe_keyword(self):
        f = _make_finding(desc="XXE in XML parser")
        self.assertEqual(self.v._select_template(f), "xxe.py")

    def test_unknown_falls_to_generic(self):
        f = _make_finding(desc="Something completely unknown")
        self.assertEqual(self.v._select_template(f), "generic_check.py")


class TestFallbackPriority(unittest.TestCase):
    """Verify 3-tier priority: CWE > boundary > keyword > generic."""

    def setUp(self):
        self.v = Verifier.__new__(Verifier)

    def test_cwe_beats_boundary_and_keyword(self):
        f = _make_finding(
            desc="SQL injection",
            cwe_id=78,  # CMDi
            boundary="HTTP→Database",  # SQLi
        )
        # CWE-78 → command_injection.py (not SQLi)
        self.assertEqual(self.v._select_template(f), "command_injection.py")

    def test_boundary_beats_keyword(self):
        f = _make_finding(
            desc="SQL injection in query",  # keyword → SQLi
            boundary="HTTP→OS",  # boundary → CMDi
        )
        # Boundary wins
        self.assertEqual(self.v._select_template(f), "command_injection.py")

    def test_keyword_when_no_cwe_no_boundary(self):
        f = _make_finding(desc="SSRF attack possible")
        self.assertEqual(self.v._select_template(f), "ssrf_check.py")

    def test_generic_when_nothing_matches(self):
        f = _make_finding(desc="Minor code quality issue")
        self.assertEqual(self.v._select_template(f), "generic_check.py")


if __name__ == "__main__":
    unittest.main()
