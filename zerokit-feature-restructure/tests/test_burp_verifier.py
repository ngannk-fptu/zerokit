"""
Tests for Hybrid Verifier Architecture — Burp MCP + Docker routing.

All tests are mocked — no Burp Suite instance or Docker required.
Covers:
  - VerificationMode selection (CWE routing)
  - Docker fallback when Burp offline
  - Per-CWE verification strategies (SQLi, XSS, SSRF, IDOR, Path Traversal)
  - Scope check safety guard
  - Evidence (request_raw + response_raw) in BurpResponse
  - Collaborator retry+backoff
"""
import asyncio
import sys
import os
import unittest
from unittest.mock import AsyncMock, MagicMock, patch, call

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.agents.verifier import Verifier, VerificationMode, BURP_MODE_CWES
from core.adapters.burp_adapter import BurpAdapter, BurpResponse, ScopeViolationError
from core.agents.burp_verifier import BurpVerifier
from core.models import StaticFinding, FindingSeverity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(cwe_id=None, desc="test vuln", location="app/user.php:42") -> StaticFinding:
    return StaticFinding(
        id="finding-001",
        description=desc,
        location=location,
        severity=FindingSeverity.HIGH,
        evidence="test",
        tool_name="semgrep",
        cwe_details={"id": cwe_id} if cwe_id is not None else None,
    )


def _make_burp_response(
    status_code=200, body="", response_time_ms=100.0,
    request_raw="GET / HTTP/1.1", response_raw="HTTP/1.1 200 OK",
    error=None,
) -> BurpResponse:
    return BurpResponse(
        status_code=status_code,
        body=body,
        response_time_ms=response_time_ms,
        request_raw=request_raw,
        response_raw=response_raw,
        error=error,
    )


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# 1. VerificationMode selection
# ---------------------------------------------------------------------------

class TestVerificationModeSelection(unittest.TestCase):
    def setUp(self):
        self.verifier = Verifier.__new__(Verifier)
        self.verifier._burp_available = True  # Burp "online"

    def test_sqli_cwe89_routed_to_burp(self):
        f = _make_finding(cwe_id=89)
        self.assertEqual(self.verifier._select_mode(f), VerificationMode.BURP_MCP)

    def test_xss_cwe79_routed_to_burp(self):
        f = _make_finding(cwe_id=79)
        self.assertEqual(self.verifier._select_mode(f), VerificationMode.BURP_MCP)

    def test_ssrf_cwe918_routed_to_burp(self):
        f = _make_finding(cwe_id=918)
        self.assertEqual(self.verifier._select_mode(f), VerificationMode.BURP_MCP)

    def test_idor_cwe639_routed_to_burp(self):
        f = _make_finding(cwe_id=639)
        self.assertEqual(self.verifier._select_mode(f), VerificationMode.BURP_MCP)

    def test_path_traversal_cwe22_routed_to_burp(self):
        f = _make_finding(cwe_id=22)
        self.assertEqual(self.verifier._select_mode(f), VerificationMode.BURP_MCP)

    def test_cmdi_cwe78_routed_to_docker(self):
        f = _make_finding(cwe_id=78)
        self.assertEqual(self.verifier._select_mode(f), VerificationMode.DOCKER)

    def test_deserialization_cwe502_routed_to_docker(self):
        f = _make_finding(cwe_id=502)
        self.assertEqual(self.verifier._select_mode(f), VerificationMode.DOCKER)

    def test_no_cwe_falls_to_docker(self):
        f = _make_finding(cwe_id=None)
        self.assertEqual(self.verifier._select_mode(f), VerificationMode.DOCKER)


# ---------------------------------------------------------------------------
# 2. Fallback to Docker when Burp offline
# ---------------------------------------------------------------------------

class TestDockerFallbackWhenBurpOffline(unittest.TestCase):
    def setUp(self):
        self.verifier = Verifier.__new__(Verifier)
        self.verifier._burp_available = False  # Burp "offline"

    def test_sqli_falls_back_to_docker_when_burp_offline(self):
        f = _make_finding(cwe_id=89)
        mode = self.verifier._select_mode(f)
        self.assertEqual(mode, VerificationMode.DOCKER,
                         "SQLi (CWE-89) should fall back to DOCKER when Burp is offline")

    def test_all_http_cwes_fall_back_to_docker(self):
        for cwe in BURP_MODE_CWES:
            f = _make_finding(cwe_id=cwe)
            self.assertEqual(self.verifier._select_mode(f), VerificationMode.DOCKER)


# ---------------------------------------------------------------------------
# 3. Scope check
# ---------------------------------------------------------------------------

class TestScopeCheck(unittest.TestCase):
    def setUp(self):
        os.environ["BURP_SCOPE_DOMAINS"] = "localhost,staging.target.com"
        self.adapter = BurpAdapter()

    def tearDown(self):
        os.environ.pop("BURP_SCOPE_DOMAINS", None)

    def test_in_scope_url_passes(self):
        # Should not raise
        self.adapter.check_scope("http://localhost:8080/api/users")

    def test_subdomain_in_scope_passes(self):
        self.adapter.check_scope("http://api.staging.target.com/login")

    def test_out_of_scope_raises(self):
        with self.assertRaises(ScopeViolationError):
            self.adapter.check_scope("http://external-victim.com/steal")

    def test_out_of_scope_blocks_send(self):
        """send_http_request must check scope before sending."""
        async def _test():
            with self.assertRaises(ScopeViolationError):
                await self.adapter.send_http_request("GET", "http://evil.com/attack")
        run(_test())


# ---------------------------------------------------------------------------
# 4. BurpVerifier strategies (mocked Burp responses)
# ---------------------------------------------------------------------------

class TestBurpVerifierStrategies(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        os.environ["BURP_SCOPE_DOMAINS"] = "localhost,127.0.0.1"
        os.environ["TARGET_ROOT_URL"] = "http://localhost:8080"
        self.mock_adapter = AsyncMock(spec=BurpAdapter)
        self.mock_adapter.target_root_url = "http://localhost:8080"
        self.mock_adapter._scope_domains = ["localhost", "127.0.0.1"]
        self.mock_adapter.check_scope = MagicMock()  # No-op scope check
        self.mock_adapter.get_active_sessions = AsyncMock(return_value={})
        self.verifier = BurpVerifier(burp=self.mock_adapter)

    async def asyncTearDown(self):
        os.environ.pop("BURP_SCOPE_DOMAINS", None)
        os.environ.pop("TARGET_ROOT_URL", None)

    async def test_sqli_timing_confirmed(self):
        """Response with delay > 4500ms → CONFIRMED."""
        self.mock_adapter.send_http_request = AsyncMock(
            return_value=_make_burp_response(
                response_time_ms=5200.0, status_code=200,
                request_raw="GET /?id=SLEEP(5) HTTP/1.1",
                response_raw="HTTP/1.1 200 OK",
            )
        )
        f = _make_finding(cwe_id=89)
        result = await self.verifier.verify(f, "http://localhost:8080/api/users")
        from core.models import ConfirmedStatus
        self.assertEqual(result.status, ConfirmedStatus.CONFIRMED)
        self.assertIn("5200", result.evidence)   # timing in evidence
        self.assertIn("SLEEP", result.poc.get("request_raw", ""))

    async def test_sqli_timing_rejected(self):
        """Fast response → REJECTED."""
        self.mock_adapter.send_http_request = AsyncMock(
            return_value=_make_burp_response(response_time_ms=80.0)
        )
        f = _make_finding(cwe_id=89)
        result = await self.verifier.verify(f, "http://localhost:8080/api/users")
        from core.models import ConfirmedStatus
        self.assertEqual(result.status, ConfirmedStatus.REJECTED)

    async def test_xss_payload_in_response_confirmed(self):
        """XSS canary reflected unescaped → CONFIRMED."""
        self.mock_adapter.send_http_request = AsyncMock(
            return_value=_make_burp_response(
                body="<html>zk_xss_canary_<script>alert(1)</script></html>",
                request_raw="GET /?q=zk_xss_canary_<script> HTTP/1.1",
            )
        )
        f = _make_finding(cwe_id=79)
        result = await self.verifier.verify(f, "http://localhost:8080/search")
        from core.models import ConfirmedStatus
        self.assertEqual(result.status, ConfirmedStatus.CONFIRMED)

    async def test_xss_payload_not_reflected_rejected(self):
        self.mock_adapter.send_http_request = AsyncMock(
            return_value=_make_burp_response(body="<html>Safe page</html>")
        )
        f = _make_finding(cwe_id=79)
        result = await self.verifier.verify(f, "http://localhost:8080/search")
        from core.models import ConfirmedStatus
        self.assertEqual(result.status, ConfirmedStatus.REJECTED)

    async def test_ssrf_collaborator_confirmed(self):
        """Collaborator gets callback → CONFIRMED."""
        self.mock_adapter.get_collaborator_payload = AsyncMock(
            return_value=("abcdef.burpcollaborator.net", "abcdef")
        )
        self.mock_adapter.send_http_request = AsyncMock(
            return_value=_make_burp_response()
        )
        self.mock_adapter.poll_collaborator = AsyncMock(return_value=True)
        f = _make_finding(cwe_id=918)
        result = await self.verifier.verify(f, "http://localhost:8080/fetch")
        from core.models import ConfirmedStatus
        self.assertEqual(result.status, ConfirmedStatus.CONFIRMED)

    async def test_ssrf_collaborator_no_callback_rejected(self):
        self.mock_adapter.get_collaborator_payload = AsyncMock(
            return_value=("xyz.burpcollaborator.net", "xyz")
        )
        self.mock_adapter.send_http_request = AsyncMock(return_value=_make_burp_response())
        self.mock_adapter.poll_collaborator = AsyncMock(return_value=False)
        f = _make_finding(cwe_id=918)
        result = await self.verifier.verify(f, "http://localhost:8080/fetch")
        from core.models import ConfirmedStatus
        self.assertEqual(result.status, ConfirmedStatus.REJECTED)

    async def test_idor_inconclusive_with_one_session(self):
        """Only 1 session → INCONCLUSIVE (can't diff)."""
        self.mock_adapter.get_active_sessions = AsyncMock(
            return_value={"user_a": {"Cookie": "session=abc"}}
        )
        f = _make_finding(cwe_id=639)
        result = await self.verifier.verify(f, "http://localhost:8080/user/profile")
        from core.models import ConfirmedStatus
        self.assertEqual(result.status, ConfirmedStatus.REJECTED)
        self.assertIn("INCONCLUSIVE", result.evidence)

    async def test_path_traversal_confirmed(self):
        """Response contains /etc/passwd content → CONFIRMED."""
        self.mock_adapter.send_http_request = AsyncMock(
            return_value=_make_burp_response(
                body="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:",
                request_raw="GET /?file=../../../../etc/passwd HTTP/1.1",
            )
        )
        f = _make_finding(cwe_id=22)
        result = await self.verifier.verify(f, "http://localhost:8080/download")
        from core.models import ConfirmedStatus
        self.assertEqual(result.status, ConfirmedStatus.CONFIRMED)


# ---------------------------------------------------------------------------
# 5. Evidence logging
# ---------------------------------------------------------------------------

class TestEvidenceLogging(unittest.TestCase):
    def test_burp_response_has_raw_fields(self):
        r = BurpResponse(
            status_code=200, body="test",
            request_raw="GET / HTTP/1.1\r\nHost: target",
            response_raw="HTTP/1.1 200 OK\r\n\r\ntest",
        )
        self.assertTrue(r.request_raw.startswith("GET"))
        self.assertTrue(r.response_raw.startswith("HTTP"))

    def test_confirmed_vuln_poc_contains_raw_http(self):
        from core.agents.burp_verifier import BurpVerifier
        from core.models import ConfirmedStatus
        finding = _make_finding(cwe_id=89)
        vuln = BurpVerifier._make_vuln(
            finding, ConfirmedStatus.CONFIRMED, "SQLi confirmed",
            request_raw="GET /?id=SLEEP(5) HTTP/1.1",
            response_raw="HTTP/1.1 200 OK",
        )
        self.assertEqual(vuln.poc["request_raw"], "GET /?id=SLEEP(5) HTTP/1.1")
        self.assertEqual(vuln.poc["response_raw"], "HTTP/1.1 200 OK")
        self.assertEqual(vuln.poc["type"], "burp_http")


if __name__ == "__main__":
    unittest.main()
