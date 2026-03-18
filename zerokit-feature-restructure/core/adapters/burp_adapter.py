"""
BurpAdapter — Integrates ZeroKit2 with Burp Suite's MCP server.

Compatible with:
  - PortSwigger official MCP extension: http://127.0.0.1:9876
  - BurpMCP (swgee):                   http://127.0.0.1:8181

Configuration (environment variables):
  BURP_MCP_URL       Base URL of the Burp MCP server (default: http://127.0.0.1:8181)
  BURP_SCOPE_DOMAINS Comma-separated list of allowed target domains (safety guard)
  TARGET_ROOT_URL    Base URL of the target application (for route mapping)
"""
import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import aiohttp

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ScopeViolationError(Exception):
    """Raised when a request URL is outside of BURP_SCOPE_DOMAINS."""


# ---------------------------------------------------------------------------
# Response dataclass
# ---------------------------------------------------------------------------

@dataclass
class BurpResponse:
    """Structured response from Burp Suite, including raw HTTP evidence."""
    status_code: int
    body: str
    headers: Dict[str, str] = field(default_factory=dict)
    response_time_ms: float = 0.0
    request_raw: str = ""    # Full raw HTTP request — saved as PoC evidence
    response_raw: str = ""   # Full raw HTTP response — saved as PoC evidence
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and 100 <= self.status_code < 600


# ---------------------------------------------------------------------------
# BurpAdapter
# ---------------------------------------------------------------------------

class BurpAdapter:
    """
    Thin HTTP client that wraps the Burp Suite MCP SSE REST interface.

    All outbound requests go through Burp's MCP endpoint which proxies them
    to the target application. This means:
      - Full network access (unlike Docker --network none)
      - Timing measurements are accurate
      - Response body available for payload detection
      - Burp Collaborator available for OOB callbacks
    """

    # Minimum MCP server version that supports poll_collaborator
    MIN_COLLABORATOR_VERSION = "1.1.0"

    def __init__(self):
        self.base_url = os.getenv("BURP_MCP_URL", "http://127.0.0.1:8181").rstrip("/")
        self.target_root_url = os.getenv("TARGET_ROOT_URL", "http://localhost:8080").rstrip("/")
        self._scope_domains = self._parse_scope_domains()
        self._session: Optional[aiohttp.ClientSession] = None
        self._mcp_version: Optional[str] = None

    # -----------------------------------------------------------------------
    # Scope enforcement
    # -----------------------------------------------------------------------

    def _parse_scope_domains(self) -> List[str]:
        raw = os.getenv("BURP_SCOPE_DOMAINS", "localhost,127.0.0.1")
        return [d.strip() for d in raw.split(",") if d.strip()]

    def check_scope(self, url: str) -> None:
        """
        Safety guard: raise ScopeViolationError if the target URL is outside
        of the configured BURP_SCOPE_DOMAINS. Called before every outbound request.
        """
        if not self._scope_domains:
            return  # No scope configured → allow all (dev/lab mode)

        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        for allowed in self._scope_domains:
            if hostname == allowed or hostname.endswith(f".{allowed}"):
                return  # In scope

        raise ScopeViolationError(
            f"URL '{url}' is outside BURP_SCOPE_DOMAINS={self._scope_domains}. "
            f"Add the domain to BURP_SCOPE_DOMAINS env var to allow this request."
        )

    # -----------------------------------------------------------------------
    # Availability & version
    # -----------------------------------------------------------------------

    async def is_available(self) -> bool:
        """Ping the MCP server. Returns False gracefully if Burp is not running."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}/mcp/sse",
                    timeout=aiohttp.ClientTimeout(total=3),
                ) as resp:
                    return resp.status in (200, 204, 405)  # Any HTTP response = Burp alive
        except Exception:
            return False

    def is_available_sync(self) -> bool:
        """Synchronous availability check for use in property setters."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Can't block — return cached or optimistic True
                return self._mcp_version is not None
            return loop.run_until_complete(self.is_available())
        except Exception:
            return False

    async def get_mcp_version(self) -> str:
        """
        Query the MCP server version.
        Returns an empty string if the endpoint is not available.
        Caches result for the lifetime of this adapter instance.
        """
        if self._mcp_version is not None:
            return self._mcp_version
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}/mcp/version",
                    timeout=aiohttp.ClientTimeout(total=3),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        self._mcp_version = data.get("version", "unknown")
                    else:
                        self._mcp_version = "unknown"
        except Exception:
            self._mcp_version = "unknown"

        # Warn if Collaborator may not be supported
        if self._mcp_version != "unknown":
            try:
                if tuple(int(x) for x in self._mcp_version.split(".")[:2]) < \
                   tuple(int(x) for x in self.MIN_COLLABORATOR_VERSION.split(".")[:2]):
                    logger.warning(
                        f"[BurpAdapter] MCP version {self._mcp_version} is older than "
                        f"{self.MIN_COLLABORATOR_VERSION} — poll_collaborator may not work."
                    )
            except ValueError:
                pass

        return self._mcp_version

    # -----------------------------------------------------------------------
    # HTTP request sending
    # -----------------------------------------------------------------------

    async def send_http_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        session_cookies: Optional[Dict[str, str]] = None,
        timeout: int = 30,
    ) -> BurpResponse:
        """
        Send a single HTTP request through Burp's MCP proxy.

        Args:
            method:          HTTP verb (GET, POST, PUT, ...)
            url:             Full target URL
            headers:         Request headers
            body:            Request body
            session_cookies: Auth cookies to inject (from get_active_sessions())
            timeout:         Seconds before request times out
        """
        self.check_scope(url)  # Safety first

        req_headers = headers or {}
        if session_cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in session_cookies.items())
            req_headers["Cookie"] = cookie_str

        payload = {
            "method": method.upper(),
            "url": url,
            "headers": req_headers,
            "body": body,
        }

        # Build raw request string for evidence
        request_raw = self._build_raw_request(method, url, req_headers, body)

        start = time.monotonic()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/mcp/send_request",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=timeout + 5),
                ) as resp:
                    data = await resp.json()
                    elapsed_ms = (time.monotonic() - start) * 1000

                    response_body = data.get("body", "")
                    response_headers = data.get("headers", {})
                    status_code = data.get("status_code", 0)
                    response_raw = self._build_raw_response(status_code, response_headers, response_body)

                    return BurpResponse(
                        status_code=status_code,
                        body=response_body,
                        headers=response_headers,
                        response_time_ms=elapsed_ms,
                        request_raw=request_raw,
                        response_raw=response_raw,
                    )

        except aiohttp.ClientError as e:
            logger.error(f"[BurpAdapter] Request failed: {e}")
            return BurpResponse(
                status_code=0,
                body="",
                response_time_ms=(time.monotonic() - start) * 1000,
                request_raw=request_raw,
                error=str(e),
            )

    async def send_requests_batch(
        self,
        requests: List[Dict],
        concurrency: int = 3,
    ) -> List["BurpResponse"]:
        """
        Send multiple requests concurrently with a cap on parallelism.
        Default concurrency=3 to prevent freezing the Burp Suite GUI.
        """
        semaphore = asyncio.Semaphore(concurrency)

        async def _send_one(req: dict) -> BurpResponse:
            async with semaphore:
                return await self.send_http_request(**req)

        tasks = [_send_one(r) for r in requests]
        return list(await asyncio.gather(*tasks, return_exceptions=False))

    # -----------------------------------------------------------------------
    # Session / authentication
    # -----------------------------------------------------------------------

    async def get_active_sessions(self) -> Dict[str, Dict[str, str]]:
        """
        Retrieve active cookies from Burp's Cookie Jar.

        Returns a dict mapping session labels to their cookie headers:
            {
              "user_a": {"Cookie": "session=abc123; csrf=xyz"},
              "user_b": {"Cookie": "session=def456; csrf=uvw"},
            }
        Returns empty dict if Burp Cookie Jar is empty or endpoint unavailable.
        Used by IDOR and Stored XSS verification strategies.
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}/mcp/cookie_jar",
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        sessions = {}
                        for i, entry in enumerate(data.get("sessions", [])):
                            label = entry.get("label") or f"user_{chr(ord('a') + i)}"
                            cookies = "; ".join(
                                f"{c['name']}={c['value']}"
                                for c in entry.get("cookies", [])
                            )
                            sessions[label] = {"Cookie": cookies}
                        return sessions
        except Exception as e:
            logger.warning(f"[BurpAdapter] Could not retrieve sessions: {e}")
        return {}

    # -----------------------------------------------------------------------
    # Burp Collaborator (OOB detection for SSRF)
    # -----------------------------------------------------------------------

    async def get_collaborator_payload(self) -> Tuple[str, str]:
        """
        Generate a Burp Collaborator payload.

        Returns:
            (payload_url, payload_id) — e.g., ("abcdef.burpcollaborator.net", "abcdef")
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/mcp/collaborator/generate",
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    data = await resp.json()
                    payload_url = data.get("payload_url", "")
                    payload_id = data.get("payload_id", payload_url.split(".")[0])
                    return payload_url, payload_id
        except Exception as e:
            raise RuntimeError(f"[BurpAdapter] Failed to get Collaborator payload: {e}")

    async def poll_collaborator(
        self,
        payload_id: str,
        timeout: int = 60,
        retry_interval: int = 3,
    ) -> bool:
        """
        Poll for Burp Collaborator callbacks with exponential backoff.

        Collaborator DNS/HTTP callbacks can take 5-15 seconds to arrive.
        Retry strategy: 3s → 6s → 12s → 24s ... up to timeout.

        Returns True if at least one interaction was received.
        """
        deadline = time.monotonic() + timeout
        interval = retry_interval
        attempt = 0

        while time.monotonic() < deadline:
            attempt += 1
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        f"{self.base_url}/mcp/collaborator/poll/{payload_id}",
                        timeout=aiohttp.ClientTimeout(total=5),
                    ) as resp:
                        data = await resp.json()
                        interactions = data.get("interactions", [])
                        if interactions:
                            logger.info(
                                f"[BurpAdapter] Collaborator callback received "
                                f"(attempt {attempt}, {len(interactions)} interaction(s))"
                            )
                            return True
            except Exception as e:
                logger.debug(f"[BurpAdapter] Poll attempt {attempt} failed: {e}")

            remaining = deadline - time.monotonic()
            sleep_time = min(interval, remaining)
            if sleep_time <= 0:
                break
            logger.debug(f"[BurpAdapter] No callback yet — retrying in {sleep_time:.1f}s")
            await asyncio.sleep(sleep_time)
            interval = min(interval * 2, 20)  # Exponential backoff cap at 20s

        logger.warning(f"[BurpAdapter] No Collaborator callback after {timeout}s")
        return False

    # -----------------------------------------------------------------------
    # Raw HTTP string builders (for evidence logging)
    # -----------------------------------------------------------------------

    @staticmethod
    def _build_raw_request(method: str, url: str, headers: dict, body: str) -> str:
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        lines = [f"{method.upper()} {path} HTTP/1.1", f"Host: {parsed.netloc}"]
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        if body:
            lines.append(body)
        return "\r\n".join(lines)

    @staticmethod
    def _build_raw_response(status_code: int, headers: dict, body: str) -> str:
        lines = [f"HTTP/1.1 {status_code}"]
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        if body:
            lines.append(body)
        return "\r\n".join(lines)
