# Hybrid Curl Verifier Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the heavy Burp Suite MCP Verifier with a native Python `Requests` engine that logs terminal-ready `curl` commands and escalates custom bypass workloads to the LLM Sandbox upon failure.

**Architecture:** 
1. Build `HttpAdapter` wrapping Python `requests`. Every out-bound request generates a `curl` equivalent string via `curlify` for terminal-transparency.
2. Replace `BurpVerifier` with an `HttpVerifier` that ports over the 8 CWE strategies (SQLi, IDOR, etc.).
3. Update `Verifier.verify_finding()` so that if `HttpVerifier` returns `INCONCLUSIVE` or fails unexpectedly (e.g., hit a WAF 403), it immediately falls back to generating a custom PoC script using the LLM Docker module.

**Tech Stack:** Python `requests`, `curlify` (or custom curl builder)

---

### Task 1: Create the HttpAdapter

**Files:**
- Create: `core/adapters/http_adapter.py`
- Create: `tests/adapters/test_http_adapter.py`

**Step 1: Write the failing test**
```python
import pytest
from unittest.mock import patch, MagicMock
# Assume HttpAdapter is built
from core.adapters.http_adapter import HttpAdapter

@patch('requests.Session.request')
def test_send_request_generates_curl(mock_request):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "OK"
    mock_request.return_value = mock_resp
    
    adapter = HttpAdapter()
    resp, curl_cmd = adapter.send_request("GET", "http://test.com/api", headers={"X-Test": "1"})
    
    assert resp.status_code == 200
    assert "curl -X GET" in curl_cmd
    assert "-H 'X-Test: 1'" in curl_cmd
```

**Step 2: Run test to verify it fails**
Run: `pytest tests/adapters/test_http_adapter.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'core.adapters.http_adapter'"

**Step 3: Write minimal implementation**
```python
# core/adapters/http_adapter.py
import requests
import urllib.parse

class HttpAdapter:
    def __init__(self):
        self.session = requests.Session()
        
    def _to_curl(self, req: requests.PreparedRequest) -> str:
        command = f"curl -X {req.method} '{req.url}'"
        for k, v in req.headers.items():
            command += f" -H '{k}: {v}'"
        if req.body:
            # Assuming str body for simplicity
            body_str = req.body.decode('utf-8') if isinstance(req.body, bytes) else req.body
            command += f" -d '{body_str}'"
        return command

    def send_request(self, method: str, url: str, **kwargs):
        req = requests.Request(method, url, **kwargs)
        prepared = self.session.prepare_request(req)
        curl_cmd = self._to_curl(prepared)
        
        # Send
        resp = self.session.send(prepared)
        return resp, curl_cmd
```

**Step 4: Run test to verify it passes**
Run: `pytest tests/adapters/test_http_adapter.py -v`
Expected: PASS

**Step 5: Commit**
```bash
git add tests/adapters/test_http_adapter.py core/adapters/http_adapter.py
git commit -m "feat(verifier): add HttpAdapter with curl translation"
```

---

### Task 2: Create the HttpVerifier (Replacing BurpVerifier)

**Files:**
- Create: `core/agents/http_verifier.py`
- Test: `tests/agents/test_http_verifier.py`

**Step 1: Write the failing test**
```python
import pytest
from unittest.mock import MagicMock
from core.agents.http_verifier import HttpVerifier
from core.models import StaticFinding

@pytest.mark.asyncio
async def test_verify_sqli():
    mock_adapter = MagicMock()
    # Mock return (Response, curl_cmd)
    mock_resp = MagicMock()
    mock_resp.elapsed.total_seconds.return_value = 6.0 # Simulating sleep
    mock_adapter.send_request.return_value = (mock_resp, "curl -X GET sqli")
    
    verifier = HttpVerifier(adapter=mock_adapter)
    finding = StaticFinding(id="f1", description="sqli", location="app.py:10", cwe_details={"id": 89})
    
    vuln = await verifier.verify(finding, target_url="http://app.local")
    assert vuln.status == "CONFIRMED"
    assert "curl -X GET sqli" in vuln.evidence
```

**Step 2: Run test to verify it fails**
Run: `pytest tests/agents/test_http_verifier.py -v`
Expected: FAIL 

**Step 3: Write minimal implementation**
```python
# core/agents/http_verifier.py
import logging
from ..models import StaticFinding, VerifiedVuln, ConfirmedStatus, FindingSeverity
from ..adapters.http_adapter import HttpAdapter

logger = logging.getLogger(__name__)

class HttpVerifier:
    def __init__(self, adapter=None):
        self.adapter = adapter or HttpAdapter()
        
    async def verify(self, finding: StaticFinding, target_url: str) -> VerifiedVuln:
        cwe = finding.cwe_details.get("id") if finding.cwe_details else None
        
        if cwe == 89:
            # SQLi Testing
            payload = "' OR SLEEP(5)--"
            resp, curl_log = self.adapter.send_request("GET", f"{target_url}?id={payload}")
            
            if resp.elapsed.total_seconds() > 4.5:
                evidence = f"SQLi CONFIRMED. Command used:\n{curl_log}"
                return VerifiedVuln(finding_id=finding.id, status=ConfirmedStatus.CONFIRMED, poc={"content": curl_log}, runtime_output=evidence, evidence=evidence)
                
        # Return INCONCLUSIVE for other things to trigger LLM Fallback
        return VerifiedVuln(finding_id=finding.id, status=ConfirmedStatus.INCONCLUSIVE, poc={}, runtime_output="No match", evidence="")
```

**Step 4: Run test to verify it passes**
Run: `pytest tests/agents/test_http_verifier.py -v`
Expected: PASS

**Step 5: Commit**
```bash
git add tests/agents/test_http_verifier.py core/agents/http_verifier.py
git commit -m "feat(verifier): implement HttpVerifier core strategies"
```

---

### Task 3: Hook LLM Fallback in Main Verifier

**Files:**
- Modify: `core/agents/verifier.py`

**Step 1: Write the failing test** (or just conceptualize since Verifier is complex)
If `HttpVerifier` returns `INCONCLUSIVE`, we must call `_generate_poc` and fallback to Docker. 

**Step 2: Write minimal implementation**
Modify `core/agents/verifier.py`:
- Import `HttpVerifier`.
- Replace `BurpVerifier` usages with `HttpVerifier`.
- In `verify_finding()`:
```python
        # --- HTTP path ---
        if mode == VerificationMode.BURP_MCP:  # Or rename to HTTP_NATIVE
            vuln = await self.http_verifier.verify(finding, target_url)
            # FALLBACK to LLM if Native Python check failed or got blocked
            if vuln.status == ConfirmedStatus.INCONCLUSIVE:
                logger.warning(f"Native HTTP check failed. Escalating to LLM Sandbox fallback...")
                mode = VerificationMode.DOCKER 
            else:
                return vuln
```

**Step 3: Commit**
```bash
git add core/agents/verifier.py
git commit -m "feat(verifier): wire HttpVerifier with LLM Docker fallback"
```
