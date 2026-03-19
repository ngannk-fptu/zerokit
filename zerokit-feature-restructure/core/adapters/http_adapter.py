import logging
import requests
from typing import Tuple, Dict, Any, Optional

logger = logging.getLogger(__name__)

class HttpAdapter:
    """
    Native HTTP Adapter wrapping requests.Session().
    Automatically generates equivalent curl commands for logging.
    """
    def __init__(self):
        self.session = requests.Session()
        # By default, don't verify SSL if we're hitting local/dev targets,
        # but keep it configurable if needed.
        self.session.verify = False

    def _to_curl(self, req: requests.PreparedRequest) -> str:
        """Converts a PreparedRequest to a curl string."""
        command = f"curl -X {req.method} '{req.url}' -k -s"
        
        if req.headers:
            for k, v in req.headers.items():
                if k.lower() in ["content-length"]:
                    continue # curl generates this automatically
                # Sanitize single quotes in headers for bash
                safe_v = str(v).replace("'", "'\\''")
                command += f" -H '{k}: {safe_v}'"
                
        if req.body:
            body_str = ""
            if isinstance(req.body, bytes):
                try:
                    body_str = req.body.decode('utf-8')
                except UnicodeDecodeError:
                    body_str = "<binary_data>"
            else:
                body_str = str(req.body)
                
            safe_body = body_str.replace("'", "'\\''")
            command += f" --data-raw '{safe_body}'"
            
        return command

    def send_request(self, method: str, url: str, **kwargs) -> Tuple[requests.Response, str]:
        """
        Sends an HTTP request and returns the response alongside the equivalent curl command.
        """
        try:
            req = requests.Request(method, url, **kwargs)
            prepared = self.session.prepare_request(req)
            curl_cmd = self._to_curl(prepared)
            
            logger.debug(f"[HttpAdapter] Executing: {curl_cmd}")
            
            # Disable SSL warnings for unverified requests
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            resp = self.session.send(prepared, timeout=10)
            return resp, curl_cmd
            
        except requests.exceptions.Timeout:
            logger.warning(f"[HttpAdapter] Timeout connecting to {url}")
            # Create a mock timeout response
            resp = requests.Response()
            resp.status_code = 408
            resp.url = url
            resp.error_type = "Timeout"
            return resp, f"# TIMEOUT: curl -X {method} '{url}'"
        except Exception as e:
            logger.error(f"[HttpAdapter] Request failed: {e}")
            resp = requests.Response()
            resp.status_code = 0
            resp.url = url
            resp.error_type = str(e)
            return resp, f"# ERROR ({e}): curl -X {method} '{url}'"
