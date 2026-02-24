import logging
import os
import json
from typing import Optional
from ..models import VerifiedVuln, RootCauseAnalysis
from ..llm_gateway import LLMGateway

logger = logging.getLogger(__name__)

class RootCauseAnalyst:
    """
    Agent responsible for analyzing confirmed vulnerabilities to determine
    the specific root cause (faulty lines, logic error) before patching.
    """
    
    def __init__(self, llm_gateway: Optional[LLMGateway] = None):
        self.llm = llm_gateway or LLMGateway()

    def analyze(self, vuln: VerifiedVuln, file_path: str, vuln_description: str) -> Optional[RootCauseAnalysis]:
        """
        Performs RCA on a verified vulnerability.
        """
        if not os.path.exists(file_path):
            logger.error(f"RCA Failed: File not found {file_path}")
            return None
            
        logger.info(f"Starting Root Cause Analysis for {vuln.finding_id} in {file_path}")

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code_content = f.read()
            
            # Crash log
            crash_log = vuln.runtime_output or "No runtime output available."
            static_trace = vuln.evidence
            
            response = self.llm.analyze_root_cause(
                vulnerability_type=vuln_description,
                original_code=code_content,
                location=file_path,
                crash_log=crash_log,
                static_trace=static_trace
            )
            
            # Parse Response
            # Handle potential markdown wrapping
            clean_json = response
            if "```json" in response:
                clean_json = response.split("```json")[1].split("```")[0]
            elif "```" in response:
                clean_json = response.split("```")[1].split("```")[0]
            
            clean_json = clean_json.strip()
            
            data = json.loads(clean_json)
            
            return RootCauseAnalysis(**data)
            
        except Exception as e:
            logger.error(f"RCA Failed for {vuln.finding_id}: {e}")
            return None
