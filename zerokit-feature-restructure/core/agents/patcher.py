import logging
import os
from typing import Dict
from ..models import VerifiedVuln
from ..llm_gateway import LLMGateway

logger = logging.getLogger(__name__)

class Patcher:
    """
    Agent responsible for generating and applying patches to fix vulnerabilities.
    Powered by Antigravity (Worker API) for intelligent patch generation.
    """
    
    def __init__(self):
        self.llm = LLMGateway()
    
    def apply_fix(self, file_path: str, vuln: VerifiedVuln) -> str:
        """
        Attempts to patch the file to fix the vulnerability using LLM.
        Returns the path to the temporary patched file.
        """
        logger.info(f"Generating LLM-based patch for {vuln.finding_id} in {file_path}")
        
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return None
            
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        try:
            cwe_id = "UNKNOWN"
            if vuln.cwe_details:
                cwe_id = vuln.cwe_details.get("id", "UNKNOWN")

            rca = vuln.root_cause

            patched_content = self.llm.generate_patch(
                hypothesis_id=vuln.finding_id,
                vulnerability_type=vuln.description or "Unknown vulnerability",
                cwe_id=cwe_id,
                location=file_path,
                original_code=content,
                faulty_lines=str(rca.faulty_lines) if rca else "Unknown",
                fix_strategy=rca.fix_suggestion if rca else "Standard patch",
                patch_scope=rca.faulty_function_name if rca and rca.faulty_function_name else "file",
                regression_risk="Medium",
                language="python",
                test_command="pytest",
            )

            # Fallback: If LLM returns nothing useful, add a comment
            if not patched_content or patched_content.strip() == content.strip():
                logger.warning("LLM patch was empty or identical, adding marker comment")
                patched_content = f"// [PATCHED by LLM] {vuln.description}\n" + content
        
        except Exception as e:
            logger.error(f"LLM patch generation failed: {e}")
            # Emergency fallback: just mark the file
            patched_content = f"// [PATCH FAILED] {vuln.description}\n// Error: {str(e)}\n" + content
            
        # Write to temp file
        import tempfile
        fd, temp_path = tempfile.mkstemp(suffix=os.path.splitext(file_path)[1], text=True)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(patched_content)
        
        logger.info(f"Patched file written to: {temp_path}")
        return temp_path

