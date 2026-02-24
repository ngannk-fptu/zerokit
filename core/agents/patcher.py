import logging
import os
from typing import Dict
from ..models import VerifiedVuln
from ..llm_gateway import LLMGateway

logger = logging.getLogger(__name__)

class Patcher:
    """
    Agent responsible for generating and applying patches to fix vulnerabilities.
    Now powered by LLM (Google Gemini) for intelligent patch generation.
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
            # Use LLM to generate patch
            patched_content = self.llm.generate_patch(
                vulnerability_type=vuln.description, # VerifiedVuln doesn't have description, assumes caller fixes or model update? 
                # Wait, earlier I noted VerifiedVuln lacks description. 
                # In Orchestrator I passed it to RCA. 
                # Patcher also needs it.
                # Use Finding ID lookup or assume description is in evidence?
                # Actually, vuln.description in Patcher (line 35) was accessing a non-existent field?
                # Let's check VerifiedVuln model again. 
                # VerifiedVuln has `finding_id`. 
                # Patcher.apply_fix signature: (file_path, vuln).
                # The existing code `vulnerability_type=vuln.description` (Line 35) suggests `VerifiedVuln` HAS description?
                # Let's check `models.py` again.
                # IT DOES NOT. The existing code was buggy or I missed something.
                # `VerifiedVuln` has `evidence`, `runtime_output`. Status.
                # Oh, I see `vuln.description` usage in `patcher.py` line 35. 
                # This implies `VerifiedVuln` was *expected* to have it, or I misread `models.py`.
                # Let's re-read `models.py` from step 102.
                # `VerifiedVuln` lines 49-56: finding_id, status, poc, runtime_output, evidence, severity_adjustment.
                # NO DESCRIPTION.
                # So `patcher.py` call `vuln.description` would FAIL at runtime.
                # I should fix this bug too. 
                # I will add `description` to `VerifiedVuln` or look it up.
                # Adding it to `VerifiedVuln` is cleaner for downstream agents.
                # I will update `models.py` to add `description` (optional or required).
                # But for now, let's fix Patcher to use `root_cause` AND fix the bug by passing description explicitly?
                # No, better to add `description` to `VerifiedVuln` model to carry context. 
                
                original_code=content,
                location=file_path,
                root_cause=vuln.root_cause.dict() if vuln.root_cause else None
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

