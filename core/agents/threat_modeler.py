import json
import logging
import uuid
from typing import List, Optional
from ..models import AttackSurface, Hypothesis, EntryPointType
from ..llm_gateway import LLMGateway

logger = logging.getLogger(__name__)

class ThreatModeler:
    """
    AI-Powered Threat Modeling Agent.
    Uses LLMGateway to analyze entry points and generate security hypotheses.
    """
    
    def __init__(self, llm_gateway: Optional[LLMGateway] = None):
        self.llm = llm_gateway or LLMGateway()

    def generate_hypotheses(self, surface: AttackSurface) -> List[Hypothesis]:
        hypotheses = []
        logger.info(f"Threat Modeling started for {len(surface.entry_points)} entry points")
        
        for ep in surface.entry_points:
            # Skip trivial entry points (simple assets, empty files)
            if self._is_trivial(ep.code_location):
                continue

            try:
                # Ask LLM for hypotheses
                response = self.llm.generate_hypotheses(
                    filename=ep.code_location,
                    signature=ep.code_location, # Using location as signature proxy strictly for now
                    route=ep.description or "Internal Function"
                )
                
                # Parse JSON Response
                # Clean markdown code blocks if present
                if "```json" in response:
                    response = response.split("```json")[1].split("```")[0].strip()
                elif "```" in response:
                    response = response.split("```")[1].split("```")[0].strip()
                    
                risks = json.loads(response)
                
                for risk in risks:
                    h = Hypothesis(
                        id=str(uuid.uuid4()),
                        description=f"{risk.get('risk')}: {risk.get('reasoning')}",
                        target_code=ep.code_location,
                        verification_plan=risk.get('suggested_check', "Standard Verification"),
                        metadata={
                            "priority": risk.get('severity', "MEDIUM"),
                            "original_entry_point_type": ep.category,
                            "llm_reasoning": risk.get('reasoning')
                        }
                    )
                    hypotheses.append(h)
                    logger.info(f"Generated Hypothesis: {h.description} ({h.metadata['priority']})")
                    
            except Exception as e:
                logger.error(f"Failed to generate hypothesis for {ep.code_location}: {e}")
                # Fallback to Basic Heuristic if LLM fails
                self._fallback_heuristic(ep, hypotheses)
        
        # Sort hypotheses by priority: CRITICAL -> HIGH -> MEDIUM -> LOW
        priority_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        hypotheses.sort(key=lambda h: priority_rank.get(h.metadata.get("priority", "LOW"), 99))
        
        return hypotheses

    def _is_trivial(self, location: str) -> bool:
        """Skip non-code or static assets"""
        ignored_exts = ['.css', '.js.map', '.png', '.jpg', '.svg', '.md', '.txt']
        return any(location.endswith(ext) for ext in ignored_exts)

    def _fallback_heuristic(self, ep, hypotheses_list):
        """Legacy keyword-based fallback"""
        priority = "LOW"
        KEYWORDS = ["admin", "auth", "login", "payment", "upload", "token"]
        content = (ep.code_location + " " + (ep.description or "")).lower()
        
        if ep.category == EntryPointType.HTTP:
            priority = "HIGH"
        if any(k in content for k in KEYWORDS):
            priority = "CRITICAL"
            
        h = Hypothesis(
            id=str(uuid.uuid4()),
            description=f"Fallback Security Check for {ep.category}",
            target_code=ep.code_location,
            verification_plan="Standard Static Scan",
            metadata={"priority": priority, "note": "Generated via Fallback"}
        )
        hypotheses_list.append(h)
