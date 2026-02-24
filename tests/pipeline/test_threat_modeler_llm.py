import logging
import os
import sys
from typing import List

# Add project root to path
sys.path.insert(0, os.path.join(os.getcwd(), ".agent"))

from pipeline.agents.threat_modeler import ThreatModeler
from pipeline.models import AttackSurface, EntryPoint, EntryPointType, Hypothesis

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def test_threat_modeler_llm():
    logger.info("Testing ThreatModeler with LLM Integration...")
    
    # Force Mock Mode for Testing
    os.environ["LLM_FALLBACK_MODE"] = "mock"
    
    # Create Mock Attack Surface
    surface = AttackSurface(
        project_name="TestProject",
        entry_points=[
            EntryPoint(
                type=EntryPointType.HTTP,
                code_location="admin/upload.php",
                description="Handles file uploads via POST"
            ),
            EntryPoint(
                type=EntryPointType.HTTP,
                code_location="api/get_user.php",
                description="Gets user by ID"
            )
        ]
    )
    
    # Initialize Agent
    agent = ThreatModeler()
    
    # Run
    hypotheses = agent.generate_hypotheses(surface)
    
    # Verify
    logger.info(f"Generated {len(hypotheses)} hypotheses")
    for h in hypotheses:
        logger.info(f"--- Hypothesis ---")
        logger.info(f"Desc: {h.description}")
        logger.info(f"Meta: {h.metadata}")
        
        # Verify LLM metadata exists (or fallback note)
        if "llm_reasoning" in h.metadata:
             logger.info("✅ LLM Reasoning present")
        elif "note" in h.metadata and "Fallback" in h.metadata["note"]:
             logger.info("⚠️ Used Heuristic Fallback (Acceptable if prompt failed)")
        else:
             logger.error("❌ Unknown hypothesis source")

if __name__ == "__main__":
    test_threat_modeler_llm()
