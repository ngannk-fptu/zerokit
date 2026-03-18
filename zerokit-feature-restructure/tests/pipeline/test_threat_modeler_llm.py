import logging
import os
import sys
from typing import List
from unittest.mock import MagicMock

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from core.agents.threat_modeler import ThreatModeler
from core.models import AttackSurface, EntryPoint, EntryPointType, Hypothesis

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

import asyncio

def test_threat_modeler_antigravity():
    async def run_test():
        logger.info("Testing ThreatModeler with Antigravity Integration (Mocked)...")
        
        # Create Mock Attack Surface
        surface = AttackSurface(
            project_name="TestProject",
            entry_points=[
                EntryPoint(
                    category=EntryPointType.HTTP,
                    code_location="admin/upload.php",
                    description="Handles file uploads via POST"
                ),
                EntryPoint(
                    category=EntryPointType.HTTP,
                    code_location="api/get_user.php",
                    description="Gets user by ID"
                )
            ]
        )
        
        # Mock LLM Gateway
        mock_llm = MagicMock()
        mock_llm.generate_hypotheses.return_value = '[{"risk": "Mock Risk", "severity": "HIGH", "reasoning": "Mock Reasoning"}]'
        
        # Initialize Agent with Mock
        agent = ThreatModeler(llm_gateway=mock_llm)
        
        # Run
        hypotheses = await agent.generate_hypotheses(surface)
        
        # Verify
        logger.info(f"Generated {len(hypotheses)} hypotheses")
        for h in hypotheses:
            logger.info(f"--- Hypothesis ---")
            logger.info(f"Desc: {h.description}")
            logger.info(f"Meta: {h.metadata}")
            
            # Verify mock data exists
            if "llm_reasoning" in h.metadata:
                 logger.info("✅ Mock LLM Reasoning present")
            else:
                 logger.error("❌ Unknown hypothesis source")

    asyncio.run(run_test())

if __name__ == "__main__":
    asyncio.run(test_threat_modeler_antigravity())
