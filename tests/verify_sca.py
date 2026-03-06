import asyncio
import os
import sys
import logging

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.tools.trivy_runner import TrivyRunner
from core.tools.dependency_check_runner import DependencyCheckRunner

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_runners():
    test_repo = os.path.abspath(".") # Scan ZeroKit itself as a test
    
    logger.info(f"--- Testing Power-Trivy on {test_repo} ---")
    trivy = TrivyRunner()
    if trivy.available:
        findings = trivy.scan_filesystem(test_repo)
        logger.info(f"Trivy found {len(findings)} findings.")
        if findings:
            logger.info(f"Sample Trivy finding: {findings[0].get('title')}")
    else:
        logger.warning("Trivy not available for testing.")

    logger.info(f"\n--- Testing Dependency-Check on {test_repo} ---")
    dc = DependencyCheckRunner()
    if dc.available:
        findings = await dc.scan_repo(test_repo)
        logger.info(f"Dependency-Check found {len(findings)} findings.")
        if findings:
            logger.info(f"Sample DC finding: {findings[0].get('id')}")
    else:
        logger.warning("Dependency-Check not available for testing (Check Java 18+ and binary path).")

if __name__ == "__main__":
    asyncio.run(test_runners())
