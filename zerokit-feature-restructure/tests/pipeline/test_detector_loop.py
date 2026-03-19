import unittest
from unittest.mock import MagicMock, AsyncMock, patch
import asyncio
import sys
import os

# Add .agent to path
current_dir = os.path.dirname(os.path.abspath(__file__))
agent_dir = os.path.abspath(os.path.join(current_dir, "..", "..", ".agent"))
sys.path.append(agent_dir)

from core.agents.detector import Detector
from core.models import Hypothesis, StaticFinding, FindingSeverity
from core.tools.semgrep_runner import ScanResult

class TestDetectorLoop(unittest.TestCase):
    def setUp(self):
        self.detector = Detector()
        self.detector.runner = AsyncMock()
        self.detector.codeql_runner = MagicMock()
        self.detector.state_manager = MagicMock()
        self.detector.llm_gateway = MagicMock()
        self.detector.llm_gateway.generate_semgrep_rule.return_value = "rules:\n..."
        self.detector.llm_gateway.fix_semgrep_rule.return_value = "rules:\n...fixed"
        
        # Disable heavy steps
        self.detector._generate_semgrep_config = MagicMock(return_value="/tmp")
        self.detector.codeql_runner.create_database_async = AsyncMock()

    @patch('os.walk')
    def test_correction_loop(self, mock_walk):
        """Test that Detector retries and fixes query on failure."""
        
        # Mock File System & State Manager
        mock_walk.return_value = [("/tmp", [], ["vuln.php"])]
        self.detector.state_manager.should_scan_file.return_value = True
        self.detector.state_manager.filter_rejected_findings.side_effect = lambda x: x # Pass through

        h = Hypothesis(id="test-h", description="Dynamic", target_code="", verification_plan="", metadata={"type": "variant"})
        
        # Mock Runner Responses:
        # 1. Main Scan (Success - irrelevant)
        # 2. Dynamic Scan 1: Fail (Syntax Error)
        # 3. Dynamic Scan 2: Success (Fixed)
        self.detector.runner.run_scan_async.side_effect = [
            ScanResult(success=True, findings=[]), # Main scan
            ScanResult(success=False, error_msg="Syntax Error: invalid yaml"), # Dynamic 1
            ScanResult(success=True, findings=[{"extra": {"message": "Found it", "severity": "ERROR"}, "path": "vuln.php", "start": {"line": 1}}]) # Dynamic 2
        ]

        # Run Scan
        findings = asyncio.run(self.detector.scan([h], "/tmp/test"))
        
        # Asserts
        self.assertEqual(self.detector.runner.run_scan_async.call_count, 3) # 1 for main scan + 2 for dynamic loop
        self.assertTrue(len(findings) > 0)
        
        # Verify the fix was applied
        # The second call to run_scan_async should have the FIXED query
        # Check LLMGateway fix called
        self.detector.llm_gateway.fix_semgrep_rule.assert_called_once()

if __name__ == '__main__':
    unittest.main()
