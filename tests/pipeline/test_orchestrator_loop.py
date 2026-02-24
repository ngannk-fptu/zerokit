import unittest
from unittest.mock import MagicMock, AsyncMock, patch
import asyncio
import sys
import os

# Add .agent to path
current_dir = os.path.dirname(os.path.abspath(__file__))
# Go up 2 levels to root (tests/pipeline -> tests -> root) then down to .agent
agent_dir = os.path.abspath(os.path.join(current_dir, "..", "..", ".agent"))
sys.path.append(agent_dir)

from pipeline.orchestrator import Orchestrator
from pipeline.models import StaticFinding, VerifiedVuln, ConfirmedStatus, FindingSeverity

class TestOrchestratorLoop(unittest.TestCase):
    def setUp(self):
        self.orchestrator = Orchestrator()
        
        # Mocks
        self.orchestrator.profiler = MagicMock()
        self.orchestrator.threat_modeler = MagicMock()
        self.orchestrator.detector = AsyncMock()
        self.orchestrator.verifier = AsyncMock()
        self.orchestrator.start_pipeline = MagicMock()
        
        # Mock Context
        self.orchestrator.context = MagicMock()
        self.orchestrator.context.repo_path = "/tmp/test"
        self.orchestrator.context.static_findings = []
        self.orchestrator.context.verified_vulns = []
        
        self.orchestrator.start_pipeline.return_value = self.orchestrator.context

    def test_loop_mechanics(self):
        """Test that the loop runs and processes variants."""
        
        # 1. Initial Findings
        finding_1 = StaticFinding(id="f1", location="file.py:1", severity=FindingSeverity.HIGH, description="Bug 1", tool_name="test", evidence="")
        self.orchestrator.context.static_findings = [finding_1]
        
        # 2. Mock Verifier (First Pass) - Confirms finding 1
        vuln_1 = VerifiedVuln(finding_id="f1", status=ConfirmedStatus.CONFIRMED, poc={}, runtime_output="", evidence="")
        self.orchestrator.verifier.verify_batch.side_effect = [
            [vuln_1], # First pass result
            [],       # Second pass result (Variant verification)
        ]
        
        # 3. Mock Detector (Feedback Scan) - Returns Variant Finding 2
        finding_2 = StaticFinding(id="f2", location="file.py:10", severity=FindingSeverity.HIGH, description="Bug 1 Variant", tool_name="test", evidence="")
        
        # Detector.scan called twice: 
        # 1. Initial Scan (we skip testing this as it's outside the loop in this strict unit test, or we mock it)
        # But wait, run_full_pipeline calls run_stage_detection FIRST. 
        # So we need to mock that too.
        
        # Let's mock run_stage_detection to just populate context
        self.orchestrator.run_stage_detection = MagicMock()
        
        # Detector.scan is called inside run_stage_feedback
        self.orchestrator.detector.scan.return_value = [finding_2]
        
        # Exec
        self.orchestrator.run_full_pipeline("/tmp/test")
        
        # Asserts
        # 1. Verify was called twice (Initial + Variant)
        self.assertEqual(self.orchestrator.verifier.verify_batch.call_count, 2)
        
        # 2. Detector scan was called (via feedback)
        self.orchestrator.detector.scan.assert_called()
        
        # 3. Findings list expanded
        self.assertEqual(len(self.orchestrator.context.static_findings), 2)
        self.assertEqual(self.orchestrator.context.static_findings[1].id, "f2")

if __name__ == '__main__':
    unittest.main()
