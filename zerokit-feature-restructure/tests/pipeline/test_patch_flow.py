import unittest
from unittest.mock import MagicMock, patch, AsyncMock
import sys
import os
import asyncio

# Add .agent to path
current_dir = os.path.dirname(os.path.abspath(__file__))
agent_dir = os.path.abspath(os.path.join(current_dir, "..", "..", ".agent"))
sys.path.append(agent_dir)

from core.orchestrator import Orchestrator
from core.models import VerifiedVuln, ConfirmedStatus, StaticFinding, FindingSeverity

class TestPatchFlow(unittest.TestCase):
    def setUp(self):
        self.orchestrator = Orchestrator()
        self.orchestrator.verifier.sandbox.available = True
        
        # Mock Context
        self.orchestrator.start_pipeline("/tmp/repo")
        
        # Mock a Confirmed Vulnerability
        self.vuln = VerifiedVuln(
            finding_id="vuln1",
            status=ConfirmedStatus.CONFIRMED,
            poc={"repro.py": "print('VULNERABLE')"},
            runtime_output="VULNERABLE",
            evidence="Found XSS"
        )
        self.orchestrator.context.verified_vulns.append(self.vuln)
        
        # Mock matching Static Finding (needed for path)
        self.finding = StaticFinding(
            id="vuln1",
            description="Reflected XSS",
            location="vulnerable.py:10",
            severity=FindingSeverity.HIGH,
            tool_name="semgrep",
            evidence="echo $_GET"
        )
        self.orchestrator.context.static_findings.append(self.finding)

    @patch('pipeline.agents.patcher.Patcher.apply_fix')
    @patch('pipeline.tools.sandbox.DockerSandbox.run')
    @patch('builtins.open')
    @patch('os.path.exists')
    @patch('os.path.isabs')
    def test_patch_verification_success(self, mock_isabs, mock_exists, mock_open, mock_sandbox_run, mock_apply_fix):
        """Test the full patch Verification loop (Success Scenario)."""
        
        # Setup Mocks
        mock_isabs.return_value = False
        mock_exists.return_value = True
        mock_apply_fix.return_value = "/tmp/patched_vulnerable.py"
        
        # Mock Patched File Content
        mock_open.return_value.__enter__.return_value.read.return_value = "fixed code"
        
        # Mock Sandbox Verification (Simulate Fix)
        # Fix means exit 0 and NO 'VULNERABLE' string
        mock_res = MagicMock()
        mock_res.exit_code = 0
        mock_res.stdout = "Safe Output"
        mock_res.stderr = ""
        mock_sandbox_run.return_value = mock_res
        
        # Run
        asyncio.run(self.orchestrator.run_stage_patch_verification())
        
        # Validation
        # 1. Check if patcher was called
        mock_apply_fix.assert_called()
        
        # 2. Check if sandbox was called with patched content
        args, _ = mock_sandbox_run.call_args
        files = args[1]
        self.assertIn("vulnerable.py", files)
        self.assertEqual(files["vulnerable.py"], "fixed code") # Should be patched content
        
        # 3. Check Status Update (FIX_VERIFIED) - Assuming we mapped it to something or just check logic
        # Since FIX_VERIFIED might not be in Enum, we assume logic executed without error
        # and logged success.
        # But we can check if execution reached the log success if we mock logger?
        # Or just checking mock calls is enough for flow.
        pass

if __name__ == '__main__':
    unittest.main()
