import sys
import os
import unittest

# Add .agent to sys.path to allow importing pipeline
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../.agent')))

from core.orchestrator import Orchestrator
from core.models import VerifiedVuln, ConfirmedStatus, FindingSeverity

class TestOrchestrator(unittest.TestCase):
    def test_orchestrator_initialization(self):
        orch = Orchestrator()
        context = orch.start_pipeline("/tmp/test-repo")
        self.assertEqual(context.repo_path, "/tmp/test-repo")
        self.assertIsNotNone(context.run_id)

    def test_verification_gate_empty(self):
        orch = Orchestrator()
        orch.start_pipeline("/tmp/test-repo")
        # No verified vulns
        report = orch.run_stage_reporting()
        self.assertIn("No verified vulnerabilities found", report)

    def test_verification_gate_success(self):
        orch = Orchestrator()
        ctx = orch.start_pipeline("/tmp/test-repo")
        
        # Mock a verified vuln
        vuln = VerifiedVuln(
            finding_id="find-1",
            status=ConfirmedStatus.CONFIRMED,
            poc={"type": "script", "content": "print('pwn')"},
            runtime_output="pwn",
            evidence="Executed successfully"
        )
        ctx.verified_vulns.append(vuln)
        
        report = orch.run_stage_reporting()
        self.assertIn("Report generated with 1 verified vulnerabilities", report)

    def test_verification_gate_filters_rejected(self):
        orch = Orchestrator()
        ctx = orch.start_pipeline("/tmp/test-repo")
        
        # Mock a rejected vuln
        vuln = VerifiedVuln(
            finding_id="find-2",
            status=ConfirmedStatus.REJECTED,
            poc={},
            runtime_output="",
            evidence="Failed to reproduce"
        )
        ctx.verified_vulns.append(vuln)
        
        report = orch.run_stage_reporting()
        self.assertIn("No verified vulnerabilities found", report)

if __name__ == '__main__':
    unittest.main()
