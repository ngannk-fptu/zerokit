import unittest
import os
import sys
from unittest.mock import MagicMock, patch

# Add .agent to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../.agent')))

from core.agents.detector import Detector
from core.models import FindingSeverity

class TestDetector(unittest.TestCase):
    
    @patch('pipeline.tools.semgrep_runner.SemgrepRunner.run_scan')
    def test_detector_flow(self, mock_run_scan):
        # Mock Semgrep output
        mock_output = [
            {
                "path": "app.py",
                "start": {"line": 10},
                "extra": {
                    "message": "Potential SQL Injection",
                    "severity": "ERROR",
                    "lines": "cursor.execute(query)"
                }
            }
        ]
        mock_run_scan.return_value = mock_output
        
        detector = Detector()
        findings = detector.scan([], "/tmp/fake")
        
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, FindingSeverity.HIGH)
        self.assertEqual(findings[0].description, "Potential SQL Injection")
        self.assertEqual(findings[0].tool_name, "semgrep")

    @patch('pipeline.tools.semgrep_runner.subprocess.run')
    def test_runner_repair_hook_logic(self, mock_subprocess):
        # This test ensures we have the logic to catch errors, even if we mock the underlying call
        from core.tools.semgrep_runner import SemgrepRunner
        runner = SemgrepRunner()
        
        # Simulate a subprocess error (e.g. invalid syntax)
        mock_subprocess.side_effect = Exception("Semgrep crashed")
        
        with self.assertRaises(Exception):
            runner.run_scan("config", "target")

if __name__ == '__main__':
    unittest.main()
