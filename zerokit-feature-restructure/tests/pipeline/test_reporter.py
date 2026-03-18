import unittest
import os
import sys

# Add .agent to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../.agent')))

from pipeline.agents.reporter import Reporter
from pipeline.models import VerifiedVuln, ConfirmedStatus, FindingSeverity

class TestReporter(unittest.TestCase):
    def test_report_generation(self):
        vuln = VerifiedVuln(
            finding_id="test-1",
            status=ConfirmedStatus.CONFIRMED,
            poc={"type": "script", "content": "print('pwn')"},
            runtime_output="Crash confirmed",
            evidence="heap-overflow",
            severity_adjustment=FindingSeverity.CRITICAL
        )
        
        reporter = Reporter()
        report = reporter.generate_report([vuln])
        
        self.assertIn("# Automated Security Pipeline Report", report)
        self.assertIn("CRITICAL", report) # Severity (Enum value likely converted to string)
        self.assertIn("Crash confirmed", report) # Runtime output
        self.assertIn("heap-overflow", report) # Evidence

    def test_empty_report(self):
        reporter = Reporter()
        report = reporter.generate_report([])
        self.assertIn("No confirmed vulnerabilities", report)

if __name__ == '__main__':
    unittest.main()
