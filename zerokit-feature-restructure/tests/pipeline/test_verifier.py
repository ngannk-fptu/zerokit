import unittest
import os
import sys

# Add .agent to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../.agent')))

from pipeline.agents.verifier import Verifier
from pipeline.models import StaticFinding, FindingSeverity, ConfirmedStatus

class TestVerifier(unittest.TestCase):
    def test_verify_asan_simulation(self):
        # Create a finding describing a buffer overflow
        finding = StaticFinding(
            id="test-1",
            description="Possible buffer overflow",
            location="main.c:10",
            severity=FindingSeverity.HIGH,
            evidence="strcpy(buf, user_input)",
            tool_name="semgrep"
        )
        
        verifier = Verifier()
        result = verifier.verify(finding)
        
        self.assertEqual(result.status, ConfirmedStatus.CONFIRMED)
        self.assertIn("AddressSanitizer", result.evidence)

    def test_verify_rejected(self):
        # Create a benign finding
        finding = StaticFinding(
            id="test-2",
            description="Just a warning",
            location="utils.py:5",
            severity=FindingSeverity.LOW,
            evidence="print('hello')",
            tool_name="semgrep"
        )
        
        verifier = Verifier()
        result = verifier.verify(finding)
        
        self.assertEqual(result.status, ConfirmedStatus.REJECTED)

if __name__ == '__main__':
    unittest.main()
