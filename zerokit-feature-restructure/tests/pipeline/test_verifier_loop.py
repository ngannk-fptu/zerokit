import unittest
import asyncio
import os
import sys
from unittest.mock import MagicMock, patch

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.agent")))

from pipeline.agents.verifier import Verifier
from pipeline.models import StaticFinding, ConfirmedStatus

class TestVerifierLoop(unittest.TestCase):
    def setUp(self):
        # Create a dummy template for testing
        self.verifier = Verifier()
        # Create mock finding
        self.finding = StaticFinding(
            id="test-123",
            description="Potential SQL Injection in login.php",
            location="login.php:12",
            severity="HIGH",
            tool_name="semgrep",
            evidence="query"
        )
        
        # Ensure template exists or mock open
        self.verifier.templates_dir = os.path.dirname(__file__) # Use current dir for test
        
    @patch('pipeline.agents.verifier.Verifier._run_sandbox')
    @patch('pipeline.agents.verifier.Verifier._generate_poc')
    def test_feedback_loop_retry(self, mock_generate, mock_sandbox):
        """
        Verify that the loop retries upon failure and eventually succeeds.
        """
        # Mock Template Selection
        self.verifier._select_template = MagicMock(return_value="mock_template.py")
        
        # Mock Generation
        mock_generate.return_value = "print('Simulated Payload')"
        
        # Mock Sandbox: Fail twice, succeed on 3rd attempt
        # Returns: (exit_code, stdout, stderr)
        mock_sandbox.side_effect = [
            (1, "", "Syntax Error"), # Attempt 1: Syntax Error (Exit 1)
            (1, "Nothing happened", "AssertionError: Failed"), # Attempt 2: Logic Failure (Exit 1)
            (0, "SQLi Detected", "") # Attempt 3: Success (Exit 0)
        ]
        
        # Run Verification
        result = asyncio.run(self.verifier.verify_finding(self.finding, "http://test.com"))
        
        # Assertions
        self.assertEqual(result.status, ConfirmedStatus.CONFIRMED)
        self.assertEqual(mock_sandbox.call_count, 3)
        self.assertEqual(result.finding_id, "test-123")
        self.assertIn("SQLi Detected", result.runtime_output)

if __name__ == "__main__":
    unittest.main()
