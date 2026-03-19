import unittest
import asyncio
import sys
import os
from unittest.mock import AsyncMock, MagicMock, patch

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.agent")))

from core.agents.detector import Detector
from core.models import FindingSeverity, StaticFinding

class TestDetectorResilience(unittest.IsolatedAsyncioTestCase):
    async def test_detector_resilience_partial_failure(self):
        """
        Verify that Detector continues if one runner crashes (e.g., CodeQL/Joern).
        Scenario: Semgrep Succeeds, Joern Crashes.
        """
        # Mock Runners
        mock_semgrep = AsyncMock()
        mock_joern = AsyncMock()
        
        # Setup Semgrep Success
        mock_semgrep_result = MagicMock()
        mock_semgrep_result.success = True
        mock_semgrep_result.duration_ms = 100
        mock_semgrep_result.findings = [{
            "path": "vuln.php",
            "start": {"line": 10},
            "extra": {
                "message": "SQLi Detected",
                "severity": "ERROR",
                "lines": "$wpdb->query(...)",
                "metadata": {"type": "sqli", "tag": "security"}
            }
        }]
        mock_semgrep.run_scan_async.return_value = mock_semgrep_result

        # Setup Joern Crash (Raise Exception)
        mock_joern.parse_code_async.side_effect = Exception("Joern Server Crash")
        
        # Initialize Detector with Mocks
        detector = Detector(semgrep_runner=mock_semgrep, joern_runner=mock_joern)
        # Mock CodeQL Runner internally
        detector.codeql_runner = AsyncMock()
        detector.codeql_runner.create_database_async.return_value = MagicMock(success=True, db_path="/tmp/db")
        detector.codeql_runner.analyze_async.return_value = MagicMock(success=True, findings=[])

        # Run Scan
        # We need dummy hypotheses and repo path
        hypotheses = [MagicMock(id="h1", description="SQLi check", metadata={"type": "sqli"})]
        repo_path = "/tmp/test-repo"
        
        # Mock dependencies using patch context managers
        # We need to return specific values for glob_has_ext if it's used, but here os.walk is mocked.
        # Detector uses os.walk to find files.
        
        with patch("os.walk") as mock_walk, \
             patch("pipeline.agents.detector.Detector._generate_semgrep_config") as mock_conf, \
             patch("pipeline.state_manager.StateManager") as MockStateManager:
             
            mock_walk.return_value = [("/tmp/test-repo", [], ["vuln.php"])]
            mock_conf.return_value = "/tmp/rules.yaml"
            
            # Mock StateManager instance
            mock_state_mgr = MockStateManager.return_value
            mock_state_mgr.should_scan_file.return_value = True # Ensure we scan
            mock_state_mgr.get_rule_error.return_value = None
            mock_state_mgr.is_rule_blacklisted.return_value = False
            mock_state_mgr.filter_rejected_findings.side_effect = lambda x: x # Identity
            
            detector.state_manager = mock_state_mgr
            
            # EXECUTE
            # We expect Detector to log the crash but return Semgrep findings
            findings = await detector.scan(hypotheses, repo_path)
            
            # ASSERTIONS
            # 1. Semgrep findings should be present
            self.assertTrue(len(findings) >= 1, "Detector returned no findings")
            found = False
            for f in findings:
                if "vuln.php" in f.location:
                   found = True
                   break
            self.assertTrue(found, "Detector missed Semgrep finding from vuln.php")
            
            print("\nTest Passed: Detector survived Joern crash.")

if __name__ == "__main__":
    unittest.main()
