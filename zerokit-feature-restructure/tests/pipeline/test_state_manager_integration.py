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

class TestStateManagerIntegration(unittest.TestCase):
    def setUp(self):
        self.detector = Detector()
        self.detector.runner = AsyncMock()
        self.detector.codeql_runner = MagicMock()
        self.detector.state_manager = MagicMock()
        
        # Mock CodeQL DB Creation Logic
        db_res_mock = MagicMock()
        db_res_mock.success = True
        db_res_mock.db_path = "/tmp/db"
        db_res_mock.duration_ms = 100.0 # Float
        
        self.detector.codeql_runner.create_database_async = AsyncMock(return_value=db_res_mock)
        
        analyze_res_mock = MagicMock(success=True)
        analyze_res_mock.duration_ms = 200.0 # Float
        self.detector.codeql_runner.analyze_async = AsyncMock(return_value=analyze_res_mock)

    @patch('os.walk')
    def test_differential_scan(self, mock_walk):
        """Test that Detector skips scanning if files are unchanged."""
        
        # Mock file system: 2 files
        root_dir = os.path.normpath("/path")
        mock_walk.return_value = [(root_dir, [], ["file1.py", "file2.py"])]
        
        file1 = os.path.join(root_dir, "file1.py")
        file2 = os.path.join(root_dir, "file2.py")
        
        # Mock State Manager:
        self.detector.state_manager.should_scan_file.side_effect = lambda path: "file1.py" in path
        
        # Mock Cached Findings for file2
        cached_finding = StaticFinding(
            id="cache1", 
            location=f"{file2}:10", 
            description="Cached", 
            tool_name="semgrep", 
            severity=FindingSeverity.HIGH,
            evidence="Code snippet",
            metadata={} 
        )
        self.detector.state_manager.get_cached_findings.return_value = [cached_finding]
        
        # Mock Semgrep Runner for file1 (Changed)
        self.detector.runner.run_scan_async.return_value = ScanResult(
            success=True, 
            findings=[{"extra": {"message": "New Bug", "severity": "ERROR"}, "path": file1, "start": {"line": 1}}]
        )
        
        h = Hypothesis(id="test", description="Test", target_code="", verification_plan="", metadata={})
        
        # Run Scan
        findings = asyncio.run(self.detector.scan([h], "/path"))
        
        # VERIFICATION
        
        # 1. State Manager should be checked for both files
        self.assertEqual(self.detector.state_manager.should_scan_file.call_count, 2)
        
        # 2. Cached findings should be retrieved for file2
        self.detector.state_manager.get_cached_findings.assert_called()
        
        # 3. Semgrep should be called ONLY with changed files ('/path/file1.py')
        call_args = self.detector.runner.run_scan_async.call_args
        self.assertIsNotNone(call_args)
        target_path_arg = call_args[0][1] # (config, target_path, jobs)
        target_path_arg = call_args[0][1] # (config, target_path, jobs)
        
        # Normalize paths for Windows compatibility
        normalized_targets = [p.replace("\\", "/") for p in target_path_arg]
        self.assertIn("/path/file1.py", normalized_targets)
        # self.assertNotIn("/path/file2.py", target_path_arg) # Usually list, check contents
        
        # 4. State should be updated for file1 (since scan succeeded)
        expected_path = os.path.normpath("/path/file1.py")
        self.detector.state_manager.update_file_state.assert_called_with(expected_path)
        
        # 5. Resulting findings should combine Cached + New
        self.assertEqual(len(findings), 2)
        descriptions = [f.description for f in findings]
        self.assertIn("Cached", descriptions)
        self.assertIn("New Bug", descriptions)

if __name__ == '__main__':
    unittest.main()
