import unittest
from unittest.mock import MagicMock, AsyncMock, patch, mock_open
import sys
import os
import asyncio

# Add .agent to path
current_dir = os.path.dirname(os.path.abspath(__file__))
agent_dir = os.path.abspath(os.path.join(current_dir, "..", "..", ".agent"))
sys.path.append(agent_dir)

from core.agents.detector import Detector
from core.models import Hypothesis

class TestDetectorSurgical(unittest.TestCase):
    def setUp(self):
        self.detector = Detector()
        self.detector.runner = AsyncMock() # Semgrep
        self.detector.codeql_runner = AsyncMock()
        self.detector.state_manager = MagicMock()
        self.detector.joern_runner = MagicMock()
        
        # Disable methods we don't test
        self.detector._generate_semgrep_config = MagicMock(return_value="/tmp")
        self.detector._run_dynamic_query_loop = AsyncMock()
        self.detector.state_manager.filter_rejected_findings = lambda x: x
        
    @patch('os.walk')
    @patch('os.path.exists')
    @patch('os.path.isfile')
    @patch('builtins.open', new_callable=mock_open)
    def test_surgical_scan_trigger(self, mock_file, mock_isfile, mock_exists, mock_walk):
        """Test that Surgical Mode is triggered and Context Expansion works."""
        
        # Setup: 2 files. A.py imports B.py.
        # Only A.py is changed. B.py should be included via context expansion.
        repo_path = os.path.abspath("/repo")
        file_a = os.path.join(repo_path, "A.py")
        file_b = os.path.join(repo_path, "B.py")
        
        # Mock OS
        mock_walk.return_value = [(repo_path, [], ["A.py", "B.py"])]
        mock_exists.return_value = True
        
        valid_files = {file_a, file_b}
        mock_isfile.side_effect = lambda path: path in valid_files
        
        # Mock File Content for Import
        file_contents = {
            file_a: "from B import foo",
            file_b: "def foo(): pass"
        }
        mock_file.side_effect = lambda f, mode='r', errors=None: mock_open(read_data=file_contents.get(f, "")).return_value
        
        # Mock State Manager: A.py is changed, B.py is unchanged
        def should_scan(f):
            return f == file_a
        self.detector.state_manager.should_scan_file.side_effect = should_scan
        
        # Mock Semgrep success
        scan_res = MagicMock()
        scan_res.success = True
        scan_res.findings = []
        scan_res.duration_ms = 100.0
        self.detector.runner.run_scan_async.return_value = scan_res
        
        # Mock CodeQL success
        ql_res = MagicMock()
        ql_res.success = True
        ql_res.db_path = "/tmp/db"
        ql_res.duration_ms = 100.0
        self.detector.codeql_runner.create_database_async.return_value = ql_res
        
        ql_analyze_res = MagicMock()
        ql_analyze_res.success = True
        ql_analyze_res.findings = []
        ql_analyze_res.duration_ms = 100.0
        self.detector.codeql_runner.analyze_async.return_value = ql_analyze_res

        # Run Scan
        h = Hypothesis(id="h1", description="desc", target_code="", verification_plan="")
        asyncio.run(self.detector.scan([h], repo_path))
        
        # Verify Context Expansion
        # _expand_context should have been called
        # And create_database_async should receive include_paths containing BOTH A.py and B.py
        
        calls = self.detector.codeql_runner.create_database_async.call_args_list
        self.assertTrue(len(calls) > 0)
        
        # Check args of first call
        args, kwargs = calls[0]
        include_paths = kwargs.get('include_paths')
        
        print(f"DEBUG: include_paths passed to CodeQL: {include_paths}")
        
        self.assertIsNotNone(include_paths)
        self.assertIn(file_a, include_paths)
        self.assertIn(file_b, include_paths)

if __name__ == '__main__':
    unittest.main()
