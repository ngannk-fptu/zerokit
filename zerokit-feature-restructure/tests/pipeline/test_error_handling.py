import unittest
import logging
import os
import sys
from unittest.mock import MagicMock, patch

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.agent")))

from core.orchestrator import Orchestrator
from core.agents.detector import Detector
from core.models import EntryPoint, EntryPointType

class TestStability(unittest.TestCase):
    def setUp(self):
        # Setup logging to capture output
        self.logger = logging.getLogger("pipeline")
        self.logger.setLevel(logging.WARNING)
        self.log_capture = []
        
        # Add handler to capture logs
        class ListHandler(logging.Handler):
            def __init__(self, log_list):
                super().__init__()
                self.log_list = log_list
            def emit(self, record):
                self.log_list.append(self.format(record))
                
        self.handler = ListHandler(self.log_capture)
        # Attach to root logger to catch everything
        logging.getLogger().addHandler(self.handler)

    def tearDown(self):
        logging.getLogger().removeHandler(self.handler)

    def test_orchestrator_fallback(self):
        """Test that Orchestrator falls back to GenericAdapter on Profiler error."""
        orchestrator = Orchestrator()
        
        # Mock context
        orchestrator.context = MagicMock()
        orchestrator.context.repo_path = "/tmp/fake_repo"
        
        # Mock profiler to raise ValueError
        orchestrator.profiler.analyze = MagicMock(side_effect=ValueError("No adapter found"))
        
        # Mock GenericAdapter to verify it's used
        with patch('pipeline.orchestrator.GenericAdapter') as MockGeneric:
            mock_adapter_instance = MockGeneric.return_value
            mock_adapter_instance.get_entry_points.return_value = [
                EntryPoint(category=EntryPointType.FILE, code_location="fake_file.txt")
            ]
            
            # Run
            orchestrator.run_stage_profiling()
            
            # Check if warning was logged
            self.assertTrue(any("Falling back to Generic Adapter" in log for log in self.log_capture), 
                           "Fallback warning not found in logs")
            
            # Check if GenericAdapter was called
            mock_adapter_instance.get_entry_points.assert_called_once()

    def test_detector_partial_context(self):
        """Test that Detector logs PARTIAL_CONTEXT on file parse error."""
        detector = Detector()
        
        # Mock open to raise exception
        with patch('builtins.open', side_effect=IOError("Permission denied")):
            # Create a dummy file that 'exists'
            with patch('os.path.exists', return_value=True):
                detector._expand_context(["/tmp/protected_file.py"], "/tmp/repo")
                
                # Check for PARTIAL_CONTEXT log
                self.assertTrue(any("PARTIAL_CONTEXT" in log for log in self.log_capture),
                               "PARTIAL_CONTEXT warning not found in logs")

if __name__ == "__main__":
    unittest.main()
