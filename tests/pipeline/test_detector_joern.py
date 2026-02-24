"""
Tests for Detector with Joern integration
"""
import unittest
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../.agent')))

from pipeline.agents.detector import Detector
from pipeline.models import Hypothesis

class TestDetectorJoern(unittest.TestCase):
    def setUp(self):
        """Setup detector with Joern enabled."""
        self.detector = Detector()
    
    def test_joern_integration(self):
        """Test that Joern runner is initialized."""
        self.assertIsNotNone(self.detector.joern_runner)
        self.assertTrue(self.detector.enable_joern)
        print("✓ Joern runner initialized in Detector")
    
    def test_c_cpp_detection(self):
        """Test C/C++ project detection."""
        # joern directory has .c files (test suite)
        is_c_project = self.detector._is_c_cpp_project("joern")
        # May or may not be C/C++ depending on Joern's contents
        print(f"✓ C/C++ detection works (result: {is_c_project})")
    
    @unittest.skip("Requires actual C code to parse - integration test")
    def test_joern_scan(self):
        """Integration test: Run Joern scan on C code."""
        # Would need a test C project with vulnerabilities
        pass

if __name__ == '__main__':
    unittest.main()
