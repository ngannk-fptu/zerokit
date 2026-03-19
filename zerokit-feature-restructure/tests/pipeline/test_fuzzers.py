"""
Tests for fuzzer runners
"""
import unittest
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../.agent')))

from core.tools.atheris_runner import AtherisRunner
from core.tools.afl_runner import AFLRunner

class TestAtherisRunner(unittest.TestCase):
    def setUp(self):
        """Setup Atheris runner."""
        self.runner = AtherisRunner()
    
    def test_atheris_initialization(self):
        """Test Atheris runner initializes."""
        self.assertIsNotNone(self.runner.workspace)
        print(f"✓ Atheris workspace: {self.runner.workspace}")
    
    def test_harness_generation(self):
        """Test Atheris harness generation."""
        harness_file = self.runner.generate_harness(
            target_module="json",
            target_function="loads"
        )
        
        self.assertTrue(os.path.exists(harness_file))
        
        # Verify harness content
        with open(harness_file, "r") as f:
            content = f.read()
            self.assertIn("atheris", content)
            self.assertIn("TestOneInput", content)
            self.assertIn("from json import loads", content)
        
        print(f"✓ Atheris harness generated: {harness_file}")
        
        # Cleanup
        os.remove(harness_file)
    
    @unittest.skip("Requires atheris installation (needs C++ compiler on Windows)")
    def test_run_fuzzing(self):
        """Integration test: Run Atheris fuzzing."""
        pass

class TestAFLRunner(unittest.TestCase):
    def setUp(self):
        """Setup AFL++ runner."""
        self.runner = AFLRunner()
    
    def test_afl_initialization(self):
        """Test AFL++ runner initializes."""
        self.assertIsNotNone(self.runner.workspace)
        print(f"✓ AFL++ workspace: {self.runner.workspace}")
        print(f"✓ AFL++ available: {self.runner.available}")
    
    @unittest.skip("Requires AFL++ installation (WSL on Windows)")
    def test_compile_target(self):
        """Integration test: Compile with AFL++."""
        pass
    
    @unittest.skip("Requires AFL++ installation")
    def test_run_fuzzing(self):
        """Integration test: Run AFL++ fuzzing."""
        pass

if __name__ == '__main__':
    unittest.main()
