"""
Tests for Jazzer integration
"""
import unittest
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../.agent')))

from core.tools.jazzer_runner import JazzerRunner

class TestJazzerRunner(unittest.TestCase):
    def setUp(self):
        """Setup Jazzer runner."""
        self.runner = JazzerRunner()
    
    def test_jazzer_initialization(self):
        """Test Jazzer runner initializes with config."""
        self.assertIsNotNone(self.runner.jazzer_jar)
        self.assertIn("jazzer", self.runner.jazzer_jar)
        print(f"✓ Jazzer JAR: {self.runner.jazzer_jar}")
    
    def test_harness_generation(self):
        """Test harness code generation."""
        harness_file = self.runner.generate_harness(
            target_class="com.example.Parser",
            target_method="parse"
        )
        
        self.assertTrue(os.path.exists(harness_file))
        
        # Verify harness content
        with open(harness_file, "r") as f:
            content = f.read()
            self.assertIn("FuzzedDataProvider", content)
            self.assertIn("fuzzerTestOneInput", content)
            self.assertIn("Parser.parse", content)
        
        print(f"✓ Harness generated: {harness_file}")
        
        # Cleanup
        os.remove(harness_file)
    
    @unittest.skip("Requires Java compiler and project classpath")
    def test_compile_harness(self):
        """Integration test: Compile generated harness."""
        pass
    
    @unittest.skip("Requires compiled harness and Jazzer JAR")
    def test_run_fuzzing(self):
        """Integration test: Run Jazzer fuzzing."""
        pass

if __name__ == '__main__':
    unittest.main()
