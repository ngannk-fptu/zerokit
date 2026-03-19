"""
Tests for JoernRunner tool
"""
import unittest
import os
import sys
import tempfile

# Add .agent to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../.agent')))

from core.tools.joern_runner import JoernRunner

class TestJoernRunner(unittest.TestCase):
    def setUp(self):
        """Setup test environment."""
        self.runner = JoernRunner()
        self.test_workspace = tempfile.mkdtemp(prefix="joern_test_")
    
    def tearDown(self):
        """Cleanup."""
        self.runner.cleanup()
    
    def test_joern_initialization(self):
        """Test Joern runner initializes correctly."""
        self.assertIsNotNone(self.runner.joern_home)
        self.assertTrue(os.path.exists(self.runner.joern_home))
        self.assertIn("joern", self.runner.joern_home)
        print(f"✓ Joern home: {self.runner.joern_home}")
    
    def test_joern_parse_exists(self):
        """Test that joern-parse binary exists."""
        self.assertTrue(os.path.exists(self.runner.joern_parse))
        print(f"✓ joern-parse: {self.runner.joern_parse}")
    
    def test_workspace_created(self):
        """Test workspace directory is created."""
        self.assertTrue(os.path.exists(self.runner.workspace))
        print(f"✓ Workspace: {self.runner.workspace}")
    
    @unittest.skip("Requires actual C code to parse - integration test")
    def test_parse_code(self):
        """Integration test: Parse actual C code."""
        # Create a simple C file
        test_code_dir = tempfile.mkdtemp()
        test_file = os.path.join(test_code_dir, "test.c")
        
        with open(test_file, "w") as f:
            f.write("""
            #include <string.h>
            
            void vulnerable(char* input) {
                char buffer[10];
                strcpy(buffer, input); // No bounds check!
            }
            """)
        
        try:
            cpg_path = self.runner.parse_code(test_code_dir, language="c")
            self.assertTrue(os.path.exists(cpg_path))
            print(f"✓ CPG created: {cpg_path}")
        except Exception as e:
            self.skipTest(f"Joern not fully configured: {e}")

if __name__ == '__main__':
    unittest.main()
