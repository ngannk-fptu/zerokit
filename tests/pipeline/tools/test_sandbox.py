import unittest
from unittest.mock import patch, MagicMock
import sys
import os

# Add .agent to path
current_dir = os.path.dirname(os.path.abspath(__file__))
agent_dir = os.path.abspath(os.path.join(current_dir, "..", "..", "..", ".agent"))
sys.path.append(agent_dir)

from pipeline.tools.sandbox import DockerSandbox

class TestDockerSandbox(unittest.TestCase):
    @patch('subprocess.run')
    def test_run_with_instrumentation(self, mock_run):
        """Test that instrumentation adds correct env vars."""
        sandbox = DockerSandbox()
        # Mock availability
        sandbox.available = True
        
        # Mock subprocess to avoid actual docker call
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "OK"
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        files = {"repro.py": "print('hello')"}
        sandbox.run("python repro.py", files, instrumentation=True)
        
        # Check if docker command contained env vars
        # We need to find the call args
        args, _ = mock_run.call_args
        cmd = args[0]
        
        # Convert cmd list to string for easier searching
        cmd_str = " ".join(cmd)
        
        self.assertIn("ASAN_OPTIONS=abort_on_error=1", cmd_str)
        self.assertIn("PYTHONMALLOC=debug", cmd_str)
        self.assertIn("MSAN_OPTIONS=", cmd_str)
        
    @patch('subprocess.run')
    def test_run_with_custom_env(self, mock_run):
        """Test custom environment variables."""
        sandbox = DockerSandbox()
        sandbox.available = True
        
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        
        files = {}
        custom_env = {"MY_VAR": "123"}
        sandbox.run("cmd", files, env_vars=custom_env)
        
        args, _ = mock_run.call_args
        cmd_list = args[0]
        
        self.assertIn("-e", cmd_list)
        self.assertIn("MY_VAR=123", cmd_list)

if __name__ == '__main__':
    unittest.main()
