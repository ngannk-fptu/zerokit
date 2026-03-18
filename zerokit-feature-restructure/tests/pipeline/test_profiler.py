import unittest
import os
import sys
import tempfile
import shutil

# Add .agent to sys.path to allow importing pipeline
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../.agent')))

from pipeline.models import PipelineContext
from pipeline.agents.profiler import RepoProfiler
from pipeline.adapters.python_adapter import PythonAdapter

class TestProfiler(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.context = PipelineContext(repo_path=self.test_dir, run_id="test-run", start_time="now")

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_python_detection(self):
        # Create a dummy python project
        with open(os.path.join(self.test_dir, "requirements.txt"), "w") as f:
            f.write("flask")
        
        adapter = PythonAdapter()
        self.assertTrue(adapter.detect(self.test_dir))

    def test_profiler_execution(self):
        # Create a dummy python project with a route
        with open(os.path.join(self.test_dir, "app.py"), "w") as f:
            f.write("from flask import Flask\napp = Flask(__name__)\n\n@app.route('/')\ndef index():\n    pass")
        
        adapter = PythonAdapter()
        profiler = RepoProfiler([adapter])
        
        # Override run_health_check to avoid actual shell commands in test
        profiler._run_health_check = lambda *args: None
        
        surface = profiler.analyze(self.context)
        self.assertEqual(len(surface.entry_points), 1)
        self.assertEqual(surface.entry_points[0].type, "HTTP")

if __name__ == '__main__':
    unittest.main()
