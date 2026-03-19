import unittest
import os
import sys

# Add .agent to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../.agent')))

from core.models import AttackSurface, EntryPoint, EntryPointType
from core.agents.threat_modeler import ThreatModeler

class TestThreatModeler(unittest.TestCase):
    def test_ranking_logic(self):
        # Create a mix of entry points
        entries = [
            EntryPoint(type=EntryPointType.CLI, code_location="cli.py:10", description="Simple CLI tool"), # MEDIUM
            EntryPoint(type=EntryPointType.HTTP, code_location="views.py:20", description="Public API"), # HIGH
            EntryPoint(type=EntryPointType.HTTP, code_location="auth.py:5", description="Login Handler"), # CRITICAL (auth keyword)
            EntryPoint(type=EntryPointType.FILE, code_location="utils.py:100", description="Helper"), # LOW
        ]
        surface = AttackSurface(entry_points=entries)
        
        modeler = ThreatModeler()
        hypotheses = modeler.generate_hypotheses(surface)
        
        self.assertEqual(len(hypotheses), 4)
        
        # Verify Sorting Order: CRITICAL -> HIGH -> MEDIUM -> LOW
        self.assertEqual(hypotheses[0].metadata["priority"], "CRITICAL")
        self.assertEqual(hypotheses[1].metadata["priority"], "HIGH")
        self.assertEqual(hypotheses[2].metadata["priority"], "MEDIUM")
        self.assertEqual(hypotheses[3].metadata["priority"], "LOW")
        
        # Verify content of top priority
        self.assertIn("auth", hypotheses[0].target_code)

if __name__ == '__main__':
    unittest.main()
