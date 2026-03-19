"""
Tests for SCA and Secret Scanning tools
"""
import unittest
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../.agent')))

from core.tools.gitleaks_runner import GitleaksRunner
from core.tools.trivy_runner import TrivyRunner

class TestGitleaksRunner(unittest.TestCase):
    def setUp(self):
        """Setup Gitleaks runner."""
        self.runner = GitleaksRunner()
    
    def test_gitleaks_initialization(self):
        """Test Gitleaks runner initializes."""
        self.assertIsNotNone(self.runner.workspace)
        print(f"✓ Gitleaks workspace: {self.runner.workspace}")
        print(f"✓ Gitleaks available: {self.runner.available}")
    
    @unittest.skipIf(not os.path.exists(".git"), "Requires git repository")
    def test_scan_repo(self):
        """Integration test: Scan current repo for secrets."""
        if not self.runner.available:
            self.skipTest("Gitleaks not installed")
        
        findings = self.runner.scan_repo(".")
        # May or may not have findings
        self.assertIsInstance(findings, list)
        print(f"✓ Gitleaks scan complete: {len(findings)} findings")

class TestTrivyRunner(unittest.TestCase):
    def setUp(self):
        """Setup Trivy runner."""
        self.runner = TrivyRunner()
    
    def test_trivy_initialization(self):
        """Test Trivy runner initializes."""
        self.assertIsNotNone(self.runner.workspace)
        print(f"✓ Trivy workspace: {self.runner.workspace}")
        print(f"✓ Trivy available: {self.runner.available}")
    
    @unittest.skip("Requires Trivy installation and project dependencies")
    def test_scan_filesystem(self):
        """Integration test: Scan filesystem for vulnerabilities."""
        if not self.runner.available:
            self.skipTest("Trivy not installed")
        
        findings = self.runner.scan_filesystem(".")
        self.assertIsInstance(findings, list)
        print(f"✓ Trivy scan complete: {len(findings)} vulnerabilities")
    
    @unittest.skip("Requires Trivy installation")
    def test_generate_sbom(self):
        """Integration test: Generate SBOM."""
        if not self.runner.available:
            self.skipTest("Trivy not installed")
        
        sbom_file = self.runner.generate_sbom(".")
        if sbom_file:
            self.assertTrue(os.path.exists(sbom_file))
            print(f"✓ SBOM generated: {sbom_file}")

if __name__ == '__main__':
    unittest.main()
