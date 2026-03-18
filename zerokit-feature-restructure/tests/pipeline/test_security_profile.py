import unittest
import os
import sys
import yaml
from unittest.mock import MagicMock

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.agent")))

from pipeline.adapters.php_adapter import PhpAdapter
from pipeline.agents.detector import Detector
from pipeline.models import SecurityProfile, Hypothesis

class TestSecurityProfile(unittest.TestCase):
    def test_php_adapter_profile(self):
        """Verify PhpAdapter returns correct WordPress profile."""
        adapter = PhpAdapter()
        profile = adapter.get_security_profile()
        
        self.assertEqual(profile.framework_specific, "wordpress-core")
        self.assertIn("intval", profile.sanitizers["sqli"])
        self.assertIn("wp_verify_nonce", profile.sanitizers["sqli"])
        self.assertIn("$wpdb->query", profile.sinks["sqli"])

    def test_detector_rule_generation(self):
        """Verify Detector generates rules with sanitizer exclusions."""
        detector = Detector()
        
        # Mock Profile
        profile = SecurityProfile(
            framework_specific="wordpress-core",
            sanitizers={"sqli": ["intval", "absint"]},
            sinks={"sqli": ["wp_db_query"]}
        )
        
        # Generate Config
        config_path = detector._generate_semgrep_config([], security_profile=profile)
        
        # Verify generated YAML
        assert config_path.endswith(".yaml")
        with open(config_path, 'r') as f:
            data = yaml.safe_load(f)
            
        rules = data["rules"]
        sqli_rule = next(r for r in rules if r["id"] == "dynamic-sqli-check")
        
        # Check patterns
        patterns = sqli_rule["patterns"]
        
        # Verify sink exists
        pattern_either = next(p for p in patterns if "pattern-either" in p)["pattern-either"]
        self.assertTrue(any("wp_db_query" in p["pattern"] for p in pattern_either))
        
        # Verify sanitizer exclusion (pattern-not-inside)
        pattern_not_inside = next(p for p in patterns if "pattern-not-inside" in p)["pattern-not-inside"]
        self.assertTrue(any("intval" in p["pattern"] for p in pattern_not_inside))
        
        # Cleanup
        os.remove(config_path)

if __name__ == "__main__":
    unittest.main()
