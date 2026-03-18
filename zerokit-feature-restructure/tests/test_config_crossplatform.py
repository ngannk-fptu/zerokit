"""Tests for cross-platform config."""
import unittest
import sys
import os
import platform

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.config import PipelineConfig


class TestConfigPaths(unittest.TestCase):
    """Verify config generates valid paths for current OS."""

    def setUp(self):
        self.config = PipelineConfig()

    def test_joern_home_is_absolute(self):
        self.assertTrue(os.path.isabs(self.config.JOERN_HOME))

    def test_no_backslash_on_unix(self):
        """On macOS/Linux, paths must not contain backslashes."""
        if platform.system() != "Windows":
            self.assertNotIn("\\", self.config.JOERN_HOME)
            self.assertNotIn("\\", self.config.JOERN_PARSE)
            self.assertNotIn("\\", self.config.JOERN_SCAN)

    def test_joern_parse_correct_extension(self):
        if platform.system() == "Windows":
            self.assertTrue(self.config.JOERN_PARSE.endswith(".bat"))
        else:
            self.assertFalse(self.config.JOERN_PARSE.endswith(".bat"))
            self.assertFalse(self.config.JOERN_PARSE.endswith(".cmd"))

    def test_joern_scan_correct_extension(self):
        if platform.system() == "Windows":
            self.assertTrue(self.config.JOERN_SCAN.endswith(".bat"))
        else:
            self.assertFalse(self.config.JOERN_SCAN.endswith(".bat"))

    def test_no_codeql_attributes(self):
        """CodeQL config removed — should not exist."""
        self.assertFalse(hasattr(self.config, "CODEQL_BIN"))
        self.assertFalse(hasattr(self.config, "CODEQL_DB_PATH"))

    def test_no_fuzzer_attributes(self):
        """Fuzzer configs removed (YAGNI)."""
        self.assertFalse(hasattr(self.config, "JAZZER_HOME"))
        self.assertFalse(hasattr(self.config, "AFL_FUZZ_PATH"))
        self.assertFalse(hasattr(self.config, "ATHERIS_WORKSPACE"))

    def test_env_var_override(self):
        """JOERN_HOME env var should override default."""
        os.environ["JOERN_HOME"] = "/custom/joern"
        try:
            cfg = PipelineConfig()
            self.assertEqual(cfg.JOERN_HOME, "/custom/joern")
        finally:
            del os.environ["JOERN_HOME"]

    def test_defaults_exist(self):
        self.assertIsNotNone(self.config.SEMGREP_RULES_PATH)
        self.assertIsNotNone(self.config.GITLEAKS_PATH)
        self.assertIsNotNone(self.config.TRIVY_PATH)
        self.assertEqual(self.config.VERIFY_TIMEOUT, 30)


if __name__ == "__main__":
    unittest.main()
