import asyncio
import sys
import os
import logging
from unittest.mock import MagicMock, AsyncMock

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../.agent")))

from pipeline.agents.detector import Detector
from pipeline.models import SecurityProfile
from pipeline.models import Hypothesis

# Monkeypatch MagicMock to support formatting
def safe_format(self, format_spec):
    return str(self)
MagicMock.__format__ = safe_format

# Setup Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Simple Mock Class to avoid MagicMock format issues
class MockRunner:
    def __init__(self, name):
        self.name = name
        
    async def create_database_async(self, *args, **kwargs):
        return MagicMock(success=True, findings=[])

    async def analyze_async(self, *args, **kwargs):
        return MagicMock(success=True, findings=[])

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name
        
    def __format__(self, format_spec):
        return self.name

async def verify_wp_advanced():
    repo_path = os.path.abspath("tests/fixtures")
    file_path = os.path.join(repo_path, "wp_advanced.php")
    
    # 1. Setup Detector with Real Semgrep
    detector = Detector()
    
    # Use Simple Mock
    detector.codeql_runner = MockRunner("MockCodeQLRunner")
    detector.joern_runner = MockRunner("MockJoernRunner")
    
    # 2. Define Security Profile (WordPress)
    security_profile = SecurityProfile(
        framework_specific="wordpress-core",
        sources=["$_GET", "$_POST"],
        sanitizers={
            "sqli": ["intval", "absint", "wp_verify_nonce", "esc_sql"], # 'prepare' REMOVED
            "xss": ["sanitize_text_field", "esc_html", "esc_attr", "wp_kses", "wp_kses_post"],
            "rce": ["escapeshellarg"],
            "lfi": ["basename"]
        },
        sinks={
            "sqli": ["$wpdb->query", "$wpdb->get_results", "$wpdb->get_var", "$wpdb->get_row"],
            "xss": ["echo", "print", "printf"],
            "rce": ["eval", "system", "exec", "shell_exec", "passthru"], # 'system' used in fixture
            "lfi": ["include", "require"]
        }
    )
    
    # 3. Create Hypotheses (Generic + Specific)
    hypotheses = [
        Hypothesis(id="h1", description="Check for SQLi", target_code="generic", verification_plan="manual", metadata={"type": "sqli"}),
        Hypothesis(id="h2", description="Check for XSS", target_code="generic", verification_plan="manual", metadata={"type": "xss"}),
        Hypothesis(id="h3", description="Check for RCE", target_code="generic", verification_plan="manual", metadata={"type": "rce"}),
    ]

    logger.info(f"Scanning {file_path} with Advanced Rules...")
    
    detector.state_manager.should_scan_file = MagicMock(return_value=True)
    
    # EXECUTE SCAN
    findings = await detector.scan(hypotheses, repo_path, security_profile)
    
    # ANALYZE FINDINGS
    print(f"\nTotal Findings: {len(findings)}")
    
    found_unsafe_prepare = False
    found_xss_taint = False
    found_rce = False
    
    for f in findings:
        if "wp_advanced.php" not in f.location: continue
        
        print(f"[{f.severity.name}] {f.description} (Line: {f.location})")
        
        # Check for Unsafe Prepare
        if "wordpress-unsafe-prepare" in f.description:
             found_unsafe_prepare = True
        elif "dynamic-sqli-check" in f.description and "prepare" in f.evidence:
             # Fallback if unsafe rule didn't trigger but it was caught as SQLi
             found_unsafe_prepare = True

        # Check for XSS (apply_filters)
        if "dynamic-xss-check" in f.description:
            found_xss_taint = True

        # Check for RCE
        if "dynamic-rce-check" in f.description and "system" in f.evidence:
            found_rce = True

    print("\n--- Verification Results ---")
    print(f"Unsafe Prepare Detection: {'✅ PASS' if found_unsafe_prepare else '❌ FAIL'}")
    print(f"Apply Filters Taint:      {'✅ PASS' if found_xss_taint else '❌ FAIL (May require taint-mode engine)'}")
    print(f"RCE Detection:            {'✅ PASS' if found_rce else '❌ FAIL'}")

if __name__ == "__main__":
    asyncio.run(verify_wp_advanced())
