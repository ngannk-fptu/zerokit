import logging
import os
import sys
from unittest.mock import MagicMock
from dotenv import load_dotenv

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from core.prompter import Prompter
from core.llm_gateway import LLMGateway

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def test_prompter():
    logger.info("Testing Prompter...")
    # Note: Using core.prompter.Prompter (was PromptLoader)
    loader = Prompter()
    
    # Test loading detector rule generation prompt
    template = loader.load("detector", "generate_rule")
    logger.info(f"✅ Loaded template: {template.method} (v{template.version})")
    
    # Test rendering
    prompt = loader.render(
        template, 
        hypothesis_id="hyp_0",
        description="SQL Injection", 
        cwe_id="89",
        language="python",
        source="request.args.get()",
        sink="execute()",
        trust_boundary="HTTP->DB",
        target="db.query", 
        context=None
    )
    if "SQL Injection" in prompt and "db.query" in prompt:
         logger.info("✅ Template rendering success")
    else:
         logger.error("❌ Template rendering failed")
         
    # Test Config
    config = loader.get_config(template, "antigravity")
    logger.info(f"✅ Config loaded: {config}")

def test_llm_gateway_integration():
    logger.info("\nTesting LLMGateway Integration (Mocked)...")
    
    # Mock the adapter inside gateway
    gateway = LLMGateway()
    gateway.adapter = MagicMock()
    gateway.adapter.call.return_value = "rules:\n  - id: mock-antigravity-rule\n    message: 'Antigravity Verified'"
    
    try:
        # Test 1: Generate Rule
        logger.info("1. Testing generate_semgrep_rule...")
        rule = gateway.generate_semgrep_rule(
            hypothesis_id="hyp_1",
            description="XSS", 
            cwe_id="79",
            language="python",
            source="input()",
            sink="print()",
            trust_boundary="HTTP->HTML"
        )
        logger.info("   -> Call completed (Mocked Antigravity)")
        if "rules:" in rule:
             logger.info("   ✅ Valid Rule returned")
        
        # Test 2: Generate PoC
        logger.info("2. Testing generate_poc...")
        gateway.adapter.call.return_value = "import requests\nprint('VULNERABLE')"
        poc = gateway.generate_poc(
            hypothesis_id="hyp_2",
            finding_description="SQLi in login", 
            cwe_id="89",
            location="login.php:12",
            language="php",
            trust_boundary="HTTP->DB",
            sink="mysqli_query"
        )
        logger.info("   -> Call completed")
        
    except Exception as e:
        logger.error(f"❌ Integration test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_prompter()
    test_llm_gateway_integration()
