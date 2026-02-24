import logging
import os
import sys
from dotenv import load_dotenv

# Add project root to path
sys.path.insert(0, os.path.join(os.getcwd(), ".agent"))

from pipeline.services.prompt_loader import PromptLoader
from pipeline.services.llm_gateway import LLMGateway

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def test_prompt_loader():
    logger.info("Testing PromptLoader...")
    loader = PromptLoader()
    
    # Test loading detector rule generation prompt
    template = loader.load("detector", "generate_rule")
    logger.info(f"✅ Loaded template: {template.method} (v{template.version})")
    
    # Test rendering
    prompt = loader.render(template, description="SQL Injection", target="db.query", context=None)
    if "SQL Injection" in prompt and "db.query" in prompt:
         logger.info("✅ Template rendering success")
    else:
         logger.error("❌ Template rendering failed")
         
    # Test Config
    config = loader.get_config(template, "gemini")
    logger.info(f"✅ Config loaded: {config}")

def test_llm_gateway_integration():
    logger.info("\nTesting LLMGateway Integration...")
    
    # Set fallback to mock for safety if no API key
    os.environ["LLM_FALLBACK_MODE"] = "mock"
    
    gateway = LLMGateway()
    
    try:
        # Test 1: Generate Rule
        logger.info("1. Testing generate_semgrep_rule...")
        rule = gateway.generate_semgrep_rule("XSS", "", "echo $v")
        logger.info("   -> Call completed (Adapter/Mock)")
        if "rules:" in rule:
             logger.info("   ✅ Valid Generic Rule returned")
        
        # Test 2: Generate PoC
        logger.info("2. Testing generate_poc...")
        poc = gateway.generate_poc("SQLi", "login.php", "php")
        logger.info("   -> Call completed")
        
    except Exception as e:
        logger.error(f"❌ Integration test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_prompt_loader()
    test_llm_gateway_integration()
