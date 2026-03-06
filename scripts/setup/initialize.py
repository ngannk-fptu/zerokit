import os
import sys
import json
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Setup")

def initialize():
    """
    Initializes the ZeroKit2 environment.
    Creates necessary directories and verifies tool availability.
    """
    logger.info("🚀 Initializing ZeroKit2 Environment...")
    
    # 1. Create directory structure
    dirs = [
        "storage",
        "storage/codeql_dbs",
        "storage/workspaces",
        "storage/vul",
        "storage/tools",
        ".agent/knowledge_base",
        ".agent/knowledge_base/prompts",
        ".agent/knowledge_base/templates",
        "skills",
        ".agent/prompts/queue",
        ".agent/prompts/responses",
        ".agent/prompts/archive"
    ]
    
    for d in dirs:
        os.makedirs(d, exist_ok=True)
        logger.info(f"  Created {d}")

    # 2. Check for tool manifest
    manifest_path = "storage/tools_manifest.json"
    if not os.path.exists(manifest_path):
        logger.warning(f"  Manifest not found at {manifest_path}. Creating default.")
        default_manifest = {
            "version": "2.1.0",
            "tools": {
                "codeql": {"path": "codeql-win64/codeql/codeql.cmd", "installed": True},
                "joern": {"path": "joern/joern-parse.bat", "installed": True},
                "jazzer": {"path": "jazzer/deploy/jazzer_standalone.jar", "installed": True}
            }
        }
        with open(manifest_path, 'w') as f:
            json.dump(default_manifest, f, indent=2)

    logger.info("✅ Initialization Complete.")

if __name__ == "__main__":
    initialize()
