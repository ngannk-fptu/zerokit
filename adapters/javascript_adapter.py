"""
JavaScriptAdapter: Language adapter for JavaScript/TypeScript projects

Detects npm, yarn, and package.json.
Handles test execution with Jest, Mocha, etc.
"""

import subprocess
import os
import json
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class JavaScriptAdapter:
    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.package_manager = self._detect_package_manager()
        self.package_json = self._load_package_json()
        logger.info(f"JavaScriptAdapter initialized: {self.package_manager}")
    
    def _detect_package_manager(self) -> Optional[str]:
        """Detect npm or yarn."""
        if os.path.exists(os.path.join(self.repo_path, "yarn.lock")):
            return "yarn"
        elif os.path.exists(os.path.join(self.repo_path, "package.json")):
            return "npm"
        else:
            return None
    
    def _load_package_json(self) -> Dict:
        """Load package.json."""
        pkg_path = os.path.join(self.repo_path, "package.json")
        if os.path.exists(pkg_path):
            try:
                with open(pkg_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load package.json: {e}")
        return {}
    
    def health_check(self) -> Dict:
        """Run build and tests."""
        if not self.package_manager:
            return {
                "build_success": False,
                "test_success": False,
                "error": "No package.json found"
            }
        
        logger.info(f"Running health check ({self.package_manager})...")
        
        try:
            # Install dependencies
            install_result = self._install_dependencies()
            
            # Build (if script exists)
            build_result = {"success": True, "output": ""}
            if "build" in self.package_json.get("scripts", {}):
                build_result = self._run_build()
            
            # Test
            test_result = {"success": False, "output": ""}
            if "test" in self.package_json.get("scripts", {}):
                test_result = self._run_tests()
            
            return {
                "build_success": build_result["success"],
                "test_success": test_result["success"],
                "install_output": install_result["output"][:500],
                "test_output": test_result["output"][:500]
            }
        
        except Exception as e:
            logger.error(f"Health check error: {e}")
            return {
                "build_success": False,
                "test_success": False,
                "error": str(e)
            }
    
    def _install_dependencies(self) -> Dict:
        """Install npm/yarn dependencies."""
        cmd = ["yarn", "install"] if self.package_manager == "yarn" else ["npm", "install"]
        
        logger.info(f"Installing dependencies with {self.package_manager}...")
        
        try:
            result = subprocess.run(
                cmd,
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            success = result.returncode == 0
            logger.info(f"Install {'succeeded' if success else 'failed'}")
            
            return {
                "success": success,
                "output": result.stdout + result.stderr
            }
        
        except Exception as e:
            logger.error(f"Install error: {e}")
            return {"success": False, "output": str(e)}
    
    def _run_build(self) -> Dict:
        """Run build script."""
        cmd = ["yarn", "build"] if self.package_manager == "yarn" else ["npm", "run", "build"]
        
        logger.info("Building project...")
        
        try:
            result = subprocess.run(
                cmd,
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            success = result.returncode == 0
            logger.info(f"Build {'succeeded' if success else 'failed'}")
            
            return {
                "success": success,
                "output": result.stdout + result.stderr
            }
        
        except Exception as e:
            logger.error(f"Build error: {e}")
            return {"success": False, "output": str(e)}
    
    def _run_tests(self) -> Dict:
        """Run test script."""
        cmd = ["yarn", "test"] if self.package_manager == "yarn" else ["npm", "test"]
        
        logger.info("Running tests...")
        
        try:
            result = subprocess.run(
                cmd,
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            success = result.returncode == 0
            logger.info(f"Tests {'passed' if success else 'failed'}")
            
            return {
                "success": success,
                "output": result.stdout + result.stderr
            }
        
        except Exception as e:
            logger.error(f"Test error: {e}")
            return {"success": False, "output": str(e)}
    
    def identify_entry_points(self) -> List[str]:
        """Identify API routes and entry points."""
        entry_points = []
        
        # Common patterns for Express, Koa, Fastify, etc.
        patterns = [
            "**/routes/**/*.js",
            "**/routes/**/*.ts",
            "**/controllers/**/*.js",
            "**/api/**/*.js",
            "**/server.js",
            "**/app.js",
            "**/index.js"
        ]
        
        for root, dirs, files in os.walk(self.repo_path):
            # Skip node_modules
            dirs[:] = [d for d in dirs if d not in ['node_modules', 'dist', 'build', '.next']]
            
            for file in files:
                if file.endswith(('.js', '.ts')):
                    # Check if in routes/controllers/api directories
                    if any(keyword in root for keyword in ['routes', 'controllers', 'api']):
                        entry_points.append(os.path.join(root, file))
                    elif file in ['server.js', 'app.js', 'index.js']:
                        entry_points.append(os.path.join(root, file))
        
        logger.info(f"Found {len(entry_points)} entry points")
        return entry_points[:50]
    
    def get_dependencies(self) -> List[str]:
        """Extract dependency list from package.json."""
        dependencies = []
        
        all_deps = {}
        all_deps.update(self.package_json.get("dependencies", {}))
        all_deps.update(self.package_json.get("devDependencies", {}))
        
        for name, version in all_deps.items():
            dependencies.append(f"{name}@{version}")
        
        logger.info(f"Found {len(dependencies)} dependencies")
        return dependencies
