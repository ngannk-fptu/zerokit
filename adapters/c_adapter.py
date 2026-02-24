"""
CAdapter: Language adapter for C/C++ projects

Detects CMake and Makefile build systems.
Handles compilation with sanitizers (ASan, UBSan, MSan).
"""

import subprocess
import os
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class CAdapter:
    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.build_system = self._detect_build_system()
        self.build_dir = os.path.join(repo_path, "build")
        logger.info(f"CAdapter initialized: {self.build_system}")
    
    def _detect_build_system(self) -> Optional[str]:
        """Detect CMake or Makefile."""
        if os.path.exists(os.path.join(self.repo_path, "CMakeLists.txt")):
            return "cmake"
        elif os.path.exists(os.path.join(self.repo_path, "Makefile")):
            return "make"
        else:
            # Check for any C/C++ source files
            for root, dirs, files in os.walk(self.repo_path):
                if any(f.endswith(('.c', '.cpp', '.cc', '.cxx')) for f in files):
                    return "manual"  # Has C/C++ files but no build system
            return None
    
    def health_check(self, enable_sanitizers: bool = False) -> Dict:
        """
        Run build and tests.
        
        Args:
            enable_sanitizers: If True, compile with ASan/UBSan
        """
        if not self.build_system:
            return {
                "build_success": False,
                "test_success": False,
                "error": "No build system detected (CMakeLists.txt or Makefile)"
            }
        
        logger.info(f"Running health check ({self.build_system}, sanitizers={'ON' if enable_sanitizers else 'OFF'})...")
        
        try:
            # Configure (for CMake)
            if self.build_system == "cmake":
                configure_result = self._configure_cmake(enable_sanitizers)
                if not configure_result["success"]:
                    return {
                        "build_success": False,
                        "test_success": False,
                        "error": configure_result["output"][:500]
                    }
            
            # Build
            build_result = self._run_build()
            
            # Test (if available)
            test_result = {"success": False, "output": ""}
            if build_result["success"]:
                test_result = self._run_tests()
            
            return {
                "build_success": build_result["success"],
                "test_success": test_result["success"],
                "build_output": build_result["output"][:500],
                "test_output": test_result["output"][:500],
                "sanitizers_enabled": enable_sanitizers
            }
        
        except Exception as e:
            logger.error(f"Health check error: {e}")
            return {
                "build_success": False,
                "test_success": False,
                "error": str(e)
            }
    
    def _configure_cmake(self, enable_sanitizers: bool) -> Dict:
        """Configure CMake project."""
        os.makedirs(self.build_dir, exist_ok=True)
        
        # CMake flags for sanitizers
        sanitizer_flags = []
        if enable_sanitizers:
            sanitizer_flags = [
                "-DCMAKE_C_FLAGS=-fsanitize=address,undefined",
                "-DCMAKE_CXX_FLAGS=-fsanitize=address,undefined"
            ]
        
        cmd = ["cmake", ".."] + sanitizer_flags
        
        logger.info("Configuring CMake...")
        
        try:
            result = subprocess.run(
                cmd,
                cwd=self.build_dir,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            success = result.returncode == 0
            logger.info(f"CMake configure {'succeeded' if success else 'failed'}")
            
            return {
                "success": success,
                "output": result.stdout + result.stderr
            }
        
        except Exception as e:
            logger.error(f"CMake configure error: {e}")
            return {"success": False, "output": str(e)}
    
    def _run_build(self) -> Dict:
        """Run build."""
        if self.build_system == "cmake":
            cmd = ["cmake", "--build", "."]
            cwd = self.build_dir
        elif self.build_system == "make":
            cmd = ["make"]
            cwd = self.repo_path
        else:
            return {"success": False, "output": "No automated build"}
        
        logger.info(f"Building with {self.build_system}...")
        
        try:
            result = subprocess.run(
                cmd,
                cwd=cwd,
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
        """Run tests."""
        if self.build_system == "cmake":
            # Try CTest
            cmd = ["ctest", "--output-on-failure"]
            cwd = self.build_dir
        elif self.build_system == "make":
            # Try make test
            cmd = ["make", "test"]
            cwd = self.repo_path
        else:
            return {"success": False, "output": "No test framework"}
        
        logger.info("Running tests...")
        
        try:
            result = subprocess.run(
                cmd,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            # CTest returns 0 for success
            success = result.returncode == 0
            logger.info(f"Tests {'passed' if success else 'failed or not found'}")
            
            return {
                "success": success,
                "output": result.stdout + result.stderr
            }
        
        except Exception as e:
            logger.warning(f"Test execution: {e}")
            return {"success": False, "output": str(e)}
    
    def identify_entry_points(self) -> List[str]:
        """Identify main() functions and entry points."""
        entry_points = []
        
        for root, dirs, files in os.walk(self.repo_path):
            # Skip build directories
            dirs[:] = [d for d in dirs if d not in ['build', '.git', 'node_modules', 'vendor']]
            
            for file in files:
                if file.endswith(('.c', '.cpp', '.cc', '.cxx')):
                    file_path = os.path.join(root, file)
                    
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            
                            # Look for main() function
                            if "int main(" in content or "void main(" in content:
                                entry_points.append(file_path)
                            
                            # Look for common entry point patterns
                            elif any(pattern in content for pattern in [
                                "WinMain",      # Windows GUI
                                "DllMain",      # Windows DLL
                                "__attribute__((constructor))"  # Linux init
                            ]):
                                entry_points.append(file_path)
                    
                    except Exception:
                        pass
        
        logger.info(f"Found {len(entry_points)} entry points")
        return entry_points[:50]
    
    def get_dependencies(self) -> List[str]:
        """
        Extract dependencies (rough heuristic).
        For C/C++, this is tricky without proper parsing.
        """
        dependencies = []
        
        # For CMake, parse CMakeLists.txt
        if self.build_system == "cmake":
            cmake_file = os.path.join(self.repo_path, "CMakeLists.txt")
            if os.path.exists(cmake_file):
                try:
                    with open(cmake_file, "r", encoding="utf-8") as f:
                        for line in f:
                            # Look for find_package, target_link_libraries
                            if "find_package(" in line or "target_link_libraries(" in line:
                                dependencies.append(line.strip())
                except Exception as e:
                    logger.error(f"Failed to parse CMakeLists.txt: {e}")
        
        # For Makefile, look for linked libraries
        elif self.build_system == "make":
            makefile = os.path.join(self.repo_path, "Makefile")
            if os.path.exists(makefile):
                try:
                    with open(makefile, "r", encoding="utf-8") as f:
                        for line in f:
                            if "-l" in line:  # Library linking flags
                                dependencies.append(line.strip())
                except Exception as e:
                    logger.error(f"Failed to parse Makefile: {e}")
        
        logger.info(f"Found {len(dependencies)} dependency references")
        return dependencies[:100]
    
    def compile_with_sanitizers(self, 
                                sanitizers: List[str] = None,
                                extra_flags: List[str] = None) -> Dict:
        """
        Compile with specific sanitizers.
        
        Args:
            sanitizers: List of sanitizers (address, undefined, memory, thread)
            extra_flags: Additional compiler flags
        
        Returns:
            Compilation result
        """
        sanitizers = sanitizers or ["address", "undefined"]
        extra_flags = extra_flags or []
        
        sanitizer_str = ",".join(sanitizers)
        
        if self.build_system == "cmake":
            # Reconfigure with sanitizers
            result = self._configure_cmake(enable_sanitizers=True)
            if not result["success"]:
                return result
            
            return self._run_build()
        
        else:
            # For make, would need to modify CFLAGS
            logger.warning("Manual sanitizer flags not implemented for Makefile")
            return {"success": False, "output": "Use CMake for sanitizer support"}
