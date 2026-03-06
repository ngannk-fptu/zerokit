"""
AFL++ Runner: Wrapper for AFL++ fuzzing (C/C++)

AFL++ is a coverage-guided fuzzer for native code.
NOTE: Requires WSL/Linux on Windows, or native Linux/macOS.

This runner handles:
1. Compiling targets with AFL++ instrumentation
2. Running afl-fuzz with corpus
3. Parsing crash reports
"""

import subprocess
import os
import logging
from typing import Dict, Optional, List
from pathlib import Path

logger = logging.getLogger(__name__)

class AFLRunner:
    def __init__(self, afl_path: str = None, workspace: str = None):
        """
        Initialize AFL++ runner.
        
        Args:
            afl_path: Path to afl-fuzz binary (defaults to 'afl-fuzz' in PATH)
            workspace: Path to store harnesses and findings
        """
        from ..config import config
        
        self.afl_fuzz = afl_path or config.AFL_FUZZ_PATH
        self.workspace = workspace or config.AFL_WORKSPACE
        
        os.makedirs(self.workspace, exist_ok=True)
        
        # Check if AFL++ is available
        self.available = self._check_afl_available()
        
        if self.available:
            logger.info(f"AFLRunner initialized: {self.afl_fuzz}")
        else:
            logger.warning("AFL++ not found - install via WSL or native Linux")
    
    def _check_afl_available(self) -> bool:
        """Check if afl-fuzz is in PATH or configured."""
        try:
            result = subprocess.run(
                [self.afl_fuzz, "--help"],
                capture_output=True,
                timeout=5
            )
            return result.returncode in [0, 1]  # AFL returns 1 for --help
        except:
            return False
    
    def compile_target(self,
                      source_file: str,
                      output_binary: str,
                      compiler: str = "afl-clang-fast",
                      extra_flags: List[str] = None) -> str:
        """
        Compile target with AFL++ instrumentation.
        
        Args:
            source_file: Path to .c/.cpp file
            output_binary: Output binary path
            compiler: AFL compiler (afl-gcc, afl-clang-fast, etc.)
            extra_flags: Additional compiler flags
        
        Returns:
            Path to instrumented binary
        """
        extra_flags = extra_flags or []
        
        cmd = [
            compiler,
            source_file,
            "-o", output_binary
        ] + extra_flags
        
        logger.info(f"Compiling with AFL++: {source_file}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                raise RuntimeError(f"AFL compilation failed: {result.stderr}")
            
            logger.info(f"Instrumented binary: {output_binary}")
            return output_binary
        
        except Exception as e:
            logger.error(f"Compilation error: {e}")
            raise
    
    def run_fuzzing(self,
                   target_binary: str,
                   input_dir: str,
                   output_dir: str = None,
                   duration_sec: int = 300,
                   memory_limit: str = "200M") -> Dict:
        """
        Run AFL++ fuzzing.
        
        Args:
            target_binary: Path to instrumented binary
            input_dir: Seed corpus directory
            output_dir: Output directory for findings
            duration_sec: Fuzzing duration
            memory_limit: Memory limit (e.g., "200M")
        
        Returns:
            Dictionary with findings
        """
        if not self.available:
            raise RuntimeError("AFL++ not available on this system")
        
        output_dir = output_dir or os.path.join(self.workspace, "output")
        os.makedirs(input_dir, exist_ok=True)
        
        # Create minimal seed if empty
        if not os.listdir(input_dir):
            seed_file = os.path.join(input_dir, "seed")
            with open(seed_file, "wb") as f:
                f.write(b"FUZZ")
        
        # afl-fuzz -i input -o output -m 200 -- ./target
        cmd = [
            self.afl_fuzz,
            "-i", input_dir,
            "-o", output_dir,
            "-m", memory_limit,
            "-V", str(duration_sec),  # Timeout in seconds
            "--",
            target_binary
        ]
        
        logger.info(f"Starting AFL++ fuzzing for {duration_sec}s...")
        
        findings = {
            "crashes": [],
            "hangs": [],
            "status": "running"
        }
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=duration_sec + 30
            )
            
            findings["status"] = "completed"
            
            # Parse crashes from output/default/crashes/
            crashes_dir = os.path.join(output_dir, "default", "crashes")
            if os.path.exists(crashes_dir):
                crash_files = [f for f in os.listdir(crashes_dir) if f.startswith("id:")]
                
                for crash_file in crash_files:
                    crash_path = os.path.join(crashes_dir, crash_file)
                    findings["crashes"].append({
                        "file": crash_file,
                        "path": crash_path
                    })
            
            logger.info(f"AFL++ complete: {len(findings['crashes'])} crashes")
        
        except subprocess.TimeoutExpired:
            findings["status"] = "timeout"
            logger.info("AFL++ timeout")
        except Exception as e:
            findings["status"] = "error"
            findings["error"] = str(e)
            logger.error(f"AFL++ error: {e}")
        
        return findings
