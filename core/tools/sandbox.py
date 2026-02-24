import logging
import subprocess
import tempfile
import os
import shutil
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

class ExecutionResult:
    def __init__(self, exit_code: int, stdout: str, stderr: str, duration_ms: float = 0.0):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.duration_ms = duration_ms

class DockerSandbox:
    """
    Executes code in an isolated Docker container.
    """
    def __init__(self, image: str = "python:3.10-slim"):
        self.image = image
        self._check_docker()

    def _check_docker(self):
        try:
            subprocess.run(["docker", "--version"], check=True, capture_output=True)
            self.available = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.warning("Docker execution is NOT available. Sandbox will fail or fallback.")
            self.available = False

    def run(self, command: str, files: Dict[str, str], timeout_sec: int = 10, env_vars: Dict[str, str] = None, instrumentation: bool = False) -> ExecutionResult:
        """
        Runs the command in a container with the provided files.
        files: Dict mapping 'filename' -> 'content'
        instrumentation: If True, enables ASan/MSan/Debug allocators.
        """
        if not self.available:
            return ExecutionResult(-1, "", "Docker not available", 0.0)

        import time
        start_time = time.time()
        
        # Prepare Environment Variables
        run_env = env_vars.copy() if env_vars else {}
        
        if instrumentation:
            # Python Memory Debugging
            run_env["PYTHONMALLOC"] = "debug"
            run_env["PYTHONDEVMODE"] = "1"
            
            # AddressSanitizer (ASan) & MemorySanitizer (MSan) configuration
            # These only work if the underlying binary/libraries are compiled with sanitizers,
            # but setting them ensures that IF they are present, they abort on error and print trace.
            run_env["ASAN_OPTIONS"] = "abort_on_error=1:detect_leaks=1:symbolize=1:halt_on_error=1"
            run_env["MSAN_OPTIONS"] = "abort_on_error=1:halt_on_error=1"
            run_env["UBSAN_OPTIONS"] = "print_stacktrace=1:halt_on_error=1"
        
        # Create temp host directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Write files
            for fname, content in files.items():
                fpath = os.path.join(temp_dir, fname)
                with open(fpath, "w") as f:
                    f.write(content)
            
            # Construct Docker command
            # Mount temp_dir to /app
            # Workdir /app
            cmd = [
                "docker", "run", "--rm",
                "--network", "none", # Isolation
                "--cpus", "1.0",
                "--memory", "512m",
                "-v", f"{temp_dir}:/app",
                "-w", "/app"
            ]
            
            # Inject Environment Variables
            for k, v in run_env.items():
                cmd.extend(["-e", f"{k}={v}"])
                
            cmd.append(self.image)
            
            # Add command parts
            # If command is "python repro.py", split it
            # But careful with shell=False. 
            # We can use 'sh -c' for complex commands or just append args
            cmd.extend(command.split())
            
            logger.info(f"Sandbox Executing: {command} in {temp_dir}")
            
            try:
                res = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout_sec
                )
                duration = (time.time() - start_time) * 1000
                return ExecutionResult(res.returncode, res.stdout, res.stderr, duration)
                
            except subprocess.TimeoutExpired:
                logger.warning("Sandbox Execution Timed Out")
                return ExecutionResult(124, "", "Timeout", timeout_sec * 1000)
            except Exception as e:
                logger.error(f"Sandbox Error: {e}")
                return ExecutionResult(-1, "", str(e), 0.0)
