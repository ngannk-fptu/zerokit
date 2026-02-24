"""
Sandbox Executor - Docker-based PoC verification engine
Executes PoC scripts in isolated containers to verify vulnerabilities
"""
import asyncio
import subprocess
import tempfile
import os
import time
import logging
from typing import Tuple, Dict
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ExecutionResult:
    """Result from sandbox PoC execution."""
    exit_code: int
    stdout: str
    stderr: str
    execution_time: float
    container_id: str = ""
    timed_out: bool = False


class SandboxExecutor:
    """
    Executes PoC scripts in Docker containers for secure verification.
    
    Security layers:
    - No network access (--network none)
    - Resource limits (memory, CPU)
    - Timeout enforcement  
    - Read-only filesystem mounts
    """
    
    def __init__(self, default_timeout: int = 30):
        """
        Initialize sandbox executor.
        
        Args:
            default_timeout: Default execution timeout in seconds
        """
        self.default_timeout = default_timeout
        logger.info("SandboxExecutor initialized with timeout=%ds", default_timeout)
    
    async def execute_php(self, script: str, timeout: int = None) -> ExecutionResult:
        """
        Execute PHP script in Docker container.
        
        Args:
            script: PHP code to execute
            timeout: Override default timeout
            
        Returns:
            ExecutionResult with outputs and status
        """
        timeout = timeout or self.default_timeout
        image = "php:7.4-cli"
        
        logger.info("Executing PHP script in Docker container (timeout=%ds)", timeout)
        
        # Create temp file for script
        with tempfile.NamedTemporaryFile(mode='w', suffix='.php', delete=False) as f:
            f.write(script)
            temp_path = f.name
        
        try:
            # Docker run command with security restrictions
            cmd = [
                "docker", "run",
                "--rm",                    # Auto-remove container
                "--network", "none",       # No network access
                "--memory", "256m",        # Memory limit
                "--cpus", "0.5",           # CPU limit
                "-v", f"{temp_path}:/poc.php:ro",  # Read-only mount
                image,
                "php", "/poc.php"
            ]
            
            result = await self._run_docker(cmd, timeout)
            
        finally:
            # Cleanup temp file
            try:
                os.unlink(temp_path)
            except Exception as e:
                logger.warning(f"Failed to cleanup temp file {temp_path}: {e}")
        
        return result
    
    async def execute_python(self, script: str, timeout: int = None) -> ExecutionResult:
        """Execute Python script in Docker container."""
        timeout = timeout or self.default_timeout
        image = "python:3.9-slim"
        
        logger.info("Executing Python script in Docker container (timeout=%ds)", timeout)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(script)
            temp_path = f.name
        
        try:
            cmd = [
                "docker", "run",
                "--rm",
                "--network", "none",
                "--memory", "256m",
                "--cpus", "0.5",
                "-v", f"{temp_path}:/poc.py:ro",
                image,
                "python", "/poc.py"
            ]
            
            result = await self._run_docker(cmd, timeout)
            
        finally:
            try:
                os.unlink(temp_path)
            except:
                pass
        
        return result
    
    async def execute_go(self, script: str, timeout: int = None) -> ExecutionResult:
        """Execute Go script in Docker container."""
        timeout = timeout or self.default_timeout
        image = "golang:1.20-alpine"
        
        logger.info("Executing Go script in Docker container (timeout=%ds)", timeout)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.go', delete=False) as f:
            f.write(script)
            temp_path = f.name
        
        try:
            cmd = [
                "docker", "run",
                "--rm",
                "--network", "none",
                "--memory", "512m",  # Go needs more memory for compilation
                "--cpus", "1.0",
                "-v", f"{temp_path}:/poc.go:ro",
                image,
                "go", "run", "/poc.go"
            ]
            
            result = await self._run_docker(cmd, timeout)
            
        finally:
            try:
                os.unlink(temp_path)
            except:
                pass
        
        return result
    
    async def execute_java(self, script: str, timeout: int = None) -> ExecutionResult:
        """Execute Java script in Docker container."""
        timeout = timeout or self.default_timeout
        image = "openjdk:11-jre-slim"
        
        logger.info("Executing Java script in Docker container (timeout=%ds)", timeout)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.java', delete=False) as f:
            f.write(script)
            temp_path = f.name
        
        try:
            cmd = [
                "docker", "run",
                "--rm",
                "--network", "none",
                "--memory", "512m",
                "--cpus", "1.0",
                "-v", f"{temp_path}:/Poc.java:ro",
                image,
                "sh", "-c", "javac /Poc.java && java -cp / Poc"
            ]
            
            result = await self._run_docker(cmd, timeout)
            
        finally:
            try:
                os.unlink(temp_path)
            except:
                pass
        
        return result
        
    async def run_project_poc(self, repo_path: str, script: str, language: str, modified_files: Dict[str, str] = None, timeout: int = None) -> ExecutionResult:
        """
        Execute PoC within the context of the entire project repository.
        Supports file overrides (patches).
        """
        import shutil
        timeout = timeout or self.default_timeout
        images = {
            "PHP": "php:7.4-cli",
            "PYTHON": "python:3.9-slim",
            "GO": "golang:1.20-alpine",
            "JAVA": "openjdk:11-jre-slim"
        }
        image = images.get(language.upper(), "python:3.9-slim")
        
        logger.info(f"Executing {language} project-level PoC (timeout={timeout}s)")
        
        # 1. Create temporary workspace
        with tempfile.TemporaryDirectory() as temp_dir:
            # 2. Copy repo to workspace
            # Optimization: could use symlinks or bind mounts, but copying is safest
            project_workdir = os.path.join(temp_dir, "app")
            shutil.copytree(repo_path, project_workdir, dirs_exist_ok=True)
            
            # 3. Apply overrides (Patches)
            if modified_files:
                for rel_path, content in modified_files.items():
                    target_path = os.path.join(project_workdir, rel_path)
                    os.makedirs(os.path.dirname(target_path), exist_ok=True)
                    with open(target_path, 'w', encoding='utf-8') as f:
                        f.write(content)
            
            # 4. Save PoC script
            poc_filename = "repro.py" if language.upper() == "PYTHON" else "repro.php"
            poc_path = os.path.join(temp_dir, poc_filename)
            with open(poc_path, 'w', encoding='utf-8') as f:
                f.write(script)
                
            # 5. Run Docker
            # Mount both the project and the PoC
            cmd = [
                "docker", "run",
                "--rm",
                "--network", "none",
                "--memory", "512m",
                "--cpus", "1.0",
                "-v", f"{project_workdir}:/app:ro",
                "-v", f"{poc_path}:/{poc_filename}:ro",
                "-w", "/app", # Run from project root
                image
            ]
            
            if language.upper() == "PHP":
                cmd.extend(["php", f"/{poc_filename}"])
            elif language.upper() == "PYTHON":
                cmd.extend(["python", f"/{poc_filename}"])
            # ... add others if needed
            
            return await self._run_docker(cmd, timeout)
    
    async def _run_docker(self, cmd: list, timeout: int) -> ExecutionResult:
        """
        Execute Docker command with timeout and capture output.
        
        Args:
            cmd: Docker command as list
            timeout: Timeout in seconds
            
        Returns:
            ExecutionResult with all outputs
        """
        start_time = time.time()
        timed_out = False
        
        try:
            logger.debug(f"Running: {' '.join(cmd)}")
            
            # Run async subprocess  
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Wait with timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                # Kill process on timeout
                logger.warning("Docker execution timed out, killing process")
                process.kill()
                await process.wait()
                timed_out = True
                stdout, stderr = b"", b"Process timed out"
            
            execution_time = time.time() - start_time
            
            return ExecutionResult(
                exit_code=process.returncode or -1,
                stdout=stdout.decode('utf-8', errors='replace'),
                stderr=stderr.decode('utf-8', errors='replace'),
                execution_time=execution_time,
                timed_out=timed_out
            )
            
        except Exception as e:
            logger.error(f"Docker execution failed: {str(e)}")
            return ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=f"Execution error: {str(e)}",
                execution_time=time.time() - start_time,
                timed_out=False
            )
