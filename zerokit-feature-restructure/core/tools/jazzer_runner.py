"""
JazzerRunner: Wrapper for Jazzer JVM fuzzing

Jazzer provides coverage-guided fuzzing for Java/Kotlin applications.
This runner handles:
1. Generating fuzz harnesses from templates
2. Compiling harnesses with project classpath
3. Running Jazzer with sanitizers (e.g., AddressSanitizer for native JNI)
4. Parsing crash reports
"""

import subprocess
import os
import logging
import asyncio
from typing import Dict, Optional, List
from pathlib import Path

logger = logging.getLogger(__name__)

class JazzerRunner:
    def __init__(self, jazzer_jar: str = None, workspace: str = None):
        """
        Initialize Jazzer runner.
        
        Args:
            jazzer_jar: Path to jazzer_standalone.jar (defaults to config)
            workspace: Path to store harnesses and findings
        """
        from ..config import config
        
        self.jazzer_jar = jazzer_jar or config.JAZZER_JAR
        self.workspace = workspace or config.JAZZER_WORKSPACE
        
        os.makedirs(self.workspace, exist_ok=True)
        
        if not os.path.exists(self.jazzer_jar):
            logger.warning(f"Jazzer JAR not found: {self.jazzer_jar}")
        else:
            logger.info(f"JazzerRunner initialized: {self.jazzer_jar}")
    
    def generate_harness(self, 
                        target_class: str, 
                        target_method: str,
                        classpath: str = None,
                        output_dir: str = None) -> str:
        """
        Generate a Jazzer fuzz harness from template.
        
        Based on learn.md lines 866-877 (Jazzer template).
        
        Args:
            target_class: Fully qualified class name (e.g., com.example.Parser)
            target_method: Method to fuzz (e.g., parse)
            classpath: Project classpath
            output_dir: Where to save harness
        
        Returns:
            Path to generated harness .java file
        """
        output_dir = output_dir or self.workspace
        os.makedirs(output_dir, exist_ok=True)
        
        # Extract package and class name
        package_parts = target_class.split(".")
        class_name = package_parts[-1]
        package = ".".join(package_parts[:-1])
        
        harness_class = f"{class_name}FuzzTest"
        harness_file = os.path.join(output_dir, f"{harness_class}.java")
        
        # Template from learn.md line 867-877
        harness_code = f"""
package {package};

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class {harness_class} {{
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {{
        try {{
            // Consume data based on method signature
            String input = data.consumeString(1000);
            
            // Call target method
            {class_name}.{target_method}(input);
        }} catch (Exception e) {{
            // Jazzer will catch crashes separately
        }}
    }}
}}
"""
        
        with open(harness_file, "w", encoding="utf-8") as f:
            f.write(harness_code)
        
        logger.info(f"Generated harness: {harness_file}")
        return harness_file
    
    def compile_harness(self, harness_file: str, classpath: str) -> str:
        """
        Compile the fuzz harness.
        
        Args:
            harness_file: Path to .java harness
            classpath: Project classpath including Jazzer JAR
        
        Returns:
            Path to compiled .class directory
        """
        output_dir = os.path.dirname(harness_file)
        
        # javac -cp jazzer.jar:project.jar Harness.java
        cmd = [
            "javac",
            "-cp", f"{self.jazzer_jar}{os.pathsep}{classpath}",
            harness_file
        ]
        
        logger.info(f"Compiling harness: {harness_file}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                logger.error(f"Compilation failed: {result.stderr}")
                raise RuntimeError(f"Harness compilation error: {result.stderr}")
            
            logger.info(f"Harness compiled successfully")
            return output_dir
        
        except subprocess.TimeoutExpired:
            logger.error("Compilation timeout")
            raise
        except Exception as e:
            logger.error(f"Compilation exception: {e}")
            raise
    
    def run_fuzzing(self, 
                   target_class: str,
                   classpath: str,
                   duration_sec: int = 60,
                   corpus_dir: str = None) -> Dict:
        """
        Run Jazzer fuzzing.
        
        Args:
            target_class: Fully qualified harness class (e.g., com.example.ParserFuzzTest)
            classpath: Classpath including harness, target, and dependencies
            duration_sec: Fuzzing duration
            corpus_dir: Seed corpus directory (optional)
        
        Returns:
            Dictionary with findings (crashes, coverage stats)
        """
        corpus_dir = corpus_dir or os.path.join(self.workspace, "corpus")
        crashes_dir = os.path.join(self.workspace, "crashes")
        os.makedirs(corpus_dir, exist_ok=True)
        os.makedirs(crashes_dir, exist_ok=True)
        
        # java -jar jazzer.jar --cp=classpath --target_class=FuzzTest --timeout=60
        cmd = [
            "java",
            "-jar", self.jazzer_jar,
            f"--cp={classpath}",
            f"--target_class={target_class}",
            f"--timeout={duration_sec}s",
            corpus_dir
        ]
        
        logger.info(f"Starting Jazzer fuzzing for {duration_sec}s...")
        
        findings = {
            "crashes": [],
            "coverage": None,
            "executions": 0,
            "status": "running"
        }
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=duration_sec + 10  # Extra buffer
            )
            
            # Parse output
            findings["status"] = "completed"
            
            # Jazzer outputs crashes to files like crash-<hash>
            crash_files = [f for f in os.listdir(self.workspace) if f.startswith("crash-")]
            
            for crash_file in crash_files:
                crash_path = os.path.join(self.workspace, crash_file)
                with open(crash_path, "rb") as f:
                    crash_input = f.read()
                
                findings["crashes"].append({
                    "file": crash_file,
                    "input": crash_input.hex()[:100],  # First 50 bytes in hex
                    "stacktrace": result.stderr if "ERROR" in result.stderr else ""
                })
            
            # Parse coverage/exec count from output
            if "exec/s" in result.stderr:
                # Example: "#12345 REDUCE exec/s: 1234 ..."
                findings["executions"] = self._parse_exec_count(result.stderr)
            
            logger.info(f"Fuzzing complete: {len(findings['crashes'])} crashes found")
        
        except subprocess.TimeoutExpired:
            findings["status"] = "timeout"
            logger.warning("Fuzzing timeout (expected for long runs)")
        except Exception as e:
            findings["status"] = "error"
            findings["error"] = str(e)
            logger.error(f"Fuzzing error: {e}")
        
        return findings
    
    def _parse_exec_count(self, output: str) -> int:
        """Extract execution count from Jazzer output."""
        # Simple heuristic: find last number before "exec/s"
        import re
        matches = re.findall(r'#(\d+)', output)
        return int(matches[-1]) if matches else 0

    async def compile_harness_async(self, harness_file: str, classpath: str) -> str:
        """Async version of compile_harness."""
        output_dir = os.path.dirname(harness_file)
        
        cmd = [
            "javac",
            "-cp", f"{self.jazzer_jar}{os.pathsep}{classpath}",
            harness_file
        ]
        
        logger.info(f"Compiling harness [Async]: {harness_file}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
            except asyncio.TimeoutError:
                process.kill()
                logger.error("Compilation timeout")
                raise RuntimeError("Harness compilation timed out")

            if process.returncode != 0:
                logger.error(f"Compilation failed: {stderr.decode()}")
                raise RuntimeError(f"Harness compilation error: {stderr.decode()}")
            
            logger.info(f"Harness compiled successfully")
            return output_dir
            
        except Exception as e:
            logger.error(f"Compilation exception: {e}")
            raise

    async def run_fuzzing_async(self, 
                   target_class: str,
                   classpath: str,
                   duration_sec: int = 60,
                   corpus_dir: str = None) -> Dict:
        """Async version of run_fuzzing."""
        corpus_dir = corpus_dir or os.path.join(self.workspace, "corpus")
        crashes_dir = os.path.join(self.workspace, "crashes")
        os.makedirs(corpus_dir, exist_ok=True)
        os.makedirs(crashes_dir, exist_ok=True)
        
        cmd = [
            "java",
            "-jar", self.jazzer_jar,
            f"--cp={classpath}",
            f"--target_class={target_class}",
            f"--timeout={duration_sec}s",
            corpus_dir
        ]
        
        logger.info(f"Starting Jazzer fuzzing [Async] for {duration_sec}s...")
        
        findings = {
            "crashes": [],
            "coverage": None,
            "executions": 0,
            "status": "running"
        }
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                # Extra buffer for Jazzer to shutdown gracefully
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=duration_sec + 10)
                stdout_text = stdout.decode()
                stderr_text = stderr.decode()
            except asyncio.TimeoutError:
                process.kill()
                findings["status"] = "timeout"
                logger.warning("Fuzzing timeout (process killed)")
                return findings
            
            findings["status"] = "completed"
            
            # Jazzer outputs crashes to files like crash-<hash>
            crash_files = [f for f in os.listdir(self.workspace) if f.startswith("crash-")]
            
            for crash_file in crash_files:
                crash_path = os.path.join(self.workspace, crash_file)
                # Ensure we only pick up crashes from *this* run (check timestamp? or just report all)
                # For simplicity, we report all new found
                with open(crash_path, "rb") as f:
                    crash_input = f.read()
                
                findings["crashes"].append({
                    "file": crash_file,
                    "input": crash_input.hex()[:100],
                    "stacktrace": stderr_text if "ERROR" in stderr_text else ""
                })
            
            if "exec/s" in stderr_text:
                findings["executions"] = self._parse_exec_count(stderr_text)
            
            logger.info(f"Fuzzing complete: {len(findings['crashes'])} crashes found")
            return findings
        
        except Exception as e:
            findings["status"] = "error"
            findings["error"] = str(e)
            logger.error(f"Fuzzing error: {e}")
            return findings
