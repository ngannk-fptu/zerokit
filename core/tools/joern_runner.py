"""
JoernRunner: Wrapper for Joern Code Property Graph (CPG) analysis

Joern provides semantic code analysis via CPG queries for C/C++, Java, and more.
This runner handles:
1. Parsing code into CPG (joern-parse)
2. Running queries (joern-scan with custom scripts)
3. Exporting results
"""

import subprocess
import json
import os
import logging
import asyncio
from typing import List, Dict, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

class JoernRunner:
    def __init__(self, joern_home: str = None, workspace: str = None):
        """
        Initialize Joern runner.
        
        Args:
            joern_home: Path to Joern installation (defaults to config)
            workspace: Path to store CPG databases (defaults to .agent/joern_workspace)
        """
        from ..config import config
        
        self.joern_home = joern_home or config.JOERN_HOME
        self.workspace = workspace or config.JOERN_WORKSPACE
        
        # Tool paths (Windows .bat vs Unix sh)
        self.joern_parse = os.path.join(self.joern_home, "joern-parse.bat" if os.name == 'nt' else "joern-parse")
        self.joern_scan = os.path.join(self.joern_home, "joern-scan.bat" if os.name == 'nt' else "joern-scan")
        self.joern_export = os.path.join(self.joern_home, "joern-export.bat" if os.name == 'nt' else "joern-export")
        
        # Ensure workspace exists
        os.makedirs(self.workspace, exist_ok=True)
        
        logger.info(f"JoernRunner initialized: {self.joern_home}")
    
    def parse_code(self, source_path: str, language: str = "c", output_name: str = None) -> str:
        """
        Parse source code into CPG.
        
        Args:
            source_path: Path to source code directory
            language: Language to parse (c, java, jssrc, python, etc.)
            output_name: Name for CPG (defaults to directory name)
        
        Returns:
            Path to generated CPG directory
        """
        if not output_name:
            output_name = os.path.basename(os.path.abspath(source_path))
        
        cpg_path = os.path.join(self.workspace, f"{output_name}.bin")
        
        # joern-parse [source] --language [lang] --output [cpg]
        cmd = [
            self.joern_parse,
            source_path,
            "--language", language,
            "--output", cpg_path
        ]
        
        logger.info(f"Parsing {source_path} with Joern ({language})...")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5min timeout for large codebases
            )
            
            if result.returncode != 0:
                logger.error(f"Joern parse failed: {result.stderr}")
                raise RuntimeError(f"Joern parse error: {result.stderr}")
            
            logger.info(f"CPG created: {cpg_path}")
            return cpg_path
        
        except subprocess.TimeoutExpired:
            logger.error("Joern parse timeout (5min)")
            raise
        except Exception as e:
            logger.error(f"Joern parse exception: {e}")
            raise
    
    def run_query(self, cpg_path: str, query_script: str, output_format: str = "json") -> List[Dict]:
        """
        Run a Joern query on a CPG.
        
        Args:
            cpg_path: Path to CPG .bin file
            query_script: Joern script content (Scala code)
            output_format: Output format (json, sarif, csv)
        
        Returns:
            Query results as list of dicts
        """
        # Write query to temp file
        query_file = os.path.join(self.workspace, "temp_query.sc")
        with open(query_file, "w", encoding="utf-8") as f:
            f.write(query_script)
        
        # joern-scan [cpg] --script [query] --format [fmt]
        output_file = os.path.join(self.workspace, f"results.{output_format}")
        
        cmd = [
            self.joern_scan,
            cpg_path,
            "--script", query_file,
            "--output", output_file,
            "--overwrite"
        ]
        
        logger.info(f"Running Joern query on {cpg_path}...")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                logger.warning(f"Joern scan warning: {result.stderr}")
                # Some queries may return 0 results but still succeed
            
            # Parse output
            if os.path.exists(output_file):
                with open(output_file, "r", encoding="utf-8") as f:
                    if output_format == "json":
                        try:
                            return json.load(f)
                        except json.JSONDecodeError:
                            # Joern sometimes outputs line-delimited JSON
                            f.seek(0)
                            return [json.loads(line) for line in f if line.strip()]
                    else:
                        return [{"raw": f.read()}]
            else:
                logger.warning(f"No output file generated: {output_file}")
                return []
        
        except subprocess.TimeoutExpired:
            logger.error("Joern query timeout")
            raise
        except Exception as e:
            logger.error(f"Joern query exception: {e}")
            raise
    
    def find_buffer_overflows(self, cpg_path: str) -> List[Dict]:
        """
        Example query: Find strcpy calls without size checks.
        Based on learn.md lines 822-841.
        """
        query = """
        // Find strcpy without preceding strlen check
        val strcpyCalls = cpg.call("strcpy").l
        
        strcpyCalls.filterNot { call =>
            call.cfgPrev.isCall.name("strlen").nonEmpty
        }.map { call =>
            Map(
                "file" -> call.file.name.headOption.getOrElse("unknown"),
                "line" -> call.lineNumber.getOrElse(-1),
                "code" -> call.code,
                "function" -> call.method.name
            )
        }.toJson
        """
        
        return self.run_query(cpg_path, query, output_format="json")
    
    async def parse_code_async(self, source_path: str, language: str = "c", output_name: str = None) -> str:
        """
        Async version of parse_code with Smart Caching.
        Checks if CPG exists and is newer than the source directory.
        """
        if not output_name:
            output_name = os.path.basename(os.path.abspath(source_path))
        
        cpg_path = os.path.join(self.workspace, f"{output_name}.bin")
        
        # --- SMART CACHING LOGIC ---
        if os.path.exists(cpg_path):
            try:
                cpg_mtime = os.path.getmtime(cpg_path)
                
                # Get latest mtime from source code
                # This could be slow for massive repos, but faster than parsing
                source_mtime = 0
                for root, dirs, files in os.walk(source_path):
                    for file in files:
                        full_path = os.path.join(root, file)
                        m = os.path.getmtime(full_path)
                        if m > source_mtime:
                            source_mtime = m
                
                if cpg_mtime > source_mtime:
                    logger.info(f"Smart Caching: CPG is up-to-date. Skipping parse for {output_name}.")
                    return cpg_path
                else:
                    logger.info("Smart Caching: Source code changed. Re-parsing...")
            except Exception as e:
                logger.warning(f"Smart Caching check failed ({e}). Proceeding to parse.")
        # ---------------------------

        cmd = [
            self.joern_parse,
            source_path,
            "--language", language,
            "--output", cpg_path
        ]
        
        logger.info(f"Parsing {source_path} with Joern ({language}) [Async]...")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
            except asyncio.TimeoutError:
                process.kill()
                logger.error("Joern parse timeout (5min)")
                raise RuntimeError("Joern parse timed out")

            if process.returncode != 0:
                logger.error(f"Joern parse failed: {stderr.decode()}")
                raise RuntimeError(f"Joern parse error: {stderr.decode()}")
            
            logger.info(f"CPG created: {cpg_path}")
            return cpg_path
            
        except Exception as e:
            logger.error(f"Joern parse exception: {e}")
            raise

    async def run_query_async(self, cpg_path: str, query_script: str, output_format: str = "json") -> List[Dict]:
        """Async version of run_query."""
        # Write query to temp file
        query_file = os.path.join(self.workspace, "temp_query.sc")
        with open(query_file, "w", encoding="utf-8") as f:
            f.write(query_script)
        
        output_file = os.path.join(self.workspace, f"results.{output_format}")
        
        cmd = [
            self.joern_scan,
            cpg_path,
            "--script", query_file,
            "--output", output_file,
            "--overwrite"
        ]
        
        logger.info(f"Running Joern query [Async] on {cpg_path}...")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
            except asyncio.TimeoutError:
                process.kill()
                raise RuntimeError("Joern query timed out")
            
            if process.returncode != 0:
                logger.warning(f"Joern scan warning: {stderr.decode()}")
            
            # Parse output
            if os.path.exists(output_file):
                # Reading file IO is still sync, but it's fast enough or could be wrapped in run_in_executor
                with open(output_file, "r", encoding="utf-8") as f:
                    if output_format == "json":
                        try:
                            content = f.read()
                            if not content.strip(): return []
                            # Handle line-delimited JSON or standard JSON
                            try:
                                return json.loads(content)
                            except json.JSONDecodeError:
                                return [json.loads(line) for line in content.splitlines() if line.strip()]
                        except Exception:
                            return []
                    else:
                        return [{"raw": f.read()}]
            else:
                logger.warning(f"No output file generated: {output_file}")
                return []
        
        except Exception as e:
            logger.error(f"Joern query exception: {e}")
            raise

    def cleanup(self):
        """Remove temporary query files."""
        temp_query = os.path.join(self.workspace, "temp_query.sc")
        if os.path.exists(temp_query):
            os.remove(temp_query)
            logger.debug("Cleaned up temp query file")

    def _extract_json_from_console(self, output: str) -> List[Dict]:
        """
        Robustly extracts JSON result from noisy Scala console output.
        Joern often prints:
        > ... banner ...
        > strict mode ...
        > [ { "result": ... } ]
        > ... prompt ...
        """
        import re
        
        # Strategy 1: Find largest JSON array [ ... ]
        # Only works if result is a list
        try:
             # Look for the last valid JSON array block
             candidates = re.findall(r'\[.*\]', output, re.DOTALL)
             if candidates:
                 # Try parsing from largest to smallest candidate? 
                 # Usually the output is one single JSON block.
                 # Let's try to locate the start of the JSON array.
                 
                 # Basic approach: Find start '[' and end ']'
                 start_idx = output.find('[')
                 end_idx = output.rfind(']')
                 
                 if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                     potential_json = output[start_idx:end_idx+1]
                     return json.loads(potential_json)
        except:
            pass
            
        # Strategy 2: Line-based (for ndjson)
        results = []
        for line in output.splitlines():
            line = line.strip()
            if not line: continue
            if line.startswith("{") and line.endswith("}"):
                try:
                    results.append(json.loads(line))
                except:
                    pass
        
        if results: 
            return results
            
        return []
