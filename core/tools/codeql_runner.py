import os
import asyncio
import logging
import json
import shutil
from typing import List, Dict, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

class CodeQLRunner:
    def __init__(self, codeql_path: str = None, workspace: str = None):
        """
        Initialize CodeQL Runner.
        Args:
            codeql_path: Path to codeql executable (or 'codeql' from PATH)
            workspace: Directory for databases and results
        """
        # Default to 'codeql' in PATH if not provided
        self.codeql_bin = codeql_path or "codeql" 
        self.workspace = workspace or os.path.join(os.getcwd(), ".agent", "artifacts", "codeql_dbs")
        os.makedirs(self.workspace, exist_ok=True)

    async def create_database_async(self, source_path: str, language: str, db_name: str = None, include_paths: List[str] = None) -> str:
        """
        Create CodeQL database asynchronously.
        If include_paths is provided, creates a partial DB (Surgical).
        """
        if not db_name:
            suffix = "_surgical" if include_paths else ""
            db_name = f"{os.path.basename(source_path)}_{language}{suffix}_db"
        
        db_path = os.path.join(self.workspace, db_name)
        
        # --- SMART CACHING ---
        if os.path.exists(db_path) and not include_paths:
            logger.info(f"Smart Caching: CodeQL DB exists at {db_path}. Skipping.")
            return db_path
            
        real_source = source_path
        
        # SURGICAL CLONING
        if include_paths:
            import tempfile
            temp_src = tempfile.mkdtemp(prefix="codeql_surgical_")
            logger.info(f"Surgical Mode: Cloning {len(include_paths)} files to {temp_src}...")
            
            for fpath in include_paths:
                if os.path.isfile(fpath) and fpath.startswith(source_path):
                    rel_path = os.path.relpath(fpath, source_path)
                    dest_path = os.path.join(temp_src, rel_path)
                    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                    shutil.copy2(fpath, dest_path)
            
            real_source = temp_src

        cmd = [
            self.codeql_bin,
            "database", "create",
            db_path,
            f"--language={language}",
            f"--source-root={real_source}",
            "--overwrite"
        ]
        
        logger.info(f"Creating CodeQL DB for {source_path} ({language})...")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=600) # 10 mins
            
            if process.returncode != 0:
                logger.error(f"CodeQL DB creation failed: {stderr.decode()}")
                raise RuntimeError(f"CodeQL Error: {stderr.decode()}")
                
            logger.info(f"CodeQL DB created: {db_path}")
            return db_path

        except Exception as e:
            logger.error(f"CodeQL Exception: {e}")
            # Cleanup failed DB
            if os.path.exists(db_path):
                shutil.rmtree(db_path, ignore_errors=True)
            raise

    async def analyze_async(self, db_path: str, query_suite: str = "security-extended", output_name: str = "results.sarif", additional_flags: List[str] = None) -> List[Dict]:
        """
        Run CodeQL Analysis.
        """
        # Ensure output name is unique if running multiple scans parallel
        if not output_name.endswith(".sarif"):
             output_name += ".sarif"
             
        output_path = os.path.join(self.workspace, output_name)
        
        cmd = [
            self.codeql_bin,
            "database", "analyze",
            db_path,
            query_suite,
            f"--output={output_path}",
            "--format=sarif-latest"
        ]
        
        if additional_flags:
            cmd.extend(additional_flags)
        
        logger.info(f"Running CodeQL Analysis on {db_path} with suite {query_suite}...")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=600)
            
            if process.returncode != 0:
                logger.error(f"CodeQL Analysis failed: {stderr.decode()}")
                # Allow partial failure? No, strict for now.
                return []
                
            logger.info(f"CodeQL Analysis complete: {output_path}")
            return self._parse_sarif(output_path)
            
        except Exception as e:
            logger.error(f"CodeQL Analysis Exception: {e}")
            return []

    def _parse_sarif(self, sarif_path: str) -> List[Dict]:
        """
        Parse SARIF output to raw dicts.
        """
        try:
            with open(sarif_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            findings = []
            for run in data.get('runs', []):
                for result in run.get('results', []):
                    # Basic extraction
                    rule_id = result.get('ruleId', 'unknown')
                    message = result.get('message', {}).get('text', '')
                    
                    locations = result.get('locations', [])
                    if locations:
                        phy_loc = locations[0].get('physicalLocation', {})
                        artifact_loc = phy_loc.get('artifactLocation', {}).get('uri', '')
                        region = phy_loc.get('region', {})
                        start_line = region.get('startLine', 0)
                        
                        findings.append({
                            "rule_id": rule_id,
                            "message": message,
                            "file": artifact_loc,
                            "line": start_line,
                            "severity": "HIGH", # Map from rule metadata in real impl
                            "tool": "codeql"
                        })
            return findings
            
        except Exception as e:
            logger.error(f"SARIF Parsing failed: {e}")
            return []
