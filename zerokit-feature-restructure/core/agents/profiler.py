import logging
import subprocess
import os
from pathlib import Path
from typing import List
from ..models import PipelineContext, AttackSurface, EntryPoint, EntryPointType
from ..tools.adapter_loader import AdapterLoader
from ..models import SecurityProfile, SecurityPattern, VulnerabilityCategory, FindingSeverity

logger = logging.getLogger(__name__)

class RepoProfiler:
    def __init__(self, adapters_dir: str = None):
        self.loader = AdapterLoader(adapters_dir=adapters_dir)

    async def analyze(self, context: PipelineContext) -> AttackSurface:
        logger.info("Starting Profiling Phase (Declarative YAML Adapter Mode)...")
        
        # 1. Detection & YAML Loading
        adapter_data = self.loader.detect_and_load(context.repo_path)
        
        if not adapter_data:
            logger.warning("No specific framework detected. Using language-based profile fallback.")
            # Use the profiles factory to detect language from file extensions
            from ..profiles import get_profile_for_repo
            context.security_profile = get_profile_for_repo(context.repo_path)
        else:
            # Populate Security Profile from YAML
            profile_data = self.loader.adapter_to_security_profile_update(adapter_data)
            context.security_profile = SecurityProfile(
                language=profile_data["language"],
                framework=profile_data["framework"],
                sources=[SecurityPattern(pattern=s, category=VulnerabilityCategory.OTHER, severity=FindingSeverity.INFO) for s in profile_data["sources"]],
                sinks=[SecurityPattern(pattern=s["name"], category=VulnerabilityCategory.OTHER, severity=s["severity"]) for s in profile_data["sinks"]],
                sanitizers=[SecurityPattern(pattern=s, category=VulnerabilityCategory.OTHER, severity=FindingSeverity.LOW) for s in profile_data["sanitizers"]]
            )
            logger.info(f"Loaded YAML Security Profile: {context.security_profile.language}/{context.security_profile.framework}")

        # 2. Attack Surface Mapping — Walk repo and collect candidates by language
        logger.info("Mapping Attack Surface...")
        lang = (context.security_profile.language or "unknown").lower()
        ext_map = {
            "python": [".py"],
            "php": [".php"],
            "java": [".java", ".kt"],
            "typescript": [".ts", ".tsx", ".js", ".mjs"],
            "javascript": [".js", ".mjs", ".cjs"],
            "csharp": [".cs"],
            "go": [".go"],
        }
        target_exts = ext_map.get(lang, [".js", ".ts", ".py", ".php"])
        
        entry_points: List[EntryPoint] = []
        skip_dirs = {".git", "node_modules", "__pycache__", "vendor", "dist", "build", ".idea", ".vscode"}
        try:
            for root, dirs, files in os.walk(context.repo_path):
                dirs[:] = [d for d in dirs if d not in skip_dirs]
                for fname in files:
                    if any(fname.endswith(ext) for ext in target_exts):
                        full_path = os.path.join(root, fname)
                        rel_path = os.path.relpath(full_path, context.repo_path)
                        entry_points.append(EntryPoint(
                            name=fname,
                            entry_point_type=EntryPointType.FILE,
                            code_location=rel_path,
                            metadata={"language": lang}
                        ))
        except Exception as e:
            logger.warning(f"Attack surface walking failed: {e}")
        
        logger.info(f"Attack surface mapped: {len(entry_points)} entry files found for {lang}.")
        
        # 3. Semantic Graph Building
        logger.info("Building Semantic Code Graph (Phase 2 Upgrade)...")
        try:
            from ..tools.semantic_graph import SemanticGraph
            sg = SemanticGraph(repo_path=context.repo_path, language=context.security_profile.language)
            context.code_graph = await sg.build()
        except Exception as e:
            logger.warning(f"Semantic Graph skipped: {e}")
            context.code_graph = {"nodes": [], "edges": [], "error": str(e)}

        return AttackSurface(entry_points=entry_points)


    def _run_health_check(self, adapter: dict, repo_path: str):
        logger.info("Performing System Health Check & Baseline...")
        
        build_cmd = adapter.get("metadata", {}).get("build_command")
        if build_cmd:
            logger.info(f"Executing Build: {build_cmd}")
            try:
                subprocess.run(build_cmd, shell=True, check=True, cwd=repo_path, capture_output=True)
                logger.info("Build Successful.")
            except subprocess.CalledProcessError as e:
                logger.error(f"Build Failed: {e.stderr}")
                raise RuntimeError("Project build failed. Aborting pipeline.")
        else:
            logger.info("No build command defined for this adapter.")

        test_cmd = adapter.get("metadata", {}).get("test_command")
        if test_cmd:
            logger.info(f"Executing Baseline Tests: {test_cmd}")
            try:
                subprocess.run(test_cmd, shell=True, cwd=repo_path, capture_output=True)
                logger.info("Baseline Tests Completed.")
            except subprocess.CalledProcessError:
                logger.warning("Baseline tests failed or had errors. Proceeding with caution.")
