import logging
import subprocess
import os
from typing import List
from ..models import PipelineContext, AttackSurface, EntryPoint, EntryPointType
from ..adapters.base import LanguageAdapter
from ..tools.adapter_loader import AdapterLoader
from ..models import PipelineContext, AttackSurface, EntryPoint, SecurityProfile, SecurityPattern, VulnerabilityCategory, FindingSeverity

logger = logging.getLogger(__name__)

class RepoProfiler:
    def __init__(self, adapters_dir: str = None):
        self.loader = AdapterLoader(adapters_dir=adapters_dir)

    async def analyze(self, context: PipelineContext) -> AttackSurface:
        logger.info("Starting Profiling Phase (Declarative YAML Adapter Mode)...")
        
        # 1. Detection & YAML Loading
        adapter_data = self.loader.detect_and_load(context.repo_path)
        
        if not adapter_data:
            logger.warning("No specific framework detected. Using generic security profile.")
            # Fallback to generic if needed, or raise
            context.security_profile = SecurityProfile(language="generic")
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

        # 2. Attack Surface Mapping (Generic for now, or use YAML entrypoints if added)
        logger.info("Mapping Attack Surface...")
        # Note: In a full implementation, the YAML would define entry point patterns too.
        # For now, we use a basic file walk or fallback.
        entry_points = [] # Simplification: actual adapters did more, but we are moving to LLM-driven recon anyway.
        
        # 3. Semantic Graph Building (Upgrade 1)
        logger.info("Building Semantic Code Graph (Phase 2 Upgrade)...")
        try:
            from ..tools.semantic_graph import SemanticGraph
            sg = SemanticGraph(repo_path=context.repo_path, language=context.security_profile.language)
            context.code_graph = await sg.build()
        except Exception as e:
            logger.error(f"Failed to build Semantic Graph: {e}")
            context.code_graph = {"nodes": [], "edges": [], "error": str(e)}


    def _run_health_check(self, adapter: LanguageAdapter, repo_path: str):
        logger.info("Performing System Health Check & Baseline...")
        
        build_cmd = adapter.get_build_command()
        if build_cmd:
            logger.info(f"Executing Build: {build_cmd}")
            # In a real agent, we would capture stdout/stderr and maybe time it
            try:
                subprocess.run(build_cmd, shell=True, check=True, cwd=repo_path, capture_output=True)
                logger.info("Build Successful.")
            except subprocess.CalledProcessError as e:
                logger.error(f"Build Failed: {e.stderr}")
                raise RuntimeError("Project build failed. Aborting pipeline.")
        else:
            logger.info("No build command defined for this adapter.")

        test_cmd = adapter.get_test_command()
        if test_cmd:
            logger.info(f"Executing Baseline Tests: {test_cmd}")
            # Failures here might be acceptable (it's a baseline), but we record it.
            try:
                subprocess.run(test_cmd, shell=True, cwd=repo_path, capture_output=True)
                logger.info("Baseline Tests Completed.")
                # TODO: Parse coverage here if possible
            except subprocess.CalledProcessError:
                logger.warning("Baseline tests failed or had errors. Proceeding with caution.")
