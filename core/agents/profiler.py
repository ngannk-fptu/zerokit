import logging
import subprocess
import os
from typing import List
from ..models import PipelineContext, AttackSurface, EntryPoint, EntryPointType
from ..adapters.base import LanguageAdapter

logger = logging.getLogger(__name__)

class RepoProfiler:
    def __init__(self, adapters: List[LanguageAdapter]):
        self.adapters = adapters

    def analyze(self, context: PipelineContext) -> AttackSurface:
        logger.info("Starting Profiling Phase...")
        
        # 1. Detection
        selected_adapter = self._detect_language(context.repo_path)
        if not selected_adapter:
            logger.error("No supported language/framework detected.")
            # Verify if we should fallback or raise. For now, we'll raise.
            raise ValueError("No supported configuration file found (e.g., requirements.txt, pom.xml).")
        
        logger.info(f"Detected framework using adapter: {selected_adapter.__class__.__name__}")

        # 2. Health Check & Baseline
        self._run_health_check(selected_adapter, context.repo_path)

        # 3. Attack Surface Mapping
        logger.info("Mapping Attack Surface...")
        entry_points = selected_adapter.get_entry_points(context.repo_path)
        
        # Populate Security Profile
        context.security_profile = selected_adapter.get_security_profile()
        logger.info(f"Loaded Security Profile: {context.security_profile.language}/{context.security_profile.framework or 'Generic'}")
        
        logger.info(f"Identified {len(entry_points)} entry points.")
        return AttackSurface(entry_points=entry_points)

    def _detect_language(self, repo_path: str) -> LanguageAdapter:
        for adapter in self.adapters:
            if adapter.detect(repo_path):
                return adapter
        return None

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
