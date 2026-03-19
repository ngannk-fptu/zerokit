"""
core/profiles.py — Multi-Language SecurityProfile Factory

Priority: .NET/C# → TypeScript/Node → Java → PHP → Python → Go
Auto-detects language from repo file extensions.
"""
import os
import logging
import yaml
from collections import Counter
from pathlib import Path
from typing import Optional, Tuple, List

from .models import (
    SecurityProfile, SecurityPattern, 
    VulnerabilityCategory, FindingSeverity, DetectionConfig
)

logger = logging.getLogger(__name__)

_PROFILES_CACHE: List[SecurityProfile] = []

def _translate_pattern(item: dict, default_severity: FindingSeverity = FindingSeverity.HIGH) -> SecurityPattern:
    """Translates YAML free-form schema into strict Pydantic SecurityPatterns"""
    pattern_val = item.get("function") or item.get("method") or item.get("annotation") or ""
    
    category = VulnerabilityCategory.OTHER
    cwe_list = item.get("cwe_concern", [])
    if isinstance(cwe_list, str): cwe_list = [cwe_list]
    cwe_val = item.get("cwe")
    if cwe_val: cwe_list.append(cwe_val)
    
    cwe_map = {
        "CWE-89": VulnerabilityCategory.SQL_INJECTION,
        "CWE-79": VulnerabilityCategory.XSS,
        "CWE-78": VulnerabilityCategory.COMMAND_INJECTION,
        "CWE-94": VulnerabilityCategory.COMMAND_INJECTION,
        "CWE-22": VulnerabilityCategory.PATH_TRAVERSAL,
        "CWE-918": VulnerabilityCategory.SSRF,
        "CWE-502": VulnerabilityCategory.DESERIALIZATION,
    }
    
    for c in cwe_list:
        if c in cwe_map:
            category = cwe_map[c]
            break
            
    severity_str = item.get("severity", "HIGH")
    severity = FindingSeverity[severity_str] if severity_str in FindingSeverity.__members__ else default_severity
    
    return SecurityPattern(
        pattern=pattern_val,
        category=category,
        severity=severity,
        description=item.get("description", "")
    )

def _load_yaml_profiles() -> List[SecurityProfile]:
    """Loads all Security Profiles directly from the Knowledge Base Adapters."""
    global _PROFILES_CACHE
    if _PROFILES_CACHE:
        return _PROFILES_CACHE
        
    adapters_dir = Path(__file__).parent.parent / ".agent" / "knowledge_base" / "adapters"
    if not adapters_dir.exists():
        logger.warning(f"Adapters logic directory not found at {adapters_dir}")
        return []
        
    profiles = []
    for yaml_file in adapters_dir.glob("*.yaml"):
        try:
            with open(yaml_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            
            det_data = data.get("detection", {})
            profile = SecurityProfile(
                language=str(data.get("language", "unknown")),
                framework=data.get("framework"),
                priority=int(data.get("priority", 0)),
                detection=DetectionConfig(**det_data) if det_data else None,
                sources=[_translate_pattern(s) for s in data.get("sources", [])],
                sinks=[_translate_pattern(s, FindingSeverity.CRITICAL) for s in data.get("sinks", [])],
                sanitizers=[_translate_pattern(s) for s in data.get("sanitizers", [])],
                metadata=data.get("metadata", {})
            )
            profiles.append(profile)
        except Exception as e:
            logger.error(f"Failed parsing Profile Architecture from {yaml_file.name}: {e}")
            
    # Sort descending by priority so complex frameworks hit first
    profiles.sort(key=lambda p: p.priority, reverse=True)
    _PROFILES_CACHE = profiles
    logger.info(f"Loaded {len(_PROFILES_CACHE)} profiles dynamically.")
    return _PROFILES_CACHE


def detect_language(repo_path: str) -> Tuple[str, Optional[str]]:
    """
    Intelligent detection using extensions, glob wildcard dependency files, and keywords.
    """
    profiles = _load_yaml_profiles()
    if not profiles:
        return ("php", "wordpress")

    counts: Counter = Counter()
    try:
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__", "vendor", "bin", "obj", ".vs", "dist", "build"}]
            for f in files:
                counts[Path(f).suffix.lower()] += 1
    except Exception as e:
        logger.warning(f"Failed indexing file tree: {e}")

    repo = Path(repo_path)
    for profile in profiles:
        if not profile.detection:
            continue
            
        ext_match = any(counts[ext] > 0 for ext in profile.detection.extensions)
        if not ext_match:
            continue
            
        dep_patts = profile.detection.dependency_files
        keywords = set(k.lower() for k in profile.detection.keywords)
        
        found_keywords = False
        if not dep_patts and not keywords:
            return (profile.language, profile.framework)
            
        for dep_pat in dep_patts:
            try:
                for dep_file_path in repo.rglob(dep_pat):
                    try:
                        with open(dep_file_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read().lower()
                            if any(kw in content for kw in keywords):
                                found_keywords = True
                                break
                    except Exception:
                        continue
                    if found_keywords:
                        break
            except Exception as e:
                logger.error(f"Glob wildcard parsing failed for pattern {dep_pat}: {e}")

        if found_keywords:
            logger.info(f"Target Acquired: {profile.language}/{profile.framework} (Score: {profile.priority})")
            return (profile.language, profile.framework)

    # Base fallback language level matching
    for profile in profiles:
        if profile.detection and any(counts[ext] > 0 for ext in profile.detection.extensions):
            return (profile.language, profile.framework)

    return ("php", "wordpress")


def build_security_profile(language: str, framework: Optional[str] = None) -> SecurityProfile:
    """Fetch structured capabilities directly from Knowledge Base cache"""
    profiles = _load_yaml_profiles()
    for p in profiles:
        if p.language == language and p.framework == framework:
            return p
    for p in profiles:
        if p.language == language:
            return p
    return profiles[0] if profiles else SecurityProfile(language="php", framework="wordpress")

def get_profile_for_repo(repo_path: str) -> SecurityProfile:
    lang, framework = detect_language(repo_path)
    return build_security_profile(lang, framework)
