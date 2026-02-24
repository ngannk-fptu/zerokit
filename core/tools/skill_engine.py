import os
import re
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class SkillEngine:
    """Discover and parse security patterns from .agent/skills/ directory."""
    
    def __init__(self, skills_dir: str = None):
        if skills_dir:
            self.skills_dir = skills_dir
        else:
            # Try multiple common locations
            paths_to_check = [
                os.path.join(os.getcwd(), "bpost-shipping-platform", ".agent", "skills"),
                os.path.join(os.getcwd(), ".agent", "skills"),
                # Logic for when running inside .agent/pipeline/tools/
                os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), 
                             "bpost-shipping-platform", ".agent", "skills")
            ]
            
            self.skills_dir = None
            for p in paths_to_check:
                if os.path.exists(p):
                    self.skills_dir = p
                    break
                    
            if not self.skills_dir:
                # Last resort fallback to current dir's .agent/skills
                self.skills_dir = os.path.join(os.getcwd(), ".agent", "skills")
            
        logger.info(f"SkillEngine: Using skills_dir: {self.skills_dir}")

    def discover_patterns(self, language: str) -> List[Dict[str, Any]]:
        """Discover patterns for a specific language from relevant skill folders."""
        patterns = []
        lang_lower = language.lower()
        
        # Robust language mapping
        lang_map = {
            "php": "php", "python": "python", "java": "java", "go": "go",
            "javascript": "node", "js": "node", "node.js": "node",
            "c#": "csharp", "csharp": "csharp", "dotnet": "csharp"
        }
        
        target_prefix = lang_map.get(lang_lower, lang_lower)
        
        if not self.skills_dir or not os.path.exists(self.skills_dir):
            return []

        for folder in os.listdir(self.skills_dir):
            folder_path = os.path.join(self.skills_dir, folder)
            if not os.path.isdir(folder_path): continue
                
            if folder.startswith(target_prefix) and ("security-patterns" in folder or "patterns" in folder):
                skill_file = os.path.join(folder_path, "SKILL.md")
                if os.path.exists(skill_file):
                    patterns.extend(self.parse_skill_md(skill_file))
                    
            if folder in ["api-patterns", "database-design", "vulnerability-scanner"]:
                skill_file = os.path.join(folder_path, "SKILL.md")
                if os.path.exists(skill_file):
                    patterns.extend(self.parse_skill_md(skill_file))
                    
        return patterns

    def parse_skill_md(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse a SKILL.md file for code patterns and return as dicts."""
        patterns = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
                
            p_regex = re.compile(r"(?:Pattern|\*\*Pattern\*\*):\s*`([^`]+)`")
            current_category = "OTHER"
            
            lines = content.split('\n')
            for line in lines:
                if line.startswith("## "):
                    header = line[3:].lower()
                    if "injection" in header:
                        if "sql" in header: current_category = "SQL_INJECTION"
                        elif "command" in header: current_category = "COMMAND_INJECTION"
                        else: current_category = "COMMAND_INJECTION"
                    elif "xss" in header: current_category = "XSS"
                    elif "traversal" in header: current_category = "PATH_TRAVERSAL"
                    elif "deserialization" in header: current_category = "DESERIALIZATION"
                    elif "csrf" in header: current_category = "CSRF"
                
                match = p_regex.search(line)
                if match:
                    p_text = match.group(1).strip()
                    clean_p = self._clean_pattern(p_text)
                    if clean_p:
                        patterns.append({
                            "pattern": clean_p,
                            "category": current_category,
                            "severity": "HIGH" if current_category != "OTHER" else "MEDIUM",
                            "description": f"Extracted from Trail of Bits Skill: {os.path.basename(os.path.dirname(file_path))}",
                            "metadata": {"source_file": file_path, "original_text": p_text}
                        })
        except Exception as e:
            logger.error(f"Error parsing skill {file_path}: {e}")
        return patterns

    def _clean_pattern(self, pattern: str) -> str:
        """Clean up pattern text."""
        if "(" in pattern:
            return pattern.split("(")[0].strip() + "("
        return pattern

if __name__ == "__main__":
    # Standalone Test
    logging.basicConfig(level=logging.INFO)
    engine = SkillEngine()
    print(f"DEBUG: Searching in {engine.skills_dir}")
    php_patterns = engine.discover_patterns("PHP")
    print(f"Discovered {len(php_patterns)} patterns for PHP")
    for p in php_patterns:
        print(f" - Found Pattern: {p['pattern']} ({p['category']})")
