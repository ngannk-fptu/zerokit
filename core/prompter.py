import os
import yaml
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass
from jinja2 import Template, Environment, FileSystemLoader

logger = logging.getLogger(__name__)

@dataclass
class PromptTemplate:
    content: str
    metadata: Dict[str, Any]
    
    @property
    def version(self) -> str:
        return self.metadata.get("version", "unknown")
        
    @property
    def method(self) -> str:
        return self.metadata.get("method", "unknown")
        
    @property
    def required_vars(self) -> list:
        return self.metadata.get("required_vars", [])

class Prompter:
    """
    Loads and renders external prompt templates with YAML frontmatter + Jinja2.
    Supports runtime hot-reloading.
    """
    
    def __init__(self, prompt_dir: str = None):
        self.prompt_dir = prompt_dir or os.path.join(os.getcwd(), ".agent", "knowledge_base", "prompts")
        self.jinja_env = Environment(loader=FileSystemLoader(self.prompt_dir))
        logger.info(f"Prompter initialized: {self.prompt_dir}")

    def load(self, agent: str, name: str) -> PromptTemplate:
        """
        Load a prompt template from file.
        e.g., load("detector", "generate_rule") -> prompts/detector/generate_rule.md
        """
        # Support both .md and .yaml extensions
        base_path = os.path.join(self.prompt_dir, agent, name)
        file_path = f"{base_path}.md"
        if not os.path.exists(file_path):
            file_path = f"{base_path}.yaml"
            
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Prompt file not found: {file_path}")
            
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Parse YAML frontmatter
            if content.startswith("---"):
                parts = content.split("---", 2)
                if len(parts) >= 3:
                    metadata = yaml.safe_load(parts[1])
                    template_content = parts[2].strip()
                    return PromptTemplate(content=template_content, metadata=metadata)
            
            # Fallback for files without frontmatter
            return PromptTemplate(content=content, metadata={})
            
        except Exception as e:
            logger.error(f"Error loading prompt {agent}/{name}: {e}")
            raise

    def render(self, template: PromptTemplate, **kwargs) -> str:
        """
        Render the Jinja2 template with variables.
        Validates required variables from metadata.
        """
        # Validate required variables
        missing = [v for v in template.required_vars if v not in kwargs]
        if missing:
            raise ValueError(f"Missing required prompt variables: {missing}")
            
        # Render Jinja2 template
        jinja_template = Template(template.content)
        return jinja_template.render(**kwargs)

    def get_config(self, template: PromptTemplate, provider: str = "default") -> Dict[str, Any]:
        """
        Get configuration (temperature, max_tokens) for a specific provider.
        """
        config = {
            "model": template.metadata.get("default_model"),
            "temperature": template.metadata.get("temperature", 0.1),
            "max_tokens": template.metadata.get("max_tokens", 4096)
        }
        
        # Apply provider overrides
        overrides = template.metadata.get("provider_overrides", {})
        if provider in overrides:
            config.update(overrides[provider])
            
        return config
