"""
Pipeline configuration with cross-platform path handling.
All paths configurable via environment variables.
"""
import os
import platform


class PipelineConfig:
    def __init__(self):
        is_windows = platform.system() == "Windows"
        ext = ".bat" if is_windows else ""

        # Joern Configuration
        default_joern = os.path.join("storage", "tools", "joern")
        self.JOERN_HOME = os.getenv("JOERN_HOME", os.path.abspath(default_joern))
        self.JOERN_PARSE = os.path.join(self.JOERN_HOME, f"joern-parse{ext}")
        self.JOERN_SCAN = os.path.join(self.JOERN_HOME, f"joern-scan{ext}")
        self.JOERN_EXPORT = os.path.join(self.JOERN_HOME, f"joern-export{ext}")
        self.JOERN_WORKSPACE = os.getenv(
            "JOERN_WORKSPACE",
            os.path.join("storage", "workspaces", "joern_workspace"),
        )

        # Semgrep (usually in PATH, rules directory configurable)
        self.SEMGREP_RULES_PATH = os.getenv(
            "SEMGREP_RULES_PATH",
            os.path.join("skills", "rules", "semgrep"),
        )

        # SCA & Secret Scanning
        self.GITLEAKS_PATH = os.getenv("GITLEAKS_PATH", "gitleaks")
        self.GITLEAKS_WORKSPACE = os.getenv(
            "GITLEAKS_WORKSPACE",
            os.path.join("storage", "workspaces", "gitleaks_workspace"),
        )
        self.TRIVY_PATH = os.getenv("TRIVY_PATH", "trivy")
        self.TRIVY_WORKSPACE = os.getenv(
            "TRIVY_WORKSPACE",
            os.path.join("storage", "workspaces", "trivy_workspace"),
        )

        # General Settings
        self.LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
        self.VERIFY_TIMEOUT = int(os.getenv("VERIFY_TIMEOUT", "30"))


config = PipelineConfig()
