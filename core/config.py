import os

class PipelineConfig:
    def __init__(self):
        # Static Analysis Tools
        self.SEMGREP_RULES_PATH = os.getenv("SEMGREP_RULES_PATH", "skills/rules/semgrep")
        self.CODEQL_DB_PATH = os.getenv("CODEQL_DB_PATH", "storage/codeql_dbs")
        # Updated to point to the new storage location
        self.CODEQL_BIN = os.getenv("CODEQL_BIN", r"storage\tools\codeql-win64\codeql\codeql.cmd")
        
        # Joern Configuration
        self.JOERN_HOME = os.getenv("JOERN_HOME", os.path.abspath(r"storage\tools\joern"))
        self.JOERN_PARSE = os.path.join(self.JOERN_HOME, "joern-parse.bat" if os.name == 'nt' else "joern-parse")
        self.JOERN_SCAN = os.path.join(self.JOERN_HOME, "joern-scan.bat" if os.name == 'nt' else "joern-scan")
        self.JOERN_EXPORT = os.path.join(self.JOERN_HOME, "joern-export.bat" if os.name == 'nt' else "joern-export")
        self.JOERN_WORKSPACE = os.getenv("JOERN_WORKSPACE", "storage/workspaces/joern_workspace")
        
        # Jazzer Configuration (JVM Fuzzing)
        self.JAZZER_HOME = os.getenv("JAZZER_HOME", os.path.abspath(r"storage\tools\jazzer"))
        self.JAZZER_JAR = os.getenv("JAZZER_JAR", os.path.join(self.JAZZER_HOME, "deploy/jazzer_standalone.jar"))
        self.JAZZER_WORKSPACE = os.getenv("JAZZER_WORKSPACE", "storage/workspaces/jazzer_workspace")
        
        # Fuzzer Configuration
        self.ATHERIS_WORKSPACE = os.getenv("ATHERIS_WORKSPACE", "storage/workspaces/atheris_workspace")
        self.AFL_FUZZ_PATH = os.getenv("AFL_FUZZ_PATH", "afl-fuzz")  # Requires WSL on Windows
        self.AFL_WORKSPACE = os.getenv("AFL_WORKSPACE", "storage/workspaces/afl_workspace")
        
        # SCA & Secret Scanning
        self.GITLEAKS_PATH = os.getenv("GITLEAKS_PATH", "gitleaks")
        self.GITLEAKS_WORKSPACE = os.getenv("GITLEAKS_WORKSPACE", "storage/workspaces/gitleaks_workspace")
        self.TRIVY_PATH = os.getenv("TRIVY_PATH", "trivy")
        self.TRIVY_WORKSPACE = os.getenv("TRIVY_WORKSPACE", "storage/workspaces/trivy_workspace")
        
        # General Settings
        self.LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
        self.VERIFY_TIMEOUT = int(os.getenv("VERIFY_TIMEOUT", "30"))

config = PipelineConfig()
