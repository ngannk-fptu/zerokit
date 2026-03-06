from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum

class EntryPointType(str, Enum):
    HTTP = "HTTP"
    CLI = "CLI"
    FILE = "FILE"
    OTHER = "OTHER"

class EntryPoint(BaseModel):
    category: EntryPointType
    code_location: str
    description: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class AttackSurface(BaseModel):
    entry_points: List[EntryPoint]

class Hypothesis(BaseModel):
    id: str
    description: str
    target_code: str
    verification_plan: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

class VulnerabilityCategory(str, Enum):
    """Security vulnerability categories for pattern matching."""
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    SSRF = "SSRF"
    XXE = "XXE"
    DESERIALIZATION = "DESERIALIZATION"
    CSRF = "CSRF"
    IDOR = "IDOR"
    BUFFER_OVERFLOW = "BUFFER_OVERFLOW"
    RACE_CONDITION = "RACE_CONDITION"
    LOGIC_ERROR = "LOGIC_ERROR"
    PROTOTYPE_POLLUTION = "PROTOTYPE_POLLUTION"
    OTHER = "OTHER"

class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class SecurityPattern(BaseModel):
    """Represents a security-relevant code pattern (source, sink, or sanitizer)."""
    pattern: str  # Regex or function name pattern
    category: VulnerabilityCategory
    severity: FindingSeverity
    description: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class SecurityProfile(BaseModel):
    """Language and framework-specific security profile."""
    language: str
    framework: Optional[str] = None
    sources: List[SecurityPattern] = Field(default_factory=list)
    sinks: List[SecurityPattern] = Field(default_factory=list)
    sanitizers: List[SecurityPattern] = Field(default_factory=list)
    validators: List[SecurityPattern] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

class StaticFinding(BaseModel):
    id: str
    hypothesis_id: Optional[str] = None
    description: str
    location: str
    severity: FindingSeverity
    evidence: str
    tool_name: str
    cwe_details: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    target_function: Optional[str] = None          # Function name to fuzz directly
    directed_fuzz_candidate: bool = False           # True = route to AFL++ directed mode
    
    # Upgrade 5.2: Advanced Analytics
    taint_trace: Optional[List[Dict[str, Any]]] = None # Source-to-Sink path
    repo_name: Optional[str] = None                # For MRVA
    repo_path: Optional[str] = None                # For MRVA
    language: Optional[str] = None                 # For MRVA

class ConfirmedStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"

class RootCauseAnalysis(BaseModel):
    crash_type: Optional[str] = "UNKNOWN" # LOGIC_ERROR, MEMORY_CORRUPTION
    description: str
    faulty_lines: List[int]
    faulty_function_name: Optional[str] = None
    fix_suggestion: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

class VerifiedVuln(BaseModel):
    finding_id: str
    status: ConfirmedStatus
    poc: Dict[str, Any] # e.g., {"type": "script", "content": "..."}
    runtime_output: str
    evidence: str
    description: Optional[str] = None # Added for context
    cwe_details: Optional[Dict[str, Any]] = None  # NEW: Enriched CWE details
    severity_adjustment: Optional[FindingSeverity] = None
    root_cause: Optional[RootCauseAnalysis] = None

class PipelineContext(BaseModel):
    repo_path: str
    run_id: str
    start_time: str
    config: Dict[str, Any] = Field(default_factory=dict)
    
    # State storage
    surface: Optional[AttackSurface] = None
    hypotheses: List[Hypothesis] = Field(default_factory=list)
    static_findings: List[StaticFinding] = Field(default_factory=list)
    verified_vulns: List[VerifiedVuln] = Field(default_factory=list)
    security_profile: Optional["SecurityProfile"] = None # NEW
    code_graph: Optional[Dict[str, Any]] = None # NEW (Upgrade 1)
    
    # Phase completion tracking (for interactive menu)
    completed_phases: List[str] = Field(default_factory=list)
    current_loop_iteration: int = 0  # For variant analysis loop tracking

