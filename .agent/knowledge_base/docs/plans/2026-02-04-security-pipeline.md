# Security Pipeline Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement a 9-phase security pipeline (Code & Build → Report) automation system.

**Architecture:** A modular Python-based agent system where each phase is handled by a specialized agent/script. The `Orchestrator` manages the data flow between phases using structured artifacts (JSON/YAML). Universal adapters handle language specifics.

**Tech Stack:** Python, LangChain/LLM (for intelligent parts), CodeQL, Semgrep, Fuzzing tools (AFL++, LibFuzzer), Docker (for sandboxing).

---

## Task 1: Environment & Orchestrator Setup

**Files:**
- Create: `.agent/pipeline/orchestrator.py`
- Create: `.agent/pipeline/config.py`
- Create: `.agent/pipeline/models.py` (Pydantic models for I/O)
- Test: `tests/pipeline/test_orchestrator.py`

**Step 1: Define Data Models**

Define the shared data structures for the pipeline (AttackSurface, Hypothesis, StaticFinding, VerifiedVuln).

```python
# .agent/pipeline/models.py
from pydantic import BaseModel
from typing import List, Optional, Dict

class EntryPoint(BaseModel):
    type: str
    code_location: str
    description: Optional[str] = None

class AttackSurface(BaseModel):
    entry_points: List[EntryPoint]
    
class Hypothesis(BaseModel):
    id: str
    description: str
    target_code: str
    verification_plan: str

class StaticFinding(BaseModel):
    id: str
    hypothesis_id: str
    description: str
    location: str
    severity: str
    evidence: str

class VerifiedVuln(BaseModel):
    finding_id: str
    status: str
    poc: Dict
    runtime_output: str
    evidence: str
```

**Step 2: Create Orchestrator Skeleton**

```python
# .agent/pipeline/orchestrator.py
from .models import AttackSurface, Hypothesis, StaticFinding, VerifiedVuln

class Orchestrator:
    def __init__(self):
        self.state = {}

    def run_phase_1_profiling(self, repo_path: str):
        # TODO: integrate RepoProfiler
        pass

    def run_pipeline(self, repo_path: str):
        print(f"Starting pipeline for {repo_path}")
        # Sequence of calls will go here
```

**Step 3: Test Orchestrator Data Flow**

```python
# tests/pipeline/test_orchestrator.py
from .agent.pipeline.orchestrator import Orchestrator
from .agent.pipeline.models import EntryPoint

def test_models():
    ep = EntryPoint(type="HTTP", code_location="main.py:10")
    assert ep.type == "HTTP"

def test_orchestrator_init():
    orch = Orchestrator()
    assert orch.state is not None
```

---

## Task 2: Phase 1 & 2 - Repo Profiler & Attack Surface Mapping

**Files:**
- Create: `.agent/pipeline/agents/profiler.py`
- Create: `.agent/pipeline/adapters/base.py`
- Create: `.agent/pipeline/adapters/python_adapter.py` (Example)
- Test: `tests/pipeline/test_profiler.py`

**Step 1: Define Adapter Interface**

```python
# .agent/pipeline/adapters/base.py
from typing import List, Dict, Any
from ..models import EntryPoint

class LanguageAdapter:
    def detect(self, path: str) -> bool:
        """Detects if this adapter applies to the repo (e.g., checks for pom.xml, requirements.txt)."""
        raise NotImplementedError
        
    def build_command(self) -> str:
        """Returns the command to build/compile the project."""
        raise NotImplementedError

    def test_command(self) -> str:
        """Returns the command to run baseline tests."""
        raise NotImplementedError

    def get_entry_points(self, path: str) -> List[EntryPoint]:
        """Parses project structure to identify API endpoints/interfaces."""
        raise NotImplementedError
```

**Step 2: Implement Profiler Agent with Health Check**

```python
# .agent/pipeline/agents/profiler.py
import subprocess
from ..models import AttackSurface, EntryPoint, PipelineContext
from ..adapters.base import LanguageAdapter

class RepoProfiler:
    def __init__(self, adapters: List[LanguageAdapter]):
        self.adapters = adapters

    def analyze(self, context: PipelineContext) -> AttackSurface:
        # 1. Detection
        selected_adapter = None
        for adapter in self.adapters:
            if adapter.detect(context.repo_path):
                selected_adapter = adapter
                break
        
        if not selected_adapter:
            raise ValueError("No suitable language adapter found.")

        # 2. Health Check & Baseline
        self._run_health_check(selected_adapter, context.repo_path)

        # 3. Attack Surface Mapping
        entry_points = selected_adapter.get_entry_points(context.repo_path)
        return AttackSurface(entry_points=entry_points)

    def _run_health_check(self, adapter, path):
        # Run build
        build_cmd = adapter.build_command()
        if build_cmd:
            # execute subprocess...
            pass
```

**Step 3: Test Profiler**

```python
# tests/pipeline/test_profiler.py
from .agent.pipeline.agents.profiler import RepoProfiler

def test_profiler_returns_surface():
    prof = RepoProfiler()
    surface = prof.analyze(".")
    assert len(surface.entry_points) > 0
```

---

## Task 3: Phase 3 - Hypothesis Generation

**Files:**
- Create: `.agent/pipeline/agents/threat_modeler.py`
- Test: `tests/pipeline/test_threat_modeler.py`

**Step 1: Implement Threat Modeler with Prioritization**

```python
# .agent/pipeline/agents/threat_modeler.py
from ..models import AttackSurface, Hypothesis, EntryPointType
import uuid

class ThreatModeler:
    CRITICAL_KEYWORDS = ["admin", "auth", "login", "password", "upload", "payment"]

    def generate_hypotheses(self, surface: AttackSurface) -> list[Hypothesis]:
        hypotheses = []
        for ep in surface.entry_points:
            priority = "MEDIUM"
            
            # Prioritization Logic
            # 1. High Exposure (HTTP) -> Bump priority
            if ep.type == EntryPointType.HTTP:
                priority = "HIGH"
            
            # 2. Critical Keywords -> Critical Priority
            if any(k in ep.code_location.lower() or k in (ep.description or "").lower() for k in self.CRITICAL_KEYWORDS):
                priority = "CRITICAL"

            h = Hypothesis(
                id=str(uuid.uuid4()),
                description=f"Automated Hypothesis for {ep.type} at {ep.code_location}",
                target_code=ep.code_location,
                verification_plan="Standard Static Scan",
                metadata={"priority": priority}
            )
            hypotheses.append(h)
        
        # Sort by priority (CRITICAL > HIGH > MEDIUM > LOW)
        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        hypotheses.sort(key=lambda x: priority_order.get(x.metadata.get("priority", "LOW"), 3))
        
        return hypotheses
```

---

## Task 4: Phase 4 & 5 - Static Scan & Potential Findings

**Files:**
- Create: `.agent/pipeline/agents/detector.py`
- Create: `.agent/pipeline/tools/semgrep_runner.py` (New)
- Test: `tests/pipeline/test_detector.py`

**Step 1: Implement Semgrep Runner with Repair Hook**

```python
# .agent/pipeline/tools/semgrep_runner.py
import subprocess
import json
from typing import List, Dict

class SemgrepRunner:
    def run_scan(self, rule_config: str, target_path: str) -> List[Dict]:
        """Runs semgrep with standard rules or custom config."""
        cmd = ["semgrep", "scan", "--config", rule_config, "--json", target_path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return json.loads(result.stdout).get("results", [])
        except subprocess.CalledProcessError as e:
            # Placeholder for Repair Loop: analyze stderr and fix rule if it was custom
            raise RuntimeError(f"Semgrep failed: {e.stderr}")

    def validate_rule(self, rule_content: str) -> bool:
        """Checks if a custom rule is valid before running (Repair Loop Entry)."""
        # cmd = ["semgrep", "--validate", ...]
        pass
```

**Step 2: Implement Detector Agent**

```python
# .agent/pipeline/agents/detector.py
from ..models import Hypothesis, StaticFinding, FindingSeverity
from ..tools.semgrep_runner import SemgrepRunner
import uuid

class Detector:
    def __init__(self):
        self.runner = SemgrepRunner()

    def scan(self, hypotheses: list[Hypothesis], repo_path: str) -> list[StaticFinding]:
        findings = []
        
        # 1. Standard Scan (MVP: Run basic security rules)
        # In future: synthesize custom queries based on hypotheses
        try:
            raw_results = self.runner.run_scan("p/security-audit", repo_path)
        except RuntimeError as e:
            print(f"Scan error: {e}") 
            raw_results = []

        # 2. Normalize Results
        for res in raw_results:
            f = StaticFinding(
                id=str(uuid.uuid4()),
                description=res['extra']['message'],
                location=f"{res['path']}:{res['start']['line']}",
                severity=FindingSeverity.HIGH, # Map from semgrep severity
                evidence=res['extra']['lines'],
                tool_name="semgrep"
            )
            findings.append(f)
            
        return findings
```

---

## Task 5: Phase 6 & 7 - Dynamic Verifier & Confirmation

**Files:**
- Create: `.agent/pipeline/agents/verifier.py`
- Create: `.agent/pipeline/tools/po_c_runner.py`
- Test: `tests/pipeline/test_verifier.py`

**Step 1: Implement Verifier Agent with Directed Strategy**

```python
# .agent/pipeline/agents/verifier.py
from ..models import StaticFinding, VerifiedVuln, ConfirmedStatus, FindingSeverity
import logging

class Verifier:
    def verify(self, finding: StaticFinding) -> VerifiedVuln:
        """
        DIRECTED VERIFICATION: Uses the finding.location to target the verification.
        SANITIZER INTEGRATION: Harnesses should be run with ASan where applicable.
        """
        # 1. Generate Harness (Mock for now)
        # In real impl: detecting language -> generating compile command with -fsanitize=address
        
        # 2. Execute PoC/Fuzz
        # runtime_output = self.runner.run(harness, input_data)
        
        # 3. Analyze Output for ASan/Crash
        status = ConfirmedStatus.INCONCLUSIVE
        evidence = ""
        
        # Mock logic
        if "ASan" in finding.description or "buffer" in finding.description:
             # Simulation of ASan catching a bug
             status = ConfirmedStatus.CONFIRMED
             evidence = "AddressSanitizer: heap-buffer-overflow..."
        else:
             status = ConfirmedStatus.REJECTED

        return VerifiedVuln(
            finding_id=finding.id,
            status=status,
            poc={"type": "script", "content": "print('exploit')"},
            runtime_output="ASan report...",
            evidence=evidence
        )
```

---

## Task 6: Phase 8 & 9 - Analysis & Reporting

**Files:**
- Create: `.agent/pipeline/agents/reporter.py`
- Test: `tests/pipeline/test_reporter.py`

**Step 1: Implement Reporter**

```python
# .agent/pipeline/agents/reporter.py
from .agent.pipeline.models import VerifiedVuln
import json

class Reporter:
    def generate_report(self, vulns: list[VerifiedVuln]) -> str:
        report = "# Vulnerability Report\n\n"
        for v in vulns:
            report += f"## Finding {v.finding_id}\nStatus: {v.status}\nEvidence: {v.evidence}\n\n"
        return report
```

---

## Task 7: Full Pipeline Integration

**Files:**
- Modify: `.agent/pipeline/orchestrator.py`

**Step 1: Connect all agents in Orchestrator**

Update `run_pipeline` in Orchestrator to instantiate all agents and pass data sequentially:
Profiler -> Surface -> ThreatModeler -> Hypotheses -> Detector -> Findings -> Verifier -> Vulns -> Reporter -> Report.

**Step 2: Integration Test**

Write a test that runs the whole pipeline end-to-end on a dummy directory.
