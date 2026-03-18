# ZeroKit2 Security Pipeline Architecture

## High-Level Data Flow

```mermaid
graph TD
    UserInput[Repo Path] --> Orchestrator
    
    subgraph Phase 1-2: Context & Surface
        Orchestrator --> Profiler[Repo Profiler]
        Profiler -->|Uses| Adapter[Language Adapter]
        Adapter -->|Build/Test| HealthCheck
        Adapter -->|AST Parse| EntryPoints
        EntryPoints --> Context_Surface[Attack Surface]
    end

    subgraph Phase 3: Hypothesis
        Context_Surface --> ThreatModeler
        ThreatModeler -->|Prioritize| Hypotheses[Rated Hypotheses]
        style Hypotheses fill:#f9f,stroke:#333
    end

    subgraph Phase 4: Static Detection
        Hypotheses --> Detector
        Detector -->|Query Synthesis| SemgrepRunner
        SemgrepRunner -->|Repair Loop| Validator
        SemgrepRunner --> RawFindings
        RawFindings --> Findings[Static Findings]
    end

    subgraph Phase 5: Dynamic Verification
        Findings --> Verifier
        Verifier -->|Directed Fuzzing| Fuzzer
        Verifier -->|Compile w/ ASan| SanitizerCheck
        Fuzzer --> RuntimeLogs
        SanitizerCheck --> CrashData
        RuntimeLogs & CrashData --> VerifiedVulns[Verified Vulnerabilities]
        style VerifiedVulns fill:#9f9,stroke:#333
    end

    subgraph Phase 6: Feedback & Report
        VerifiedVulns --> FeedbackLoop{Variant Analysis?}
        FeedbackLoop -- Yes --> Detector
        FeedbackLoop -- No --> Reporter
        Reporter -->|Evidence Packaging| FinalReport[Markdown/JSON Report]
    end

    classDef agent fill:#e1f5fe,stroke:#01579b,stroke-width:2px;
    class Profiler,ThreatModeler,Detector,Verifier,Reporter agent;
```

## Component Breakdown

1.  **Orchestrator (`orchestrator.py`)**:
    *   Manages the lifecycle using `PipelineContext`.
    *   Enforces the **Verification Gate**: Only `CONFIRMED` vulnerabilities pass to the Reporter.

2.  **Repo Profiler (`profiler.py` + `adapters/`)**:
    *   **Smart Detection**: Identifies language (Python/Java/Go) and build system (Maven/Pip).
    *   **Health Check**: Runs build/test commands to establish a baseline.
    *   **Attack Surface**: Maps API endpoints (HTTP) and CLI inputs.

3.  **Threat Modeler (`threat_modeler.py`)**:
    *   **Prioritization**: Ranks entry points (CRITICAL, HIGH, MEDIUM, LOW) based on keywords (`admin`, `auth`) and exposure (`HTTP`).

4.  **Detector (`detector.py` + `tools/semgrep_runner.py`)**:
    *   **Static Scanning**: Wraps Semgrep.
    *   **Repair Loop**: Ready to handle syntax errors in generated queries.

5.  **Verifier (`verifier.py`)**:
    *   **Directed Verification**: Targets specific code locations found by Detector.
    *   **Sanitizer Integration**: Simulates checking for AddressSanitizer (ASan) crashes to catch memory errors.

6.  **Reporter (`reporter.py`)**:
    *   **Evidence Packaging**: Includes PoC, Stack Traces, and Static Traces in the final report.
    *   **Variant Analysis**: The Loop triggers a re-scan for verified patterns.
