# ZeroKit2: Autonomous Security Research Engine

ZeroKit2 is an advanced, agentic vulnerability hunting pipeline designed for deep code analysis and autonomous proof-of-concept (PoC) generation. It implements a 10-phase security research protocol powered by LLMs and industry-standard static analysis tools.

## 🏭 The 10-Phase Agentic Pipeline

| Stage | Agent | Responsibility |
|-------|-------|-------|
| **1. Baseline** | Orchestrator | Health Check & Build Verification |
| **2. Map** | Mapper | Universal Mapping & Surface Analysis |
| **3. Deep Logic** | Threat Modeler | CWE Mapping & Logical Hypotheses |
| **4. Detect** | Detector | Hybrid SAST (Semgrep, CodeQL) |
| **5. Fuzz** | HarnessAgent | Fuzzing & Parser Analysis |
| **6. Verify** | Verifier | Autonomous PoC Generation & Execution |
| **7. RCA** | RootCause | Root Cause Analysis |
| **8. Feedback** | Variant | Variant Analysis & Pattern Recognition |
| **9. Patch** | Patcher | Autonomous Remediation & Verification |
| **10. Report** | Reporter | Final Security Report Generation |

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- Docker (for sandbox verification)
- Semgrep & CodeQL (optional, used by Detector)

### Installation
```bash
git clone https://github.com/your-username/ZeroKit2.git
cd ZeroKit2
pip install -r requirements.txt
```

### Usage
Run a full hunt on a target repository:
```bash
python hunt_pipeline.py --repo /path/to/target/code
```

## 🛡️ Key Features
- **Hybrid Signal Boost**: Combines multiple SAST engines to reduce false positives.
- **Differential Scanning**: Only analyzes changed files to speed up CI/CD integration.
- **Self-Correction Loop**: Automatically fixes Semgrep rules and PoC scripts based on execution feedback.
- **Docker Sandbox**: Verifies vulnerabilities in an isolated environment.

## 📂 Project Structure
- `core/`: Engine logic and agent orchestrators.
- `adapters/`: Interfaces for LLM providers and security tools.
- `.agent/`: Workflows, skills, and specialized agent instructions.
- `scripts/`: Utility scripts for environment setup.
- `test_vul/`: Proof-of-Concept examples and templates.

---
*Developed for Advanced Security Research.*
