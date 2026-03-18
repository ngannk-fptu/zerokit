# ZeroKit2 🛡️ (v5.2)

> **Autonomous Security Research Engine**
> *Semantic Graph ↔ MRVA ↔ Taint Path Explanation*

ZeroKit2 is a powerful agentic security pipeline designed to map codebases, generate complex security hypotheses, and verify them using automated dynamic analysis. Version 5.2 introduces advanced semantic reasoning and multi-repo variant hunting.

---

## 🚀 Key Features (v5.2 Upgrades)

*   **🧠 Antigravity Worker API**: Fully autonomous, file-based intelligence. No external API keys or cloud dependencies for the core pipeline logic.
*   **🕸️ Semantic Code Graph**: Uses Joern/CodeQL/Tree-sitter to build a unified Code Property Graph (CPG) for deep data-flow analysis.
*   **🔍 Taint Path Explanation**: Automatically narrates the path from user-controlled Source to vulnerable Sink in a human-readable format.
*   **🏹 Dynamic MRVA**: Multi-Repo Variant Analysis with automated PoC verification across thousands of targets.
*   **🏭 9-Phase Pipeline**: Baseline -> Map -> Deep Logic -> Detect -> Fuzz -> Verify -> RCA -> Feedback -> Report.
*   **✅ Verified-Only Reporting**: ZeroKit enforces a strict "No Proof = No Vuln" policy. Every reported bug is backed by a successful PoC execution.

---

## 🏗️ Architecture

ZeroKit2 uses a **Collaborative Agentic Ecosystem**:

1.  **Repo Profiler**: Maps attack surface and builds the Semantic Graph.
2.  **Threat Modeler**: Generates security hypotheses using semantic reachability.
3.  **Detector**: Orchestrates SAST scans and identifies high-signal candidates.
4.  **Explainer**: Traces and narrates data-flow paths (Taint Flow).
5.  **Harness Agent**: Automatically generates and repairs fuzzer harnesses.
6.  **Verifier**: Executes Proof-of-Concepts (PoCs) in isolated Docker sandboxes.
7.  **Patcher**: Generates and verifies security fixes.

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/your-org/zerokit2
cd zerokit2

# Install Core Dependencies
pip install -r requirements.txt

# Setup Environment
cp .env.example .env
# Set ANTIGRAVITY_QUEUE_DIR regarding your Agentic setup
```

## 🛠️ External Tool Prerequisites

ZeroKit v5.2 relies on several external security tools. You must install these for the full pipeline to function:

### 1. Core SAST Engines
- **Semgrep**: `pip install semgrep` (Ensure it is in your PATH).
- **CodeQL**: Download the [CodeQL Bundle](https://github.com/github/codeql-action/releases). 
  - Windows: Extract to `storage/tools/codeql-win64/`.
  - Linux/Mac: Extract anywhere and update `CODEQL_BIN` in `core/config.py` or set via `.env`.
- **Joern**: Install from [joern.io](https://joern.io/). Extract to `storage/tools/joern/`.

### 2. DAST & Verification (CRITICAL)
- **Docker**: Must be installed and running. The Verifier executes Proof-of-Concepts (PoCs) in isolated containers. **No Docker = No Verification.**

### 3. Scanning & Recon
- **Gitleaks**: Download from [GitHub](https://github.com/gitleaks/gitleaks/releases) and add to PATH.
- **Trivy**: Install from [aquasecurity/trivy](https://github.com/aquasecurity/trivy).

### 4. Fuzzing (Optional)
- **AFL++**: Requires WSL or native Linux.
- **Atheris/Jazzer**: `pip install atheris`. For Jazzer, place the JAR in `storage/tools/jazzer/`.

---

## 🎯 Usage

To run a deep security audit on a target codebase:

```bash
python hunt_pipeline.py <path_to_project>
```

The pipeline will:
1.  Run baseline SCA/Misconfig scans.
2.  Construct a Code Property Graph (CPG).
3.  Generate hypotheses based on trust boundaries.
4.  Run directed static scans and explain finding paths.
5.  Attempt to verify findings by generating and running PoCs.
6.  Generate a final `report.md` with verified vulnerabilities.

---

## 📂 Project Structure

- `core/`: Primary orchestration and agent logic.
- `.agent/knowledge_base/`: Declarative framework adapters (YAML) and prompter templates.
- `storage/`: Result history, CodeQL databases, and CPG artifacts.
- `tests/`: Comprehensive test suite for pipeline intelligence.

---

## 📜 Documentation
- [LEARN.md](learn.md): Technical deep-dive into the security patterns and Joern/CodeQL integration.
- [ARCHITECTURE.md](ARCHITECTURE.md): Detailed agent communication and data-flow diagrams.
