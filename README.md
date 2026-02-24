# ZeroKit2 🛡️

> **Autonomous Security Research Pipeline**
> *Hypothesize. Verify. Patch.*

ZeroKit2 is an agentic framework that maps codebases, constructs security hypotheses, verifies them with dynamic exploits, and patches them automatically.

---

## 🚀 Key Features (v5.0)

*   **🧠 Thinking Agents**: Powered by **Google Gemini Pro** via a smart LLM Gateway.
*   **🏭 4-Stage Pipeline**: Map -> Threat Model -> Detect -> Verify.
*   **⚡ Prompt Externalization**: Prompts managed as `.md` files with Hot-Reload.
*   **🛡️ Deep Logic Hunting**: Antigravity (Intelligent Worker API) analyzes code metadata to find IDOR, Access Control, and Business Logic flaws.
*   **✅ Auto-Verification**: Writes & executes Python PoCs to **prove** bugs (No Proof = No Report).
*   **🔧 Auto-Patching**: Generates diffs to fix verified vulnerabilities.

## 🏗️ Architecture

The system uses a **Factory Line** architecture where intelligent agents collaborate:

1.  **Repo Profiler**: Maps the attack surface.
2.  **Threat Modeler**: "Thinks" about potential risks (`analyze_risk`).
3.  **Detector**: Writes dynamic Semgrep rules (`generate_rule`).
4.  **Verifier**: Writes & Runs Exploits (`generate_poc`).
5.  **Patcher**: Fixes the code (`generate_patch`).

See [ARCHITECTURE.md](ARCHITECTURE.md) for details.

## 📂 Workspace Navigator

This repository is structured as follows to facilitate security research and tool development:

### 🔬 Research & Audits
- `Piranha-XSS-Audit/`: Dedicated folder for the Piranha CMS research.
    - `analysis/`: Contains `hunt-pipeline-analysis.md` and Semgrep results.
    - `planning/`: Roadmap and implementation plans for the audit.
    - `scripts/`: Finalized exploit scripts for the Piranha CMS.
- `bpost-shipping-platform/`: Security research related to the bpost shipping platform.

### 🧪 Proof of Concepts & Labs
- `test_vul/`: The active "Vulnerability Lab".
    - `piranha_lab/`: A local environment for testing Piranha vulnerabilities.
    - `repro_*.py`: Iterative reproduction scripts (use `repro_piranha_xss.py` for the final exploit).
- `piranha.core/`: Source code of the target CMS (Piranha CMS v10.x).

### 🛠️ ZeroKit2 Core Engine
- `core/`: Primary logic for the agentic pipeline (Orchestrator, Agents).
- `adapters/`: Adapters for external tools (Semgrep, LLMs, Docker).
- `SecOpsAgentKit/`: Internal library for security agent behaviors.
- `storage/`: Persistent storage for scan results, logs, and artifacts.

### 📜 Utilities
- `scripts/`: General-purpose automation scripts (e.g., `mass_hunt.py`, `download.py`).
- `tests/`: Unit and integration tests for the ZeroKit2 framework.

---


## 📦 Installation

```bash
# Clone
git clone https://github.com/your-org/zerokit2
cd zerokit2

# Install Deps
pip install -r requirements.txt

# Configure .env
cp .env.example .env
# Edit .env with your Google Gemini API Key
```

## 🎯 Usage

### Option 1: Antigravity Integration (Recommended)

Run the full pipeline with direct Antigravity integration:

**Terminal 1: Start Antigravity Monitor**
```bash
python .agent/scripts/antigravity_monitor.py
```

**Terminal 2: Run Pipeline**
```bash
python hunt_pipeline.py <path_to_target>
```

The monitor will:
- Watch for incoming prompts from agents
- Display prompts for your review
- Auto-execute routine tasks (like `fix_semgrep_rule`)
- Request manual confirmation for critical tasks (like `generate_hypotheses`, `generate_patch`)
- Write responses back to the pipeline

### Option 2: External API Mode

If you prefer using Gemini API directly:

1. Set `LLM_PROVIDER=gemini` in `.env`
2. Add your `GOOGLE_API_KEY`
3. Run: `python hunt_pipeline.py <path_to_target>`

### Testing the Threat Modeler

```bash
python tests/pipeline/test_threat_modeler_llm.py
```
