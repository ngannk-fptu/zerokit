# ZeroKit2 Utility Scripts 📜

This folder contains a collection of Python and Shell scripts used to automate common security research tasks within the ZeroKit2 framework.

## 📁 Script Inventory

- **`download.py`**: Automated target acquisition and repo cloning.
- **`mass_hunt.py`**: Orchestrates large-scale vulnerability scans across multiple repositories.
- **`hunt_pipeline.py`**: The main entry point for the 10-phase agentic hunt protocol.
- **`test_sandbox.py`**: A utility for testing code snippets in a safe, isolated container (if configured).

## 🚀 Usage

Most scripts are designed to be run from the root directory.

### Running a Pipeline Hunt
```bash
python scripts/hunt_pipeline.py /path/to/target
```

### Mass Repository Scanning
```bash
python scripts/mass_hunt.py --targets targets.txt --output results.json
```

## 🛠️ Development

When adding new scripts:
1. Ensure they are modular and follow the `clean-code` skill protocol.
2. Add a brief description to this README.
3. Use relative paths where possible to ensure portability across teammate environments.
