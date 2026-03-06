---
description: Dependency & Reachability Workflow. Finds reachable CVEs in project dependencies.
---

1. Execute a dependency scan using `Trivy` or `Gitleaks` to identify known CVEs in the project's manifests (e.g., `package.json`, `composer.json`, `requirements.txt`).
2. Map the **Attack Surface** of the project to identify all external entry points.
3. Perform **Reachability Analysis**: Determine if the project's code actually calls the vulnerable functions within the flagged dependencies.
4. Filter out "Dormant" vulnerabilities that are not reachable from the attack surface.
5. Report only those CVEs that pose a real, reachable risk to the application.
