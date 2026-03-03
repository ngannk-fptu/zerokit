---
description: Profile target repository, detect stack/build, and map attack surface.
---

1. Detect dominant language(s) and framework(s).
2. Identify build/test entry commands and run baseline health check when allowed.
3. Enumerate attack surface elements:
- HTTP endpoints
- RPC handlers
- message consumers
- CLI entrypoints
- deserialization/parsing boundaries
4. Identify likely trust boundaries and high-risk sinks per language.
5. Produce normalized `attack_surface` entries with file/line references.
6. Mark uncertain mappings for follow-up in threat modeling.
