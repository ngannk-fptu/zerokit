---
description: Fuzzing Orchestration Workflow. Generates harnesses and fuzzes parsers.
---

1. Use `AdapterLoader` to detect the project tech stack (Python, Java, PHP, C/C++).
2. Identify high-risk "Sinks" (parsers, deserialization points, network handlers) using `grep_search`.
3. Invoke Antigravity (Prompter) to generate a fuzzing harness specifically for the detected language:
   - Python: Atheris
   - Java: Jazzer
   - C/C++: AFL++ / LibFuzzer
4. Deploy the harness to `storage/workspaces/fuzz_workspace`.
5. Run the fuzzer via the appropriate runner in `core/tools/`.
6. Monitor for crashes and unique hangs.
7. If a crash is found, trigger the **Root Cause Analysis (RCA)** phase and generate a `VerifiedVuln`.
