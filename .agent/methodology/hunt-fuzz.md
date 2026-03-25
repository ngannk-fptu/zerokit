---
description: Specialized subflow for fuzzing-focused verification.
---

1. Start from `methodology/master-harness.md` and complete Phase 01-03 first.
2. During Phase 04, prioritize fuzzing for parser/deserialization/input-heavy sinks.
3. Select fuzzer approach by language:
- .NET/Java: JVM/.NET-compatible fuzz strategies
- TypeScript/JavaScript: parser and serialization input fuzzing
- Go/Python/C/C++: native or harness-based fuzzing
4. Capture crashes, hangs, and minimized repro inputs as verification evidence.
5. Continue with Phase 05 and Phase 06 from the master workflow.
