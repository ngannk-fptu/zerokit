---
description: Verification gate phase. Confirm exploitability with runnable evidence using Docker sandbox isolation.
---

0. Run pre-flight check: `docker info`. If Docker is unavailable, halt immediately  do not fall back to local execution.
1. For each high-confidence candidate, generate a minimal PoC tied to the exact code location and attack path.
   - **DoS / ReDoS / Resource Exhaustion hypotheses**: Use `knowledge_base/templates/poc/http_dos_timeout.py` as the base. The PoC MUST catch `requests.Timeout` / `ConnectionError` and treat them as exploit success (`exit 0`). A server that hangs IS the proof. Never exit non-zero on a timeout for a DoS hypothesis.
2. Build an isolated Docker sandbox per finding using the `docker-sandbox-verifier` skill:
   - detect stack from `findings.json`
   - fill `Dockerfile.template` variables for the detected stack
   - `docker build -t zerokit-sandbox-{finding_id} .`
3. Inject and execute the PoC inside the container  never on the local host:
   - `docker run --rm --network=host zerokit-sandbox-{finding_id}`
   - capture: stdout, stderr, exit code
   - `docker rmi zerokit-sandbox-{finding_id}`
4. Capture evidence per finding:
   - docker commands used
   - container stdout / stderr
   - exit code (0 = exploit triggered)
   - path to `repro.py` artifact
5. Mark finding status using strict outcomes:
   - `confirmed`: exit code 0 and output matches expected exploit behavior
   - `rejected`: evidence disproves exploitability
   - `inconclusive`: ambiguous result — retry with adjusted payload and rebuild sandbox
   - **DoS exception**: if PoC exited non-zero due to a network `Timeout` and hypothesis type is DoS, do NOT mark `rejected` — rewrite the PoC using `http_dos_timeout.py` template and retry.
6. Enforce hard gate: do not promote any finding to the final list without `confirmed` evidence from a sandboxed run.