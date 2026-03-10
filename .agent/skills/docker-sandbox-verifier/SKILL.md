---
name: docker-sandbox-verifier
description: >
  Builds and manages ephemeral Docker sandboxes for PoC verification in Phase 4 of the hunt-pipeline.
  Handles the full container lifecycle: stack detection -> Dockerfile generation -> image build ->
  PoC injection -> sandboxed execution -> result capture -> cleanup.
  Use this skill whenever the Verifier needs to run a repro.py or exploit script in isolation.
  Never run PoC scripts on the local host -- always delegate to this skill.
allowed-tools:
  - Read
  - Write
  - Bash
---

# Docker Sandbox Verifier

Manages ephemeral Docker containers for fully isolated PoC execution during Phase 4.

## How It Works

Use `Dockerfile.template` as the single base. Replace the `{{VARIABLE}}` placeholders
based on the detected stack (see table below), then build and run.

---

## Step 1  Stack Detection

Read `findings.json` or inspect the repo for these indicators:

| Indicator files | Detected Stack |
|----------------|---------------|
| `*.csproj`, `*.sln`, `appsettings.json` | `dotnet` |
| `requirements.txt`, `*.py`, `pyproject.toml` | `python` |
| `package.json`, `*.js`, `*.ts` | `node` |
| `go.mod`, `*.go` | `go` |
| `pom.xml`, `build.gradle`, `*.java` | `java` |
| `composer.json`, `*.php` | `php` |
| `Gemfile`, `*.rb` | `ruby` |

If ambiguous, default to **python**.

---

## Step 2  Fill Dockerfile.template

Open `Dockerfile.template` and replace all `{{VARIABLE}}` blocks using this reference table:

| Stack | `{{BASE_IMAGE}}` | `{{SYSTEM_DEPS}}` | `{{RUNTIME_DEPS}}` | `{{POC_FILE}}` | `{{BUILD_STEP}}` | `{{RUN_CMD}}` |
|-------|-----------------|-------------------|--------------------|----------------|-----------------|---------------|
| python | `python:3.12-slim` | `apt-get update && apt-get install -y curl wget && rm -rf /var/lib/apt/lists/*` | `pip install --no-cache-dir requests urllib3` | `repro.py` | `# none` | `["python", "repro.py"]` |
| node | `node:20-slim` | `apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*` | `npm install -g axios node-fetch` | `repro.js` | `# none` | `["node", "repro.js"]` |
| dotnet | `mcr.microsoft.com/dotnet/sdk:8.0` | `apt-get update && apt-get install -y curl wget && rm -rf /var/lib/apt/lists/*` | `# none` | `repro/` | `RUN dotnet build repro/ -c Release` | `["dotnet", "run", "--project", "repro/"]` |
| go | `golang:1.22-alpine` | `apk add --no-cache curl wget` | `# none` | `repro.go` | `RUN go build -o repro repro.go` | `["./repro"]` |
| java | `eclipse-temurin:21-jdk-alpine` | `apk add --no-cache curl wget` | `# none` | `repro.java` | `RUN javac repro.java` | `["java", "repro"]` |
| php | `php:8.3-cli-alpine` | `apk add --no-cache curl wget` | `# none` | `repro.php` | `# none` | `["php", "repro.php"]` |
| ruby | `ruby:3.3-slim` | `apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*` | `gem install httparty` | `repro.rb` | `# none` | `["ruby", "repro.rb"]` |

> **Note:** For `{{BUILD_STEP}}` = `# none`, remove that line entirely from the generated Dockerfile.
> For `{{RUNTIME_DEPS}}` = `# none`, replace with `echo "no runtime deps"`.

---

## Step 3  Image Build

```bash
docker build -t zerokit-sandbox-{finding_id} .
```

- `finding_id` = sanitized finding ID from `findings.json` (e.g. `sqli-001`, `lfi-002`).
- On build failure: log error, mark finding `inconclusive`, skip to cleanup.

---

## Step 4  Write PoC

Write `repro.py` (or equivalent) to the working directory. Rules for the PoC:

- Exit `0` on successful exploit trigger.
- Exit non-zero on failure or expected defense.
- Print human-readable evidence to stdout.

> **⚠️ DoS / Availability Hypothesis Special Rule:**
> If the hypothesis type is **Denial of Service (DoS, ReDoS, Resource Exhaustion)**,
> the PoC **MUST** treat a `requests.Timeout` (or equivalent network timeout) as a
> **successful exploit** and exit `0`.
> A server that hangs and never responds IS the proof of the vulnerability.
> Use `timeout=10` for the exploit request. Catch the `Timeout` exception, print
> `[+] DoS SUCCESS: server did not respond within timeout — resource exhaustion confirmed`
> and then call `sys.exit(0)`.
> **Never let the PoC bubble up a Timeout as a generic Exception and exit non-zero.**
> Use the template at `knowledge_base/templates/poc/http_dos_timeout.py` as the base.

---

## Step 5  Sandboxed Execution

```bash
docker run --rm \
  --network=host \
  -v "$(pwd)/repro.py:/app/repro.py:ro" \
  zerokit-sandbox-{finding_id} 2>&1 | tee /tmp/sandbox-{finding_id}.log
echo "EXIT:$?"
```

> Use `--network=host` when PoC needs to reach a local target (e.g. ASP.NET on localhost:5000).
> For self-contained PoCs, omit `--network=host` for full isolation.

---

## Step 6  Cleanup

```bash
docker rmi zerokit-sandbox-{finding_id}
```

Always run even if execution failed.

---

## Step 7  Result Mapping

Return to Phase 4:

```json
{
  "finding_id": "lfi-001",
  "exit_code": 0,
  "stdout": "...",
  "log_path": "/tmp/sandbox-lfi-001.log",
  "status": "confirmed"
}
```

| Exit Code | stdout shows exploit? | Status |
|-----------|----------------------|--------|
| 0 | Yes | `confirmed` |
| non-zero |  | `rejected` |
| 0 | No / ambiguous | `inconclusive` |

---

## Error Handling

| Scenario | Action |
|----------|--------|
| `docker info` fails | Halt. Notify operator. No fallback. |
| `docker build` fails | Log. Mark `inconclusive`. Cleanup. |
| `docker run` timeout (>120s) | Kill. Mark `inconclusive`. |
| Stack not in table | Default to `python`. Log `PARTIAL_CONTEXT`. |
| PoC catches `requests.Timeout` on a DoS hypothesis | **This IS success.** PoC must `exit 0`. Do NOT mark `rejected`. |
| PoC exits non-zero after network Timeout on non-DoS hypothesis | Normal failure. Mark `rejected`. |