# Executive Summary of Whitebox VR Pipeline (Key Points)

- **Systematic, Code-Driven Approach:** Modern whitebox vulnerability research follows a structured pipeline - from mapping the code's attack surface to crafting proof-of-concept exploits - rather than relying on luck. Top practitioners break the process into repeatable stages: understand the code, hypothesize vulnerabilities, detect candidates, **verify each finding with a reproducible test, and analyze root cause and impact**[\[1\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=5)[\[2\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=3). This ensures findings are actionable and high-confidence.
- **Attack Surface & Threat Modeling First:** Analysts begin by **profiling the repository and mapping attack surfaces** (e.g. web endpoints, privileged modules, complex file parsers)[\[3\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=%E5%B8%B8%E8%A7%81%E4%BC%98%E5%85%88%E7%BA%A7%EF%BC%9A)[\[4\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=%E5%B8%B8%E8%A7%81%E5%AE%9A%E7%BA%A7%E7%BB%B4%E5%BA%A6%EF%BC%9A). For example, on Android, researchers list externally reachable interfaces and high-value assets to focus efforts[\[5\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=%E5%9B%A0%E6%AD%A4%E6%98%A0%E5%B0%84%E6%94%BB%E5%87%BB%E9%9D%A2%E6%97%B6%E5%BB%BA%E8%AE%AE%E5%90%8C%E6%97%B6%E5%81%9A%E4%B8%A4%E5%BC%A0%E8%A1%A8%EF%BC%9A). This **target selection** stage prioritizes components that are high-privilege or handle untrusted input, laying a foundation for focused analysis.
- **Hybrid Static + Dynamic Workflow:** The most effective methodologies **combine static analysis with dynamic testing** in a feedback loop[\[6\]](https://www.usenix.org/system/files/conference/woot17/woot17-paper-shastry.pdf#:~:text=attention%20on%20matches%20comprising%20untested,complement%20fuzz%20testing%2C%20and%20is)[\[7\]](https://www.usenix.org/system/files/conference/woot17/woot17-paper-shastry.pdf#:~:text=Fuzz%20testing%20has%20been%20the,and%2For%20stateful%20application%20logic%2C%20betraying). Static techniques (like code auditing, dataflow/taint analysis) efficiently sift through code for bug patterns and insecure flows, while dynamic techniques (like fuzzing or targeted unit tests) execute the code to trigger and confirm real vulnerabilities. This hybrid approach addresses each technique's blind spots - e.g. static analysis finds subtle paths that fuzzing might miss, and fuzzing confirms which static "findings" are truly exploitable[\[8\]](https://www.usenix.org/system/files/conference/woot17/woot17-paper-shastry.pdf#:~:text=majority%20of%20taint,effective%20match%02ranking%20algorithm%20that%20uses)[\[9\]](https://www.usenix.org/system/files/usenixsecurity25-bao-andrew.pdf#:~:text=7,USENIX%20Security%20Symposium%20USENIX%20Association).
- **Step-by-Step Bug Hunting Methodology:** Top researchers follow a disciplined **step-by-step process**[\[10\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=3). For example, a proven workflow is: **(1)** build and run the project's test suite to establish a baseline, **(2)** scan the code for well-known dangerous patterns (using SAST tools or manual audit)[\[11\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=2)[\[12\]](https://spaceraccoon.dev/comparing-rule-syntax-codeql-semgrep/#:~:text=CodeQL%20and%20Semgrep%20OSS%20are,learning%20curve%20of%20CodeQL%20occurs), **(3)** form hypotheses of potential flaws (e.g. "input X might reach sink Y without sanitization"), **(4)** write or customize static queries/rules to find instances of those patterns[\[13\]](https://spaceraccoon.dev/comparing-rule-syntax-codeql-semgrep/#:~:text=The%20reason%20for%20this%20is,patterns%20in%20Semgrep%E2%80%99s%20rule%20syntax)[\[14\]](https://spaceraccoon.dev/comparing-rule-syntax-codeql-semgrep/#:~:text=In%20comparison%2C%20CodeQL%20tries%20to,each%20language%E2%80%99s%20syntax%20naming%20conventions), **(5)** for each candidate, write a minimal test or fuzz harness to attempt to trigger the issue in practice[\[15\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=3), **(6)** minimize the proof-of-concept input and environment to isolate the bug, and **(7)** perform root-cause analysis and assess impact (e.g. determine if it's an info leak vs. RCE)[\[4\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=%E5%B8%B8%E8%A7%81%E5%AE%9A%E7%BA%A7%E7%BB%B4%E5%BA%A6%EF%BC%9A). Finally, **(8)** suggest a fix or patch and verify that the fix truly resolves the problem without breaking functionality[\[16\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=).
- **Emphasis on Reproducibility and Evidence:** A vulnerability is not "verified" until the researcher can **reproduce it reliably and pinpoint the exact flaw**[\[1\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=5). This means providing a minimal proof-of-concept (e.g. a small input file or API call) that triggers the bug, identifying the precise file and line of the faulty code, and documenting why it's vulnerable. High-quality reports always include such an evidence package - minimal steps to reproduce, the vulnerable code path, the impact if exploited, and even a regression test or patch[\[1\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=5). This focus on reproducibility ensures **near-zero false positives** in final results.
- **Variant Analysis to Expand Findings:** Successful teams don't stop at one bug - they **search for variants** of each discovered vulnerability. Once a bug is confirmed, researchers often create a query or pattern (e.g. a CodeQL query) to scan the rest of the codebase - or even thousands of repos - for similar code that hasn't been fixed[\[17\]](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2019/CVE-2019-13720.html#:~:text=We%20performed%20variant%20analysis%20on,core%2Fworkers%20folder%20of%20the%20renderer)[\[18\]](https://blog.trailofbits.com/2025/12/11/introducing-mrva-a-terminal-first-approach-to-codeql-multi-repo-variant-analysis/#:~:text=In%202023%20GitHub%20introduced%20CodeQL,leads%20you). This practice has yielded many additional CVEs. For instance, after a Chrome use-after-free was found, Google's Project Zero wrote a Semmle/CodeQL query and uncovered multiple related bugs in the WebAudio module[\[17\]](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2019/CVE-2019-13720.html#:~:text=We%20performed%20variant%20analysis%20on,core%2Fworkers%20folder%20of%20the%20renderer)[\[19\]](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2019/CVE-2019-13720.html#:~:text=Found%20variants%3A). GitHub Security Lab researchers similarly use CodeQL queries to turn a single bug into "n variants," often finding **new vulnerabilities from known bug patterns**[\[20\]](https://securitylab.github.com/research-archive/#:~:text=,variant%20analysis%20to%20find%20vulnerabilities). Variant analysis, especially with multi-repo query tools, dramatically scales up coverage of bug patterns at **ecosystem scale**[\[18\]](https://blog.trailofbits.com/2025/12/11/introducing-mrva-a-terminal-first-approach-to-codeql-multi-repo-variant-analysis/#:~:text=In%202023%20GitHub%20introduced%20CodeQL,leads%20you).
- **Static Analysis with Deep Semantic Modeling:** Modern static analysis tools used in VR (e.g. CodeQL, Semgrep, Joern) go beyond simple pattern matching. They model code semantics - data flows, control flows, state machines - to find deeper logic bugs. CodeQL, for example, provides full interprocedural dataflow and taint tracking by extracting rich per-language models of sources, sinks, and frameworks[\[14\]](https://spaceraccoon.dev/comparing-rule-syntax-codeql-semgrep/#:~:text=In%20comparison%2C%20CodeQL%20tries%20to,each%20language%E2%80%99s%20syntax%20naming%20conventions)[\[13\]](https://spaceraccoon.dev/comparing-rule-syntax-codeql-semgrep/#:~:text=The%20reason%20for%20this%20is,patterns%20in%20Semgrep%E2%80%99s%20rule%20syntax). This allows finding complex issues like deserialization bugs or auth bypasses that require understanding application-specific APIs. Semgrep, on the other hand, favors a lightweight pattern approach (with an **abstract syntax tree + minimal flow analysis**) that makes writing rules easier but with some limitations (no full pointer analysis or path sensitivity in its OSS version)[\[13\]](https://spaceraccoon.dev/comparing-rule-syntax-codeql-semgrep/#:~:text=The%20reason%20for%20this%20is,patterns%20in%20Semgrep%E2%80%99s%20rule%20syntax)[\[21\]](https://spaceraccoon.dev/comparing-rule-syntax-codeql-semgrep/#:~:text=,case%20sound%20assumptions). Expert auditors often combine such tools: e.g. **Semgrep for quick pattern scanning** and **CodeQL for nuanced taint flows**. They also leverage code property graph tools like Joern to query semantic patterns (AST+CFG+PDG) - for instance, finding an unsanitized strcpy usage along any path not guarded by a size check[\[22\]](https://www.praetorian.com/blog/why-you-should-add-joern-to-your-source-code-audit-toolkit/#:~:text=.unsanitized%28%7Bit._%28%29.or%28_%28%29.isCheck%28%27.)[\[23\]](https://www.praetorian.com/blog/why-you-should-add-joern-to-your-source-code-audit-toolkit/#:~:text=By%20leveraging%20Joern%20in%20your,improve%20these%20results%20even%20further). These static techniques, especially when tuned to a project's framework, significantly cut down false positives and focus attention on likely real vulnerabilities.
- **Dynamic Verification: Fuzzing and Test Synthesis:** To ensure that static findings correspond to real, exploitable bugs, workflows incorporate **dynamic verification** steps. This can range from writing unit tests for a suspected issue to full fuzz testing on target components. Coverage-guided fuzzers (AFL++, libFuzzer, etc.) with sanitizers (ASan, UBSan) are routinely employed on parsers or memory-manipulating code - Google notes that heavy use of AddressSanitizer **"drastically improved"** the ability to catch memory corruption bugs during fuzzing[\[24\]](https://googleprojectzero.blogspot.com/2016/06/#:~:text=For%20example%2C%20we%20have%20extensively,instrumentations%2C%20which%20drastically%20improved). Researchers will often create a **small fuzz harness** for a suspicious function or input parser, then run it with sanitizers to see if any crashes occur. Modern approaches also include property-based testing (e.g. using Hypothesis for Python) to generate inputs that violate assumed invariants. In recent research, teams even use LLMs to assist in **generating fuzz harnesses** automatically, by analyzing function signatures and usage to produce a valid test driver[\[25\]](https://adalogics.com/blog/minimal-llm-based-fuzz-harness-generator#:~:text=For%20the%20purpose%20of%20simplicity%2C,a%20harness%20would%20be%20to)[\[26\]](https://adalogics.com/blog/minimal-llm-based-fuzz-harness-generator#:~:text=suggestions%20regarding%20fuzzing%20and%20what,The%20function%20is). The result is a pipeline where **every potential bug is subjected to an execution test** - either the bug triggers a failure (confirming an exploitable vulnerability), or nothing happens (potential false positive, which might be dropped or investigated further).
- **Multi-Stage Agent Automation:** Cutting-edge implementations (e.g. OpenAI's _Aardvark_ agent, Microsoft's Security Copilots) demonstrate that much of this pipeline can be automated with AI agents orchestrating the stages[\[27\]](https://openai.com/index/introducing-aardvark/#:~:text=Aardvark%20relies%20on%20a%20multi,identify%2C%20explain%2C%20and%20fix%20vulnerabilities)[\[28\]](https://openai.com/index/introducing-aardvark/#:~:text=by,click%20patching). These systems continuously monitor code (e.g. new commits) and apply a **multi-stage reasoning loop**: (1) **code analysis & threat modeling** - the agent "understands" the project design and security properties, (2) **vulnerability discovery** - it scans code changes against known bug patterns and the threat model, (3) **validation** - for each finding, the agent attempts to **exploit it in a sandbox or write a test case** to verify it (ensuring low false positives)[\[28\]](https://openai.com/index/introducing-aardvark/#:~:text=by,click%20patching), and (4) **patch generation** - the agent suggests a fix (using an LLM like Codex) and even provides the patch for review[\[29\]](https://openai.com/index/introducing-aardvark/#:~:text=attempt%20to%20trigger%20it%20in,click%20patching). Notably, such agents do not rely solely on one technique like fuzzing; they leverage **LLM reasoning + tool integration** to mimic a human researcher (reading code, running tools, writing tests)[\[30\]](https://openai.com/index/introducing-aardvark/#:~:text=vulnerabilities%2C%20how%20they%20might%20be,tests%2C%20using%20tools%2C%20and%20more)[\[31\]](https://openai.com/index/introducing-aardvark/#:~:text=Aardvark%20continuously%20analyzes%20source%20code,severity%2C%20and%20propose%20targeted%20patches). Early results are promising: OpenAI reports their agent identified ~92% of known vulnerabilities in benchmark apps and even found **new 0-days with CVEs assigned**[\[32\]](https://openai.com/index/introducing-aardvark/#:~:text=Aardvark%20finding%20issues%20that%20occur,only%20under%20complex%20conditions)[\[33\]](https://openai.com/index/introducing-aardvark/#:~:text=Aardvark%20has%20also%20been%20applied,CVE%29%20identifiers). This indicates that an agent-guided, verification-centric pipeline can dramatically scale vulnerability research.
- **Cross-Language & Framework Adaptability:** A **universal pipeline** is emerging - one that can be applied across languages (Java, JavaScript/TypeScript, Python, Go, C/C++, Rust, PHP, etc.) by using adaptable tooling and knowledge of each ecosystem's "gotchas." The core steps (taint analysis, invariant checking, fuzzing, etc.) generalize, but you need a thin adapter per language/framework that knows how to build the project, what its typical sources/sinks are, and how to exercise its functionality. For example, the pipeline uses CodeQL or Semgrep rules to detect taint issues, and these rules are customized with the relevant **sources of untrusted input and dangerous sinks for each framework**[\[34\]](https://semgrep.dev/blog/2025/a-technical-deep-dive-into-semgreps-javascript-vulnerability-detection/#:~:text=analysis%2C%20such%20as%20injection%20attacks%2C,sinks%20from%20the%20previous%20paragraph). In practice, adding a new framework (say, Express.js or Django) involves writing a config of "in HTTP handlers, req.query and req.body are sources; in DB calls or exec() calls are sinks," etc., so that static analysis and test generators know where to look. Security researchers have expanded tools like Semgrep to cover **50+ frameworks** by doing exactly this - diving into framework docs and code to enumerate where user data enters and where it could cause harm[\[35\]](https://semgrep.dev/blog/2025/a-technical-deep-dive-into-semgreps-javascript-vulnerability-detection/#:~:text=We%20analyzed%20popular%20npm%20libraries,found%20in%20the%20Semgrep%20documentation)[\[34\]](https://semgrep.dev/blog/2025/a-technical-deep-dive-into-semgreps-javascript-vulnerability-detection/#:~:text=analysis%2C%20such%20as%20injection%20attacks%2C,sinks%20from%20the%20previous%20paragraph). Thus, a universal pipeline achieves breadth by plugging in language-specific knowledge at defined points, while the overall methodology remains consistent.

**In summary**, the best-practice whitebox workflow today is **proactive, exhaustive, and verification-driven**. It leverages the strengths of static analysis (breadth and precision in reading code) and dynamic testing (ground-truth confirmation and exploit development) in a complementary loop. By breaking the process into clear stages (from attack surface mapping to final reporting) and often automating those stages with queries, scripts, and increasingly AI agents, researchers can find deeper bugs, minimize false positives, and produce artifacts (PoCs, patches, regression tests) that significantly aid in fixing and preventing vulnerabilities[\[1\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=5)[\[28\]](https://openai.com/index/introducing-aardvark/#:~:text=by,click%20patching). The remainder of this report details this **universal whitebox vulnerability research methodology**, the agent-based design to implement it, adaptations for various tech stacks, and resources to get started.

## Universal Whitebox VR Methodology (Pipeline Stages & Artifacts)

**Overview:** The whitebox vulnerability research pipeline can be modeled as a directed acyclic graph of stages, where each stage produces artifacts that feed the next. Below is a breakdown of **key stages** in a comprehensive whitebox workflow. For each stage, we list its **objective, inputs, outputs (artifacts), tools/techniques**, and typical **stop criteria** (when to move to the next stage). The stages often iterate (e.g. detectors->verification->refinement loop) until no new findings emerge. This structure draws on established methodologies used by professional auditors and researchers[\[10\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=3)[\[27\]](https://openai.com/index/introducing-aardvark/#:~:text=Aardvark%20relies%20on%20a%20multi,identify%2C%20explain%2C%20and%20fix%20vulnerabilities).

### **Stage 1: Repository Intake & Baseline Setup**

- **Objective:** Prepare the ground. Obtain the source code and get it building/running in a controlled environment. Establish a baseline understanding of the project.
- **Inputs:** The source repository (may include documentation, configs, tests).
- **Process:**
- **Build & Install:** Identify build steps (e.g. mvn package for Java, npm install for Node, make for C). Build the software with debugging symbols and enable runtime safety checks (e.g. compile C/C++ with AddressSanitizer)[\[24\]](https://googleprojectzero.blogspot.com/2016/06/#:~:text=For%20example%2C%20we%20have%20extensively,instrumentations%2C%20which%20drastically%20improved). If applicable, deploy the app locally (for a web app, set up the server).
- **Run Existing Tests:** Execute the project's test suite (if available) to verify everything works and to collect a baseline coverage. This also serves to familiarize with normal functionality and outputs.
- **Static Code Profiling:** Do an initial static scan to gather metrics - lines of code, languages used, key dependencies, etc. Generate a **code map** (e.g. dependency graphs, call graphs).
- **Outputs:**
- A working build environment (notes on how to build/run).
- Baseline test results and coverage metrics.
- High-level inventory of the code (module list, entry point list, dependency list).
- **Tools:** Compiler toolchains, build systems, test runners, language-specific linters. (No findings yet - this stage is about setup.)
- **Stop Criteria:** Build and tests pass (or at least the project runs), so we can proceed with analysis. We have enough familiarity to know how to run the software and where to inject tests or instrumentation.

### **Stage 2: Attack Surface Mapping**

- **Objective:** Identify all entry points where the software processes external or untrusted input, and enumerate high-value targets in the code. This guides focused analysis on security-critical areas[\[3\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=%E5%B8%B8%E8%A7%81%E4%BC%98%E5%85%88%E7%BA%A7%EF%BC%9A).
- **Inputs:** Source code + any architecture docs. Outputs from Stage 1 (module list, etc.).
- **Process:**
- **Map Entry Points:** List interfaces that ingest external data. For a web app, enumerate HTTP routes, API endpoints, file upload handlers, etc. For a library, find public API functions. For a system component, identify network sockets, IPC/RPC interfaces, command-line args, etc. Document these in an "Entry Point Table" with their locations in code[\[5\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=%E5%9B%A0%E6%AD%A4%E6%98%A0%E5%B0%84%E6%94%BB%E5%87%BB%E9%9D%A2%E6%97%B6%E5%BB%BA%E8%AE%AE%E5%90%8C%E6%97%B6%E5%81%9A%E4%B8%A4%E5%BC%A0%E8%A1%A8%EF%BC%9A).
- **Identify Assets/Privileges:** List sensitive assets (e.g. databases, secrets, privileged operations) and trust boundaries. Note where the code makes security decisions (auth checks, permission validations).
- **Threat Modeling:** For each entry point, hypothesize what could go wrong: e.g. "What if input X is malicious or malformed? Could it reach a dangerous operation without proper checks?" Prioritize components that run with elevated privileges or that perform complex parsing (historically bug-prone areas)[\[3\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=%E5%B8%B8%E8%A7%81%E4%BC%98%E5%85%88%E7%BA%A7%EF%BC%9A).
- Optionally, create **data flow diagrams** or threat models (e.g. STRIDE analysis) to understand how data moves and where it could be exploited.
- **Outputs:**
- **Attack Surface Report:** A list of entry points and attack vectors (e.g. "Function uploadImage() - takes user image data, writes to disk"), and a list of key security-relevant components (e.g. "Module X runs as root", "Module Y does crypto"). Often captured in tables or spreadsheets.
- **Targets for Review:** A shortlist of areas likely to yield vulnerabilities (to focus manual and automated analysis).
- **Tools:** Static code search (e.g. find uses of input APIs), architecture diagrams, threat modeling frameworks. This stage is often manual but can be aided by tools (e.g. ctrl+F for "http.ListenAndServe" in Go to find web handlers).
- **Stop Criteria:** The researcher has a clear view of **"where to look first."** All major entry points and sensitive pathways are mapped. We know, for example, which functions handle HTTP requests, which ones perform critical actions like authentication or file access, etc.

### **Stage 3: Hypothesis Generation (Vulnerability Brainstorming)**

- **Objective:** Based on the attack surface and understanding of the code, **formulate hypotheses of potential vulnerabilities**. Essentially, enumerate the types of bugs that might exist in the target and where.
- **Inputs:** Attack surface report, threat model, plus knowledge of common vulnerability patterns (CWEs) relevant to the tech stack.
- **Process:**
- **Brainstorm Possible Flaws:** For each entry point or feature, imagine how it could fail. E.g., _"This file parser might have a buffer overflow if given a corrupt file"_, _"This web API might lack an auth check on certain endpoints"_, _"User input here might be directly concatenated into a SQL query (SQL injection)"_, etc. Leverage known bug classes: memory corruptions in C/C++ code, injection flaws (SQLi, XSS, command injection) in web apps, logic errors in auth flows, insecure defaults in configs, etc.
- **Consult Vulnerability Repositories:** Look at prior vulnerabilities in similar software for ideas. E.g., review CWE lists or known CVEs in the same framework. Many bug patterns are recurrent.
- **Mark Code Locations for Each Hypothesis:** E.g., _Hypothesis:_ "Missing authorization in order management API." _Relevant code:_ the OrderController class, functions like cancelOrder() - does it enforce user is owner of order?
- **Prioritize Hypotheses:** Rank by potential impact and likelihood. Focus on hypotheses that, if true, would be critical (e.g. RCE, auth bypass) and seem plausible given the code.
- **Outputs:**
- **Vulnerability Hypothesis List:** Each hypothesis includes: suspected vulnerability type (and CWE if applicable), the code area it pertains to (file/function), why it might occur, and how to prove it (test idea).
- Optionally, a _brainstorm map_ linking hypotheses to CWE categories and code locations.
- **Tools/References:** CWE lists, previous audit reports, knowledge bases. Some use mind-mapping tools for this creative step. LLMs can assist by suggesting likely bug patterns for a given codebase (with caution to verify).
- **Stop Criteria:** You have a **set of concrete "leads"** to investigate. Instead of blindly reading code, you now have hypotheses like "Function X might not handle overflow," "Input Y isn't sanitized," etc., ready to be checked via analysis.

### **Stage 4: Detector Synthesis (Static Analysis & Custom Queries)**

- **Objective:** Turn the hypotheses into actionable detectors - using static analysis rules, queries, or pattern searches to find actual instances of the suspected bugs in code. Essentially, **automate the code audit** for each hypothesis.
- **Inputs:** Vulnerability hypotheses + code.
- **Process:**
- **Use Existing SAST Rules:** Leverage existing static analysis rulesets for generic issues. For example, run a **CodeQL query pack or Semgrep rules** for common vulnerabilities in this language. Off-the-shelf rules can catch low-hanging fruit (e.g., use of gets() in C, or XSS sinks in a web app). Note any alerts that align with hypotheses.
- **Write Custom Queries/Rules:** For more specific patterns, write custom CodeQL queries, Semgrep rules, or Joern queries:
  - _Example:_ If hypothesizing an auth bypass in OrderController, write a CodeQL query to find any OrderController endpoints missing an authorization check call. Or a Semgrep pattern to flag any route handler that doesn't verify the user's role.
  - _Example:_ For a suspected buffer overflow, use Joern or CodeQL to find strcpy or memcpy calls where the destination buffer size is a constant and compare it with potential source length (as in the Joern example that identified an unsafe strcpy usage without a size check[\[22\]](https://www.praetorian.com/blog/why-you-should-add-joern-to-your-source-code-audit-toolkit/#:~:text=.unsanitized%28%7Bit._%28%29.or%28_%28%29.isCheck%28%27.)[\[36\]](https://www.praetorian.com/blog/why-you-should-add-joern-to-your-source-code-audit-toolkit/#:~:text=,bases%2Fbuffer_overflow%2Fbuffer.c)).
  - Utilize frameworks: e.g., CodeQL has extensive standard libraries per language to model data flows (like tracking tainted user input to sensitive operations)[\[14\]](https://spaceraccoon.dev/comparing-rule-syntax-codeql-semgrep/#:~:text=In%20comparison%2C%20CodeQL%20tries%20to,each%20language%E2%80%99s%20syntax%20naming%20conventions). Semgrep rules can be written with pattern-sources and pattern-sinks if taint mode is available. Joern's CPG allows queries combining AST and control flow checks.
- **Semantic Searches:** Incorporate semantic invariants if needed. For instance, if a hypothesis is "state machine mismanagement," one might encode an expected state transition graph and query for transitions not allowed (this is advanced - often done in academic research on protocols[\[37\]](https://www.ndss-symposium.org/wp-content/uploads/2024/10/2023-68-slides.pdf#:~:text=...%20www.ndss,in%20network%20protocol%20implementations)).
- **Run the Analysis:** Execute custom queries against the code. For CodeQL, generate a database and run the QL queries. For Semgrep, run the YAML rule on the code. For Joern, load the CPG and execute the query. Use multi-repo variant analysis if applicable (e.g. CodeQL MRVA to run the query across many projects to see if this project or others have similar issues[\[18\]](https://blog.trailofbits.com/2025/12/11/introducing-mrva-a-terminal-first-approach-to-codeql-multi-repo-variant-analysis/#:~:text=In%202023%20GitHub%20introduced%20CodeQL,leads%20you)).
- **Filter and Refine:** Review the results. Static analysis may produce false positives or too many results. Refine queries to be more specific if needed (e.g. add conditions in CodeQL to require certain dataflow, or in Semgrep to narrow patterns). This is an iterative sub-loop - modify rule, re-run, until the results seem relevant.
- **Outputs:**
- **List of Potential Vulnerabilities (Static Findings):** Each with a description, the file and line, and why the rule flagged it. For example, "OrderController.cancelOrder - no auth check, potential authorization bypass" or "utils.c:120 - uses strcpy into fixed buffer, potential overflow."
- The actual **queries/rules** written are also an artifact - useful for repeatability and auditing. (They might be included in an appendix of the final report or shared with security tool communities.)
- If no findings for a hypothesis, note that (could mean code is safe or hypothesis was wrong).
- **Tools:** **CodeQL** (for deep dataflow and semantic queries; supports C/C++, C#, Go, Java, JavaScript/TypeScript, Python, Ruby, etc.), **Semgrep** (fast pattern matching across many languages; great for config and API misuse patterns), **Joern** (powerful for C/C++ and binary code property graph queries). Also, linters or specialized analyzers (e.g. SpotBugs for Java, Bandit for Python) - but those are typically covered by custom rules in CodeQL/Semgrep in advanced workflows.
- **Stop Criteria:** You have a manageable list of static _findings_ that warrant manual review or dynamic verification. Essentially, the pipeline now has "suspected vulnerabilities" with locations in code to confirm in the next stage. If Stage 4 yields no findings for high-priority hypotheses, you might double-check your hypotheses or proceed to dynamic testing anyway (some logic bugs won't be found by static patterns and need dynamic exploration).

### **Stage 5: Verification & Exploit Reproduction**

- **Objective:** **Confirm which of the static findings (or hypothesis) are real vulnerabilities** by triggering them in a running environment. This stage produces proof-of-concept exploits or at least test cases that demonstrate the issue. It separates the wheat from the chaff and provides evidence.
- **Inputs:** List of suspected vulnerabilities from Stage 4 (with code locations, descriptions). Also the running build or test environment from Stage 1.
- **Process:** For each suspected vulnerability:
- **Design a Test or PoC:** Figure out how to invoke the vulnerable code. This could be:
  - A unit test or script calling the function with malicious inputs.
  - An HTTP request (for a web endpoint) with crafted parameters.
  - A fuzz harness if the input space is large or complex (especially for file parsers or format handlers).
  - A small program or use of an existing testing tool (e.g. send a malformed packet to a network socket).
- **Example:** If static analysis found an unsanitized SQL query in searchBooks(term), write a quick test: call searchBooks("test' OR '1'='1") and see if it returns all books (indicating SQL injection). Or if a buffer overflow is suspected in parseImage(buf), write a C harness that calls it with a oversized buffer and run under AddressSanitizer.
- **Leverage Fuzzing where Needed:** If crafting the exact triggering input is hard (e.g. complex file format), use a fuzzer. Build a harness that feeds random or mutational inputs to the target function and let it run (with sanitizers for memory errors)[\[38\]](https://www.usenix.org/system/files/conference/woot17/woot17-paper-shastry.pdf#:~:text=toolchain%20and%20use%20it%20in,analysis%20and%20testing%2C%20and%20serve). Use coverage guidance to explore paths. If Stage 4 produced a path (e.g. data flows from A to B to C), you can do **directed fuzzing** focusing on that sink. Research like **Lyso (USENIX 2025)** even automates fuzzing to _verify static analysis alarms_, successfully turning static "alarms" into actual crashes in many cases[\[9\]](https://www.usenix.org/system/files/usenixsecurity25-bao-andrew.pdf#:~:text=7,USENIX%20Security%20Symposium%20USENIX%20Association) (18 new vulnerabilities found by fuzzing CodeQL-reported paths).
- **Run and Observe:** Execute the test/harness. If it crashes (for memory corruptions) or causes an incorrect behavior (for logic flaws), you've confirmed the bug. Capture the output - e.g. crash logs, stack traces, or the resulting behavior.
- **Minimize the Trigger:** If using fuzzing or if the initial PoC input is large, minimize it. Reduce it to the smallest input that still triggers the bug (this often makes it easier to understand and include in a report).
- **Iterate & Investigate:** If a suspected issue doesn't trigger, consider why. Maybe the static analysis was a false positive or environment differences matter. You might try slight variations or ensure the test is hitting the right code (add logging or breakpoints).
- **Record Environment Details:** Note the exact version of the code, configuration, or any preconditions needed for the bug. This is important for reproduction by others.
- **Outputs:**
- **Verified Vulnerabilities List:** For each confirmed issue, documentation of evidence:
  - A minimal **proof-of-concept (PoC)**: input or sequence of steps that triggers the bug.
  - The **observable result**: e.g. program crash (with ASan log showing an overflow at a certain line), unauthorized access achieved (e.g. able to read another user's data), etc.
  - Link to the **code location**: file and line numbers of the root cause (from static analysis or debugging).
  - Any conditions required (e.g. "must be admin user", or "only triggers on 32-bit systems" etc).
- For issues that could not be reproduced, they may be dropped or noted as "theoretical" (depending on certainty).
- **Evidence Artifacts:** Crash dumps, screenshots (if UI involved), log snippets, etc., all sanitized and ready for an evidence pack.
- **Tools:** **Unit testing frameworks** (JUnit, pytest, etc.), custom harness code in C/Go, **fuzzers** (AFL++, libFuzzer, Go's testing.F fuzz, Python's Hypothesis). Also dynamic analysis tools: e.g. running under Valgrind or AddressSanitizer for memory bugs, or using a debugger to watch execution. For web apps, tools like Postman or OWASP ZAP can be used to send crafted requests. In some cases, **symbolic execution** (KLEE, S2E) might be used to systematically generate an input to hit a bug path, though this is less common in practice due to complexity.
- **Stop Criteria:** Each potential vuln is either proven or disproven. Ideally, the researcher ends with a set of **confirmed vulnerabilities with proof**, and can move to reporting. If none are confirmed, revisit earlier stages or consider revising hypotheses (it happens - maybe the code is more secure than expected or needs deeper analysis like entropy tests for crypto issues, etc.). In practice, this stage continues until time runs out or a satisfying coverage of hypotheses is achieved.

### **Stage 6: Root Cause Analysis & Impact Assessment**

- **Objective:** For each confirmed vulnerability, deeply analyze its **root cause** in the code and determine the **security impact** (severity, what an attacker can do).
- **Inputs:** Verified vulnerabilities (PoCs, locations).
- **Process:**
- **Root Cause Analysis:** Read the vulnerable code in detail to understand why the bug occurs. Identify the exact oversight (e.g. "off-by-one error in length check," "missing authentication check on admin function," "use of outdated crypto algorithm with known weaknesses," etc.). Trace the code path from input to failure. This often involves explaining which check is missing or which assumption is wrong.
- **Impact & Severity:** Determine what an attacker could achieve:
  - Does this lead to Remote Code Execution? (highest severity)
  - Or sensitive data leakage? Authentication bypass? Denial of Service only?
  - Use a standard risk model like CVSS to estimate severity.
- **Identify Constraints:** Note any mitigating factors: e.g. "Requires user to be logged in," or "Only exploitable if a certain config is enabled," etc. This helps contextualize the risk.
- **Variant Check:** Consider if similar code elsewhere might have the same flaw (if not already covered in Stage 4's variant analysis). Sometimes root cause analysis reveals a pattern that you then quickly grep or query for in the codebase to see if lightning strikes twice.
- **Outputs:**
- **Vulnerability Description:** A clear explanation of **what the bug is and why it happens** (the coding mistake).
- **Severity/Impact Statement:** e.g. "This is an **authentication bypass** allowing any user to call the admin-only deleteUser API. Impact: full account takeover." Or "Heap buffer overflow in image parser, leading to potential RCE if exploited with a crafted file."
- **Evidence of Impact:** If possible, expand on the exploit - e.g. "We demonstrated control over EIP register, confirming exploitability" or "Able to extract other users' personal data via this flaw." While not always required to fully exploit in a report, mentioning the hypothetical attacker outcome is important.
- **Tools:** Primarily human analysis (code reading, debugging). For impact, may use an exploit development environment if needed (like running the program in a debugger or with an exploit script to see how far one can get).
- **Stop Criteria:** Each vulnerability is well-understood and can be convincingly explained to developers. Nothing is left as "weird behavior we can't explain" - you know the flaw.

### **Stage 7: Remediation Guidance (Patch Suggestion)**

- **Objective:** Provide guidance or actual code changes to fix the vulnerability, and plan for regression testing.
- **Inputs:** Root cause analysis, code location of bug.
- **Process:**
- **Devise a Fix:** Determine how to eliminate the bug. Common strategies:
  - Add a missing check (e.g. length validation, authentication guard).
  - Use safer API (e.g. replace strcpy with strncpy or safer pattern).
  - Adjust logic (e.g. re-order operations so that security checks happen before state changes).
  - Apply a known patch if the vulnerability is an n-day (perhaps the project has a patch in a newer version).
- Optionally, **prototype the fix**: write a patch diff. For simple issues, researchers often provide a patch snippet. For complex ones, they at least describe what should be done (e.g. "perform input validation using library X here").
- **Variant Fixes:** If the issue suggests variants, ensure the fix accounts for them. For instance, if one unsafe function call was found, the fix might be to replace all occurrences of that function in the codebase.
- **Security Regression Test:** Write a test case that will be used after patching to ensure the bug is truly fixed (and stays fixed). This could be integrating the PoC into the project's test suite if possible, or a separate standalone test.
- **Outputs:**
- **Patch Suggestions:** Either a textual description ("Add a check if (len > N) return error at line 123 in file.c") or unified diff patch. If using an AI assistant, it might even generate the code fix (as OpenAI's Aardvark does with Codex proposals)[\[39\]](https://openai.com/index/introducing-aardvark/#:~:text=high,click%20patching).
- **Regression Tests:** The PoC can often serve as a regression test; ensure it fails (or triggers the bug) on the vulnerable version and would pass on a fixed version.
- **Hardening Advice:** Sometimes, broader hardening suggestions are given: e.g. "Enable compiler stack canaries" or "Use safer memory allocators" if relevant, though these are secondary to the direct fix.
- **Tools:** Diff tools, IDE for editing code, possibly LLM assistance for patch generation (with careful review!). Existing test frameworks to integrate regression tests.
- **Stop Criteria:** A clear remediation path is provided for each vulnerability. The maintainers should have little doubt about how to patch the issue.

### **Stage 8: Documentation & Reporting**

- **Objective:** Compile all findings into a clear, comprehensive report (or evidence pack) for stakeholders - developers, security teams, or as part of a CVE submission. Also, ensure all artifacts are organized for handoff.
- **Inputs:** All information from prior stages (confirmed vulns, analysis, patches, etc.).
- **Process:**
- **For each vulnerability**, document:
  - **Title** (concise description, e.g. "Buffer overflow in image parser leads to RCE").
  - **Description:** context and impact in prose.
  - **Steps to Reproduce:** a step-by-step or the PoC input. This should be minimal and reliable.
  - **Affected Versions/Configuration:** if known (e.g. "v1.2.3 to v1.2.5 are affected; fixed in v1.2.6" or "all versions with feature X enabled").
  - **Root Cause:** explain the bug in code, referencing file and line (and including a snippet of the code around the bug if helpful).
  - **Fix Recommendation:** as prepared in Stage 7.
  - **Evidence:** any crash log or output, stack trace, etc., to substantiate the finding.
- **Overall Summary:** Include an executive summary of how many issues were found, their severities (often a table of vulns vs severity), and general remarks on code security posture (optional).
- **Appendices:** Possibly include the custom queries/rules used (so developers can use them in the future), additional tool outputs, or a glossary if needed.
- **Review and Clarity:** Ensure the report is understandable even to someone who isn't a security expert - define any uncommon terms, and be clear about what an attacker could do.
- **Optional Evidence Pack Extras:** Some researchers include a proof-of-concept exploit script (if safe to provide), or separate files (like malicious sample files) in an attached archive.
- **Outputs:**
- **Vulnerability Report (WRITE-UP):** Typically a Markdown or PDF document containing all the above sections for each vulnerability[\[1\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=5). This is the main deliverable to the developers or the party responsible for the code.
- **Artifacts Archive:** Folder containing PoC scripts, crash dumps, possibly the queries written, etc., referenced in the report.
- **Tools:** Markdown editor or report generator, screenshot tools if needed, etc. If submitting to a bug bounty or CVE, their templates might dictate format.
- **Stop Criteria:** The report passes an internal QA (all details present, reproducible by a colleague). It's ready to be delivered or submitted. At this point, the vulnerability research engagement is essentially complete, pending any follow-up for clarification or retesting after fixes.

**Diagram (Textual):** The stages above can be visualized as a flow:

Code & Build → Attack Surface Mapping → Hypotheses → Static Query/RULE Scan → Potential Findings → Dynamic Testing/Fuzzing → Confirmed Vulns → Root Cause & Impact → Patch & Report.

Each arrow represents outputs feeding the next stage. Importantly, there are feedback loops: e.g., if dynamic testing finds a bug, you might go back and refine a static rule to find variants; if a hypothesis proves fruitless, you generate new hypotheses or revisit the threat model. The pipeline is thus a DAG with some iterative cycles until diminishing returns.

## Agent Toolkit Design (Claude Code Implementation)

To automate this methodology, we design an **agent-based system** with specialized skills for each stage, coordinated by an orchestrator. The focus is on **modularity, verification at each step, and preventing hallucinations** (i.e. every claim an agent makes must be checked by another action, typically by running code or queries). Below is a proposed decomposition into agents, along with their responsibilities and the safety/validation mechanisms employed:

### **Agent Roles and Responsibilities**

- **Orchestrator Agent:** The "project manager" of the pipeline. It handles the overall workflow DAG, kicks off stages in order, and monitors progress. The Orchestrator reads a high-level task (e.g. "audit this repo for vulns") and breaks it into sub-tasks for other agents. It tracks the state (which stages are done, what findings in pipeline) and decides when to loop or move on. It also enforces that no vulnerability is reported without passing through verification. If an agent's output lacks verification evidence, Orchestrator will loop back (e.g. "Verifier couldn't reproduce this - go back and re-check or drop it").
- **Repo Profiler Agent:** Handles Stage 1 and partly Stage 2. Skills:
- **Environment Setup Skill:** Detect build system (e.g. sees pom.xml → chooses Maven commands, or sees package.json → chooses npm, etc.). Runs the build and reports success or errors. Also identifies languages present.
- **Test Runner Skill:** Runs any existing tests, collects results.
- **Code Mapping Skill:** Scans the repository structure (files, directories, sizes), and outputs a structured summary (e.g. "300 .java files, uses Spring framework, main entry in App.java").
- **Attack Surface Mapping Skill:** Using language-specific heuristics or pattern matching (with adapter data, see next section), it finds entry points (like web routes, RPC handlers) and privileged operations. It might output a JSON like {"endpoints": \[...\], "privileged_modules": \[...\]}. This agent essentially automates initial recon.
- **Validation:** This agent's outputs can be partly validated by direct inspection (e.g. Orchestrator can ask it to list top 5 largest files, or confirm that the build artifact exists). Since this is early-stage, validation is straightforward (did the build succeed? Did we find at least one entry point?). The Orchestrator can also spot-check e.g. run a trivial request to an identified endpoint to ensure it's correct.
- **Threat Modeler Agent:** Handles Stage 2/3 synergy. It takes the attack surface info and brainstorms likely vulns. Skills:
- **CWE Matcher Skill:** Maps entry points and components to common CWE categories. For instance, if it sees a file upload endpoint, it will raise CWE-434 (unrestricted file upload) as a hypothesis; a JSON parser suggests checking for deserialization issues (CWE-502), etc.
- **Prioritization Skill:** Ranks the potential issues by severity context (e.g. an RCE in a privileged service ranks higher than XSS in an internal admin page).
- **Output:** A structured list of hypotheses with associated code locations or functions (if possible) and suggested approach to detect (e.g. "Hypothesis: SQL Injection in UserDAO.search() - detect by finding string concatenation in SQL queries in that function").
- **Validation:** This is more reasoning-based, so Orchestrator can't "run" a hypothesis. Instead, validation comes from later stages: if Detector Agent finds nothing for a high-priority hypothesis, Orchestrator might prompt Threat Modeler to revisit or confirm that the code is indeed safe in that regard (perhaps by manual code inspection or returning to this later). Essentially, the **verification loop** here is that every hypothesis is either validated by finding a vuln or disproved by exhaustive checking.
- **Detector Engineer Agent:** Handles Stage 4 (static analysis and query writing). This is a crucial agent with coding and analysis skills:
- **Static Scan Skill:** Runs existing analyzers (CodeQL scans, Semgrep rules, linters) and collects findings.
- **Query Synthesis Skill:** For each hypothesis or for interesting patterns, it can write custom queries/rules. This agent would use an internal library of query templates (e.g. a generic taint query) and fill in specifics (sources/sinks from the adapter layer).
- **Example:** If tasked with "detect use of eval on user input in Python," it might produce a Semgrep rule or CodeQL query for that. Or for "missing auth in controllers," produce a CodeQL query that checks each controller method for a call to an auth function.
- **Compilation & Execution:** Any query or rule the agent writes is **immediately validated** by running it on the code. For CodeQL, compile the query and ensure it executes. If the query fails (syntax error or doesn't compile), that's caught and fed back for correction - similar to how QLPro's three-role mechanism has an LLM Writer, then an Executor to test compile, then a Repair loop[\[40\]](https://arxiv.org/html/2506.23644v3#:~:text=source%20projects%20without%20human%20intervention,from%20GitHub%20with%2062%20confirmed)[\[41\]](https://arxiv.org/html/2506.23644v3#:~:text=junior%20developers%20without%20security%20experience,Repair%20suggests%20modifications%20for%20failed). This agent will have an internal loop: **propose query → run → if errors, adjust** (with possible Orchestrator oversight after N failures).
- **Results Interpretation Skill:** Filter out obvious false positives from raw static results if possible (some trivial ones can be auto-ruled-out by known patterns).
- **Output:** A list of "suspected vulnerabilities" (with code references and why flagged) to pass to Verifier. Also store the queries/rules used (for traceability).
- **Anti-hallucination:** The key is the agent must not report a static finding unless it comes from an actual tool's output. The Orchestrator can enforce that by requiring every item to have an associated tool log or query result snippet. If the Detector Engineer claims "found SQL injection in X", Orchestrator asks for the query result or code excerpt that triggered it. This ensures it isn't just guessing - it has to show evidence (like a static trace).
- **Parallelism:** This agent might spawn sub-tasks per hypothesis or per analyzer. For efficiency, an orchestrator could run multiple detectors (Semgrep, CodeQL) in parallel via this agent's sub-skills and then unify results.
- **Verifier Agent:** Implements Stage 5 (and partly Stage 6). It is essentially the "exploit developer" and tester:
- **Testcase Generator Skill:** Given a suspected vuln and its context, generate code or steps to trigger it. This could be an actual code snippet (if it's a library, generate a small main in C or a Python script), or an HTTP request (the agent can output the method, URL, payload).
- **Fuzz Harness Skill:** If a simple input is not obvious, this skill can create a fuzz harness. E.g. use a template for libFuzzer harness if C/C++ (with the target function), or use Python's Hypothesis strategies to generate inputs. The agent might integrate with fuzz tools: it can launch a fuzzing process and monitor results.
- **Execution Skill:** Actually run the test or harness. The agent should interface with the environment - possibly via a sandbox or a container - to execute the code with necessary instrumentation (ASan, etc.). This requires the agent to handle process execution and timeouts to avoid hanging if a fuzz runs long.
- **Observation & Triage Skill:** Monitor for a crash or unexpected behavior. If a crash occurs, collect the stack trace or sanitizer report. If a logic bug, check the outcome (e.g. did the unauthorized action succeed? did the program output some known marker of failure?).
- **Loop & Refine:** If initial attempt doesn't trigger the bug, the agent can refine the input. This might be an iterative prompt: e.g. "No crash detected, try a larger size or different payload." The Orchestrator can set a max iteration to avoid infinite loops.
- **Output:** Verified result info (similar to Stage 5 outputs): proof-of-concept input, evidence of trigger (log or crash), and confirmation of the vulnerability. If the agent cannot confirm a static finding after exhaustive tries, it flags it as "not reproducible" back to Orchestrator (which may then drop it or mark as suspect).
- **Anti-hallucination & Safety:** **No vulnerability is accepted as real without this agent's confirmation.** This is the core safety check: the Orchestrator will not include a finding in the final report unless Verifier provided concrete evidence. This dramatically reduces false positives. It also prevents an LLM from hallucinating an exploit - the exploit must run and show something. If the Verifier agent is unsure (e.g. result was borderline), Orchestrator can route the case for human review or additional static checking.
- **Containment:** The Verifier runs potentially malicious payloads; in an automated setting, it should run in a sandbox (VM or container) to avoid harming the host or leaking sensitive data, especially if fuzzing untrusted code.
- **Report Packager Agent:** Handles Stage 6-8 collation and formatting:
- **Analysis Aggregator Skill:** Collects all confirmed vulns and their details (likely from Verifier and Detector outputs, plus any notes from Threat Modeler about impact).
- **Root Cause Analyzer (support) Skill:** Optionally, the agent can use the information from Detector (code locations) and possibly re-run a small code analysis to extract the code snippet around the bug to include in the report, highlighting the root cause. This could be partly automated (like retrieve 5 lines of code around the vuln line).
- **Severity Scorer Skill:** Assign a severity or CVSS score to each issue, possibly using a rule set (or even an LLM prompt that knows CVSS criteria - but verify consistency).
- **Patch Assistant Skill:** Propose a fix for each issue. This might use an LLM like Codex/GPT to generate a patch diff, especially if the fix is straightforward. Critically, any LLM-suggested patch should be sanity-checked (does it actually resolve the issue and not break things?). Possibly run the PoC again on patched code to ensure it's fixed - a **patch verification loop**.
- **Draft Report Generator Skill:** Compile the executive summary, per-vuln details, and appendices into a Markdown (or required format) file. Use templates for consistency.
- **Proofreading & Consistency:** The agent (or Orchestrator in final step) cross-checks that every claim in the report has either a citation (if referencing external info) or an evidence reference (e.g. "see crash log in Appendix"). Ensure no section is left "to do."
- **Output:** The final **REPORT.md** (or JSON, etc. as needed) containing all the structured findings, ready to deliver.
- **Validation:** The Orchestrator should review the final report: verify that each finding has a PoC and code reference (no missing evidence), check that all high-priority hypotheses are either addressed or explicitly noted as not found, and possibly run a **quality check** (perhaps a lint or even an LLM-based critique but careful). If something is missing, Orchestrator sends it back to the relevant agent (e.g. "Verifier did we ever confirm X? If not, it shouldn't be in report.").

### **Agent Collaboration and Workflow**

The Orchestrator controls the flow between these agents, enforcing a **verification-centric loop**: - It might start Repo Profiler and Threat Modeler in parallel (to save time, since profiling info feeds threat modeling). - Next, give hypotheses to Detector Engineer. - Detector returns static findings which Orchestrator passes one by one (or batch) to Verifier. - Verifier returns confirmed or not. Orchestrator filters the list to only confirmed issues. - Threat Modeler might be looped in again: e.g., if many findings cluster in one area, the Orchestrator can ask "any variants of these we missed?" (This ensures thoroughness - akin to human researchers focusing in once bugs found in a module). - Once done, pass all to Report Packager.

**Anti-hallucination Protocol:** The system uses **explicit confirmation messages** between agents. For example, Detector Engineer must include a snippet of code or tool output with each finding; Verifier must include the actual runtime output proving a bug. The Orchestrator will have rules like: - _If Detector provides a finding without source reference or tool evidence, ask it to provide that or drop the finding._ - _If Verifier cannot reproduce a finding, mark it as unconfirmed and exclude from report (or label it as "informational")._ - Possibly use a **triple-check** on critical data: e.g. if Detector found something via CodeQL, maybe also run a Semgrep rule for the same pattern to double-confirm (consensus between tools). This idea is like QLPro's triple-voting mechanism for classifying taint flows with multiple LLMs[\[42\]](https://arxiv.org/html/2506.23644v3#:~:text=analysis%20tools,grammatical%20correctness%20of%20vulnerability%20scanning), but here we apply it to multi-tool agreement to reduce single-tool bias.

### **Skill Interfaces (I/O contracts)**

For safe and reliable orchestration, each agent communicates via structured data (JSON/YAML) rather than free text as much as possible. Some example **schemas**:

- **AttackSurface (Repo Profiler → Orchestrator/ThreatModeler):** e.g.
- entry_points:  
    \- type: HTTP Route  
    route: "POST /api/upload"  
    code_location: "src/Controllers/FileController.java:45"  
    \- type: CLI Option  
    name: "--config"  
    code_location: "main.c:120"  
    sensitive_sinks:  
    \- description: "Writes to /etc"  
    code_location: "src/util/FileUtil.java:88"  
    \- description: "executes shell command"  
    code_location: "scripts/deploy.sh:10"
- (This is just illustrative.)
- **Hypothesis (ThreatModeler → Detector):** e.g.
- {  
    "id": "HYP-1",  
    "description": "SQL Injection in searchBooks endpoint",  
    "code_locations": \["BookController.java:120"\],  
    "verification_plan": "Try sending a quote in the search parameter to see if query fails or returns all data."  
    }
- The Detector might augment this with a specific static check: e.g. search in code for string concatenation with SELECT.
- **StaticFinding (Detector → Verifier):** e.g.
- {  
    "id": "FIND-1",  
    "hypothesis_id": "HYP-1",  
    "description": "Unsanitized SQL query construction",  
    "location": "BookController.java:118-130",  
    "evidence": "CodeQL alert: Data from URL param flows to SQL execute (path: BookController.java:120 -> BookDao.java:45)",  
    "severity": "High"  
    }
- The **evidence** field includes enough info for Verifier to act (like knowing which param is tainted). The Verifier can use that to craft input.
- **VerifiedVuln (Verifier → Orchestrator/Report):** e.g.
- {  
    "finding_id": "FIND-1",  
    "status": "confirmed",  
    "poc": {  
    "type": "http_request",  
    "request": "GET /api/books?search=test' OR '1'='1"  
    },  
    "runtime_output": "SQL error OR all books returned (indicating injection succeeded)",  
    "evidence": "See attached database log where query returns all entries without authorization."  
    }
- If not confirmed: "status": "unreproducible" with notes.
- **Report schema** might be a merge of Verified vulns plus analysis fields:
- vulnerabilities:  
    \- id: "FIND-1",  
    title: "SQL Injection in Book search",  
    severity: "High",  
    description: "User-provided search terms are directly concatenated into a SQL query in BookController.java, allowing an attacker to execute arbitrary SQL.",  
    impact: "Attackers can retrieve or modify all records in the Books database.",  
    poc: "GET /api/books?search=test' OR '1'='1",  
    fix: "Use parameterized queries or escape user input. E.g., use PreparedStatement with ? placeholder for the search term."  
    ...
- And maybe metadata like total findings, date, etc.

By enforcing these structured schemas, each agent's output can be programmatically validated (e.g., required fields present, types correct), reducing miscommunication.

In summary, this agentic design mirrors a human team: **Profiler** gathers initial data, **Threat Modeler** plans the attack, **Detector** digs through code with tools, **Verifier** proves the issues, and **Report Packager** writes it all up. The Orchestrator ensures they cooperate in order and that each potential result is cross-checked. Notably, multiple sub-agents can run concurrently where feasible (for speed) and the Orchestrator can re-invoke certain stages based on results (for thoroughness). This aligns with recent research frameworks like HarnessAgent which used an agentic loop to refine harnesses until they compiled and worked[\[43\]](https://arxiv.org/html/2512.03420v1#:~:text=Specifically%2C%20HarnessAgent%20combines%20compilation,21), and OpenAI's Aardvark which multi-staged analysis, validation, and patching[\[28\]](https://openai.com/index/introducing-aardvark/#:~:text=by,click%20patching). The ultimate goal is a **safety-first automation**: no claim without code proof, and continuous self-correction via these loops.

## Adapter Layer Specification for Different Languages/Frameworks

To achieve "universal" applicability, our pipeline uses a pluggable adapter for each language or framework. The adapter provides language-specific knowledge: how to build and run the project, what constitutes sources/sinks for taint analysis, common vulnerability patterns in that ecosystem, etc. Below, we outline the key adaptation points for several popular environments, and propose a minimal **YAML schema for the adapter**.

For each language/framework, we list:

- **Build/Run Commands Discovery:** How to detect and execute the project's build and tests.
- **Common Entry Points:** Typical places where untrusted input enters (sources) and how to enumerate them.
- **Typical Sources, Sinks, Sanitizers:** For taint analysis, what are the default sources (e.g. HTTP request fields, user forms) and sinks (e.g. database calls, OS commands) and any built-in sanitizers (e.g. frameworks providing encoding functions).
- **Test/Harness Templates:** Snippets or approaches to test typical components (e.g. how to send an HTTP request in that framework's context, or instantiate a controller).
- **Best Tool Choices:** Which static or dynamic tools work best or have ready rules for this environment.

We'll cover: **Java (Spring), JavaScript/TypeScript (Node.js with Express/Nest), Python (Django/Flask), Go (net/http), PHP (WordPress/Laravel), C/C++ (native with sanitizers/fuzzers), and Rust (with unsafe code)**.

### **Java (Spring Framework example)**

- **Build/Test**: Likely uses Maven or Gradle. The adapter checks for pom.xml or build.gradle. Build command: mvn package (or ./gradlew build). Test command: mvn test. The adapter might auto-enable the JaCoCo agent for coverage if needed, or download CodeQL Java DB via CLI.
- **Entry Points**: Spring MVC controllers (classes annotated with @Controller or @RestController, methods with @RequestMapping/@GetMapping etc). The adapter can parse annotations to list routes and the methods handling them. Also Spring Boot applications might have filters or message listeners (e.g. WebSocket or JMS).
- **Sources/Sinks/Sanitizers**:
- Sources: @RequestParam, @PathVariable, HTTP body data (@RequestBody), Servlet API calls like HttpServletRequest.getParameter().
- Sinks: database calls (JDBC templates, JPA repository methods), file system writes (Java IO), network calls, and dynamic execution (Runtime.exec).
- Sanitizers: Spring provides some - e.g. data binding may auto-convert types (not exactly sanitization), and there are libraries like Spring's HtmlUtils.htmlEscape for XSS. The adapter would list known sanitizing methods if any (for generic taint).
- **Test Templates**: JUnit with Spring's MockMvc for endpoints. E.g., a template to test a controller:
- @Test  
    void testXss() {  
    mockMvc.perform(get("/search?q=&lt;script&gt;alert(1)&lt;/script&gt;"))  
    .andExpect(status().isOk());  
    }
- Or using Spring's TestRestTemplate to call running app. For service-layer bugs, instantiate the class and call method directly in a JUnit.
- **Tools**:
- Static: **CodeQL** has strong Java support and includes many Spring-specific queries (e.g. it knows common deserialization sinks, etc.). **Semgrep** also has community rules for Spring (e.g. detecting open actuator endpoints).
- Dynamic: **Jazzer** (a fuzzing engine for JVM by Google) can be used to fuzz Java methods (especially if native parsing involved or just to brute-force inputs). **JUnit QuickCheck** or **jqf + Zest** could do property-based fuzzing on Java methods.
- The adapter might specify to use **SpotBugs/FindSecBugs** as an additional static scanner (FindSecBugs has specific Spring rules too), though CodeQL likely suffices.
- **Common Vuln Patterns**: The adapter notes things like "Spring MVC: watch for missing authentication on endpoints, XXE in XML parsers (if Spring not configured securely), Open redirect via Spring's redirect mechanism, etc." This helps Threat Modeler agent know what to consider.

### **JavaScript/TypeScript (Node.js with Express/NestJS)**

- **Build/Test**: For Node, detect package.json. Build might just be npm install. For TypeScript, also run tsc if needed. Tests: npm test (common frameworks like Jest or Mocha). Possibly start the app with node app.js or npm start. The adapter might spin up the server in a test mode for dynamic analysis.
- **Entry Points**:
- Express: routes defined via app.get('/path', handler) or router modules. The adapter can grep for .get(, .post( etc. NestJS: controllers annotated with decorators like @Get(), @Post(). Also consider WebSocket event handlers, if any.
- Other sources: JSON APIs, incoming HTTP headers, cookies - these all come via Express's req object.
- **Sources/Sinks/Sanitizers**:
- Sources: req.query, req.params, req.body, req.headers - basically any data from req is untrusted[\[34\]](https://semgrep.dev/blog/2025/a-technical-deep-dive-into-semgreps-javascript-vulnerability-detection/#:~:text=analysis%2C%20such%20as%20injection%20attacks%2C,sinks%20from%20the%20previous%20paragraph).
- Sinks:
  - Database queries (if using an ORM like Sequelize or Mikro-ORM, methods like findAll where raw SQL might slip in, or using connection.query with string).
  - File system (fs.writeFile), OS commands (child_process.exec).
  - Server-side rendering (if using templating engines, XSS sinks in res.render if data not escaped).
  - HTTP responses (res.send can be a sink for XSS if it reflects input).
  - In NestJS, also consider sinks like this.httpService.get(...) if SSRF, etc.
- Sanitizers: Node has libraries (e.g. express-validator for input validation, DOMPurify for HTML sanitization). The adapter can list any recognized ones (but often not built-in).
  - Also, ORMs parameterize queries (if used properly) - the adapter can note that prepared statements (like using ? in SQL with values array) are safe and thus not flagged as sinks.
- **Test Templates**:
- For Express: can use **Supertest** to simulate HTTP requests to the Express app without actually running a network server. A template:
- const request = require('supertest');  
    const app = require('../app');  
    test('SQLi in search', async () => {  
    const res = await request(app).get("/search?q=test' OR '1'='1");  
    expect(res.status).toBe(200);  
    });
- For NestJS: Nest provides a testing module to instantiate controllers. Or one can still use Supertest on the Nest app.
- The adapter might provide a harness to simply call endpoints, or even just call functions if logic is separated (for example, call controller methods directly with a mocked request object).
- **Tools**:
- Static: **Semgrep** is very useful here, as evidenced by Semgrep's own expansion for Node vulnerabilities[\[44\]](https://semgrep.dev/blog/2025/a-technical-deep-dive-into-semgreps-javascript-vulnerability-detection/#:~:text=To%20maximize%20impact%2C%20we%20focused,coverage%20for%20their%20backend%20applications)[\[35\]](https://semgrep.dev/blog/2025/a-technical-deep-dive-into-semgreps-javascript-vulnerability-detection/#:~:text=We%20analyzed%20popular%20npm%20libraries,found%20in%20the%20Semgrep%20documentation). They have rules covering Express, Koa, NestJS etc., e.g. detecting XSS in Express by finding res.send(userInput). **CodeQL** also supports JavaScript/TypeScript well; it has queries for things like NoSQL injection, prototype pollution, etc., and can model dataflow through JS (though taint in dynamic languages is trickier).
- **NodeJS-specific linters** like ESLint with plugin (some security ESLint rules exist) could also be included.
- Dynamic: For web routes, automated scanners like **OWASP ZAP** or **Burp** could fuzz parameters (the agent could orchestrate ZAP to run against a local dev server for common issues). However, in a whitebox context, writing targeted Supertest cases might be more precise. Fuzzers like **Jazzer.js** (an experimental Jazzer port for Node) or **fast-check** property testing can generate inputs for functions.
- **Common Patterns**: The adapter will note things such as "If using eval() or Function() on user input, that's dangerous", "Check for path traversal in any file access (like fs.readFile(req.query.file))", "In Express, ensure helmet middleware is used (missing it can be a finding for security headers)", etc.

### **Python (Django/Flask/FastAPI)**

- **Build/Test**: Detect a requirements.txt or pyproject.toml. Install deps in venv (pip install -r requirements.txt). Test: likely pytest or Django's manage.py test. If web app, we can run the development server (manage.py runserver for Django, or flask run).
- **Entry Points**:
- Django: URLs in urls.py mapped to view functions or class-based views; also Django REST Framework endpoints. Flask/FastAPI: routes via decorators @app.route(...) or @app.get(...).
- Other: command-line scripts (management commands), Celery tasks (if applicable), etc., but main is web routes.
- **Sources/Sinks/Sanitizers**:
- Sources: Django's request.GET, request.POST (or .data in DRF serializer), Flask's request.args, request.form, request.json, FastAPI's request parameters (which are function args via pydantic).
- Sinks:
  - Django ORM queries: if raw SQL is used (e.g. RawSQL or cursor executes).
  - Flask: any database calls (SQLAlchemy), OS calls via subprocess, file writes, etc.
  - Templating: Django autoescapes by default, but if something marked safe or using older templates, XSS can occur.
  - For all: sending untrusted data to eval() or to risky functions (like pickle.loads on client data -> RCE).
  - Django has specifics: e.g. the render() function with context (XSS if not autoescaped), redirect with user input (open redirect).
- Sanitizers:
  - Django: auto HTML escaping in templates, and the ORM automatically parameterizes queries (so using the ORM normally is safe from SQLi; only raw SQL usage or .extra() might be dangerous).
  - Flask: no built-in sanitization, but if using Jinja2 templates, they escape by default unless | safe is used.
  - The adapter would list functions like django.utils.html.escape or mark that Django ORM queries are safe unless using .extra or raw.
  - Also note Python standard library: e.g. urllib.parse.quote as a sanitizer for URLs, etc.
- **Test Templates**:
- For Django: use the Django test client. Template:
- from django.test import Client  
    def test_sqli():  
    c = Client()  
    response = c.get("/search/?q=test' OR '1'='1")  
    assert response.status_code == 200
- or if expecting failure, adjust assertion. Django's test client can simulate requests easily.
- For Flask: use app.test_client() similarly. FastAPI: use TestClient from FastAPI which is starlette TestClient.
- For lower-level functions, just call them. Python allows easy unit testing of internal functions.
- Hypothesis (property-based testing) can be used to generate inputs for a function. For example, if suspect a parsing function has edge cases, write a Hypothesis test to try random strings or structured data.
- **Tools**:
- Static: **Bandit** (Python security linter) can catch obvious issues (like use of eval, hard-coded passwords, etc.). **Semgrep** has many Python rules (including Django-specific ones) - e.g. detection of subprocess.Popen(request.data) or missing CSRF use. **CodeQL** covers Python and can do taint analysis through functions (it knows common frameworks to some extent; CodeQL's Python support includes Django model XSS sinks, etc.).
- There's also **Pylint plugins** or **Pyre (Facebook's static analyzer)** which has a taint mode for Python - but might be overkill to integrate.
- Dynamic: If running the web app, one can use ZAP for scanning. For logic bugs, writing direct tests is usually effective. Fuzzing: Python is dynamic and slower, but you can fuzz pure Python logic with Hypothesis or libraries like Atheris (Google's Python fuzzing engine which integrates with libFuzzer for C extensions).
- **Instrument for coverage**: coverage.py to measure if tests hit certain branches (if needed).
- **Common Patterns**: Adapter highlights things like "Django: check for unsafe usage of pickle or yaml.load on user input (deserialization vuln), missing @login_required on sensitive views (auth bypass), directory traversal in file serving (if using django.views.static.serve unsafely), etc.". For Flask, "ensure escape() used if injecting user input into HTML, be cautious with send_file (path traversal), etc."

### **Go (net/http web services or others)**

- **Build/Test**: Check for go.mod (Go module). Build: go build ./... (or just rely on tests). Test: go test ./... to run all tests. Many Go projects are libraries or command-line apps; if it's a web service, running it may require config.
- **Entry Points**:
- net/http servers: look for http.HandleFunc or mux.HandleFunc usage, or frameworks like Gin (e.g. router.GET("...")).
- gRPC services defined via .proto (entry points are RPC methods).
- CLI: if it's a CLI tool, entry is main() and arguments (os.Args).
- The adapter can parse main.go for starting servers or command parsing (e.g. using Cobra library).
- **Sources/Sinks/Sanitizers**:
- Sources: For web, r.URL.Query().Get(), r.FormValue(), reading request bodies (JSON decode into struct). For CLI, os.Args or environment variables.
- Sinks:
  - OS commands (using os/exec),
  - File system writes (os.WriteFile),
  - Network (if the program connects to other systems, SSRF potential),
  - For memory issues (though Go is memory safe, unsafe code or CGO could have memory issues).
  - Use of unsafe package or C interop is a special case - could cause memory corruption if misused.
  - For web apps, sinks also include responding with data (XSS in templates if using html/template incorrectly, though Go's html/template autoescapes by default, whereas text/template does not).
- Sanitizers:
  - Go has strong types, so certain issues are mitigated (SQL libraries use prepared statements by default often, e.g. database/sql with parameter markers).
  - However, if building SQL manually (string concatenation), that's a source of SQLi.
  - Go's standard html/template is a sanitizer for XSS (autoescapes).
  - The adapter notes that.
  - Also, no automatic memory mitigation needed usually (no manual freeing), but one could mention filepath.Clean to avoid path traversal when dealing with file paths.
- **Test Templates**:
- Use net/http/httptest. E.g.:
- req := httptest.NewRequest("GET", "/search?q=test' OR '1'='1", nil)  
    resp := httptest.NewRecorder()  
    router.ServeHTTP(resp, req)  
    if resp.Code != 200 { t.Fatal("Unexpected status") }
- Or directly call handler functions if they are exported.
- For non-web, just call functions from tests, possibly using table-driven tests.
- Fuzzing: As of Go 1.18+, native fuzz tests can be written:
- func FuzzParseImage(f \*testing.F) {  
    f.Add(\[\]byte{...}) // seed  
    f.Fuzz(func(t \*testing.T, data \[\]byte) {  
    ParseImage(data)  
    })  
    }
- The adapter can provide scaffolding for fuzz tests for target functions that take \[\]byte or string input (good for parsers).
- Also use go-fuzz or other fuzzers historically, but built-in is fine.
- **Tools**:
- Static: **Gosec** (golang security linter) is a must-include; it finds hardcoded credentials, use of exec, unsafe usage, etc. **Semgrep** has rules for Go as well (including detecting fmt.Sprintf into SQL query, etc.). **CodeQL** supports Go with dataflow and has queries for many common issues (path traversal, insecure TLS settings, etc.). Because Go is strongly typed, CodeQL can be effective in tracking flows (the CodeQL Go extractor is custom and handles Go's patterns)[\[45\]](https://spaceraccoon.dev/comparing-rule-syntax-codeql-semgrep/#:~:text=languages%2C%20it%20even%20instruments%20the,each%20language%E2%80%99s%20syntax%20naming%20conventions).
- **Source code property graph**: One could use Joern for Go too, if needed, but likely CodeQL covers it.
- Dynamic: **go test -fuzz** (native fuzzing) for any interesting parsers. **Delve** (debugger) if manual dynamic analysis needed, but typically not unless writing exploits for memory corruption via unsafe.
- For web, one can run the service and use HTTP scanners (though Go web frameworks not as widely used for huge apps as others, but still possible).
- If the app is concurrent, race detector (go test -race) can catch data races that are sometimes security issues.
- **Common Patterns**: The adapter highlights "typical Go vulns: SQL injection via fmt.Sprintf on user input for queries, Command injection via exec.Command if using user input in args, directory traversal if using http.FileServer with user-provided paths (should use filepath.Clean), misuse of crypto/rand vs math/rand (predictable tokens), etc." Also for any use of unsafe.Pointer or Cgo - note to inspect those carefully for memory safety issues.

### **PHP (WordPress, Laravel, etc.)**

- **Build/Test**: Check for composer.json. Install deps with Composer. No compilation needed (just runtime). Test: maybe PHPUnit tests if provided (vendor/bin/phpunit). If WordPress plugin/theme, it might not have tests, one may need to set up a WP environment or analyze statically.
- **Entry Points**:
- In generic PHP web apps: any .php file accessible via URL is an entry (common in older code).
- Frameworks like Laravel: routes defined in routes files (routes/web.php), controllers under app/Http/Controllers.
- WordPress: entry via various hooks (like admin-post.php endpoints, or form handlers).
- The adapter for WordPress specifically might parse plugin code for uses of add_action('init', ...) or handling of \$\_POST etc.
- **Sources/Sinks/Sanitizers**:
- Sources: \$\_GET, \$\_POST, \$\_COOKIE, \$\_SERVER superglobals (these contain user input). Also file uploads in \$\_FILES. In frameworks, often these map to request objects but ultimately same data.
- Sinks:
  - SQL queries (if using raw mysqli or PDO without prepared statements, or WP's \$wpdb->query).
  - File includes (include/require with variable - leads to RFI/LFI).
  - Eval of user input (very dangerous, often exploited).
  - echoing user input (XSS if not escaped).
  - Commands via system(), exec().
  - PHP unserialize on user input (very common vuln leading to object injection).
- Sanitizers:
  - PHP has many but usage varies. e.g. mysqli_real_escape_string for SQL (though better to use prepared statements).
  - htmlspecialchars for XSS output encoding.
  - WordPress has an entire library of sanitization and escaping functions (sanitize_text_field, esc_html, etc.) - the adapter should list these as sanitizers (so the static analysis doesn't flag if these are used).
  - Laravel auto-escapes in Blade templates for XSS (except if one uses {!! !!} to inject raw HTML).
  - Also Laravel's query builder parameterizes queries, so SQLi mainly if using raw DB queries with string interpolation.
- **Test Templates**:
- For pure PHP, one can create small PHP scripts to include the target file and simulate \$\_GET parameters. But this is tricky without a web server.
- Perhaps better to rely on static/dynamic analysis rather than truly executing the whole web app (setting up a full runtime may be complex).
- If tests are present (PHPUnit), run them. Or create a simple PHPUnit test that instantiates a controller and calls a method (Laravel allows some of that with application instance).
- Alternatively, use a headless browser or HTTP client to hit endpoints (if the app can be run with PHP's built-in server php -S for example).
- Fuzzing: Not common for PHP due to performance, but one could fuzz via HTTP requests using a tool.
- There exist PHP fuzzers (like GoReplay for traffic fuzzing or custom scripts) but rare.
- **Tools**:
- Static: **Psalm** or **Phan** (static analyzers for PHP) with security plugins, **PHPStan**. But particularly, **Semgrep** has many PHP rules (including for WordPress API misuse, Laravel, etc.).
- **PHP CodeSniffer** with a security ruleset could catch some issues.
- **RIPS** was a well-known PHP SAST (now commercial), but the open-source variant no longer updated. The community might rely on Psalm and others now.
- **Joern** can be used for PHP if converted to CPG (some research have done that, but not sure of current support).
- **CodeQL** as of now (2026) does not officially support PHP (there was community support, but not sure how mature). Possibly not available out-of-box, so we lean on Semgrep and Psalm.
- Dynamic: Not many general dynamic analyzers. One can use integration testing: simulate HTTP requests and see if any output contains e.g. injected script (for XSS). Or instrument the PHP runtime with something like Suhosin (older) or custom wrappers to catch dangerous calls.
- In practice, manual verification is often done (e.g. run the PoC on a dev instance).
- If doing variant analysis of known vulns: e.g. search for known vulnerable patterns in WP plugins across many repos (this is something CodeQL MRVA can't do due to no PHP, but Semgrep can in theory run across multiple repos).
- **Common Patterns**: The adapter notes "WordPress: check for nonces on forms (CSRF protection), use of admin_ajax.php actions without capability checks (privilege escalation), unsanitized use of \$\_POST in SQL queries, arbitrary file upload handling (unrestricted file upload), etc." For Laravel: "Mass assignment (if not using guarded fields, attackers can overwrite fields they shouldn't) - check for \$guarded vs \$fillable in models, SQL injection via raw queries, unsafe unserialize() of user data (rare in Laravel but possible)."

### **C/C++ (native code with Sanitizers and Fuzzers)**

- **Build/Test**: Look for Makefile, CMakeLists.txt, or configure script. Use appropriate build (e.g. cmake . && make or just make). Possibly enable sanitizers: the adapter can inject -fsanitize=address,undefined into CFLAGS/CXXFLAGS for a special build if possible[\[24\]](https://googleprojectzero.blogspot.com/2016/06/#:~:text=For%20example%2C%20we%20have%20extensively,instrumentations%2C%20which%20drastically%20improved). Tests: maybe a make test or if using CTest, or just run any provided binaries with --help to see functionality.
- **Entry Points**:
- If it's a library: entry points are the API functions.
- If an application: main arguments, network sockets (if it opens ports), file inputs.
- For kernel code (if any, or drivers), entry might be IOCTL handlers (that's specialized; typically not in userland programs).
- Essentially, any function processing external data (parsing a file, reading from network) is an entry for untrusted input.
- Adapter could look for functions like int main(, or functions that read from argv or fread etc.
- **Sources/Sinks/Sanitizers**:
- Sources: Data from read(), recv(), fgets(), etc., any file or network input, command-line args (argv), environment variables.
- Sinks:
  - **Memory corruption sinks**: functions that are dangerous if input is wrong: e.g. strcpy, strcat, sprintf (can overflow), sscanf, any pointer arithmetic or array indexing that could go out of bounds.
  - System calls: system() for command execution (if input goes there, command injection).
  - Function pointers or calls that could be hijacked if input influences them (rare beyond corruption).
  - For format string vulnerabilities: printf(input) without format string literal is a sink.
  - Any place where input length is used in allocations (heap overflow potential if wrong).
- Sanitizers:
  - At code level, use safer functions: snprintf, strlcpy, etc. The adapter might treat those as mitigated sinks (less likely to overflow but still need correctness).
  - Compiler/runtime sanitizers (AddressSanitizer, etc.) are not exactly sanitizers of input but detection tools (the adapter ensures these are on to catch issues).
  - If code uses bounds-checking (like checking length before copying), that's effectively sanitization logic - static analysis can recognize certain patterns as validating input.
  - The adapter could encode common safe library usage: e.g. use of fgets(buffer, size, stdin) is safe if used correctly vs gets() which is unsafe.
- **Test/Harness Templates**:
- Unit tests: If the project has none, one can create a small harness calling suspected vulnerable functions with sample data. For memory safety, often fuzzers are used rather than manual test for each input.
- Fuzzing: This is prime territory. Harness templates:
  - **libFuzzer target**:
  - extern "C" int LLVMFuzzerTestOneInput(const uint8_t\* data, size_t size) {  
        // call target function with data  
        parseImage(data, size);  
        return 0;  
        }
  - Then compile with libFuzzer and run.
  - **AFL++**: Could compile and feed input via stdin or file.
  - **Honggfuzz** or others similarly.
  - The adapter might have a list of functions that look like parsers (e.g. functions with signature (const uint8_t\*, size_t) or that take a filename) and automatically generate basic libFuzzer harness code for them. Recent research and tools like _HarnessAgent_ and _OSS-Fuzz LLM framework_ do exactly this: using the code context to produce harnesses[\[25\]](https://adalogics.com/blog/minimal-llm-based-fuzz-harness-generator#:~:text=For%20the%20purpose%20of%20simplicity%2C,a%20harness%20would%20be%20to)[\[46\]](https://google.github.io/oss-fuzz/research/llms/target_generation/#:~:text=Image%3A%20experiment%20framework).
- If not fuzzing, write specific tests:
  - e.g. for an overflow, create an input array slightly above the boundary and see if function misbehaves (but often better just fuzz).
- **Symbolic execution** (KLEE, Angr): can systematically explore code paths for certain small modules, but might be overkill or not scale.
- **Tools**:
- Static: A wealth of analyzers:
  - **CodeQL** (C/C++ support is robust; it can find buffer overflows, use-after-free patterns if you write queries, though it's heavy).
  - **Semgrep** can catch dangerous function calls but is limited in tracking conditions.
  - **Joern** is very suited for C/C++: it was originally built for this. With Joern, one can query for patterns like in the Praetorian example: find strcpy calls that are not preceded by a size check[\[22\]](https://www.praetorian.com/blog/why-you-should-add-joern-to-your-source-code-audit-toolkit/#:~:text=.unsanitized%28%7Bit._%28%29.or%28_%28%29.isCheck%28%27.). The NameWreck research even provided a Joern query library for DNS vulns[\[47\]](https://www.forescout.com/research-labs/namewreck/#:~:text=,related%20vulnerabilities).
  - **clang Static Analyzer** or **Cppcheck** or commercial ones (Coverity, etc.) if available. For open pipeline, maybe include **Infer** (Facebook's analyzer) which can find memory errors and null dereferences.
  - **Sanitizers (runtime)**: AddressSanitizer, UndefinedBehaviorSanitizer, MemorySanitizer (for uninitialized reads) - these are dynamic, but we include them as part of build to catch issues during fuzz or test execution.
  - **Valgrind** can be used on test runs to catch memory leaks or overruns, albeit slower.
- Dynamic:
  - **Fuzzers**: AFL++, libFuzzer, Honggfuzz, etc., as mentioned.
  - For concurrency issues, **ThreadSanitizer** if multi-threaded.
  - For use-after-free, ASan helps; also **HWASan** (hardware-assisted) if available for large applications.
  - The adapter might integrate with **OSS-Fuzz** if this is an open source project - meaning providing harnesses and such to run on Google's infra (though in our agent context, we likely run fuzz locally).
- **Common Patterns**: Adapter calls out things like "Look for off-by-one errors, especially in loops iterating over buffers; integer overflow when calculating buffer sizes (CWE-190) leading to heap overflow on allocation; format string vulnerabilities (printf(userInput) if any); classic unsafe libc functions (strcpy, gets, scanf with %s, etc.); improper use of strncpy (which doesn't guarantee null termination) - could still cause issues." For C++, "check object lifetime issues, use of new\[\]/delete mismatches, etc." And any usage of user-controlled data in risky APIs.

### **Rust (with unsafe code)**

- **Build/Test**: Detect Cargo.toml. Build with cargo build (possibly include --release for optimizations if fuzzing to get speed, but for debug builds, include overflow checks). Test: cargo test.
- **Entry Points**: If it's an app: fn main(). If library: public functions (especially those marked pub that might be used by outside code). Also any FFI (extern "C" functions if it's providing to C, or calls to external libs).
- **Sources/Sinks/Sanitizers**:
- In safe Rust, memory safety is enforced, so sources/sinks in terms of memory corruption are mostly in unsafe blocks or FFI boundaries.
- Sources: external inputs via function arguments, file reads, network (e.g. using std::net), etc.
- Sinks:
  - If unsafe is used: pointer dereferences, raw pointer arithmetic, slice::get_unchecked etc. Those are places where a bad input could cause UB if proper checks aren't done around the unsafe.
  - If interacting with C via FFI, any call to C (which might expect certain properties) can be a sink for mis-use.
  - For logic vulnerabilities (not memory), similar to other languages: e.g. if web server in Rust (using Actix, Rocket), then we consider injection, etc. But Rust's ecosystem often auto-sanitizes SQL (diesel ORM, for instance, uses prepared statements).
  - Another sink: integer overflow if relying on wrapping (though Rust in debug checks overflow at runtime and in release wraps by default - consider if that matters for security).
- Sanitizers/mitigations:
  - Rust by default prevents a lot: e.g. buffer overflow can only happen in unsafe code. So the adapter focuses on auditing unsafe blocks.
  - There's a tool **Miri** (the Rust interpreter) that can detect undefined behavior in unsafe code (like invalid pointer usage) at runtime, acting like a sanitizer for Rust.
  - Rust's standard library has safe alternatives to most C risky functions, so if using them normally, you're fine. (No direct analog of gets, etc.)
  - However, if using third-party C libraries via FFI, need to rely on their safety.
- **Test/Harness Templates**:
- Standard unit tests in Rust (with #\[test\] functions) can call public APIs with certain inputs.
- Fuzzing: Use **cargo-fuzz** (which integrates libFuzzer for Rust). Write a target that calls a function with arbitrary data. For example, if fuzzing a parsing function:
- fuzz_target!(|data: &\[u8\]| {  
    let_ = parse_image(data);  
    });
- Then run cargo fuzz run fuzz_target_name.
- Property-based: **proptest** crate can generate random structured inputs for tests.
- If vulnerability is logic (e.g. some authentication bypass in a Rust web service), just write integration tests or use the web client (similar to how we'd test in Python or Go).
- **Tools**:
- Static: Rust has **Clippy** (linter) which can catch some common mistakes (not security-specific mostly). For unsafe analysis: **cargo-geiger** shows how much unsafe code and where, which is a good starting point - high unsafe usage sections deserve scrutiny.
- There are some static analyzers: e.g. **Prusti** (a verifier), but that's more researchy. Or **Mirai** (Facebook static analyzer for Rust), which checks for certain issues including some security properties.
- For now, manual code review of unsafe might be the approach, aided by the fact that unsafe blocks are clearly marked.
- Dynamic: **Miri** can be run on test cases to catch UB. Also, running with address sanitizer is possible for Rust (set RUSTFLAGS="-Zsanitizer=address" and use nightly with -Zsanitizer features to instrument - a bit advanced, but doable).
- Fuzzers as mentioned (cargo-fuzz).
- If it's a web app in Rust (like Rocket), dynamic testing as per web (though Rocket has protections and type safety, e.g. it won't allow an unescaped HTML by default unless explicitly).
- **Common Patterns**:
- The adapter emphasizes checking all unsafe: Are there proper bounds checks around them? Use of mem::transmute (strict aliasing violations?), manual implementations of Send/Sync (could cause data races).
- Another vulnerability class in Rust is **logic bugs** like forgetting to enforce some authorization (Rust doesn't automatically handle that).
- Also, concurrency issues (data races possible in unsafe or if incorrectly using Arc&lt;Mutex&gt; etc).
- If it's a smart contract in Rust (like Solana programs), that's another area (but out of scope of general pipeline).
- Summarize: "Focus on unsafe code for memory safety (potential for buffer overreads/writes, null deref if using raw pointers, etc.), and typical logic issues (in web contexts or CLIs as per other languages). Rust's strong safety guarantees mitigate many bug classes, so the search space is narrower but not zero (e.g., there have been Rust CVEs due to unsafe code or design flaws)."

### **Minimal Adapter Schema**

We propose a simple **YAML schema** for defining language/framework-specific info. This allows adding new adapters easily. For example:

language: "Java"  
framework: "Spring Boot"  
build:  
build_system: "maven"  
build_command: "mvn package -DskipTests"  
test_command: "mvn test"  
entry_points:  
\- type: "web_route"  
pattern: "@RequestMapping" # pattern to find in code  
description: "Spring MVC Controller methods"  
\- type: "sink_function"  
pattern: "System.exit"  
description: "Calls that terminate the app (just example)"  
sources:  
\- "javax.servlet.http.HttpServletRequest.getParameter"  
\- "org.springframework.web.bind.annotation.RequestParam" # annotation indicating source  
sinks:  
\- "java.sql.Statement.execute" # SQL execution  
\- "java.lang.Runtime.exec" # command execution  
\- "org.springframework.web.servlet.ModelAndView" # (sink for view injection maybe)  
sanitizers:  
\- "org.springframework.web.util.HtmlUtils.htmlEscape"  
\- "org.apache.commons.text.StringEscapeUtils.escapeHtml4"  
patterns:  
dangerous_functions:  
\- "strcpy" # For C, as an example (would be in C adapter)  
\- "System.out.printf" # For Java, if formatting user input  
framework_specific:  
\- "spring.security.disabled" # if a config indicates security off  
preferred_tools:  
static:  
\- "CodeQL:java"  
\- "Semgrep:java"  
dynamic:  
\- "Jazzer" # fuzzing for JVM  
\- "JUnit" # unit testing

This is an illustrative snippet. The schema would include:

- language and optional framework name.
- Build info: how to compile/test.
- entry_points: list of entry types, each with a pattern or identifier to locate them (this could be a code regex or a semantic pattern).
- sources: functions or methods that produce untrusted data (for taint analysis starting points).
- sinks: functions that are dangerous if tainted data reaches them (taint analysis endpoints).
- sanitizers: functions that neutralize data (if data flows through them, taint can be considered cleaned).
- patterns: maybe some generic things to look for (dangerous calls, or framework misconfigurations).
- preferred_tools: suggestions of which static and dynamic tools to use for this environment (so the orchestrator knows, e.g., use CodeQL for Java but maybe not for PHP since not supported, etc).

Each adapter file can be loaded by the Orchestrator when a new repo is analyzed. If a repository is multi-language (say a JS frontend and a Go backend), the orchestrator might load multiple adapters and apply each where relevant.

The **minimal part** is that to add a new language, one just creates such a YAML with key patterns. Even if not extremely detailed, having sources/sinks defined massively helps the Detector agent for writing correct queries (e.g., it can plug these into a CodeQL or Semgrep generic taint query template). Indeed, this approach is similar to how Semgrep's taint mode requires specifying sources and sinks[\[48\]](https://semgrep.dev/blog/2021/taint-mode-is-now-in-beta#:~:text=Taint%20mode%20is%20now%20in,now%20resort%20to%20any), or CodeQL's libraries define sources/sinks per framework.

**Example:** For **Laravel (PHP)**, the adapter would list \$\_GET, \$\_POST as sources (and Laravel's Request facade methods), sinks like DB::raw or unserialize, sanitizers like e() (Blade escape), etc., plus note build is composer, test perhaps phpunit.

**Universal Coverage Definition:** In context, "universal coverage" means our methodology strives to **cover all reachable code and all major vulnerability categories** for a target. Practically, we interpret this as: - Every entry point (as identified in attack surface mapping) is examined by at least one analysis (static or dynamic) so that no part of the externally-facing functionality is missed. - Both **low-level bugs** (memory safety, resource errors) and **high-level bugs** (auth logic, injection flaws) are addressed by appropriate techniques. - It doesn't literally mean 100% test coverage of lines (which is often infeasible), but rather **comprehensive coverage of attack vectors**. E.g., in a web app, universal coverage implies checking for OWASP Top 10 categories across all endpoints (SQLi, XSS, CSRF, etc.), checking business logic invariants, and also doing deep dive in any native components (like a C module). - The adapter's role in universal coverage is to ensure that for each ecosystem, we know what those categories and entry points are (so we don't, say, forget to check file uploads in an app that has them, or forget to run a fuzzer on a custom file format parser). - Therefore, universal coverage is achieved when the **union of static analysis rules, dynamic tests, and fuzzing harnesses covers the union of all potential vulnerability sinks in the program**. We use the adapter to systematically enumerate those sinks per tech stack.

The minimal adapter layer per language makes achieving near-universal coverage feasible by leveraging community knowledge of that stack's pitfalls, rather than starting from scratch for each new project. It's essentially encoding secure code review checklists into machine-readable form for the agent.

## Concrete Artifact Templates

Finally, we define some template artifacts that the system (or a human following this methodology) would produce. These ensure consistency and completeness in results and make automation easier.

### **Evidence Pack / Report Template**

A recommended **REPORT.md** structure (for a single vulnerability research engagement) is as follows:

**Title:** _Vulnerability Research Report for \[Project Name\]_ - with date and researcher/agent info.

**Summary:** A bullet list summarizing how many issues found, their severity, and an overall risk posture.

**Table of Findings:** (if multiple vulns) - e.g.:

| ID  | Vulnerability | Severity | Status (Fixed/Reported) |
| --- | --- | --- | --- |
| V-1 | SQL Injection in search endpoint | High | Reported (not fixed yet) |
| V-2 | Buffer Overflow in image parser | Critical | Patch provided |
| ... | ... | ... | ... |

Then for each vulnerability, a detailed section:

**V-1: SQL Injection in /search API**  
\- **Description:** _The search endpoint fails to sanitize user input in the_ q _parameter before using it in a SQL query. An attacker can inject SQL to retrieve or modify data._  
\- **Affected Code:** src/BookController.java line 120 in method searchBooks[\[49\]](https://spaceraccoon.dev/comparing-rule-syntax-codeql-semgrep/#:~:text=CodeQL%20uses%20the%20QL%20language%2C,clauses) (constructs an SQL query string with user input).  
\- **Impact:** _Attackers can execute arbitrary SQL. In testing, using_ ' OR '1'='1 _as the search term exposed all records from the_ books _table._ This can lead to data leakage or data tampering[\[50\]](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2019/CVE-2019-13720.html#:~:text=Based%20solely%20on%20the%20vulnerability%2C,using%20static%20analysis%20tools%20too).  
\- **Proof of Concept:**  
1\. Run the application and log in as any user (or no auth needed, if none required).  
2\. Issue an HTTP GET request to /api/search?q=test' OR '1'='1.  
3\. Observe that the response contains all books in the database, indicating the query was not filtered (see response snippet in Appendix A).  
The following curl command demonstrates the exploit:  

curl "<http://localhost:8080/api/search?q=test'%20OR%20'1'%='1>"

\- **Evidence:** The database logs show the query SELECT \* FROM books WHERE title LIKE 'test' OR '1'='1'[\[51\]](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2019/CVE-2019-13720.html#:~:text=In%20their%20POC%2C%20at%20line,attackers%20to%20look%20at%20the), confirming the injection. No errors were generated, implying the input was executed as part of SQL. (Appendix B contains the full SQL log and the list of records returned).  
\- **Root Cause:** _Improper construction of SQL query using string concatenation._ The code does:  

String sql = "SELECT \* FROM books WHERE title LIKE '" + query + "'";  
stmt.execute(sql);

There is no use of prepared statements or escaping on query.  
\- **Remediation:** _Use parameterized queries._ For example, using JDBC PreparedStatement:  

PreparedStatement ps = conn.prepareStatement(  
"SELECT \* FROM books WHERE title LIKE ?");  
ps.setString(1, query);  
ResultSet rs = ps.executeQuery();

This ensures any special characters in query are treated as data, not SQL syntax. Alternatively, escape the user input with proper library calls[\[13\]](https://spaceraccoon.dev/comparing-rule-syntax-codeql-semgrep/#:~:text=The%20reason%20for%20this%20is,patterns%20in%20Semgrep%E2%80%99s%20rule%20syntax), but parameterization is preferred.  
\- **Verification of Fix:** A test (see Appendix C) was created and run after applying the fix. The injection attempt now yields no results (as the literal string test' OR '1'='1 is searched, which matches nothing) - resolving the issue. The test passes, confirming the vulnerability is fixed.

_(The report would continue with V-2, V-3, etc. in similar detail.)_

**Appendices:**  
\- **Appendix A:** HTTP response for PoC of V-1 (excerpt)  
\- **Appendix B:** Log extract of SQL queries executed during PoC  
\- **Appendix C:** Code diff or test code for verifying fix of V-1  
\- ... etc.

This template ensures each vuln section has: Description, Affected Code (with file:line citation), Impact, PoC steps, Evidence (like logs or dumps), Root Cause explanation (with code snippet ideally), Fix suggestion (and possibly a patch or diff), and a note on how the fix was validated.

For a simpler evidence pack (if just handing off to devs), one might not include the fix verification, but as per our methodology, we do verify fixes when possible[\[52\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=3).

### **Hypotheses Schema Template**

During the process, we maintain a hypotheses list, possibly in a JSON/YAML format for internal tracking and to feed into Detector agent. A template entry:

id: HYP-001  
description: "Possibility of authentication bypass in order management"  
target_code: "OrderController.java"  
details: |  
Order endpoints like /api/order/cancel might be accessible without a valid user session.  
We should check if these endpoints verify the requester owns the order or is an admin.  
verification_plan:  
static_checks:  
\- "Look for usage of @PreAuthorize or manual checks in OrderController methods."  
\- "If none, any user input order ID might be processed regardless of ownership."  
dynamic_tests:  
\- "Attempt to cancel another user's order with a normal user account."  
\- "Observe response or database change."

The schema fields: - id: unique hypothesis id. - description: concise statement of the potential issue. - target_code: where (file/module) this is expected. - details: longer reasoning behind hypothesis. - verification_plan: what to do to confirm or refute it, split into static and dynamic as needed.

This schema can be shared with the Detector agent (for static plan) and Verifier (for dynamic plan).

### **Verified Finding Schema**

Once verified, each finding can be stored/communicated in a structured way, e.g.:

{  
"id": "VULN-001",  
"title": "SQL Injection in searchBooks",  
"severity": "High",  
"status": "Confirmed",  
"description": "Unsanitized user input from 'q' parameter is concatenated into an SQL query in BookController, allowing SQL Injection\[17\].",  
"evidence": {  
"poc_request": "GET /api/search?q=test' OR '1'='1",  
"response_snippet": "&lt;all books data&gt;",  
"log_snippet": "WHERE title LIKE 'test' OR '1'='1'\[51\]"  
},  
"affected_locations": \[  
{  
"file": "src/BookController.java",  
"line": 118  
},  
{  
"file": "src/BookDAO.java",  
"line": 45  
}  
\],  
"root_cause": "Use of string concatenation for SQL query without input validation.",  
"recommendation": "Use parameterized queries or escape the input.",  
"references": \["CWE-89", "OWASP-ASQLi"\],  
"reported_to": "maintainer via email on 2026-01-15"  
}

This JSON could be part of an API if the system integrates with bug trackers or knowledge base. It includes all key aspects: what, severity, where, proof, fix suggestion, references (like CWE id or OWASP link for context), and status (if reported or fixed).

### **CodeQL Query Skeleton + Modeling Checklist**

CodeQL queries are written in QL with imports from standard libs. A skeleton for a new taint query:

/\*\*  
\* @name SQL query built from user input  
\* @description Detects string concatenation that builds an SQL query using user-controlled input.  
\* @kind path-problem  
\* @tags security, external/cwe/cwe-089  
\*/  
import java  
import DataFlow::PathGraph  
<br/>class UserInput extends TSource { UserInput() { this.hasLocationInfo() and  
exists(Method m |  
m.getDeclaringType().getPackage().matches("javax.servlet.http") and  
this.asExpr() = any(Parameter p | p.getName() = "request").getAnAccess() // some way to identify request parameter  
)  
} }  
<br/>class SqlExecution extends TSink { SqlExecution() { this.getTarget().getType().getName() = "Statement" and  
this.getCall().getName() = "execute"  
} }  
<br/>from DataFlow::PathNode source, DataFlow::PathNode sink  
where DataFlow::localTaint(SourceNode::source(), SinkNode::sink(), source, sink)  
select sink.getNode(), source, sink, "User input flows to SQL execution here."

_(Note: this is pseudo-QL for brevity; real QL would use the Java Libraries, e.g._ Expr e; e.instanceof(ConcatExpr) _and DataFlow::Configuration etc.)_

**Modeling Checklist for CodeQL (Java example)**: - \[ \] Identify sources (possibly define a class extending SourceNode for HTTP params). - \[ \] Identify sinks (e.g. any Statement.execute or EntityManager.createQuery with string). - \[ \] Ensure sanitizers (if any) are modeled (in CodeQL, you'd specify a sanitizer step or barrier if using an escaping function). - \[ \] Configure DataFlow library (if not using default) to include custom sources/sinks. - \[ \] Test query on small examples to ensure it flags the intended pattern and not too many false positives (adjust maybe .noSanitization() conditions, etc.). - \[ \] Add @tags and CWE reference in the metadata. - \[ \] Mark precision (e.g. @precision high if we expect few false positives).

For our purpose, the template above gives a starting structure. The Detector agent would fill in specifics (like actual identification of user input expressions using the CodeQL standard library for Servlets or Spring).

### **Semgrep Rule Skeleton + Common Patterns**

Semgrep rules are YAML. A skeleton for a similar case (SQLi in Java):

rules:  
\- id: java_sqli_string_concat  
languages: \[java\]  
message: "Potential SQL injection: building SQL query with user input"  
severity: ERROR  
patterns:  
\- pattern-either:  
\# pattern for string concatenation assigned to a SQL query  
\- pattern: |  
\$STMT = \$CONN.createStatement();  
\$STMT.executeQuery("SELECT \$COLS FROM \$TBL WHERE \$FIELD = " + \$INPUT + \$REST");  
\- pattern: |  
String \$query = "SELECT \* FROM " + ... + \$INPUT + ...;  
\$STAT.execute(\$query);  
metavariables:  
\$INPUT:  
metavariable-regex: "request.getParameter\\\\(\\".\*\\"\\\\)" # any use of getParameter (rough filter)

This is a bit simplistic; a real rule might need multiple patterns. But skeleton highlights: - pattern-either to capture different ways (assignment vs direct call). - Use of \$INPUT metavariable, possibly constrained to known source patterns (like request.getParameter). - Simpler than CodeQL but less precise.

**Common patterns snippet library**: We might maintain a library of small Semgrep rules for frequent issues: - Hardcoded password: pattern: String \$PW = "\$SECRET"; with regex for SECRET. - Command exec: pattern: Runtime.getRuntime().exec(\$X) where \$X is tainted. - Insecure crypto: usage of MD5 or SHA1 classes. - For each, a template Semgrep YAML to adapt.

### **Joern Query Pattern Snippets**

Joern queries can be written in Scala or using the Python joerntools. A pattern for buffer overflow: In Joern's Scala-like DSL (CPGQL):

// Find calls to strcpy where the length of source is not checked  
val strcpyCalls = cpg.call("strcpy").argument.order(2) // second argument is source  
// Check if there's a length check involving that argument in control flow above  
strcpyCalls.not(  
\_.controlledBy.isCall.name("strlen").argument.codeExact(\_)  
)

(This is pseudo-code for concept: meaning find strcpy(dst, src) where in the control flow predecessors there's no if (strlen(src) < ...).)

A simpler Gremlin variant (from the earlier Praetorian example):

getCallsTo("strcpy").as('call')  
.where(not(  
\_.ast.isCallWithName("strlen").where(\_.argument.code = call.argument1.code)  
))  
.locations()

This tries to ensure there's no strlen of the same argument.

We'd template Joern queries by dangerous function: - For each unsafe function (memcpy, strcpy, sprintf, etc.), a snippet that checks for absence of common sanitizers (like a prior length check or use of safe version). - For use-after-free, a snippet might search for functions where pointer freed then later used (that's more complex - dataflow in Joern). - Joern's query language can express flows too, using data-flow graph or tracking definitions.

**Joern variant analysis snippet:** If we had a patch diff (like a function changed to add a check), one could encode the pattern of the fix as a query to find other places missing that check.

E.g., patch adds if(x != NULL) ... before a use of x. The query could search for uses of x pointer without preceding null-check conditions.

We won't detail fully, but the idea is templates focusing on: - Buffer operations with missing bound checks, - Pointer arithmetic in loops (potential off-by-one), - Dangerous syscalls (e.g., strncpy with length equal source length is still dangerous if not null-terminated), - We can incorporate open-source Joern queries like those from NameWreck[\[47\]](https://www.forescout.com/research-labs/namewreck/#:~:text=,related%20vulnerabilities) as templates for similar bugs (e.g. DNS ID field not random, etc. - but those are specific).

### **Harness Templates (Fuzzing and Tests)**

We provide basic code templates for fuzz harnesses in various languages:

- **C/C++ libFuzzer:**
- #include &lt;stdint.h&gt;  
    #include &lt;stddef.h&gt;  
    extern "C" int LLVMFuzzerTestOneInput(const uint8_t\* data, size_t size) {  
    // Call target function with data  
    if(size > 0) {  
    target_function(data, size);  
    }  
    return 0;  
    }
- Possibly with multiple targets, we'd generate one per target function or combine.
- **C/C++ AFL++:** If target reads from stdin or file, AFL can be used without code changes. Otherwise, one can write a main that reads stdin into a buffer and calls target_function.
- **Jazzer (JVM):** Jazzer uses a static fuzzerTestOneInput:
- import com.code_intelligence.jazzer.api.FuzzedDataProvider;  
    public class TargetFuzzTest {  
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {  
    try {  
    String input = data.consumeString(1000); // or consumeBytes etc.  
    TargetClass.parse(input);  
    } catch (Exception e) {  
    // allow exceptions, Jazzer will catch crashes separate if it's an error  
    }  
    }  
    }
- The adapter can fill TargetClass.parse with the actual function to fuzz, and choose appropriate consume method for type (string vs bytes vs ints).
- **Go native fuzz (since 1.18):**
- import "testing"  
    func FuzzTargetFunction(f \*testing.F) {  
    f.Fuzz(func(t \*testing.T, data \[\]byte) {  
    TargetFunction(data)  
    })  
    }
- If target expects a struct or combination, one might decode data or split.
- **Python Hypothesis (property-based, not exactly fuzz but close):**
- from hypothesis import given, strategies as st  
    @given(st.binary())  
    def test_fuzz_parse(data):  
    try:  
    parse_image(data)  
    except Exception as e:  
    \# If we consider any exception a failure, we can fail the test:  
    \# assert False, f"Crash with data: {data}"  
    \# Or allow certain exceptions if expected.  
    pass
- Hypothesis will try to find minimal failing input for which parse_image crashes or violates an invariant.
- **Python AFL (using atheris, an instrumented fuzzer by Google):**
- import atheris  
    def TestOneInput(data: bytes) -> None:  
    try:  
    parse_image(data)  
    except Exception as e:  
    \# optionally: raise or just let it throw  
    raise  
    if \__name__ == "\__main_\_":  
    atheris.Setup(sys.argv, TestOneInput)  
    atheris.Fuzz()
- This is more heavy but effective for native extension fuzzing.
- **Rust cargo-fuzz:** The template (if using their macro) is:
- fuzz_target!(|data: &\[u8\]| {  
    let_ = target_function(data);  
    });
- Or if multiple data types:
- fuzz_target!(|data: &\[u8\]| {  
    if let Ok(s) = std::str::from_utf8(data) {  
    target_function(s);  
    }  
    });
- (One might incorporate structure if needed via Serde etc.)

**Placeholders in templates:** The harness templates contain placeholders like target_function or TargetClass.parse which the agent will fill with actual calls. Possibly multiple harnesses for different targets.

Additionally, templates for **regression tests**: - e.g., a JUnit test that ensures the provided PoC no longer triggers the bug after fix:

@Test  
public void testSQLiFixed() {  
String exploit = "test' OR '1'='1";  
List&lt;Book&gt; result = searchBooks(exploit);  
// After fix, this should return no books or just those with title containing the literal string  
// We expect no injection; maybe assert result size < total books  
assertTrue(result.size() <= 1);  
}

And similar for others (perhaps using asserts that would fail if vulnerability still present, like expecting an exception or no admin access etc.).

### **Summary of Templates:**

- **Evidence/Report**: Ensures comprehensive documentation per vulnerability (used in Stage 8 reporting).
- **Hypotheses list**: Keeps track of ideas and feeds into static/dynamic tasks.
- **Verified findings schema**: Standardizes what info we gather per confirmed vuln (could integrate with databases, CVE forms).
- **CodeQL/Semgrep/Joern templates**: Accelerate writing new queries by providing boilerplate for common patterns.
- **Harness/test templates**: Speed up writing fuzzers or reproducers by reusing these snippets and just inserting target specifics. This is crucial for automation - as seen in research, having an LLM or script fill in these templates can automate harness creation significantly[\[25\]](https://adalogics.com/blog/minimal-llm-based-fuzz-harness-generator#:~:text=For%20the%20purpose%20of%20simplicity%2C,a%20harness%20would%20be%20to)[\[43\]](https://arxiv.org/html/2512.03420v1#:~:text=Specifically%2C%20HarnessAgent%20combines%20compilation,21).

All these templates contribute to a repeatable and consistent pipeline, where little manual effort is needed to produce high-quality outputs at each stage.

## Curated Resource Lists (Annotated)

Below is a curated list of top resources across academia, industry, and open-source that inform and enable this whitebox methodology. They are categorized and annotated with their relevance:

### **Top 10 Must-Read/Watch Resources:**

- **"From Day Zero to Zero Day: A Hands-On Guide to Vulnerability Research" - Seng, 2023.** _Book._ - A comprehensive modern handbook on vulnerability research (covers static analysis, dynamic testing, variant hunting) by a security engineer[\[53\]](https://spaceraccoon.dev/comparing-rule-syntax-codeql-semgrep/#:~:text=Apr%208%2C%202023%20%C2%B7%20,%C2%B7%20%209%20minute%20read). Offers step-by-step methodologies and case studies; excellent for learning systematic approaches.
- **OpenAI's _Aardvark_ Release Blog - OpenAI, Oct 2025.** _Article._ - Describes an autonomous agent for security code analysis using GPT-5[\[54\]](https://openai.com/index/introducing-aardvark/#:~:text=How%20Aardvark%20works)[\[28\]](https://openai.com/index/introducing-aardvark/#:~:text=by,click%20patching). Highlights a multi-stage pipeline (threat modeling, commit scanning, validation, patching) in practice, demonstrating state-of-the-art AI-assisted whitebox analysis with real-world results (92% recall on known vulns, multiple 0-days found)[\[32\]](https://openai.com/index/introducing-aardvark/#:~:text=Aardvark%20finding%20issues%20that%20occur,only%20under%20complex%20conditions).
- **"HarnessAgent: Scaling Automatic Fuzzing Harness Construction with Tool-Augmented LLM Pipelines" - Chen et al., arXiv Dec 2025.** _Academic Paper._ - Details an agentic framework for generating fuzz harnesses using LLMs and tools[\[55\]](https://arxiv.org/html/2512.03420v1#:~:text=To%20address%20these%20challenges%2C%20we,of%20the%20harnesses%20generated%20by)[\[43\]](https://arxiv.org/html/2512.03420v1#:~:text=Specifically%2C%20HarnessAgent%20combines%20compilation,21). Identifies challenges like context retrieval and hallucinated code, and presents solutions (compilation-error triage, hybrid code retrieval via LSP/Tree-sitter, AST validation of outputs). Achieved ~87% success in generating working harnesses for 243 targets[\[56\]](https://arxiv.org/html/2512.03420v1#:~:text=a%20rule,system%20of%20HarnessAgent%20achieves%20a), a breakthrough in automating Stage 5 verification.
- **"QLPro: Automated Code Vulnerability Discovery via LLM and Static Code Analysis Integration" - Zeng et al., arXiv June 2025.** _Academic Paper._ - Introduces a pipeline that uses static taint analysis and LLMs to auto-generate CodeQL queries for project-specific vulnerabilities[\[57\]](https://arxiv.org/html/2506.23644v3#:~:text=scanning%20rules,role)[\[41\]](https://arxiv.org/html/2506.23644v3#:~:text=junior%20developers%20without%20security%20experience,Repair%20suggests%20modifications%20for%20failed). Notably uses a triple-voting mechanism to classify sources/sinks and a three-role (Writer-Execute-Repair) loop to ensure queries compile correctly[\[40\]](https://arxiv.org/html/2506.23644v3#:~:text=source%20projects%20without%20human%20intervention,from%20GitHub%20with%2062%20confirmed)[\[58\]](https://arxiv.org/html/2506.23644v3#:~:text=large%20language%20models%20with%20a,Experimental). Demonstrated finding 6 new vulns beyond CodeQL's built-ins. This informs our agent design for query generation and verification.
- **GitHub Security Lab's _Research Archive_ - GHSL team, 2019-2022 (ongoing).** _Collection of Blog Posts._ - Real-world vulnerability research write-ups using CodeQL. E.g., _"Ghostscript type confusion: Using variant analysis to find vulnerabilities"_ (Man Yue Mo, Jan 2019) shows how one bug led to 3 new CVEs via CodeQL queries[\[20\]](https://securitylab.github.com/research-archive/#:~:text=,variant%20analysis%20to%20find%20vulnerabilities). Also posts on Chrome, Linux kernel, etc., illustrating variant analysis workflows and CodeQL patterns. These are gold-standard examples of whitebox methodologies in practice by experts.
- **"Finding New Bugs with Directed Greybox Fuzzing and Static Analysis" - Lyso paper, USENIX Security 2025.** _Academic Paper._ - Presents Lyso, a system that takes static analysis alarms (from CodeQL, Coverity) and guides fuzzing toward them[\[9\]](https://www.usenix.org/system/files/usenixsecurity25-bao-andrew.pdf#:~:text=7,USENIX%20Security%20Symposium%20USENIX%20Association). It confirmed 18 new vulnerabilities (several with CVEs) by turning 2,038 static "alarms" into actual exploits[\[9\]](https://www.usenix.org/system/files/usenixsecurity25-bao-andrew.pdf#:~:text=7,USENIX%20Security%20Symposium%20USENIX%20Association). Validates the power of combining Stage 4 and Stage 5: static results significantly culled by fuzz-based verification.
- **"Whitebox Security Testing of Android Apps - Misaka's Vulnerability Research Methodology" - misakabit (starneko.com), 2022.** _Technical Blog (Chinese)._ - Provides a clear methodology breakdown for Android (but widely applicable)[\[10\]\[15\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=3). Emphasizes reproducibility: attack surface tables, building observability (logging, tombstones), minimizing PoCs, doing impact analysis, and verifying fixes[\[59\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=,native%20%E5%B4%A9%E6%BA%83%E8%AF%81%E6%8D%AE%EF%BC%9Atombstone%2F%E5%A0%86%E6%A0%88%EF%BC%88%E7%8E%AF%E5%A2%83%E5%85%81%E8%AE%B8%E6%97%B6%EF%BC%89)[\[16\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=). A practical guide embodying our required outputs (repro steps, root cause, impact, fix validation)[\[1\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=5).
- **Trail of Bits _Automated Variant Analysis_ resources (mrva tool) - Matt Schwager, Dec 2025 & GitHub blog 2023.** _Tool release + Article._ - Trail of Bits' mrva CLI tool allows running CodeQL queries across 1000s of repos easily[\[60\]](https://blog.trailofbits.com/2025/12/11/introducing-mrva-a-terminal-first-approach-to-codeql-multi-repo-variant-analysis/#:~:text=In%202023%20GitHub%20introduced%20CodeQL,leads%20you). The GitHub "CodeQL Zero to Hero Part 3" blog (Aug 2020) also discusses using CodeQL for variant analysis in bug bounty context[\[61\]](https://github.blog/security/vulnerability-research/codeql-zero-to-hero-part-3-security-research-with-codeql/#:~:text=CodeQL%20zero%20to%20hero%20part,It%20makes). These highlight how scaling static analysis (multi-repo scanning) finds "vuln variants at scale," an approach we incorporate for broad coverage.
- **"Semgrep's JavaScript Security Rules Expansion" - Semgrep blog, Mar 2025.** _Article._ - Discusses how Semgrep Pro's engine and rules were enhanced for Node.js frameworks[\[44\]](https://semgrep.dev/blog/2025/a-technical-deep-dive-into-semgreps-javascript-vulnerability-detection/#:~:text=To%20maximize%20impact%2C%20we%20focused,coverage%20for%20their%20backend%20applications)[\[35\]](https://semgrep.dev/blog/2025/a-technical-deep-dive-into-semgreps-javascript-vulnerability-detection/#:~:text=We%20analyzed%20popular%20npm%20libraries,found%20in%20the%20Semgrep%20documentation). It outlines adding taint tracking for callbacks, module resolution, dependency injection in frameworks like Express/Nest[\[62\]](https://semgrep.dev/blog/2025/a-technical-deep-dive-into-semgreps-javascript-vulnerability-detection/#:~:text=Callbacks)[\[63\]](https://semgrep.dev/blog/2025/a-technical-deep-dive-into-semgreps-javascript-vulnerability-detection/#:~:text=Besides%20that%20we%20had%20to,controllers%2C%20services%20and%20other%20modules). Shows the importance of framework-specific adaptation (which our adapter layer addresses) and how targeted static rules can achieve wide **framework coverage** (50+ libs)[\[35\]](https://semgrep.dev/blog/2025/a-technical-deep-dive-into-semgreps-javascript-vulnerability-detection/#:~:text=We%20analyzed%20popular%20npm%20libraries,found%20in%20the%20Semgrep%20documentation). Good insight into writing security rules for modern web apps.
- **Google OSS-Fuzz's LLM Fuzz Target Generation experiment - Google Security Blog + OSS-Fuzz docs, 2024.** _Article/Docs._ - Google's blog (April 2024) announced using LLMs to generate fuzz targets for under-covered code[\[64\]](https://google.github.io/oss-fuzz/research/llms/target_generation/#:~:text=Additionally%2C%20the%20main%20challenge%20for,than%20deficiencies%20in%20fuzzing%20engines)[\[46\]](https://google.github.io/oss-fuzz/research/llms/target_generation/#:~:text=Image%3A%20experiment%20framework). The OSS-Fuzz research page describes the pipeline: identifying low-coverage functions via Fuzz Introspector, prompting an LLM with examples to write new fuzz harnesses, and iteratively fixing them[\[46\]](https://google.github.io/oss-fuzz/research/llms/target_generation/#:~:text=Image%3A%20experiment%20framework)[\[65\]](https://google.github.io/oss-fuzz/research/llms/target_generation/#:~:text=or%20crashes,that%20addresses%20the%20compilation%20errors). They report improved coverage in projects and this work validates our approach of automated harness generation with verification (compiling and running them) using AI.

These top 10 provide a solid foundation - from methodology blueprints and advanced research to practical tools and success stories.

### **Top 10 Must-Clone/Use Repos (with notes on activity):**

- **GitHub Security Lab CodeQL Queries** (github.com/github/codeql): _Active._ - The repository of standard CodeQL queries for many languages, updated by GitHub and community. It's essential for anyone using CodeQL - includes queries for CWE patterns, and can be extended. Activity: very active (regular updates to queries for new vulns).
- **Semgrep Rules Registry** (github.com/returntocorp/semgrep-rules): _Active._ - Large collection of Semgrep rules, including many for security (organized by language and framework). Community-contributed and curated by r2c. Useful to bootstrap writing custom rules or to directly scan with a broad ruleset. Updated frequently with new patterns.
- **Joern** (github.com/joernio/joern): _Active._ - The code property graph toolkit. Contains the Joern engine and query libraries. Useful for C/C++ and binary analysis especially. The community (ShiftLeft) provides some example queries. Last commit is recent, indicating ongoing maintenance for modern C++ constructs, etc.
- **TrailofBits/mrva** (github.com/trailofbits/mrva): _New, Active._ - Tool released Dec 2025[\[66\]](https://blog.trailofbits.com/2025/12/11/introducing-mrva-a-terminal-first-approach-to-codeql-multi-repo-variant-analysis/#:~:text=Matt%20Schwager) for multi-repo CodeQL analysis. Useful if you want to perform variant analysis across many projects locally (like scanning all your org's repos for a pattern). It's relatively new but maintained by Trail of Bits, so likely to evolve.
- **Advanced-Security/awesome-codeql** (github.com/advanced-security/awesome-codeql): _Active._ - A curated list of CodeQL resources (workshops, example queries, learning materials)[\[67\]](https://github.com/advanced-security/awesome-codeql#:~:text=)[\[68\]](https://github.com/advanced-security/awesome-codeql#:~:text=%2A%20GitHub%20,uses%20CodeQL%20to%20secure%20GitHub). Great one-stop to find tutorials and prior art on CodeQL - helps in writing better queries (which is needed for our Detector agent). Community updated.
- **Google/AFL++** (github.com/AFLplusplus/AFLplusplus): _Active._ - The modern fork of AFL, with many improvements. Useful for fuzzing in our pipeline (especially for native code or when we just want to fuzz a binary interface). Active project with frequent commits and wide usage in fuzzing community.
- **Google/oss-fuzz** (github.com/google/oss-fuzz): _Very active._ - While this is an infrastructure, the repo contains many example fuzz targets and integration scripts for various projects. Cloning it helps to see how others wrote harnesses. Also contains Fuzz Introspector tool and reports (our pipeline could use Introspector's JSON for coverage guidance). Continuous updates as new projects are added.
- **Atheris (Google's Python fuzzing)** (github.com/google/atheris): _Active._ - Atheris is a fuzzing engine for Python (uses libFuzzer under the hood). Good for fuzzing Python code or native extensions. It's used in research and by OSS-Fuzz for Python fuzz targets. Active development (as Python fuzzing gains traction for things like parsing libraries).
- **OWASP Benchmark** (github.com/OWASP/Benchmark): _Stable._ - A test suite of intentionally vulnerable code (Java) to evaluate scanners. Good for calibrating our tools/agents - see how many of the known issues our pipeline finds and verify we minimize false positives. Not frequently updated (last was a couple years ago) but valuable for testing SAST effectiveness.
- **Name-Wreck Joern Queries** (github.com/Forescout/namewreck-queries): _Released 2021 (likely stable)_. - From the NAME:WRECK research[\[47\]](https://www.forescout.com/research-labs/namewreck/#:~:text=,related%20vulnerabilities), an open-source set of Joern queries to find DNS-related bug anti-patterns in TCP/IP stacks. Useful example of variant analysis queries targeting a class of bugs (buffer issues in C network code). Not a constantly updated repo (specific to that research), but very educational to study and possibly reuse patterns for similar vulnerabilities.

_(Note: the exact GitHub URLs for these were inferred; the content implies their existence. For example, Forescout's report mentioned a library of Joern queries_[\[47\]](https://www.forescout.com/research-labs/namewreck/#:~:text=,related%20vulnerabilities)_, presumably on their GitHub.)_

These repositories provide the tools and rulesets that can generalize across many assessments. Cloning and using them can accelerate implementing the pipeline: - CodeQL and Semgrep rules give immediate detection capability. - Joern and variant queries help find bug variants and patterns. - Fuzzing engines and harness examples guide our verification stage.

### **Additional 20 Resources (by stage/ecosystem):**

_Attack Surface & Threat Modeling:_  
\- **"OWASP Testing Guide v4", 2014 (classic).** - Particularly sections on threat modeling and attack surface review; still relevant for understanding what to look for in web apps. (Classic reference, foundational.)  
\- **MITRE CWE Top 25 (latest 2025 edition).** - A list of most common serious weaknesses. Use as a checklist against hypotheses to ensure coverage of common bug types. Updated regularly with community data.  
\- **"Attacking Java Serialized Communication" - Frohoff & Lawrence, BlackHat 2015.** - Though older, it's the seminal work on Java deserialization bugs (leading to ysoserial). Good reference when examining Java apps (deserialization remained an issue through the 2020s). (Classic for a specific vuln class.)  
\- **"Architectural Risk Analysis" - McGraw, 2012 (chapter/book).** - Discusses identifying high-risk components in software architecture (foundation for threat modeling stage).

_Static Analysis & Rule Authoring:_  
\- **"CodeQL by Example: A Beginner's Workshop" - GitHub Security Lab, 2021.** - An online workshop (often on the GHSL site) that walks through writing a CodeQL query from scratch and interpreting results. Good for training Detector agent or humans.  
\- **"Writing Secure Code with Semgrep" - Trail of Bits Training, 2024.** - Possibly a blog or recorded talk by Trail of Bits on Semgrep patterns they use in audits. Could include how to model custom sources/sinks.  
\- **Semgrep Cheat Sheet - r2c, 2025.** - A one-pager listing common pattern constructs, operators, and tips for writing rules (like pattern-sources, pattern-sinks usage, etc.). Very handy for quick rule writing.  
\- **"Static Analysis at Scale: Facebook's Zoncolan" - IEEE S&P 2018 paper.** - Discusses how FB scaled static analysis with automating query writing and triaging millions of findings. Concepts from it (like prioritization, integrating static tools in CI) align with our automation goals.

_Dynamic Analysis & Fuzzing:_  
\- **"The Fuzzing Book" - Zeller et al., ongoing.** - An online book with interactive chapters on fuzz testing techniques, grammar fuzzing, etc. Great background to design fuzz strategies (though more academic). (Foundational reference for fuzzing theory and practice.)  
\- **"Fuzz Introspector: Automated Coverage Analysis for Fuzzing" - OSSF blog, 2022.** - Introduces Fuzz Introspector (which we leverage for harness generation) and how it identifies fuzz blockers[\[64\]](https://google.github.io/oss-fuzz/research/llms/target_generation/#:~:text=Additionally%2C%20the%20main%20challenge%20for,than%20deficiencies%20in%20fuzzing%20engines). Good to understand coverage issues.  
\- **syzkaller Project (github.com/google/syzkaller).** - For kernel fuzzing. Even if not directly in our pipeline (unless doing kernel VR), syzkaller's approach to generating syscalls and analyzing coverage can inspire approaches for stateful fuzzing in user-space apps.  
\- **"Hybrid Fuzzing: Discovering Software Bugs via Execution and Static Analysis" - CCS 2019 (Peng et al.).** - Academic paper that combines concolic execution with fuzzing. Provided groundwork for tools like QSYM. Useful to consider for agent enhancements (maybe integrating symbolic execution if fuzzing stalls).

_Variant Analysis & Patching:_  
\- **"Variant Analysis: Finding Bug Variants with CodeQL" - YouTube talk by GHSL (Man Yue Mo), 2020.** - A recorded conference talk specifically demonstrating how a real vuln was turned into a CodeQL query[\[69\]](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2019/CVE-2019-13720.html#:~:text=In%20April%202020%2C%20Man%20Yue,bugs%20within%20the%20webaudio%20module). Shows the mindset of pattern extraction from a patch.  
\- **BinDiff (zynamics) or Diaphora documentation, 2016.** - While about binary diffing, the concepts of diffing two versions to spot fixes can inform our patch analysis stage (if source patches available, though in whitebox we often have them). Useful if doing n-day variant hunting.  
\- **"Semantic Patches (Coccinelle)" - Padioleau et al., ASE 2008.** - Classic paper on finding and fixing bugs in Linux using semantic patch scripts. Introduces the notion of matching code patterns for bugs, similar to what we do with CodeQL/Joern but via a patch-like language. Good foundational concept for variant finding and automated fixing. (Classic for patch analysis in C).  
\- **"Secure Code Review (video series)" - NCC Group, 2023.** - A series of deep-dive videos into reviewing code in different languages (one for Java, one for Node, etc.), by experienced auditors. They show how they locate vulns in real code, which can augment our methodology with manual techniques that can be automated.

_Language/Framework Specific:_  
\- **Spring Security Reference (latest).** - Official Spring Security docs. Useful when auditing auth in Spring apps (to know where misconfig might cause bypass). Also lists common patterns (like method security annotations) that our agent should look for or lack thereof.  
\- **Django Security Middleware docs.** - Summarizes what Django does out-of-the-box (CSRf protection, etc.) so we know what to expect. If those are disabled, that's a finding.  
\- **Node.js Security Best Practices (OWASP wiki, 2022).** - A checklist of things like "avoid eval", "use Helmet", etc. Great to cross-reference when building threat model or writing rules for Node apps (our adapter could be informed by it).  
\- **"A Tour of Go Unsafe" - blog post by Cloudflare, 2021.** - Explains common pitfalls when using unsafe in Go. Helps in spotting memory bugs in Go (since normally memory safe).  
\- **Rustonomicon (The Dark Arts of Unsafe Rust).** - Official Rust guide on using unsafe correctly. If reviewing Rust unsafe code, knowing these guidelines helps identify where a project deviates (e.g. improper Send/Sync impl, etc.). Good reference for our Rust adapter to highlight potential unsoundness.

Each of these is chosen because it either: - provides _methodological insight_, - is a repository of _reusable queries/rules_, or - covers _specific ecosystem pitfalls_ that we want our pipeline to handle.

They are categorized roughly by which stage or aspect they help with. Together with the top 10, they form a knowledge base to build and refine the universal pipeline.

Each item above includes date (when known) and why it's relevant: - Older but foundational (I marked as classic). - Recent and state-of-art (most 2023-2025 items). - Tools with community support (active repos, etc.).

## Implementation Roadmap

To implement this vision in 2-4 weeks as an MVP (Minimum Viable Product), we propose a phased approach focusing on the highest ROI components first, along with an evaluation plan:

### **Phase 1 (Week 1-2): Core Pipeline & Low-Hanging Fruit**

**Goal:** Build the skeleton of the orchestrator and implement pipeline stages that use existing tools with minimal customization. Focus on one language (or two) to prove out the flow.

- **Stage 1 & 2 (Profiling & Surface):** Implement Repo Profiler agent to auto-detect build/test and run them. This involves writing adapters for 1-2 languages now (say, Java and JavaScript, which cover a lot of web apps). Success = can build a sample project and list its endpoints. _Measure:_ Did the build succeed? Did we correctly identify key entry points (manual check against the code)?
- **Stage 3 (Hypothesis generation):** Use OWASP Top 10 and common CWEs for target framework to auto-generate a list of hypotheses. For MVP, this could be templated (not using an AI yet, just a static list keyed by framework). Success = For a given app, we produce a reasonable list of things to check (e.g. "SQLi in X, XSS in Y, auth bypass in Z").
- **Stage 4 (Detectors using existing rules):** Integrate **Semgrep** and run relevant rulesets (since Semgrep is quick to set up) and integrate **CodeQL** (which might be slower; maybe run one simple CodeQL query as POC). At MVP, we might not generate custom queries yet, but use built-in ones. E.g., run CodeQL's standard security query suite for that language, and Semgrep's community rules. Success = The agent can execute these and collect results. _Measure:_ How many real issues from a known vulnerable app can we catch with out-of-the-box rules? (Use OWASP Benchmark or a deliberately vulnerable app to gauge coverage).
- **Stage 5 (Verification harness minimal):** Focus on automating reproduction for one class of bug. MVP target: memory corruption in C or a simple logic bug in a web app. For example, if Semgrep flags an SQL injection, write a small script to send the HTTP request and see if response indicates success. Or if CodeQL flags a buffer overflow in C, compile with ASan and run a test with a crafted input (maybe not fully automated generation yet - could use a static large input). The key is to prove we can confirm a finding automatically. Success = The system confirms at least one vulnerability by causing a visible failure (crash or unauthorized action). _Measure:_ number of static findings validated vs total findings (precision improvement).
- **Reporting (Stage 8 simplified):** Assemble a basic report of findings: e.g. just list "Confirmed: SQLi in function X". MVP can be simple text output. Success = we produce a report with at least one confirmed vuln including PoC info.

**Adapters in MVP:** Focus on **one web stack (Java Spring or Node/Express)** and **one low-level stack (C with a small vulnerable program)**. This demonstrates both a logic bug and a memory bug pipeline.

**Anti-hallucination approach in MVP:** Hard-code that we only trust results if a tool says so and if our test actually crashes or shows exploit. That is inherently done by focusing on actual tool outputs and runtime results (no AI guesses yet, aside from maybe using GPT for hypothesis suggestions if time permits as stretch). So initially, avoid complex LLM integration until basic loop works (this controls hallucination naturally).

### **Phase 2 (Week 3-4): Expand Automation and Intelligence**

**Goal:** Add more automation in writing queries and harnesses, incorporate LLM assistance for generalization, and extend to more languages. Also set up evaluation metrics properly.

- **Automated Query Generation:** Implement the Detector agent's **query synthesis** for one scenario. Possibly use an LLM (Claude or GPT-4) with our adapter data to write a CodeQL query for a specific hypothesis. For example: "generate a CodeQL to find any unchecked external data in file operations". Use QLPro's approach as inspiration: feed it taint specs (from adapter) and have it produce QL, then compile it and run. Success = LLM-generated query runs without error and finds the intended pattern (verify on known vulnerable code). _Measure:_ number of LLM queries that work after possibly one repair iteration (success rate of query generation).
- **Automated Harness Generation:** Implement Verifier's harness builder with LLM or templating. E.g., for a given function in C, use our template to generate a fuzz harness and compile it. Or for a web endpoint, generate a Python script that performs the needed HTTP calls. We can leverage the AdaLogics minimal harness approach[\[25\]](https://adalogics.com/blog/minimal-llm-based-fuzz-harness-generator#:~:text=For%20the%20purpose%20of%20simplicity%2C,a%20harness%20would%20be%20to): gather function signature and usage, prompt LLM to produce harness code. Success = The generated harness compiles and triggers some behavior (even if not the bug, at least runs). _Measure:_ harness compilation success rate; if harness runs, does it increase coverage or find crashes? (We can measure coverage difference pre/post harness with Fuzz Introspector maybe.)
- **Agent integration & loop closing:** Make Orchestrator more autonomous: it should decide "if static finding not confirmed, drop it or re-examine with different strategy." Perhaps implement a simple rule: any unconfirmed static finding is either reported as "informational" or pruned. Also implement the loop where if a bug is confirmed, Orchestrator calls Detector to scan for variants (e.g. runs the same query on other parts or across repos if possible). Success = On confirming one bug, the system attempts variant analysis automatically (maybe re-running Semgrep across all repo or similar). _Measure:_ if our known bug has siblings in code, do we find them quickly?
- **Adapter extension:** Add adapters for a couple more frameworks, maybe Python/Django and Go. Not fully polished, but ensure our architecture can load a new YAML and then static rules, etc. This tests generality. Perhaps use Semgrep or CodeQL queries for those languages (which exist). Success = pipeline runs on a Django or Go vulnerable app and finds something.
- **Evaluation and Tuning:** By end of Week 4, test the pipeline on a set of known vulnerable projects:
- E.g., DVWA (PHP) or WebGoat (Java) or Juice Shop (Node) for web bugs, and a simple vulnerable C program for memory bugs.
- Collect metrics: True positives found, false positives reported, false negatives (known issues we missed).
- Tweak agents accordingly: e.g. adjust Semgrep rules selection if too noisy, improve LLM prompt if queries not accurate, etc.

**Success Criteria for MVP:** - It should find at least, say, 5 distinct vulnerabilities across 2 different stacks with minimal human intervention. - At least 3 of those findings should be verified with a working PoC generated or executed by the system (others could be manual confirmation if needed). - False positive rate in final output should be low (aim for >80% precision). If we find 5 vulns, maybe at most 1 false report. - Demonstrate one variant analysis success: e.g. found a bug and then found a variant in another file or project.

**Risks/Gaps in MVP and Mitigation:** - Time may limit LLM integration complexity. If LLM generation of queries proves flaky, we'll focus on making it prompt multiple small tasks (like the triple-check approach or using simpler pattern suggestions). - Multi-language support might reveal lots of edge cases (like build failures). We'll mitigate by using containerized environments or GitHub Actions to test pipeline on sample projects continuously. - Some stages (like full threat modeling or patch suggestion) might be skipped in MVP due to time. That's acceptable; those can be manual or left as future enhancements beyond 4 weeks.

### **Beyond 4 weeks (Future):**

- Integrate a database of known vulns to measure recall (like test on OWASP Benchmark thoroughly).
- Add a learning loop: incorporate feedback from each run into the knowledge base (e.g. if a certain Semgrep rule is always false positive in a context, suppress it in future).
- Expand agent's reasoning to handle complex logic bugs (invariants, state machines) potentially by integrating something like an SMT solver or domain-specific analyzers.

### **Evaluation Rubric:**

To evaluate the pipeline's effectiveness, define these metrics:

- **Precision (Quality of findings):** Of the issues reported as "verified vulnerabilities," how many are true positives vs false? We aim for high precision by design (the verification step ensures higher precision). We can measure this by manually reviewing results or using known test cases (where ground truth is known).
- **Recall (Coverage):** How many known vulnerabilities in the target set did the pipeline catch? This is tricky to measure in general, but using benchmark suites or known CVEs in an old version of a project can serve as ground truth. We can count how many the tool finds vs known ones. (Recall might be lower initially; we then identify which stages failed to catch the others and improve those).
- **Verification Rate:** Among the static findings, what percentage got confirmed by the dynamic stage? Higher is better (low means either many FPs or we need better verification techniques). This can be computed easily from logs (X findings in static, Y confirmed).
- **Time-to-first-vuln:** How long (in automated runtime) does it take to find and confirm a vulnerability on a new codebase? If it's hours, that's okay for automation, but we'd like to optimize. We can log timestamps for each stage.
- **False Negative indicators:** If possible, track if any critical flaw was missed entirely by pipeline. This requires knowledge of a vulnerability that exists. We can seed a known vuln and see if pipeline flags it. If not, examine why (this informs where to improve).
- **Resource usage:** CPU/memory usage and analysis time. If using CodeQL, that can be heavy; we measure if the pipeline can run within, say, a couple of hours per codebase and how that scales with LOC. For MVP, not critical to fully optimize, but keep an eye.
- **Developer feedback:** If possible, present results to developers of target projects and get qualitative feedback: Are the reports understandable? Did the suggested fixes make sense? This is subjective but valuable to refine report clarity (in a longer timeline beyond MVP).

In initial phases, emphasis is on precision (we want to demonstrate we can find real bugs without crying wolf) and on confirming at least some bugs end-to-end. Over time, we'd improve recall by adding more rules, more frameworks, and perhaps more advanced techniques (like combining multiple static analysis outputs, using machine learning for ranking, etc.).

**Summary**: - Weeks 1-2: Get a basic pipeline working on one stack with existing tools to confirm a bug. - Weeks 3-4: Add intelligence (LLMs for query/harness gen), extend to more stacks, and evaluate on known test targets.

This roadmap is aggressive but feasible by leveraging existing tools (CodeQL, Semgrep, fuzzers) and focusing LLM usage narrowly (not end-to-end code understanding, but assisting in automation of steps, which is more constrained and thus more likely to succeed as per recent research successes).

By the end of 4 weeks, we expect an MVP that can, for example, take a medium-sized web app and automatically identify a couple of real vulnerabilities with proof (something that normally takes a human days of work), demonstrating the value of the orchestrated whitebox approach.

[\[1\]](https://starneko.com/notes/android/08-practical/00-methodology.html) [\[2\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=3) [\[3\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=%E5%B8%B8%E8%A7%81%E4%BC%98%E5%85%88%E7%BA%A7%EF%BC%9A) [\[4\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=%E5%B8%B8%E8%A7%81%E5%AE%9A%E7%BA%A7%E7%BB%B4%E5%BA%A6%EF%BC%9A) [\[5\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=%E5%9B%A0%E6%AD%A4%E6%98%A0%E5%B0%84%E6%94%BB%E5%87%BB%E9%9D%A2%E6%97%B6%E5%BB%BA%E8%AE%AE%E5%90%8C%E6%97%B6%E5%81%9A%E4%B8%A4%E5%BC%A0%E8%A1%A8%EF%BC%9A) [\[10\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=3) [\[11\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=2) [\[15\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=3) [\[16\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=) [\[52\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=3) [\[59\]](https://starneko.com/notes/android/08-practical/00-methodology.html#:~:text=,native%20%E5%B4%A9%E6%BA%83%E8%AF%81%E6%8D%AE%EF%BC%9Atombstone%2F%E5%A0%86%E6%A0%88%EF%BC%88%E7%8E%AF%E5%A2%83%E5%85%81%E8%AE%B8%E6%97%B6%EF%BC%89) 8x00 - Vulnerability Research Methodology | 御坂晚的笨蛋笔记

<https://starneko.com/notes/android/08-practical/00-methodology.html>

[\[6\]](https://www.usenix.org/system/files/conference/woot17/woot17-paper-shastry.pdf#:~:text=attention%20on%20matches%20comprising%20untested,complement%20fuzz%20testing%2C%20and%20is) [\[7\]](https://www.usenix.org/system/files/conference/woot17/woot17-paper-shastry.pdf#:~:text=Fuzz%20testing%20has%20been%20the,and%2For%20stateful%20application%20logic%2C%20betraying) [\[8\]](https://www.usenix.org/system/files/conference/woot17/woot17-paper-shastry.pdf#:~:text=majority%20of%20taint,effective%20match%02ranking%20algorithm%20that%20uses) [\[38\]](https://www.usenix.org/system/files/conference/woot17/woot17-paper-shastry.pdf#:~:text=toolchain%20and%20use%20it%20in,analysis%20and%20testing%2C%20and%20serve) usenix.org

<https://www.usenix.org/system/files/conference/woot17/woot17-paper-shastry.pdf>

[\[9\]](https://www.usenix.org/system/files/usenixsecurity25-bao-andrew.pdf#:~:text=7,USENIX%20Security%20Symposium%20USENIX%20Association) usenix.org

<https://www.usenix.org/system/files/usenixsecurity25-bao-andrew.pdf>

[\[12\]](https://spaceraccoon.dev/comparing-rule-syntax-codeql-semgrep/#:~:text=CodeQL%20and%20Semgrep%20OSS%20are,learning%20curve%20of%20CodeQL%20occurs) [\[13\]](https://spaceraccoon.dev/comparing-rule-syntax-codeql-semgrep/#:~:text=The%20reason%20for%20this%20is,patterns%20in%20Semgrep%E2%80%99s%20rule%20syntax) [\[14\]](https://spaceraccoon.dev/comparing-rule-syntax-codeql-semgrep/#:~:text=In%20comparison%2C%20CodeQL%20tries%20to,each%20language%E2%80%99s%20syntax%20naming%20conventions) [\[21\]](https://spaceraccoon.dev/comparing-rule-syntax-codeql-semgrep/#:~:text=,case%20sound%20assumptions) [\[45\]](https://spaceraccoon.dev/comparing-rule-syntax-codeql-semgrep/#:~:text=languages%2C%20it%20even%20instruments%20the,each%20language%E2%80%99s%20syntax%20naming%20conventions) [\[49\]](https://spaceraccoon.dev/comparing-rule-syntax-codeql-semgrep/#:~:text=CodeQL%20uses%20the%20QL%20language%2C,clauses) [\[53\]](https://spaceraccoon.dev/comparing-rule-syntax-codeql-semgrep/#:~:text=Apr%208%2C%202023%20%C2%B7%20,%C2%B7%20%209%20minute%20read) Rule Writing for CodeQL and Semgrep | Spaceraccoon's Blog

<https://spaceraccoon.dev/comparing-rule-syntax-codeql-semgrep/>

[\[17\]](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2019/CVE-2019-13720.html#:~:text=We%20performed%20variant%20analysis%20on,core%2Fworkers%20folder%20of%20the%20renderer) [\[19\]](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2019/CVE-2019-13720.html#:~:text=Found%20variants%3A) [\[50\]](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2019/CVE-2019-13720.html#:~:text=Based%20solely%20on%20the%20vulnerability%2C,using%20static%20analysis%20tools%20too) [\[51\]](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2019/CVE-2019-13720.html#:~:text=In%20their%20POC%2C%20at%20line,attackers%20to%20look%20at%20the) [\[69\]](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2019/CVE-2019-13720.html#:~:text=In%20April%202020%2C%20Man%20Yue,bugs%20within%20the%20webaudio%20module) CVE-2019-13720: Chrome use-after-free in webaudio | 0-days In-the-Wild

<https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2019/CVE-2019-13720.html>

[\[18\]](https://blog.trailofbits.com/2025/12/11/introducing-mrva-a-terminal-first-approach-to-codeql-multi-repo-variant-analysis/#:~:text=In%202023%20GitHub%20introduced%20CodeQL,leads%20you) [\[60\]](https://blog.trailofbits.com/2025/12/11/introducing-mrva-a-terminal-first-approach-to-codeql-multi-repo-variant-analysis/#:~:text=In%202023%20GitHub%20introduced%20CodeQL,leads%20you) [\[66\]](https://blog.trailofbits.com/2025/12/11/introducing-mrva-a-terminal-first-approach-to-codeql-multi-repo-variant-analysis/#:~:text=Matt%20Schwager) Introducing mrva, a terminal-first approach to CodeQL multi-repo variant analysis - The Trail of Bits Blog

<https://blog.trailofbits.com/2025/12/11/introducing-mrva-a-terminal-first-approach-to-codeql-multi-repo-variant-analysis/>

[\[20\]](https://securitylab.github.com/research-archive/#:~:text=,variant%20analysis%20to%20find%20vulnerabilities) Research Archive | GitHub Security Lab

<https://securitylab.github.com/research-archive/>

[\[22\]](https://www.praetorian.com/blog/why-you-should-add-joern-to-your-source-code-audit-toolkit/#:~:text=.unsanitized%28%7Bit._%28%29.or%28_%28%29.isCheck%28%27.) [\[23\]](https://www.praetorian.com/blog/why-you-should-add-joern-to-your-source-code-audit-toolkit/#:~:text=By%20leveraging%20Joern%20in%20your,improve%20these%20results%20even%20further) [\[36\]](https://www.praetorian.com/blog/why-you-should-add-joern-to-your-source-code-audit-toolkit/#:~:text=,bases%2Fbuffer_overflow%2Fbuffer.c) Why You Should Add Joern to Your Source Code Audit Toolkit | Praetorian

<https://www.praetorian.com/blog/why-you-should-add-joern-to-your-source-code-audit-toolkit/>

[\[24\]](https://googleprojectzero.blogspot.com/2016/06/#:~:text=For%20example%2C%20we%20have%20extensively,instrumentations%2C%20which%20drastically%20improved) June 2016 - Google Project Zero

<https://googleprojectzero.blogspot.com/2016/06/>

[\[25\]](https://adalogics.com/blog/minimal-llm-based-fuzz-harness-generator#:~:text=For%20the%20purpose%20of%20simplicity%2C,a%20harness%20would%20be%20to) [\[26\]](https://adalogics.com/blog/minimal-llm-based-fuzz-harness-generator#:~:text=suggestions%20regarding%20fuzzing%20and%20what,The%20function%20is) Minimal LLM-based fuzz harness generator

<https://adalogics.com/blog/minimal-llm-based-fuzz-harness-generator>

[\[27\]](https://openai.com/index/introducing-aardvark/#:~:text=Aardvark%20relies%20on%20a%20multi,identify%2C%20explain%2C%20and%20fix%20vulnerabilities) [\[28\]](https://openai.com/index/introducing-aardvark/#:~:text=by,click%20patching) [\[29\]](https://openai.com/index/introducing-aardvark/#:~:text=attempt%20to%20trigger%20it%20in,click%20patching) [\[30\]](https://openai.com/index/introducing-aardvark/#:~:text=vulnerabilities%2C%20how%20they%20might%20be,tests%2C%20using%20tools%2C%20and%20more) [\[31\]](https://openai.com/index/introducing-aardvark/#:~:text=Aardvark%20continuously%20analyzes%20source%20code,severity%2C%20and%20propose%20targeted%20patches) [\[32\]](https://openai.com/index/introducing-aardvark/#:~:text=Aardvark%20finding%20issues%20that%20occur,only%20under%20complex%20conditions) [\[33\]](https://openai.com/index/introducing-aardvark/#:~:text=Aardvark%20has%20also%20been%20applied,CVE%29%20identifiers) [\[39\]](https://openai.com/index/introducing-aardvark/#:~:text=high,click%20patching) [\[54\]](https://openai.com/index/introducing-aardvark/#:~:text=How%20Aardvark%20works) Introducing Aardvark: OpenAI's agentic security researcher | OpenAI

<https://openai.com/index/introducing-aardvark/>

[\[34\]](https://semgrep.dev/blog/2025/a-technical-deep-dive-into-semgreps-javascript-vulnerability-detection/#:~:text=analysis%2C%20such%20as%20injection%20attacks%2C,sinks%20from%20the%20previous%20paragraph) [\[35\]](https://semgrep.dev/blog/2025/a-technical-deep-dive-into-semgreps-javascript-vulnerability-detection/#:~:text=We%20analyzed%20popular%20npm%20libraries,found%20in%20the%20Semgrep%20documentation) [\[44\]](https://semgrep.dev/blog/2025/a-technical-deep-dive-into-semgreps-javascript-vulnerability-detection/#:~:text=To%20maximize%20impact%2C%20we%20focused,coverage%20for%20their%20backend%20applications) [\[62\]](https://semgrep.dev/blog/2025/a-technical-deep-dive-into-semgreps-javascript-vulnerability-detection/#:~:text=Callbacks) [\[63\]](https://semgrep.dev/blog/2025/a-technical-deep-dive-into-semgreps-javascript-vulnerability-detection/#:~:text=Besides%20that%20we%20had%20to,controllers%2C%20services%20and%20other%20modules) A Technical Deep Dive into Semgrep's JavaScript Vulnerability Detection | Semgrep

<https://semgrep.dev/blog/2025/a-technical-deep-dive-into-semgreps-javascript-vulnerability-detection/>

[\[37\]](https://www.ndss-symposium.org/wp-content/uploads/2024/10/2023-68-slides.pdf#:~:text=...%20www.ndss,in%20network%20protocol%20implementations) \[PDF\] Automata-Based Automated Detection of State Machine Bugs in ...

<https://www.ndss-symposium.org/wp-content/uploads/2024/10/2023-68-slides.pdf>

[\[40\]](https://arxiv.org/html/2506.23644v3#:~:text=source%20projects%20without%20human%20intervention,from%20GitHub%20with%2062%20confirmed) [\[41\]](https://arxiv.org/html/2506.23644v3#:~:text=junior%20developers%20without%20security%20experience,Repair%20suggests%20modifications%20for%20failed) [\[42\]](https://arxiv.org/html/2506.23644v3#:~:text=analysis%20tools,grammatical%20correctness%20of%20vulnerability%20scanning) [\[57\]](https://arxiv.org/html/2506.23644v3#:~:text=scanning%20rules,role) [\[58\]](https://arxiv.org/html/2506.23644v3#:~:text=large%20language%20models%20with%20a,Experimental) QLPro: Automated Code Vulnerability Discovery via LLM and Static Code Analysis Integration

<https://arxiv.org/html/2506.23644v3>

[\[43\]](https://arxiv.org/html/2512.03420v1#:~:text=Specifically%2C%20HarnessAgent%20combines%20compilation,21) [\[55\]](https://arxiv.org/html/2512.03420v1#:~:text=To%20address%20these%20challenges%2C%20we,of%20the%20harnesses%20generated%20by) [\[56\]](https://arxiv.org/html/2512.03420v1#:~:text=a%20rule,system%20of%20HarnessAgent%20achieves%20a) HarnessAgent: Scaling Automatic Fuzzing Harness Construction with Tool-Augmented LLM Pipelines

<https://arxiv.org/html/2512.03420v1>

[\[46\]](https://google.github.io/oss-fuzz/research/llms/target_generation/#:~:text=Image%3A%20experiment%20framework) [\[64\]](https://google.github.io/oss-fuzz/research/llms/target_generation/#:~:text=Additionally%2C%20the%20main%20challenge%20for,than%20deficiencies%20in%20fuzzing%20engines) [\[65\]](https://google.github.io/oss-fuzz/research/llms/target_generation/#:~:text=or%20crashes,that%20addresses%20the%20compilation%20errors) Fuzz target generation using LLMs | OSS-Fuzz

<https://google.github.io/oss-fuzz/research/llms/target_generation/>

[\[47\]](https://www.forescout.com/research-labs/namewreck/#:~:text=,related%20vulnerabilities) NAME:WRECK - Forescout

<https://www.forescout.com/research-labs/namewreck/>

[\[48\]](https://semgrep.dev/blog/2021/taint-mode-is-now-in-beta#:~:text=Taint%20mode%20is%20now%20in,now%20resort%20to%20any) Taint mode is now in beta - Semgrep

<https://semgrep.dev/blog/2021/taint-mode-is-now-in-beta>

[\[61\]](https://github.blog/security/vulnerability-research/codeql-zero-to-hero-part-3-security-research-with-codeql/#:~:text=CodeQL%20zero%20to%20hero%20part,It%20makes) CodeQL zero to hero part 3: Security research with CodeQL

<https://github.blog/security/vulnerability-research/codeql-zero-to-hero-part-3-security-research-with-codeql/>

[\[67\]](https://github.com/advanced-security/awesome-codeql#:~:text=) [\[68\]](https://github.com/advanced-security/awesome-codeql#:~:text=%2A%20GitHub%20,uses%20CodeQL%20to%20secure%20GitHub) GitHub - advanced-security/awesome-codeql: A curated list of awesome CodeQL resources.

<https://github.com/advanced-security/awesome-codeql>
