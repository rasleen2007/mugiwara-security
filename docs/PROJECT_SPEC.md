# Mugiwara Security — Master Project Specification

> **Status:** Draft Architecture Specification  
> **Target Version:** 0.1.0  
> **License:** Apache 2.0 / Open Source  

---

## 1. Project Vision

**Mugiwara Security** is an open-source, autonomous AI-powered security testing and vulnerability verification platform. 

Named with the spirit of the *Straw Hat Crew*—fearless, exploratory, protective, resilient, and collaborative—Mugiwara Security empowers developers and DevSecOps teams to discover, safely validate, and fix security vulnerabilities in software applications before malicious actors can exploit them.

Unlike legacy security scanners that produce hundreds of noisy, unvalidated warnings, Mugiwara Security pairs **intelligent AI security agents** with **isolated execution sandboxes** to actively verify whether suspected vulnerabilities are genuinely exploitable in a realistic runtime environment. Every verified finding comes with concrete, reproducible evidence (Proof-of-Concept scripts, exact HTTP traces, and execution logs) and clear, actionable remediation guidance.

---

## 2. Problem Statement

1. **The False Positive Avalanche:** Traditional Static Application Security Testing (SAST) and Dynamic Application Security Testing (DAST) tools generate overwhelming numbers of alerts. Security and development teams spend up to 70% of their triage time investigating non-issues or unexploitable edge cases.
2. **Lack of Business & Runtime Context:** Static scanners analyze code without executing it; dynamic scanners fire blind, pre-programmed payloads. Neither understands custom application logic, multi-step authentication flows, or contextual business rules.
3. **The Verification Dilemma:** Proving an alert is a real vulnerability requires manual penetration testing by skilled security engineers, which is expensive, slow, and does not scale with modern continuous deployment.
4. **Execution Hazards:** Fuzzing or executing active security probes against live or poorly isolated environments risks data corruption, service downtime, or runaway resource exhaustion.

---

## 3. Goals

- **Autonomous Multi-Agent Security Testing:** Orchestrate specialized AI agents (Recon, Discovery, Verification, Remediation) that analyze application source code, configuration, and runtime endpoints.
- **Evidence-Backed Verification:** Eliminate false positives by executing safe, dynamic Proof-of-Concept (PoC) tests inside isolated sandboxes to confirm exploitability before reporting.
- **Strictly Sandboxed Execution:** Run target applications and security probes inside secure, ephemeral containers with strict resource, timeout, and network guardrails.
- **Multi-Provider LLM Abstraction:** Support top-tier LLM providers (Anthropic Claude, OpenAI, Google Gemini) alongside local, privacy-preserving open-weight models (via Ollama / vLLM / LiteLLM).
- **Developer-Centric CLI & Reports:** Provide an intuitive command-line interface with rich visual diagnostics, as well as machine-readable standard exports (SARIF v2.1.0, JSON, Markdown).
- **Automated AI Remediation:** Generate verified code diffs and patches that resolve confirmed vulnerabilities without breaking existing functionality.
- **Modular & Extensible Architecture:** Design clean, decoupled Python modules with strict type hints, allowing community contributors to add new security agents, sandbox runtimes, or LLM providers.

---

## 4. Non-Goals

- **Not an Offensive Attack Toolkit:** Mugiwara Security is built strictly for defensive application security and authorized testing. It does not include DDoS tools, unauthorized network sniffers, or malicious malware generators.
- **Not a Replacement for Human Security Audits:** While it automates deep technical testing, it does not replace formal regulatory compliance audits or high-assurance human architectural reviews.
- **Not a Blind Fuzzer:** Mugiwara Security prioritizes semantic reasoning and contextual exploitation over dumping millions of random string mutations.
- **Not a Closed SaaS Monolith:** The core engine is designed to run locally, on developer machines, and in self-hosted CI/CD runners without mandatory third-party cloud lock-in.

---

## 5. Target Users

1. **Software Engineers & Developers:** Developers who want immediate, accurate security feedback on their pull requests without wading through false alarms.
2. **DevSecOps & AppSec Engineers:** Security teams looking to automate continuous security regression testing in CI/CD pipelines with standardized SARIF outputs.
3. **Penetration Testers & Security Researchers:** Professionals who want an intelligent AI assistant to assist in endpoint mapping, logic flaw discovery, and rapid PoC drafting.
4. **Open-Source Maintainers:** Maintainers who need automated security audits for incoming community contributions without requiring dedicated security personnel.

---

## 6. High-Level Architecture

The platform is structured into clean, decoupled layers with strict unidirectional dependencies:

```
┌─────────────────────────────────────────────────────────────┐
│                       CLI & UI Layer                        │
│             (Typer, Rich, Configuration Loader)             │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                Orchestration & Workflow Engine              │
│       (Scan Coordinator, Task Scheduler, State Store)        │
└───────┬──────────────────────┬──────────────────────┬───────┘
        │                      │                      │
┌───────▼────────┐     ┌───────▼────────┐     ┌───────▼────────┐
│  AI Agent Core │     │ LLM Provider   │     │ Sandbox Runtime│
│ - Recon Agent  │     │   Abstraction  │     │ - Docker Engine│
│ - Discovery Ag.│◄───►│ - Anthropic    │     │ - Network Gate │
│ - Verifier Ag. │     │ - OpenAI       │     │ - Execution    │
│ - Remediation  │     │ - Gemini       │     │   Monitor      │
│                │     │ - Ollama/Local │     │                │
└───────┬────────┘     └────────────────┘     └───────┬────────┘
        │                                             │
        └──────────────────────┬──────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                 Findings & Evidence Model                   │
│          (Pydantic Schemas: Finding, Evidence, PoC)         │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                  Exporters & Integrations                   │
│             (SARIF, JSON, Markdown, GitHub PR)              │
└─────────────────────────────────────────────────────────────┘
```

### Architectural Principles
- **Separation of Concerns:** Agents do not talk to Docker directly; they interact through a sandbox abstraction. CLI does not talk to LLMs directly; it interacts through the orchestrator.
- **Strict Typing:** All data transfer objects (DTOs) and internal states are governed by Pydantic models.
- **Asynchronous by Design:** Long-running security tasks, LLM completions, and sandbox operations utilize Python `asyncio`.
- **Fault Tolerance:** Agent failures, LLM rate limits, and container crashes are handled gracefully without aborting the entire scan session.

---

## 7. CLI Architecture

The CLI is the primary user touchpoint, built using **Typer** and styled with **Rich** for responsive terminal output.

### Command Structure

```bash
# Initialize project configuration and verify environment
mugiwara init

# Execute a security scan (local project directory or .zip archive)
mugiwara scan <path_or_zip> [options]
    --profile [fast | standard | deep]
    --provider [anthropic | openai | gemini | ollama]
    --model <model_name>
    --sandbox [docker | none]
    --output <file_path>
    --format [sarif | json | md | text]
    --dry-run

# Manage sandbox environments
mugiwara sandbox status
mugiwara sandbox cleanup

# Inspect and export findings
mugiwara report show <report_id>
mugiwara report export <report_id> --format sarif -o report.sarif

# Apply AI-generated fixes
mugiwara fix <finding_id> [--interactive | --apply-all]

# View and update configuration
mugiwara config show
mugiwara config set <key> <value>
```

### Terminal UX Features
- Live interactive status spinner and progress bars during multi-phase scans.
- Structured summary tables highlighting vulnerability counts by severity (Critical, High, Medium, Low, Info).
- Color-coded diff views for proposed code remediations.
- Meaningful exit codes (e.g., `0` for clean, `1` for scan error, `2` for critical/high vulnerabilities found).

---

## 8. LLM Provider Abstraction

To avoid vendor lock-in and support both cutting-edge cloud models and on-premises local models, Mugiwara uses a unified `BaseLLMProvider` protocol.

```
                  ┌──────────────────────┐
                  │  BaseLLMProvider     │
                  │  (Abstract Protocol) │
                  └──────────┬───────────┘
                             │
       ┌─────────────────────┼─────────────────────┬─────────────────────┐
       │                     │                     │                     │
┌──────▼────────┐     ┌──────▼────────┐     ┌──────▼────────┐     ┌──────▼────────┐
│ Anthropic     │     │ OpenAI        │     │ Gemini        │     │ Ollama /      │
│ Provider      │     │ Provider      │     │ Provider      │     │ Local Provider│
└───────────────┘     └───────────────┘     └───────────────┘     └───────────────┘
```

### Core Provider Capabilities
1. **Async Text Completion & Chat:** Streaming and non-streaming responses.
2. **Structured Output Enforcement:** Guaranteed JSON validation matching Pydantic schemas (using function calling / JSON mode / tool use).
3. **Token & Cost Tracking:** Automatic tracking of prompt tokens, completion tokens, and estimated cost per scan session.
4. **Retry & Backoff:** Built-in exponential backoff handling rate limits (HTTP 429) and transient network failures.
5. **Model Registry:** Pluggable model configuration allowing easy mapping of agent roles to suitable models (e.g., fast model for code parsing, high-reasoning model for exploit synthesis).

---

## 9. Sandbox Architecture

Security verification requires running code, sending payloads, and evaluating responses. Executing dynamic tests directly on a host machine is dangerous. Mugiwara isolates all active execution inside ephemeral Docker containers.

```
┌─────────────────────────────────────────────────────────────┐
│                         Host OS                             │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐   │
│   │               Mugiwara Security Engine              │   │
│   └──────────────────────────┬──────────────────────────┘   │
│                              │ Docker SDK / Unix Socket     │
│   ┌──────────────────────────▼──────────────────────────┐   │
│   │              Docker Container Sandbox               │   │
│   │                                                     │   │
│   │   - Non-root user (uid: 1000)                       │   │
│   │   - Read-only root filesystem (where applicable)    │   │
│   │   - Isolated bridge network                         │   │
│   │   - Memory limit: 2GB (configurable)                │   │
│   │   - CPU quota: 2.0 cores (configurable)             │   │
│   │   - Execution timeout: 60s per command              │   │
│   │   - Mounted workspace volume: /workspace (isolated) │   │
│   │                                                     │   │
│   │   [ Target App Instance ] ◄── [ Test Probe / PoC ]  │   │
│   │                                                     │   │
│   └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Sandbox Guardrails
- **Ephemeral Lifecycle:** Containers are created per scan/test session and automatically destroyed on completion or crash.
- **Resource Constraints:** Hard CPU and memory quotas prevent container-based Denial of Service or fork bombs.
- **Network Boundaries:** Test containers operate on a private Docker bridge network; outbound internet traffic can be blocked or restricted via policy.
- **Command Sanitization & Timeouts:** Every dynamic command executed within the sandbox is monitored with a strict timeout clock.

---

## 10. AI Agent Architecture

Mugiwara employs a multi-agent collaborative model where specialized agents perform distinct roles under the supervision of the **Orchestrator Agent**.

```
                           ┌───────────────────────────┐
                           │    Orchestrator Agent     │
                           │   (Mission Coordinator)   │
                           └─────────────┬─────────────┘
                                         │
        ┌────────────────────────────────┼────────────────────────────────┐
        │                                │                                │
┌───────▼───────────────┐    ┌───────────▼───────────┐    ┌───────────────▼───────┐
│  Reconnaissance Agent │    │  Vulnerability Agent  │    │  Verification Agent   │
│ - Tech Stack ID       │    │ - OWASP Pattern Match │    │ - PoC Synthesis       │
│ - Attack Surface Map  │    │ - Logic Flaw Analysis │    │ - Sandbox Execution   │
│ - Endpoint Discovery  │    │ - Suspected Findings  │    │ - Evidence Capture    │
└───────────────────────┘    └───────────────────────┘    └───────────────┬───────┘
                                                                          │
                                                              ┌───────────▼───────┐
                                                              │ Remediation Agent │
                                                              │ - Code Patch Gen  │
                                                              │ - Re-verification │
                                                              └───────────────────┘
```

### Agent Roles & Responsibilities

1. **Orchestrator Agent:**
   - Analyzes target repository layout and scan configuration.
   - Plans scan phases and delegates tasks to specialized sub-agents.
   - Tracks global state, token budgets, and overall execution time.

2. **Reconnaissance Agent:**
   - Scans source code and configurations to detect frameworks (e.g., FastAPI, Express, Django, Spring), databases, authentication middleware, and public routes.
   - Builds a structured **Attack Surface Map** containing endpoints, HTTP methods, expected input parameters, and authentication requirements.

3. **Vulnerability Discovery Agent:**
   - Analyzes code paths and data flow from input sources to sinks.
   - Evaluates potential vulnerabilities against standard catalogs (OWASP Top 10, CWE).
   - Generates candidates for the **Suspected Findings** list with hypothesized vulnerability mechanisms.

4. **Exploit Verification Agent:**
   - Takes suspected findings and synthesizes minimal, safe Proof-of-Concept (PoC) validation scripts or HTTP requests.
   - Executes the PoC inside the isolated sandbox.
   - Evaluates outputs (status codes, canary tokens, error messages) to determine if the vulnerability is genuine or a false positive.

5. **Remediation Agent:**
   - Takes verified findings and the original source files.
   - Produces clean, idiomatic unified code diffs that remediate the flaw.
   - Requests re-testing against the PoC to confirm the fix works and prevents regressions.

---

## 11. Finding and Evidence Model

To guarantee reliability, findings must be strictly structured and supported by verifiable evidence.

```
┌─────────────────────────────────────────────────────────────┐
│                           Finding                           │
│  - id: UUID                                                 │
│  - title: str                                               │
│  - description: str                                         │
│  - category: VulnerabilityCategory (enum: SQLI, XSS, ...)   │
│  - severity: Severity (enum: CRITICAL, HIGH, MED, LOW, INFO)│
│  - status: FindingStatus (SUSPECTED, VERIFIED, FP, FIXED)   │
│  - cwe_id: Optional[str] (e.g., "CWE-89")                   │
│  - cvss_score: Optional[float]                              │
│  - file_location: SourceLocation (file, start_line, ...)    │
│  - evidence: Optional[Evidence]                             │
│  - remediation: Optional[Remediation]                       │
└──────────────────────────────┬──────────────────────────────┘
                               │
               ┌───────────────┴───────────────┐
               │                               │
┌──────────────▼──────────────┐ ┌──────────────▼──────────────┐
│          Evidence           │ │         Remediation         │
│ - poc_script: str           │ │ - explanation: str          │
│ - http_request: str         │ │ - unified_diff: str         │
│ - http_response: str        │ │ - target_file: str          │
│ - stdout_log: str           │ │ - fixed_lines: range        │
│ - canary_found: bool        │ │ - is_verified_fixed: bool   │
│ - verified_at: datetime     │ └─────────────────────────────┘
└─────────────────────────────┘
```

---

## 12. Security Model

Because Mugiwara Security handles security-sensitive source code and executes dynamic vulnerability probes, it adheres to rigorous defensive principles:

1. **Safe Canary Payloads:** Exploit payloads synthesized by the verification agent must be non-destructive. For example:
   - Command injection: Proves execution via harmless token echoing or `whoami`, never `rm`, `cat /etc/shadow`, or outbound network beacons.
   - SQL Injection: Uses boolean/arithmetic assertions (`1=1`, canary string concatenation), never `DROP`, `DELETE`, or data exfiltration.
   - File Traversal: Verifies reading of a harmless test marker or non-sensitive known file.
2. **Credential Redaction:** Automatic regex-based redaction of API keys, bearer tokens, passwords, and private secrets from all logs, stdout, and exported reports.
3. **Scope Enforcement:** Scans only target explicitly authorized local directories or .zip archives. Remote URL scanning is not supported.
4. **Least Privilege Runtime:** All containerized testing runs under unprivileged user IDs without host Docker socket sharing into child containers.

---

## 13. Repository Structure

The repository follows standard Python modern packaging with the `src/` layout:

```
mugiwara-security/
├── docs/
│   ├── PROJECT_SPEC.md              # Master specification (this document)
│   ├── ARCHITECTURE.md              # Architectural deep dives & diagrams
│   └── adr/                         # Architecture Decision Records
│       └── 0001-initial-architecture.md
├── src/
│   └── mugiwara/
│       ├── __init__.py              # Package metadata and version
│       ├── __main__.py              # python -m mugiwara entrypoint
│       ├── cli/
│       │   ├── __init__.py
│       │   ├── main.py              # Main Typer app & command routing
│       │   ├── console.py           # Rich console & theme configuration
│       │   └── commands/            # CLI subcommands
│       │       ├── __init__.py
│       │       ├── init.py
│       │       ├── scan.py
│       │       ├── sandbox.py
│       │       ├── report.py
│       │       └── fix.py
│       ├── core/
│       │   ├── __init__.py
│       │   ├── config.py            # Pydantic Settings & YAML loader
│       │   ├── exceptions.py        # Typed exception hierarchy
│       │   └── logging.py           # Structured logging setup
│       ├── models/
│       │   ├── __init__.py
│       │   ├── finding.py           # Finding, Severity, Category models
│       │   ├── evidence.py          # Evidence & PoC models
│       │   ├── remediation.py       # Patch & Diff models
│       │   └── report.py            # ScanReport & SARIF serializers
│       ├── providers/
│       │   ├── __init__.py
│       │   ├── base.py              # BaseLLMProvider protocol & DTOs
│       │   ├── factory.py           # Provider instantiation factory
│       │   ├── mock.py              # Mock provider for unit testing
│       │   ├── openai.py            # OpenAI API implementation
│       │   ├── anthropic.py         # Anthropic Claude implementation
│       │   ├── gemini.py            # Google Gemini implementation
│       │   └── ollama.py            # Ollama / Local API implementation
│       ├── sandbox/
│       │   ├── __init__.py
│       │   ├── base.py              # BaseSandbox abstraction
│       │   ├── docker.py            # Docker-based container runner
│       │   └── process.py           # Mock / Local process fallback
│       ├── agents/
│       │   ├── __init__.py
│       │   ├── base.py              # BaseAgent class & state management
│       │   ├── orchestrator.py      # Scan coordination agent
│       │   ├── recon.py             # Reconnaissance & mapping agent
│       │   ├── discovery.py         # Vulnerability candidate agent
│       │   ├── verification.py      # Exploit verification agent
│       │   └── remediation.py       # Code fix generation agent
│       └── utils/
│           ├── __init__.py
│           ├── diff.py              # Git diff parsing & applying
│           └── redaction.py         # Sensitive data scrubbing
├── tests/
│   ├── conftest.py                  # Global pytest fixtures
│   ├── unit/                        # Fast unit tests (no network/docker)
│   │   ├── test_config.py
│   │   ├── test_models.py
│   │   ├── test_providers.py
│   │   └── test_cli.py
│   ├── integration/                 # Integration tests (mocked I/O)
│   │   └── test_scan_workflow.py
│   └── fixtures/                    # Sample codebases & vulnerable apps
│       └── sample_vulnerable_app/
├── pyproject.toml                   # Build config, dependencies, tool settings
├── README.md                        # User introduction and quickstart
├── LICENSE                          # Apache 2.0 Open Source License
└── .gitignore                       # Git ignore rules
```

---

## 14. Testing Strategy

Quality and safety are verified through a multi-tiered testing hierarchy:

1. **Unit Tests (Fast, Isolated):**
   - Test data models, serialization/deserialization, config loaders, and CLI option parsing.
   - Use `MockLLMProvider` to test prompt rendering and response parsing without making real API calls.
   - Must run in `< 5 seconds` with zero network access required.
2. **Integration Tests (Subsystem Interaction):**
   - Test orchestrator workflows with simulated agent outputs.
   - Test SARIF export compliance against the official OASIS SARIF v2.1.0 schema validator.
3. **Sandbox & Fixture Tests (Container Verification):**
   - Execute controlled test scans against known intentionally vulnerable micro-apps (fixtures in `tests/fixtures/`).
   - Validate that real vulnerabilities are marked `VERIFIED` with complete evidence, and benign controls are marked `FALSE_POSITIVE` or discarded.
4. **Coverage Standard:**
   - Minimum target code coverage: **85%** across all core modules.
   - Mandatory type-checking via `mypy --strict`.

---

## 15. CI/CD Strategy

All repository automation is managed through GitHub Actions:

- **Lint & Static Analysis (`lint.yml`):**
  - Code formatting and linting via `ruff format --check` and `ruff check`.
  - Static type checking via `mypy src tests`.
- **Test Matrix (`test.yml`):**
  - Automated test runs across Python versions **3.10, 3.11, and 3.12**.
  - Code coverage reporting uploaded as build artifacts.
- **Security & Dependency Audit (`security.yml`):**
  - Dependency vulnerability scanning via `pip-audit`.
  - Static security scanning of the codebase using `bandit` or `semgrep`.
- **Automated Releases (`release.yml`):**
  - Tagged Git releases automatically build wheels and publish to PyPI with build provenance.

---

## 16. Development Rules for AI Coding Agents

When working on Mugiwara Security, all AI coding agents must follow these strict operational rules:

1. **Respect Phase Boundaries:** Implement ONLY the current active phase. Never scaffold or write empty stubs for future phases ahead of time.
2. **Strict Type Annotations:** Every function, parameter, return value, and class attribute must have explicit type annotations.
3. **No Unhandled Errors:** All operations that can fail (filesystem I/O, API calls, Docker commands) must catch specific exceptions and re-raise or wrap them into typed `MugiwaraError` exceptions.
4. **Zero-Fluff Code & Simple Maintainability:** Write clean, self-documenting code. Avoid over-engineering, unnecessary design patterns, or premature optimizations.
5. **No Network Calls in Unit Tests:** Unit tests must never contact external LLM APIs or external servers. Always use dependency injection and mock providers.
6. **Preserve User Code & Configs:** Never delete or overwrite user files, test fixtures, or existing configurations without explicit permission.

---

## 17. Complete Phased Roadmap

```
Phase 1: Foundation (Current Target)
   │  ├── Project setup (pyproject.toml, ruff, mypy, pytest)
   │  ├── Core configuration & Settings (pydantic-settings)
   │  ├── Domain data models (Finding, Evidence, Remediation, Report)
   │  ├── CLI base commands (init, config, version, scan --dry-run)
   │  ├── LLM provider protocol & Mock provider
   │  └── Comprehensive unit test suite
   │
Phase 2: Sandboxed Application Execution
   │  ├── Docker sandbox runtime management
   │  ├── Ephemeral container lifecycle & network isolation
   │  ├── Command execution monitor with timeouts & telemetry
   │  └── Safety boundaries & automatic cleanup handlers
   │
Phase 3: Security Agents
   │  ├── Agent base class & prompt management engine
   │  ├── Reconnaissance Agent (tech stack & attack surface mapping)
   │  ├── Vulnerability Discovery Agent (heuristic & semantic scanning)
   │  └── Orchestration loop with token budgeting
   │
Phase 4: Exploit Validation and Evidence
   │  ├── Exploit Verification Agent (PoC synthesis)
   │  ├── Sandbox-isolated dynamic exploit execution
   │  ├── Evidence capture (HTTP traffic, logs, canary tokens)
   │  └── False positive elimination engine
   │
Phase 5: CI/CD and GitHub Integration
   │  ├── Official GitHub Action packaging
   │  ├── SARIF v2.1.0 report exporter for GitHub Security tab
   │  ├── Pull Request comment annotations
   │  └── Configurable build-fail severity thresholds
   │
Phase 6: AI-Assisted Remediation
      ├── Remediation Agent (code patch generation)
      ├── Sandbox fix verification (regression testing against PoC)
      └── Interactive CLI patch applicator (`mugiwara fix`)
```

---

*This master specification serves as the single source of truth for the architecture and implementation of Mugiwara Security.*
