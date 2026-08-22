# Mugiwara Security

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

**Mugiwara Security** is an open-source, autonomous AI-powered security testing and vulnerability verification platform.

It pairs **AI security agents** with an **isolated Docker sandbox** to discover suspected vulnerabilities in a codebase, then actively verify them by executing safety-screened Proof-of-Concept probes against the running application inside an ephemeral container — reporting every finding with one of three honest outcomes and attaching concrete evidence (PoC script, HTTP trace, execution logs).

**Status:** Phases 1–4 of the [roadmap](docs/PROJECT_SPEC.md) are complete — foundation, sandboxed execution, security agents, and exploit validation with evidence. CI/CD integration (Phase 5) and AI-assisted remediation (Phase 6) are next.

---

## How It Works

1. **Recon** — collects sources, maps the tech stack, and statically extracts HTTP route declarations.
2. **Discovery** — heuristic rules (plus LLM reasoning when a real provider is configured) flag suspected vulnerabilities with locations and CWEs.
3. **Verification** — for each reachable high-severity candidate, the platform synthesizes a harmless PoC probe, screens it against a strict safety policy, stages it alongside the target in a sandbox, boots the target inside an ephemeral container, executes the probe, and evaluates the result.
4. **Report** — findings are emitted with status transitions and full evidence; false positives are excluded from the actionable count.

### Honest Tri-State Verification

Every dynamically tested candidate receives exactly one outcome:

| Outcome | Meaning |
|---|---|
| `VERIFIED` | The probe observed the canary token or a reproducible injection differential against the live target. Evidence is attached. |
| `FALSE_POSITIVE` | The target ran cleanly and the probe could not confirm exploitability. The finding is eliminated from actionable counts — evidence of the attempt is still attached. |
| `UNVERIFIED` | The probe could not run meaningfully (target failed readiness, timed out, produced no parsable verdict). Status stays `SUSPECTED`; nothing is claimed either way. |

Canary-based claims require the generated canary token to actually be observed echoing back — verdicts that claim success without observation are rejected.

### Attached Evidence

Each terminal outcome (`VERIFIED` / `FALSE_POSITIVE`) attaches:

- The exact **PoC script** that ran (after safety screening)
- Step-by-step **reproduction steps**
- The captured **HTTP trace** (method, URL, response status, body snippet)
- **Execution logs** from both the target process and the probe
- The **canary token** used and whether it was observed
- Verification timestamp and sandbox runtime duration

---

## Features

- Multi-phase agent pipeline (recon → discovery → verification) with token budgeting and graceful degradation
- Heuristic vulnerability engine (SQL injection, command injection, deserialization, unsafe YAML load, eval/exec, hardcoded secrets, debug mode, and more) with CWE mapping
- Ephemeral Docker sandbox hardened by construction: non-root user, read-only root filesystem, no host network or socket access, all capabilities dropped, hard memory/CPU/PID quotas, per-session internal network blocking outbound internet, guaranteed teardown
- Deterministic mock LLM provider with automatic synthesis of safety-screened verification plans (zero-network demos)
- Strict PoC safety screening before anything executes (banned destructive SQL verbs, probe-call allowlists, import allowlists, loopback-only URLs, size caps)
- Rich CLI: `scan`, `config`, `sandbox status/cleanup`, plus declared stubs for future phases (`report`, `fix`)
- JSON report export with configurable evidence inclusion

## Installation

Prerequisites: Python 3.10+, [uv](https://github.com/astral-sh/uv) (recommended), and Docker Desktop/Engine for dynamic verification.

```bash
git clone https://github.com/your-org/mugiwara-security.git
cd mugiwara-security

uv sync --extra dev          # or: uv pip install -e ".[dev]"
uv run mugiwara --version
```

## Docker Demo Setup

Dynamic verification runs the target inside the stock `python:3.12-slim` image, which has no outbound network by design. Targets whose dependencies are not preinstalled cannot start, so build the demo image once:

```bash
docker build -f docker/demo-sandbox.Dockerfile -t mugiwara-sandbox-py-demo:latest .
```

The committed `mugiwara.yaml` already points `sandbox.image` at it and selects the mock provider, so the demo commands below work as-is on a fresh checkout.

## Demo

```bash
# 1. Verify the sandbox backend
uv run mugiwara sandbox status

# 2a. Scan the sample fixture: dynamic verification runs and honestly
#     eliminates its SQLi candidate as a FALSE POSITIVE (the fixture's
#     entry point never registers the vulnerable route at runtime).
uv run mugiwara scan tests/fixtures/sample_vulnerable_app

# 2b. Scan the coherent demo target: the synthesized probe genuinely
#     confirms SQL injection inside the real container -> VERIFIED by PoC.
uv run mugiwara scan examples/coherent_sqli_app

# 3. Export a machine-readable report with full evidence
uv run mugiwara scan examples/coherent_sqli_app -o report.json --format json
```

`--provider mock` is the default via config; pass `--sandbox none` to skip dynamic verification, or `--skip-verification` to report suspected findings only.

## Testing

```bash
uv run pytest                        # 293 tests passing
uv run ruff check . && uv run ruff format --check .
uv run mypy src tests                # strict mode
```

The two real-container integration tests skip automatically when Docker is unavailable; all other tests are hermetic and network-free.

## Limitations (Honest Scope)

- The **mock LLM provider is currently the reliable path**; OpenAI/Anthropic/Gemini/Ollama providers are deferred to a future phase and fail fast with a clear message if selected.
- `report show`, `report export`, and `fix` are declared future-phase stubs.
- `scan --format sarif|markdown` is rejected until the Phase 5 SARIF exporter lands; supported scan output formats today are `text` and `json`.
- AI-assisted remediation is Phase 6 work; nothing modifies your code today.
- The sample fixture's SQLi finding is eliminated as a false positive at runtime (its entry point and routes live in disjoint Flask apps); use `examples/coherent_sqli_app` to see a live `VERIFIED` result.

## Roadmap

- **Phase 5 — CI/CD & GitHub Integration**: genuine SARIF 2.1.0 export, GitHub Action packaging, PR annotations
- **Phase 6 — AI-Assisted Remediation**: patch generation verified against stored PoCs

See [docs/PROJECT_SPEC.md](docs/PROJECT_SPEC.md) for the full architecture and specification.

---

## License

Mugiwara Security is licensed under the [Apache License 2.0](LICENSE).
