# Mugiwara Security

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

**Mugiwara Security** is an open-source, autonomous AI-powered security testing and vulnerability verification platform.

It pairs **AI security agents** with an **isolated Docker sandbox** to discover suspected vulnerabilities in a codebase, then actively verify them by executing safety-screened Proof-of-Concept probes against the running application inside an ephemeral container — reporting every finding with one of three honest outcomes, attaching concrete evidence, and generating sandbox-proven remediation patches for confirmed issues.

**Status:** All roadmap phases through Phase 8 are implemented: foundation, sandboxed execution, security agents, exploit validation with evidence, CI/CD integration with genuine SARIF 2.1.0 export, AI-assisted remediation with sandbox-verified fixes, persisted report lifecycle, and release hardening.

---

## How It Works

1. **Recon** — collects sources, maps the tech stack, and statically extracts HTTP route declarations.
2. **Discovery** — heuristic rules (plus LLM reasoning when an Ollama provider is configured) flag suspected vulnerabilities with locations and CWEs.
3. **Verification** — for each reachable high-severity candidate, the platform synthesizes a harmless PoC probe, screens it against a strict safety policy, stages it alongside the target in a sandbox, boots the target inside an ephemeral container, executes the probe, and evaluates the result.
4. **Remediation** — for verified findings, the remediation agent proposes a patch, applies it to an *isolated copy* of the target, and re-runs the original PoC in the sandbox to prove the fix works before you ever touch your working tree.
5. **Report** — findings are emitted with status transitions and full evidence; false positives are excluded from the actionable count. Every scan is persisted to a local report store for later inspection and export.

### Honest Tri-State Verification

Every dynamically tested candidate receives exactly one outcome:

| Outcome | Meaning |
|---|---|
| `VERIFIED` | The probe observed the canary token or a reproducible injection differential against the live target. Evidence is attached. |
| `FALSE_POSITIVE` | The target ran cleanly and the probe could not confirm exploitability. The finding is eliminated from actionable counts — evidence of the attempt is still attached. |
| `UNVERIFIED` | The probe could not run meaningfully (target failed readiness, timed out, produced no parsable verdict). Status stays `SUSPECTED`; nothing is claimed either way. |

Canary-based claims require the generated canary token to actually be observed echoing back — verdicts that claim success without observation are rejected. Remediation outcomes follow the same honesty rule: `VERIFIED_FIXED`, `NOT_FIXED`, or `FAILED`, backed by a re-executed PoC.

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

- Multi-phase agent pipeline (recon → discovery → verification → remediation) with token budgeting and graceful degradation
- Heuristic vulnerability engine (SQL injection, command injection, deserialization, unsafe YAML load, eval/exec, hardcoded secrets, debug mode, and more) with CWE mapping
- Ephemeral Docker sandbox hardened by construction: non-root user, read-only root filesystem, no host network or socket access, all capabilities dropped, hard memory/CPU/PID quotas, per-session internal network blocking outbound internet, guaranteed teardown
- Opt-in dependency-aware sandbox images derived from the target's `requirements.txt` (see below)
- Local-first LLM support: deterministic mock provider (zero-network demos) and Ollama for real local models; remote cloud providers fail closed by design
- Strict PoC safety screening before anything executes (banned destructive SQL verbs, probe-call allowlists, import allowlists, loopback-only URLs, size caps)
- Automatic secret redaction in evidence, logs, and exported reports
- Persisted report lifecycle: every scan is stored locally; list, inspect, export, and delete reports via the CLI
- AI-assisted remediation that never modifies your working tree — patches are proven on isolated copies and returned as reviewable bundles
- Local web dashboard (`mugiwara ui`): start scans, browse persisted reports and findings, export documents, and generate sandbox-proven fixes — bound to 127.0.0.1 only
- Exports: JSON, genuine SARIF 2.1.0 for GitHub Code Scanning, and Markdown

## Installation

Prerequisites: Python 3.10+, [uv](https://github.com/astral-sh/uv) (recommended), and Docker Desktop/Engine for dynamic verification and remediation.

```bash
git clone https://github.com/your-org/mugiwara-security.git
cd mugiwara-security

uv sync --extra dev          # or: uv pip install -e ".[dev]"
uv run mugiwara --version
```

## LLM Providers

Mugiwara is local-first: source code never leaves your machine unless you explicitly allow it.

| Provider | Status | Notes |
|---|---|---|
| `mock` | Fully supported | Deterministic, zero-network; synthesizes safe verification plans automatically. Default in the committed demo config. |
| `ollama` | Fully supported | Real reasoning via your local [Ollama](https://ollama.com) daemon. Default in code configuration. |
| `openai` / `anthropic` / `gemini` | Fail closed by design | No client implementation exists yet; selecting them raises a clear error regardless of `llm.allow_remote`. |

### Setting up Ollama

```bash
# 1. Install and start Ollama (https://ollama.com), then pull a model:
ollama pull llama3.2

# 2. Point Mugiwara at it (the daemon defaults to http://localhost:11434):
uv run mugiwara scan examples/coherent_sqli_app \
    --provider ollama --model llama3.2

# or persist the choice in mugiwara.yaml:
#   llm:
#     provider: ollama
#     model: llama3.2
#     api_base: http://localhost:11434   # optional override
```

The provider enforces its egress policy at construction time: endpoints must be on the local machine unless `llm.allow_remote: true` is set explicitly.

## Sandbox Images

Dynamic verification runs the target inside a container image. Two options:

1. **Stock image** (default): `python:3.12-slim`. It has no outbound network by design, so targets whose dependencies are not preinstalled cannot start.
2. **Demo image**: build once and use via the committed `mugiwara.yaml`:

    ```bash
    docker build -f docker/demo-sandbox.Dockerfile -t mugiwara-sandbox-py-demo:latest .
    ```

3. **Dependency-aware images** (opt-in): set `sandbox.auto_build_image: true` (optionally `sandbox.image_build_timeout_seconds`, default 300) and Mugiwara derives an ephemeral `mugiwara/tgt-<hash>` image from the target's root `requirements.txt` using a fixed template. Package downloads happen once at image-build time under a hard timeout; runtime containers keep every guardrail above unchanged. Requires no manual steps per target.

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

# 3. Export machine-readable reports with full evidence
uv run mugiwara scan examples/coherent_sqli_app -o report.json --format json
uv run mugiwara scan examples/coherent_sqli_app -o report.sarif --format sarif
uv run mugiwara scan examples/coherent_sqli_app -o report.md --format markdown
```

Pass `--skip-verification` to report suspected findings only, `--no-save-report` to disable persistence, or `--dry-run` to preview the plan. Progress and status tables go to stderr; when streaming `--format sarif` or `--format markdown` without `-o`, the document itself goes to stdout so pipes stay clean.

Scans accept either a project directory or a `.zip` archive (extracted into a disposable workspace that is always cleaned up).

## Reports

Every scan persists a full report envelope under `.mugiwara/reports/` (anchored to the scanned project):

```bash
uv run mugiwara report list                          # newest first
uv run mugiwara report show <report_id>
uv run mugiwara report export <report_id> --format sarif -o findings.sarif
uv run mugiwara report export <report_id> --format markdown
uv run mugiwara report delete <report_id>            # add --yes to skip confirmation
```

Export formats: `json`, `sarif`, `markdown`.

## Web Dashboard

```bash
uv run mugiwara ui            # full workbench on http://127.0.0.1:8420
```

The workbench is a localhost-only interface over the same engine the CLI uses — not a second scanner:

- **Scan a Project** by entering an authorized local directory or uploading a `.zip`; uploads pass through the identical hardened ZIP intake (traversal, symlink, encryption, size, and entry-count protections included).
- Live progress follows the deterministic pipeline phases (Collecting → Reconnaissance → Discovery → Verification → Complete) using secret-free counters only.
- Reports view lists everything in the existing report store with view/export/delete actions; findings expand to show details, remediation guidance, and evidence exactly as stored.
- **Generate Fix Bundle** runs the real `RemediationService.run_stored_report` flow with its fail-closed binding intact: patches are always applied to the exact directory recorded in the report, proven against the original PoC, and displayed with sea-trial results.
- Settings is a read-only view of effective configuration; changes belong in `mugiwara.yaml` / the CLI.

Security posture: binds to 127.0.0.1 only (non-loopback addresses are refused), validates every path server-side, never executes shell commands, never exposes Docker or sandbox internals, and adds `no-store`/`nosniff` headers to every response.

The classic single-bundle viewer remains available: `mugiwara ui fix-bundle.json`.

## Fixing Findings

```bash
# Generate + sandbox-verify patches for up to N verified findings,
# writing a reviewable fix bundle (scan + remediations) for 'mugiwara ui':
uv run mugiwara fix examples/coherent_sqli_app -o fix-bundle.json

# Re-run against a previously stored report instead of re-scanning:
uv run mugiwara fix . --report <report_id> --project-root .
```

Remediation applies each proposed patch to an **isolated copy** of the project, boots it in the sandbox, and re-runs the original PoC. Exit codes: `0` fixed or nothing actionable, `1` operational error, `2` any patch ended `NOT_FIXED`/`FAILED`. Your original files are never modified; apply reviewed changes yourself.

## CI / GitHub Actions

### Exit-code contract (`mugiwara scan`)

| Code | Meaning |
|---|---|
| `0` | Scan completed with no actionable critical/high findings (medium/low/info findings may still be present; false positives excluded). |
| `1` | Operational failure: bad configuration, unsupported provider/format, I/O error. Nothing is claimed about findings. |
| `2` | Actionable critical/high findings found — **either VERIFIED or SUSPECTED** (unverified). False positives never count. Check the report/summary to see which outcomes were confirmed dynamically. |

UNVERIFIED probes keep their findings in the SUSPECTED state; they are reported honestly as unconfirmed and are never presented as verified vulnerabilities.

### SARIF 2.1.0

```bash
uv run mugiwara scan examples/coherent_sqli_app -o mugiwara-results.sarif --format sarif
```

The exporter emits genuine SARIF 2.1.0 (not Mugiwara's internal schema): tool/driver metadata, one rule per vulnerability category with CWE tags, severity→level mapping (`CRITICAL`/`HIGH` → `error`, `MEDIUM` → `warning`, `LOW`/`INFO` → `note`), stable result fingerprints, and evidence (PoC script, HTTP trace, canary status) under result properties when enabled.

Without `--output`, `--format sarif` streams the SARIF JSON to stdout for piping.

### Reusable composite action

`.github/actions/mugiwara-scan` installs the project, runs a scan with the deterministic mock provider (no network or API keys required), writes SARIF, and fails on actionable critical/high findings:

```yaml
- uses: your-org/mugiwara-security/.github/actions/mugiwara-scan@main
  with:
    target: "."
    sarif-output: "mugiwara-results.sarif"
    fail-on-findings: "true"

- uses: github/codeql-action/upload-sarif@v3
  if: ${{ hashFiles('mugiwara-results.sarif') != '' }}
  with:
    sarif_file: "mugiwara-results.sarif"
```

This repository runs its own instance of that pipeline in `.github/workflows/security-scan.yml`.

## Security Model

- **Safe payloads:** probes prove execution with harmless canary tokens and boolean assertions — never destructive SQL verbs, file destruction, or outbound beacons. Every synthesized PoC passes static safety screening before execution.
- **Redaction:** API keys, bearer tokens, passwords, and private secrets are regex-redacted from logs, evidence, and exports.
- **Scope enforcement:** only explicitly authorized local directories or `.zip` archives are scanned; remote URL scanning does not exist.
- **Egress control:** LLM traffic must terminate on the local machine unless `llm.allow_remote: true`; cloud providers additionally fail closed while unimplemented.
- **Least privilege runtime:** containers run non-root with dropped capabilities, read-only root filesystems, resource quotas, and no access to the host Docker socket or outside internet.

## Testing & Quality Gates

```bash
uv run pytest                        # unit + integration suite
uv run ruff check .                  # lint
uv run ruff format --check .         # formatting
uv run mypy src                      # strict type checking
uv run pyrefly check                 # static semantic analysis
```

All tests except two real-container integration tests are hermetic and network-free; those skip automatically when Docker is unavailable.

## Limitations (Honest Scope)

- Supported providers today are `mock` and `ollama`. OpenAI/Anthropic/Gemini fail fast with a clear message by design until client implementations land.
- Dynamic verification targets Python web applications whose entry point can be booted inside the sandbox; other runtimes are out of scope for now.
- Scanning accepts local directories and ZIP archives only — no URL scanning.
- The sample fixture's SQLi finding is eliminated as a false positive at runtime (its entry point and routes live in disjoint Flask apps); use `examples/coherent_sqli_app` to see a live `VERIFIED` result.
- Pull-request comment annotations are not implemented; CI integration is SARIF upload plus exit codes.
- `mugiwara fix` proves patches on isolated copies but never applies them to your working tree; reviewing and applying the bundle is a human step.

## Roadmap

All phases of the original specification are implemented through Phase 8 (release hardening). Future work beyond this scope would include remote cloud providers behind the existing egress gate and additional verification runtimes — see [docs/PROJECT_SPEC.md](docs/PROJECT_SPEC.md) for the architecture and explicit non-goals.

---

## License

Mugiwara Security is licensed under the [Apache License 2.0](LICENSE).
