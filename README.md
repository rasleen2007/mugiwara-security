# Mugiwara Security

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

**Mugiwara Security** is an open-source, autonomous AI-powered security testing and vulnerability verification platform.

It combines **intelligent AI security agents** with **isolated execution sandboxes** to actively discover, safely validate, and fix security vulnerabilities with verifiable proof (Proof-of-Concept scripts, exact HTTP traces, and execution logs).

---

## Architecture & Specification

For detailed architecture diagrams, agent models, sandbox design, and the complete phased development roadmap, see:
- [docs/PROJECT_SPEC.md](docs/PROJECT_SPEC.md)

---

## Getting Started (Development)

### Prerequisites
- Python 3.10 or higher
- [uv](https://github.com/astral-sh/uv) (recommended) or standard `pip` / `venv`

### Setup Environment
```bash
# Clone the repository
git clone https://github.com/your-org/mugiwara-security.git
cd mugiwara-security

# Create and activate virtual environment using uv
uv venv
.venv\Scripts\activate     # On Windows
# source .venv/bin/activate # On Linux/macOS

# Install in editable mode with development dependencies
uv pip install -e ".[dev]"
```

### Running Tests & Quality Checks
```bash
# Run test suite
uv run pytest

# Check code formatting and linting
uv run ruff check .
uv run ruff format --check .

# Run static type checking
uv run mypy src tests
```

---

## Roadmap

- **Phase 1 — Foundation** *(In Progress)*
- **Phase 2 — Sandboxed Application Execution**
- **Phase 3 — Security Agents**
- **Phase 4 — Exploit Validation and Evidence**
- **Phase 5 — CI/CD and GitHub Integration**
- **Phase 6 — AI-Assisted Remediation**

---

## License

Mugiwara Security is licensed under the [Apache License 2.0](LICENSE).
