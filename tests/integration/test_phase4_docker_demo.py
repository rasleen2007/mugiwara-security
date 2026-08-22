"""Real Docker sandbox integration tests for the Phase 4 mock-provider demo.

Exercises the complete verification path end to end: mock LLM synthesis of a
deterministic VerificationPlan, PoC safety screening, staging, real container
execution with the target application booted inside, verdict evaluation, and
evidence attachment. Skips automatically when the Docker daemon is unreachable
or the prebuilt demo image (docker/demo-sandbox.Dockerfile) has not been
built locally:

    docker build -f docker/demo-sandbox.Dockerfile \
        -t mugiwara-sandbox-py-demo:latest .

Note: the sample fixture intentionally defines disjoint Flask instances
(app.py never registers routes.py), so its /users route 404s at runtime and
the honest dynamic outcome for the SQLi candidate is FALSE_POSITIVE with full
evidence attached. The coherent tmp-path target below proves the VERIFIED
flip inside a real container.
"""

from pathlib import Path
from typing import Any

import pytest

from mugiwara.agents.models import AttackSurfaceMap, Endpoint, SuspectedFindingsReport
from mugiwara.agents.orchestrator import ScanOrchestrator, SessionPhase
from mugiwara.agents.poc_safety import screen_poc
from mugiwara.core.config import LLMProviderType, MugiwaraSettings, SandboxConfig, SandboxMode
from mugiwara.models.finding import FindingStatus
from mugiwara.providers.mock import MockLLMProvider
from mugiwara.sandbox.docker import DockerSandbox

FIXTURE_APP = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "sample_vulnerable_app"

DEMO_IMAGE = "mugiwara-sandbox-py-demo:latest"

COHERENT_TARGET_SOURCE = '''\
"""Tiny coherent Flask target used to exercise real-container verification."""

import sqlite3

from flask import Flask, request

app = Flask(__name__)
_connection = sqlite3.connect("users.db")
_connection.execute(
    "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)"
)
_connection.execute("INSERT INTO users VALUES (1, 'demo-user')")
_connection.commit()
_connection.close()


@app.route("/users")
def list_users():
    """List users matching an unfiltered name parameter."""
    username = request.args.get("username", "")
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    rows = str(cursor.fetchall())
    connection.close()
    return rows


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
'''


def _docker_client() -> Any:
    """Return a live docker client, or None when the daemon is unreachable."""
    try:
        return DockerSandbox(SandboxConfig())._ensure_client()
    except Exception:
        return None


def _demo_image_available() -> bool:
    """Return True when the local daemon already has the demo image built."""
    client = _docker_client()
    if client is None:
        return False
    try:
        client.images.get(DEMO_IMAGE)
    except Exception:
        return False
    return True


pytestmark = [
    pytest.mark.skipif(
        not DockerSandbox.is_docker_available(),
        reason="Docker daemon unavailable",
    ),
    pytest.mark.skipif(
        not _demo_image_available(),
        reason=f"demo image '{DEMO_IMAGE}' not built (see docker/demo-sandbox.Dockerfile)",
    ),
]


def _demo_settings() -> MugiwaraSettings:
    settings = MugiwaraSettings()
    settings.llm.provider = LLMProviderType.MOCK
    settings.sandbox.mode = SandboxMode.DOCKER
    settings.sandbox.image = DEMO_IMAGE
    return settings


def _queued_surface(source_file: str) -> AttackSurfaceMap:
    return AttackSurfaceMap(
        summary="Flask service.",
        endpoints=[Endpoint(path="/users", method="GET", source_file=source_file)],
    )


async def test_mock_provider_demo_reports_honest_false_positive_in_container() -> None:
    """Fixture run: full Phase 4 path ends in evidence-backed FALSE_POSITIVE."""
    provider = MockLLMProvider()
    provider.add_structured_response(_queued_surface("routes.py"))
    provider.add_structured_response(SuspectedFindingsReport(findings=[]))

    result = await ScanOrchestrator(_demo_settings()).run(str(FIXTURE_APP))

    assert result.diagnostics.degraded is False
    assert SessionPhase.VERIFICATION in result.phases_completed
    diagnostics = result.diagnostics
    assert diagnostics.sandbox_backend == "docker"
    assert diagnostics.verification_candidates == 1
    assert diagnostics.verification_attempted == 1
    assert diagnostics.verification_false_positives == 1

    fps = [
        f
        for f in result.report.findings
        if f.category.value == "sql_injection" and f.evidence is not None
    ]
    assert len(fps) == 1, "exactly the reachable routes.py SQLi candidate gets evidence"
    sqli = fps[0]
    assert sqli.location is not None and sqli.location.file_path.endswith("routes.py")
    assert sqli.status is FindingStatus.FALSE_POSITIVE
    evidence = sqli.evidence
    assert evidence is not None
    assert evidence.canary_token
    assert evidence.canary_token.startswith("MUGIWARA_CANARY_")
    assert evidence.canary_found is False
    screening = screen_poc(evidence.poc_script or "", max_bytes=16_384)
    assert screening.allowed, screening.reasons
    assert evidence.http_trace is not None
    assert evidence.http_trace.response_status_code == 404
    assert evidence.stdout_log is not None and "Running on" in evidence.stdout_log
    assert evidence.verified_at is not None


async def test_mock_provider_demo_verifies_sqli_in_real_container(
    tmp_path: Path,
) -> None:
    """Coherent target run: the synthesized probe flips SQLi to VERIFIED live."""
    (tmp_path / "app.py").write_text(COHERENT_TARGET_SOURCE, encoding="utf-8")

    provider = MockLLMProvider()
    provider.add_structured_response(_queued_surface("app.py"))
    provider.add_structured_response(SuspectedFindingsReport(findings=[]))

    result = await ScanOrchestrator(_demo_settings()).run(str(tmp_path))

    assert result.diagnostics.degraded is False
    assert SessionPhase.VERIFICATION in result.phases_completed
    diagnostics = result.diagnostics
    assert diagnostics.sandbox_backend == "docker"
    assert diagnostics.verification_candidates >= 1
    assert diagnostics.verification_verified >= 1

    verified = [f for f in result.report.findings if f.status is FindingStatus.VERIFIED]
    assert verified, "coherent SQLi target must reach VERIFIED in a real container"
    evidence = verified[0].evidence
    assert evidence is not None
    assert evidence.canary_token
    assert evidence.canary_token.startswith("MUGIWARA_CANARY_")
    assert evidence.canary_found is True
    screening = screen_poc(evidence.poc_script or "", max_bytes=16_384)
    assert screening.allowed, screening.reasons
    assert evidence.http_trace is not None
    assert evidence.http_trace.response_status_code is not None
    assert evidence.stdout_log is not None and "Running on" in evidence.stdout_log
    assert evidence.verified_at is not None
