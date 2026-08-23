"""Real Docker sandbox integration test for Phase 6 AI-assisted remediation.

Exercises the complete remediation path end to end against a real container:
scan (heuristic discovery -> mock PoC verification) -> mock Shipwright patch
(f-string SQLi to parameterized SQL) -> isolated application on a disposable
copy -> re-execution of the ORIGINAL PoC with the ORIGINAL canary token ->
honest VERIFIED_FIXED only because the exploit demonstrably stops reproducing.

Skips automatically when the Docker daemon is unreachable or the demo image
has not been built:

    docker build -f docker/demo-sandbox.Dockerfile \
        -t mugiwara-sandbox-py-demo:latest .
"""

import asyncio
from pathlib import Path
from typing import Any

import pytest

from mugiwara.core.config import LLMProviderType, MugiwaraSettings, SandboxConfig, SandboxMode
from mugiwara.models.remediation import RemediationStatus
from mugiwara.remediation.service import RemediationService, build_remediation_bundle
from mugiwara.sandbox.docker import DockerSandbox

DEMO_IMAGE = "mugiwara-sandbox-py-demo:latest"

COHERENT_TARGET_SOURCE = '''\
"""Tiny coherent Flask target used to exercise real-container remediation."""

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


async def test_phase6_full_auto_remediation_proves_fix_in_container(tmp_path: Path) -> None:
    """No queued responses: every agent auto-synthesizes; the fix must be proven."""
    target = tmp_path / "coherent_app"
    target.mkdir()
    app_file = target / "app.py"
    app_file.write_text(COHERENT_TARGET_SOURCE, encoding="utf-8")

    settings = MugiwaraSettings()
    settings.llm.provider = LLMProviderType.MOCK
    settings.sandbox.mode = SandboxMode.DOCKER
    settings.sandbox.image = DEMO_IMAGE

    result = await RemediationService(settings).run(str(target))

    assert result.report.records, "verified finding must produce a remediation record"
    record = result.report.records[0]
    assert record.status is RemediationStatus.VERIFIED_FIXED
    assert record.sandbox_backend == "docker"
    assert record.reason is not None and "no longer reproduces" in record.reason

    patched = record.patched_content or ""
    assert '"SELECT * FROM users WHERE name = ?"' in patched
    assert "(username,)" in patched
    assert 'f"SELECT' not in patched and "'{username}'" not in patched

    evidence = record.post_validation_evidence
    assert evidence is not None
    assert evidence.canary_found is False
    assert evidence.canary_token
    assert evidence.canary_token.startswith("MUGIWARA_CANARY_")

    # The original working tree is byte-for-byte untouched.
    assert app_file.read_text(encoding="utf-8") == COHERENT_TARGET_SOURCE

    bundle = build_remediation_bundle(result, tool_version="test")
    assert bundle["summary"]["VERIFIED_FIXED"] == 1
    assert bundle["remediations"][0]["status"] == "VERIFIED_FIXED"


def test_phase6_sync_wrapper_matches_async_path(tmp_path: Path) -> None:
    """The synchronous helper drives the same proven-fix outcome."""
    target = tmp_path / "coherent_app_sync"
    target.mkdir()
    (target / "app.py").write_text(COHERENT_TARGET_SOURCE, encoding="utf-8")

    settings = MugiwaraSettings()
    settings.llm.provider = LLMProviderType.MOCK
    settings.sandbox.mode = SandboxMode.DOCKER
    settings.sandbox.image = DEMO_IMAGE

    from mugiwara.remediation.service import run_remediation

    asyncio.set_event_loop(None)
    result = run_remediation(settings, str(target))

    assert len(result.report.records) == 1
    assert result.report.records[0].status is RemediationStatus.VERIFIED_FIXED
