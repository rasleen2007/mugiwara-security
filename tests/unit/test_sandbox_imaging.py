"""Unit tests for dependency-aware sandbox imaging (S5).

Every test is hermetic: Docker interactions run against in-memory fakes,
and no test requires a daemon or network access.
"""

import asyncio
import io
import re
import tarfile
import threading
from pathlib import Path

import pytest

from mugiwara.agents.sources import CollectedSources, SourceFile, WorkspaceCollector
from mugiwara.core.config import MugiwaraSettings, SandboxConfig, SandboxMode
from mugiwara.core.exceptions import SandboxImageBuildError
from mugiwara.sandbox.docker import DEFAULT_SANDBOX_IMAGE
from mugiwara.sandbox.imaging import (
    DependencyImageBuilder,
    DependencyManifest,
    build_dependency_dockerfile,
    dependency_image_tag,
    detect_dependency_manifest,
    resolve_dependency_image,
)

REQUIREMENTS = "flask==3.0.0\nrequests>=2.31\n"

TAG_PATTERN = re.compile(r"^mugiwara/tgt-[0-9a-f]{16}$")


def _source(relative_path: str, content: str) -> SourceFile:
    """Build one collected source entry."""
    return SourceFile(
        relative_path=relative_path,
        absolute_path=Path("<memory>") / relative_path,
        size_bytes=len(content.encode("utf-8")),
        line_count=content.count("\n"),
        content=content,
    )


def _sources(*files: SourceFile) -> CollectedSources:
    """Wrap collected files into the collector's result shape."""
    return CollectedSources(files=list(files))


def _manifest() -> DependencyManifest:
    """Return a canonical manifest for tag/dockerfile tests."""
    return DependencyManifest(
        filename="requirements.txt",
        content=REQUIREMENTS,
        size_bytes=len(REQUIREMENTS.encode("utf-8")),
    )


class FakeBuiltImage:
    """Image handle returned by the fake build call."""

    def __init__(self, tags: list[str]) -> None:
        self.tags = tags


class FakeImagesApi:
    """Fake client.images collection covering get/build for imaging."""

    def __init__(
        self,
        local: set[str] | None = None,
        build_error: Exception | None = None,
    ) -> None:
        self.local: set[str] = local or set()
        self.build_error = build_error
        self.get_calls: list[str] = []
        self.build_kwargs: list[dict[str, object]] = []

    def get(self, name: str) -> dict[str, str]:
        self.get_calls.append(name)
        if name not in self.local:
            raise RuntimeError(f"image {name} not found locally")
        return {"id": name}

    def build(self, **kwargs: object) -> tuple[FakeBuiltImage, list[dict[str, str]]]:
        self.build_kwargs.append(kwargs)
        if self.build_error is not None:
            raise self.build_error
        tag = str(kwargs["tag"])
        self.local.add(tag)
        return FakeBuiltImage([tag]), []


class FakeClient:
    """Minimal docker client carrying only an images collection."""

    def __init__(self, images: FakeImagesApi) -> None:
        self.images = images


class FakeBuildError(Exception):
    """Stand-in for docker.errors.BuildError carrying a log payload."""

    def __init__(self, log: list[dict[str, str]]) -> None:
        super().__init__("The command '/bin/sh' returned a non-zero code: 1")
        self.msg = log


# ---------------------------------------------------------------------------
# Manifest detection.
# ---------------------------------------------------------------------------


def test_detect_manifest_root_requirements() -> None:
    """A root-level requirements.txt is detected verbatim."""
    manifest = detect_dependency_manifest(_sources(_source("requirements.txt", REQUIREMENTS)))

    assert manifest is not None
    assert manifest.filename == "requirements.txt"
    assert manifest.content == REQUIREMENTS
    assert manifest.size_bytes == len(REQUIREMENTS.encode("utf-8"))


def test_detect_manifest_absent_returns_none() -> None:
    """Targets without a manifest keep the default image flow."""
    sources = _sources(_source("app.py", "print('hi')\n"))

    assert detect_dependency_manifest(sources) is None


def test_detect_manifest_blank_returns_none() -> None:
    """An empty requirements file declares nothing."""
    sources = _sources(_source("requirements.txt", "   \n\n"))

    assert detect_dependency_manifest(sources) is None


def test_detect_manifest_nested_ignored() -> None:
    """Only root-level manifests count; vendored copies cannot hijack builds."""
    sources = _sources(_source("vendor/sub/requirements.txt", REQUIREMENTS))

    assert detect_dependency_manifest(sources) is None


def test_detect_manifest_oversized_rejected() -> None:
    """Oversized manifests fail closed instead of feeding the daemon."""
    bloated = "# padding comment line to inflate the manifest size\n" * 12_000

    with pytest.raises(SandboxImageBuildError, match="exceeds"):
        detect_dependency_manifest(_sources(_source("requirements.txt", bloated)))


def test_detect_manifest_binary_nul_rejected() -> None:
    """Binary garbage masquerading as text fails closed."""
    with pytest.raises(SandboxImageBuildError, match="UTF-8"):
        detect_dependency_manifest(_sources(_source("requirements.txt", "\x00\x01\x02bin")))


# ---------------------------------------------------------------------------
# Deterministic tagging and fixed Dockerfile template.
# ---------------------------------------------------------------------------


def test_tag_deterministic_and_wellformed() -> None:
    """Identical inputs yield identical tags; format is repo+16 hex."""
    first = dependency_image_tag(DEFAULT_SANDBOX_IMAGE, _manifest())
    second = dependency_image_tag(DEFAULT_SANDBOX_IMAGE, _manifest())

    assert first == second
    assert TAG_PATTERN.match(first)


def test_tag_changes_with_inputs() -> None:
    """Any change of base image or manifest bytes produces a new identity."""
    other_manifest = DependencyManifest(
        filename="requirements.txt",
        content="flask==2.9.9\n",
        size_bytes=13,
    )

    assert dependency_image_tag(DEFAULT_SANDBOX_IMAGE, _manifest()) != (
        dependency_image_tag(DEFAULT_SANDBOX_IMAGE, other_manifest)
    )
    assert dependency_image_tag("python:3.11-slim", _manifest()) != (
        dependency_image_tag(DEFAULT_SANDBOX_IMAGE, _manifest())
    )


def test_dockerfile_template_is_fixed_shape() -> None:
    """Manifest travels as a context file; never interpolated into RUN."""
    dockerfile = build_dependency_dockerfile(DEFAULT_SANDBOX_IMAGE)

    lines = dockerfile.splitlines()
    assert lines[0] == f"FROM {DEFAULT_SANDBOX_IMAGE}"
    assert lines[1] == "COPY mugiwara-dependencies.txt /tmp/mugiwara-dependencies.txt"
    pip_line = next(line for line in lines if "pip install" in line)
    assert "--requirement /tmp/mugiwara-dependencies.txt" in pip_line
    assert lines[-1] == "USER 1000:1000"
    # Target-controlled text must not appear anywhere in the instructions.
    for requirement_line in REQUIREMENTS.strip().splitlines():
        assert requirement_line not in dockerfile


# ---------------------------------------------------------------------------
# Builder behavior over the fake daemon.
# ---------------------------------------------------------------------------


def test_cache_hit_skips_build() -> None:
    """An existing tag matching current inputs is reused untouched."""
    tag = dependency_image_tag(DEFAULT_SANDBOX_IMAGE, _manifest())
    images = FakeImagesApi(local={tag})
    builder = DependencyImageBuilder(FakeClient(images))

    resolved = builder.ensure_image(
        DEFAULT_SANDBOX_IMAGE,
        _manifest(),
        timeout_seconds=30,
    )

    assert resolved == tag
    assert images.get_calls == [tag]
    assert images.build_kwargs == []


def test_cache_miss_builds_once_then_caches() -> None:
    """First miss builds from a tar context; second call hits the cache."""
    images = FakeImagesApi()
    builder = DependencyImageBuilder(FakeClient(images))
    expected_tag = dependency_image_tag(DEFAULT_SANDBOX_IMAGE, _manifest())

    first = builder.ensure_image(DEFAULT_SANDBOX_IMAGE, _manifest(), timeout_seconds=30)
    second = builder.ensure_image(DEFAULT_SANDBOX_IMAGE, _manifest(), timeout_seconds=30)

    assert first == second == expected_tag
    assert len(images.build_kwargs) == 1
    assert len(images.get_calls) == 2  # miss + one subsequent hit

    kwargs = images.build_kwargs[0]
    assert kwargs["tag"] == expected_tag

    raw_context = io.BytesIO(kwargs["fileobj"].read())  # type: ignore[attr-defined]
    with tarfile.open(fileobj=raw_context) as context:
        names = sorted(context.getnames())
        assert names == ["Dockerfile", "mugiwara-dependencies.txt"]
        manifest_payload = context.extractfile("mugiwara-dependencies.txt")
        assert manifest_payload is not None
        assert manifest_payload.read().decode("utf-8") == REQUIREMENTS


def test_build_failure_raises_typed_error_with_log_tail() -> None:
    """Package-install failures surface as typed errors with the log tail."""
    log = [{"stream": f"step {index}\n"} for index in range(20)]
    log.append({"stream": "ERROR: ResolutionImpossible for flask==999.999\n"})
    images = FakeImagesApi(build_error=FakeBuildError(log))
    builder = DependencyImageBuilder(FakeClient(images))

    with pytest.raises(SandboxImageBuildError, match="ResolutionImpossible") as excinfo:
        builder.ensure_image(DEFAULT_SANDBOX_IMAGE, _manifest(), timeout_seconds=30)

    assert "build log tail" in str(excinfo.value)


def test_build_result_without_expected_tag_fails_closed() -> None:
    """A daemon success that omits the requested tag is treated as failure."""
    images = FakeImagesApi()

    def mislabeled_build(**kwargs: object) -> tuple[FakeBuiltImage, list[dict[str, str]]]:
        images.build_kwargs.append(kwargs)
        return FakeBuiltImage(["mugiwara/tgt-deadbeefdeadbeef"]), []

    images.build = mislabeled_build  # type: ignore[method-assign]
    builder = DependencyImageBuilder(FakeClient(images))

    with pytest.raises(SandboxImageBuildError, match="without producing"):
        builder.ensure_image(DEFAULT_SANDBOX_IMAGE, _manifest(), timeout_seconds=30)


# ---------------------------------------------------------------------------
# resolve_dependency_image policy.
# ---------------------------------------------------------------------------


async def test_resolve_disabled_returns_none_even_with_manifest() -> None:
    """Auto-build stays opt-in: default settings never trigger builds."""
    sources = _sources(_source("requirements.txt", REQUIREMENTS))
    client = FakeClient(FakeImagesApi())

    resolved = await resolve_dependency_image(SandboxConfig(), sources, client=client)

    assert resolved is None


async def test_resolve_non_docker_backend_returns_none() -> None:
    """Image builds are pointless for backends that never run containers."""
    config = SandboxConfig(auto_build_image=True, mode=SandboxMode.MOCK)
    sources = _sources(_source("requirements.txt", REQUIREMENTS))

    resolved = await resolve_dependency_image(config, sources, client=FakeClient(FakeImagesApi()))

    assert resolved is None


async def test_resolve_without_manifest_keeps_fallback() -> None:
    """No manifest means unchanged fallback semantics even when enabled."""
    config = SandboxConfig(auto_build_image=True)
    sources = _sources(_source("app.py", "print('hi')\n"))

    resolved = await resolve_dependency_image(config, sources, client=FakeClient(FakeImagesApi()))

    assert resolved is None


async def test_resolve_builds_derived_tag_from_config_base(monkeypatch: pytest.MonkeyPatch) -> None:
    """Enabled + manifest yields the deterministic tag built on config.image."""
    base = "python:3.11-slim"
    config = SandboxConfig(auto_build_image=True, image=base, image_build_timeout_seconds=60)
    sources = _sources(_source("requirements.txt", REQUIREMENTS))
    images = FakeImagesApi()
    client = FakeClient(images)

    resolved = await resolve_dependency_image(config, sources, client=client)

    assert resolved == dependency_image_tag(base, _manifest())
    assert len(images.build_kwargs) == 1


async def test_resolve_hard_timeout_raises_typed_error() -> None:
    """Exceeding the wall-clock budget abandons the build explicitly."""

    release = threading.Event()

    class SlowImagesApi(FakeImagesApi):
        def build(self, **kwargs: object) -> tuple[FakeBuiltImage, list[dict[str, str]]]:
            self.build_kwargs.append(kwargs)
            release.wait(timeout=10)
            return FakeBuiltImage([str(kwargs["tag"])]), []

    config = SandboxConfig(
        auto_build_image=True,
        image_build_timeout_seconds=1,
    )
    sources = _sources(_source("requirements.txt", REQUIREMENTS))
    try:
        with pytest.raises(SandboxImageBuildError, match="timeout") as excinfo:
            await asyncio.wait_for(
                resolve_dependency_image(config, sources, client=FakeClient(SlowImagesApi())),
                timeout=5,
            )
        # The typed error comes from the resolver's own budget (1s), well
        # before the outer safety net at 5s.
        assert "1s" in str(excinfo.value)
    finally:
        release.set()


# ---------------------------------------------------------------------------
# End-to-end wiring through the orchestrator.
# ---------------------------------------------------------------------------


async def test_orchestrator_selects_dependency_image(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verification requests the derived image when auto-build is enabled."""
    from mugiwara.agents.orchestrator import ScanOrchestrator, SessionPhase
    from mugiwara.providers.mock import MockLLMProvider
    from mugiwara.sandbox.mock import MockSandbox

    root = tmp_path / "proj"
    root.mkdir()
    (root / "app.py").write_text("value = 1\nprint(value)\n", encoding="utf-8")
    (root / "requirements.txt").write_text(REQUIREMENTS, encoding="utf-8", newline="\n")

    captured: dict[str, object] = {}
    sandbox = MockSandbox()

    def fake_get_sandbox(config: SandboxConfig, **kwargs: object) -> MockSandbox:
        captured["image"] = kwargs.get("image")
        return sandbox

    monkeypatch.setattr(
        "mugiwara.agents.orchestrator.get_provider", lambda _config: MockLLMProvider()
    )
    monkeypatch.setattr("mugiwara.agents.orchestrator.get_sandbox", fake_get_sandbox)
    monkeypatch.setattr(
        "mugiwara.sandbox.imaging._acquire_client",
        lambda: FakeClient(
            FakeImagesApi(local={dependency_image_tag(DEFAULT_SANDBOX_IMAGE, _manifest())})
        ),
    )

    settings = MugiwaraSettings()
    settings.sandbox.mode = SandboxMode.DOCKER
    settings.sandbox.auto_build_image = True

    result = await ScanOrchestrator(settings).run(str(root))

    assert SessionPhase.VERIFICATION in result.phases_completed
    assert captured["image"] == dependency_image_tag(DEFAULT_SANDBOX_IMAGE, _manifest())


async def test_orchestrator_default_flow_unchanged_when_disabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without auto-build the orchestrator keeps the historical image choice."""
    from mugiwara.agents.orchestrator import ScanOrchestrator, SessionPhase
    from mugiwara.providers.mock import MockLLMProvider
    from mugiwara.sandbox.mock import MockSandbox

    root = tmp_path / "proj"
    root.mkdir()
    (root / "app.py").write_text("value = 1\nprint(value)\n", encoding="utf-8")

    captured: dict[str, object] = {}

    def fake_get_sandbox(config: SandboxConfig, **kwargs: object) -> MockSandbox:
        captured["image"] = kwargs.get("image")
        return MockSandbox()

    monkeypatch.setattr(
        "mugiwara.agents.orchestrator.get_provider", lambda _config: MockLLMProvider()
    )
    monkeypatch.setattr("mugiwara.agents.orchestrator.get_sandbox", fake_get_sandbox)

    settings = MugiwaraSettings()
    settings.sandbox.mode = SandboxMode.MOCK

    result = await ScanOrchestrator(settings).run(str(root))

    assert SessionPhase.VERIFICATION in result.phases_completed
    assert captured["image"] == DEFAULT_SANDBOX_IMAGE


# ---------------------------------------------------------------------------
# Wiring through the remediation sea trial.
# ---------------------------------------------------------------------------

_SEA_TRIAL_SOURCE = '''\
"""Tiny coherent Flask target used to exercise remediation flows."""

import sqlite3

from flask import Flask, request

app = Flask(__name__)


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

_PATCHED_SOURCE = _SEA_TRIAL_SOURCE.replace(
    "cursor.execute(f\"SELECT * FROM users WHERE name = '{username}'\")",
    'cursor.execute("SELECT * FROM users WHERE name = ?", (username,))',
)

_POC_SCRIPT = (
    "import json, os, urllib.request\n"
    'url = os.environ["MUGIWARA_TARGET_URL"]\n'
    'canary = os.environ["MUGIWARA_CANARY"]\n'
    "body = urllib.request.urlopen(url + '/users?username=' + canary, timeout=5).read().decode()\n"
    'verdict = {"canary_found": canary in body, "http_status": 200}\n'
    'print("MUGIWARA_VERDICT: " + json.dumps(verdict))\n'
)


def _sea_trial_result(*, verdict: bool) -> object:
    """Compose a MockSandbox ExecResult carrying harness markers."""
    from mugiwara.agents.poc_safety import POC_LOG_MARKER, TARGET_LOG_MARKER
    from mugiwara.sandbox.base import ExecResult

    stdout = (
        f"{TARGET_LOG_MARKER}\n"
        " * Running on http://127.0.0.1:5000\n"
        f"{POC_LOG_MARKER}\n"
        'MUGIWARA_VERDICT: {"canary_found": '
        + str(verdict).lower()
        + ', "http_status": 200, "notes": "trial"}\n'
        "MUGIWARA_EXIT:0 READY:0\n"
    )
    return ExecResult(
        command=["sh", "-c", "harness"],
        exit_code=0,
        stdout=stdout,
        duration_seconds=0.25,
        timed_out=False,
    )


def _seed_remediation_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    auto_build: bool,
) -> tuple[object, object]:
    """Create a tmp Flask target and the context for one remediation call."""
    from mugiwara.agents.base import AgentContext
    from mugiwara.core.config import MugiwaraSettings
    from mugiwara.providers.mock import MockLLMProvider

    root = tmp_path / "target"
    root.mkdir()
    (root / "app.py").write_text(_SEA_TRIAL_SOURCE, encoding="utf-8", newline="\n")
    (root / "requirements.txt").write_text(REQUIREMENTS, encoding="utf-8", newline="\n")

    settings = MugiwaraSettings()
    settings.sandbox.mode = SandboxMode.DOCKER if auto_build else SandboxMode.MOCK
    settings.sandbox.auto_build_image = auto_build

    provider = MockLLMProvider()
    sources = WorkspaceCollector(settings.agents).collect(root)
    ctx = AgentContext(provider=provider, settings=settings, sources=sources, target_root=str(root))
    return ctx, provider


async def test_remediation_sea_trial_selects_dependency_image(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sea trials ride the same derived image as verification when enabled."""
    from mugiwara.agents.models import RemediationPlan
    from mugiwara.models.evidence import Evidence
    from mugiwara.models.finding import (
        Finding,
        FindingStatus,
        Severity,
        SourceLocation,
        VulnerabilityCategory,
    )
    from mugiwara.models.remediation import RemediationStatus
    from mugiwara.remediation.service import RemediationService
    from mugiwara.sandbox.mock import MockSandbox

    ctx, provider = _seed_remediation_context(tmp_path, monkeypatch, auto_build=True)
    provider.add_structured_response(
        RemediationPlan(
            finding_ref=0,
            file_path="app.py",
            patched_content=_PATCHED_SOURCE,
            explanation="parameterized query",
        )
    )

    finding = Finding(
        title="Dynamic SQL construction",
        description="User input is interpolated into a SQL statement.",
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=Severity.HIGH,
        cwe_id="CWE-89",
        location=SourceLocation(file_path="app.py", start_line=15),
        status=FindingStatus.VERIFIED,
        evidence=Evidence(
            poc_script=_POC_SCRIPT,
            canary_token="MUGIWARA_CANARY_unit42",
            canary_found=True,
            reproduction_steps=["step one"],
        ),
    )

    captured: dict[str, object] = {}
    sandbox = MockSandbox()
    sandbox.add_result(_sea_trial_result(verdict=False))

    def fake_get_sandbox(config: SandboxConfig, **kwargs: object) -> MockSandbox:
        captured["image"] = kwargs.get("image")
        return sandbox

    monkeypatch.setattr("mugiwara.remediation.service.get_sandbox", fake_get_sandbox)
    monkeypatch.setattr(
        "mugiwara.sandbox.imaging._acquire_client",
        lambda: FakeClient(
            FakeImagesApi(local={dependency_image_tag(DEFAULT_SANDBOX_IMAGE, _manifest())})
        ),
    )

    record = await RemediationService(ctx.settings)._remediate_one(ctx, finding, 0, "app.py", 5000)

    assert record.status is RemediationStatus.VERIFIED_FIXED
    assert captured["image"] == dependency_image_tag(DEFAULT_SANDBOX_IMAGE, _manifest())


async def test_remediation_build_failure_reports_honestly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unavailable dependency image fails the record without false claims."""
    from mugiwara.core.exceptions import SandboxImageBuildError
    from mugiwara.models.evidence import Evidence
    from mugiwara.models.finding import (
        Finding,
        FindingStatus,
        Severity,
        SourceLocation,
        VulnerabilityCategory,
    )
    from mugiwara.models.remediation import RemediationStatus
    from mugiwara.remediation.service import RemediationService

    ctx, _provider = _seed_remediation_context(tmp_path, monkeypatch, auto_build=True)

    finding = Finding(
        title="Dynamic SQL construction",
        description="User input is interpolated into a SQL statement.",
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=Severity.HIGH,
        cwe_id="CWE-89",
        location=SourceLocation(file_path="app.py", start_line=15),
        status=FindingStatus.VERIFIED,
        evidence=Evidence(
            poc_script=_POC_SCRIPT,
            canary_token="MUGIWARA_CANARY_unit42",
            canary_found=True,
            reproduction_steps=["step one"],
        ),
    )

    def failing_resolve(config: SandboxConfig, sources: object) -> str:
        raise SandboxImageBuildError("daemon rejected the build")

    monkeypatch.setattr("mugiwara.remediation.service.resolve_dependency_image", failing_resolve)

    record = await RemediationService(ctx.settings)._remediate_one(ctx, finding, 0, "app.py", 5000)

    assert record.status is RemediationStatus.FAILED
    assert record.reason is not None
    assert "dependency-aware sandbox image unavailable" in record.reason
    assert "daemon rejected the build" in record.reason
