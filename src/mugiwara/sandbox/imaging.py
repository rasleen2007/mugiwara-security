"""Dependency-aware ephemeral sandbox image construction.

When an authorized target declares its dependencies (``requirements.txt``),
dynamic verification is far more useful against an image that already has
those packages installed. This module builds such images on demand from a
fixed, Mugiwara-controlled Dockerfile template:

- The manifest is treated as project-controlled input, but only its *file
  contents* ever enter the build context; no target-supplied Dockerfile,
  hook, or command is ever executed.
- Image identity is a deterministic SHA-256 over the base image plus the
  exact manifest bytes, so a cached ``mugiwara/tgt-<hash>`` tag can never
  silently mismatch the inputs it claims to represent.
- Package installation happens exclusively at IMAGE BUILD time. Runtime
  verification containers keep the existing hardened profile unchanged:
  internal bridge network with no outbound access, non-root, read-only
  root filesystem, dropped capabilities, resource ceilings.
- Builds have a hard wall-clock timeout and fail closed as typed
  :class:`~mugiwara.core.exceptions.SandboxImageBuildError` failures so
  callers degrade with an explicit diagnostic instead of pretending the
  environment matches the project.

The module deliberately contains no dependency-resolution logic: it reads
one flat manifest today and is structured so additional manifest formats
can be added alongside :func:`detect_dependency_manifest` later.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import tarfile
from dataclasses import dataclass
from importlib import import_module
from typing import TYPE_CHECKING, Any, Final

from mugiwara.core.config import SandboxConfig, SandboxMode
from mugiwara.core.exceptions import (
    SandboxConnectionError,
    SandboxImageBuildError,
)
from mugiwara.sandbox.docker import DEFAULT_SANDBOX_IMAGE, _from_env

if TYPE_CHECKING:
    from mugiwara.agents.sources import CollectedSources

MANIFEST_NAME: Final = "requirements.txt"

IMAGE_REPO_PREFIX: Final = "mugiwara/tgt-"

MAX_MANIFEST_BYTES: Final = 256 * 1024

_IMAGE_TAG_DIGEST_CHARS: Final = 16

_SANDBOX_BUILD_USER: Final = "1000:1000"

_MANIFEST_STAGING_NAME: Final = "mugiwara-dependencies.txt"


@dataclass(frozen=True)
class DependencyManifest:
    """A validated dependency manifest collected from the scan target.

    Attributes:
        filename: Manifest file name as declared by the project.
        content: Exact UTF-8 text of the manifest.
        size_bytes: Size of the manifest in bytes.
    """

    filename: str
    content: str
    size_bytes: int


def detect_dependency_manifest(sources: CollectedSources) -> DependencyManifest | None:
    """Detect a supported dependency manifest among the collected sources.

    Only a root-level ``requirements.txt`` participates in S5; nested
    manifests are ignored so a stray vendored copy cannot silently change
    the verification image. Blank manifests are equivalent to absent ones.

    Args:
        sources: Files collected from the authorized target.

    Returns:
        The validated manifest, or None when the target declares nothing.

    Raises:
        SandboxImageBuildError: If the manifest exceeds the size limit or
            is not valid UTF-8 text (NUL bytes indicate binary content).
    """
    for source in sources.files:
        if source.relative_path != MANIFEST_NAME:
            continue
        raw = source.content.encode("utf-8", errors="replace")
        if b"\x00" in raw[:1024]:
            msg = f"Dependency manifest '{MANIFEST_NAME}' is not valid UTF-8 text."
            raise SandboxImageBuildError(msg)
        if len(raw) > MAX_MANIFEST_BYTES:
            msg = (
                f"Dependency manifest '{MANIFEST_NAME}' is {len(raw)} bytes which "
                f"exceeds the {MAX_MANIFEST_BYTES} byte safety limit."
            )
            raise SandboxImageBuildError(msg)
        if not source.content.strip():
            return None
        return DependencyManifest(
            filename=MANIFEST_NAME,
            content=source.content,
            size_bytes=len(raw),
        )
    return None


def dependency_image_tag(base_image: str, manifest: DependencyManifest) -> str:
    """Derive the deterministic cache tag for one base/manifest pair.

    Args:
        base_image: Base image the ephemeral image will be built from.
        manifest: Validated dependency manifest.

    Returns:
        A tag of the form ``mugiwara/tgt-<16 hex chars>``.
    """
    identity = json.dumps(
        {"base_image": base_image, "manifest": manifest.content},
        sort_keys=True,
    ).encode("utf-8")
    digest = hashlib.sha256(identity).hexdigest()[:_IMAGE_TAG_DIGEST_CHARS]
    return f"{IMAGE_REPO_PREFIX}{digest}"


def build_dependency_dockerfile(base_image: str) -> str:
    """Render the fixed Dockerfile used for every dependency image.

    The template never interpolates target-controlled strings; manifest
    contents travel as a context file consumed by ``pip``. The derived
    image drops to the same unprivileged user the runtime sandbox uses.

    Args:
        base_image: Parent image for the build.

    Returns:
        Dockerfile text.
    """
    return (
        f"FROM {base_image}\n"
        f"COPY {_MANIFEST_STAGING_NAME} /tmp/{_MANIFEST_STAGING_NAME}\n"
        "RUN pip install --no-cache-dir --disable-pip-version-check "
        f"--requirement /tmp/{_MANIFEST_STAGING_NAME} \\\n"
        f" && rm -f /tmp/{_MANIFEST_STAGING_NAME}\n"
        f"USER {_SANDBOX_BUILD_USER}\n"
    )


def _build_context(manifest: DependencyManifest, dockerfile: str) -> io.BytesIO:
    """Pack the fixed Dockerfile and the manifest into an in-memory tar."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, payload in (
            ("Dockerfile", dockerfile.encode("utf-8")),
            (_MANIFEST_STAGING_NAME, manifest.content.encode("utf-8")),
        ):
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(payload))
    buffer.seek(0)
    return buffer


class DependencyImageBuilder:
    """Thin wrapper performing guarded builds over an injected Docker client."""

    def __init__(self, client: Any) -> None:
        """Store the Docker client used for lookups and builds."""
        self._client = client

    def ensure_image(
        self,
        base_image: str,
        manifest: DependencyManifest,
        *,
        timeout_seconds: float,
    ) -> str:
        """Return a local image matching the base/manifest pair exactly.

        An existing tag whose identity hash matches the current inputs is
        reused; anything else triggers a fresh build. Failures — including
        package-install errors surfaced through the build log — raise a
        typed error and never fall back to an unrelated image.

        Args:
            base_image: Parent image for the build.
            manifest: Validated dependency manifest.
            timeout_seconds: Hard wall-clock budget for the daemon build.

        Returns:
            The matching local image tag.

        Raises:
            SandboxImageBuildError: If the daemon rejects or fails the
                build, or the result does not carry the requested tag.
        """
        tag = dependency_image_tag(base_image, manifest)
        try:
            self._client.images.get(tag)
            return tag
        except Exception:
            pass

        dockerfile = build_dependency_dockerfile(base_image)
        context = _build_context(manifest, dockerfile)
        try:
            outcome = self._client.images.build(
                fileobj=context,
                custom_context=True,
                tag=tag,
                rm=True,
                labels={"mugiwara.managed": "true"},
            )
        except Exception as exc:
            logs = _extract_build_log_tail(exc)
            msg = f"Dependency image build failed for '{tag}' (base {base_image}): {exc}" + (
                f"; build log tail: {logs}" if logs else ""
            )
            raise SandboxImageBuildError(msg) from exc

        built = outcome[0]
        built_tags: list[str] = []
        entries = built if isinstance(built, (list, tuple)) else [built]
        for entry in entries:
            built_tags.extend(getattr(entry, "tags", None) or [])
        if tag not in built_tags:
            msg = f"Dependency image build reported success without producing '{tag}'."
            raise SandboxImageBuildError(msg)
        return tag


def _extract_build_log_tail(exc: Exception, *, lines: int = 12) -> str:
    """Pull the last readable log lines out of a docker-py BuildError."""
    stream = getattr(exc, "msg", None)
    if isinstance(stream, list):
        chunks: list[str] = []
        for item in stream:
            payload = item.get("stream") if isinstance(item, dict) else str(item)
            if payload:
                chunks.append(str(payload).rstrip())
        return "\n".join(chunks[-lines:])
    return ""


def _acquire_client() -> Any:
    """Resolve a live Docker client for image operations, failing typed."""
    try:
        import_module("docker")
    except ImportError as exc:
        msg = "The Docker SDK is not installed; dependency images are unavailable."
        raise SandboxConnectionError(msg) from exc
    try:
        client = _from_env()
        client.ping()
    except SandboxConnectionError:
        raise
    except Exception as exc:
        msg = f"Docker daemon is not reachable: {exc}"
        raise SandboxConnectionError(msg) from exc
    return client


async def resolve_dependency_image(
    config: SandboxConfig,
    sources: CollectedSources,
    *,
    client: Any | None = None,
) -> str | None:
    """Resolve the container image dynamic verification should run against.

    Behavior:

    - Auto-build disabled or a non-Docker sandbox backend → ``None``.
    - No usable manifest → ``None`` (unchanged fallback semantics).
    - Otherwise the deterministic ``mugiwara/tgt-<hash>`` tag, built on
      demand within the configured hard timeout.

    Args:
        config: Sandbox configuration (mode-independent knobs ignored).
        sources: Collected target files scanned for a manifest.
        client: Optional pre-built Docker client (test injection); when
            omitted a daemon-backed client is acquired lazily.

    Returns:
        An explicit image override string, or None to keep defaults.

    Raises:
        SandboxImageBuildError: On invalid manifests or failed/timed-out
            builds; callers must treat verification as unavailable.
    """
    if not config.auto_build_image or config.mode is not SandboxMode.DOCKER:
        return None
    manifest = detect_dependency_manifest(sources)
    if manifest is None:
        return None

    resolved_client: Any = client if client is not None else _acquire_client()

    base_image = config.image or DEFAULT_SANDBOX_IMAGE
    builder = DependencyImageBuilder(resolved_client)
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(
                builder.ensure_image,
                base_image,
                manifest,
                timeout_seconds=float(config.image_build_timeout_seconds),
            ),
            timeout=float(config.image_build_timeout_seconds),
        )
    except asyncio.TimeoutError as exc:
        msg = (
            f"Dependency image build exceeded the hard timeout of "
            f"{config.image_build_timeout_seconds}s and was abandoned."
        )
        raise SandboxImageBuildError(msg) from exc
