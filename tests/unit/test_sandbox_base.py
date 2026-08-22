"""Unit tests for sandbox DTOs, workspace mount safety boundaries, and BaseSandbox."""

from pathlib import Path

import pytest

from mugiwara.core.exceptions import SandboxWorkspaceError
from mugiwara.sandbox.base import (
    WORKSPACE_CONTAINER_ROOT,
    ExecResult,
    WorkspaceMount,
    _validate_path_safety,
    validate_workspace_container_path,
    validate_workspace_host_path,
)


def _assert_safety_rejected(path: Path, home: Path | None) -> None:
    """Helper asserting the structural safety check rejects a path."""
    with pytest.raises(SandboxWorkspaceError):
        _validate_path_safety(path, home)


def test_exec_result_defaults_and_succeeded() -> None:
    """Verify ExecResult defaults and success semantics."""
    ok = ExecResult(command=["true"], exit_code=0)
    failed = ExecResult(command=["false"], exit_code=1)
    killed = ExecResult(command=["runaway"], exit_code=None, timed_out=True)

    assert ok.stdout == ""
    assert ok.stderr == ""
    assert ok.duration_seconds == 0.0
    assert ok.succeeded is True
    assert failed.succeeded is False
    assert killed.succeeded is False


def test_workspace_container_path_accepts_workspace_subtree() -> None:
    """Verify container-side paths inside /workspace are accepted and normalized."""
    assert validate_workspace_container_path("/workspace") == "/workspace"
    assert validate_workspace_container_path("/workspace/project/src") == "/workspace/project/src"
    assert WORKSPACE_CONTAINER_ROOT == "/workspace"


@pytest.mark.parametrize(
    ("candidate", "reason"),
    [
        ("/etc", "outside workspace subtree"),
        ("/etc/passwd", "outside workspace subtree"),
        ("/var/run/docker.sock", "docker socket target"),
        ("/usr/bin", "outside workspace subtree"),
        ("/root/.ssh", "outside workspace subtree"),
        ("workspace", "relative path"),
        ("/workspace/../etc", "parent traversal"),
        ("/workspace/./sub", "dot segment traversal"),
        ("/workspace//sub", "non-normalized path"),
        ("/workspaces", "similar-but-outside prefix"),
        ("/workspace-sub", "prefix confusion attack"),
    ],
)
def test_workspace_container_path_rejects_unsafe_targets(candidate: str, reason: str) -> None:
    """Verify hostile container-side mount targets are rejected."""
    with pytest.raises(SandboxWorkspaceError):
        validate_workspace_container_path(candidate)


def test_path_safety_rejects_filesystem_roots() -> None:
    """Verify filesystem/drive roots are rejected on any platform representation."""
    _assert_safety_rejected(Path("/"), None)
    _assert_safety_rejected(Path("C:\\"), None)
    _assert_safety_rejected(Path("//server/share"), None)
    _assert_safety_rejected(Path("\\\\"), None)
    _assert_safety_rejected(Path("/"), Path("/"))


def test_path_safety_rejects_home_directory() -> None:
    """Verify mounting the user home directory itself is rejected."""
    home = Path("/home/testuser")
    _assert_safety_rejected(home, home)
    # A project subdirectory of home remains acceptable.
    _validate_path_safety(home / "projects" / "webapp", home)


def test_path_safety_rejects_protected_system_locations() -> None:
    """Verify top-level system directories are refused as mount sources."""
    forbidden_targets = [
        "/etc",
        "/etc/nginx",
        "/etc/nginx/nginx.conf",
        "/usr",
        "/usr/local/lib",
        "/var",
        "/var/lib/docker",
        "/bin",
        "/sbin",
        "/boot",
        "/dev",
        "/proc",
        "/sys",
        "/opt/app",
        "/srv/data",
        "/lib/modules",
        "C:\\Windows",
        "C:\\Windows\\System32\\config",
        "C:\\Program Files\\App",
        "C:\\Program Files (x86)\\App",
        "C:\\ProgramData\\Secrets",
        "D:\\Windows\\Temp",
    ]
    for target in forbidden_targets:
        _assert_safety_rejected(Path(target), Path("/home/testuser"))

    # User-space locations remain mountable.
    _validate_path_safety(Path("/home/testuser/workspaces/target-app"), Path("/home/testuser"))
    _validate_path_safety(Path("D:\\work\\target-app"), None)
    _validate_path_safety(Path("/home/testuser"), None)


def test_path_safety_rejects_sensitive_components() -> None:
    """Verify paths inside credential stores are rejected anywhere in the tree."""
    sensitive_targets = [
        "/home/user/.ssh/id_rsa",
        "/home/user/.ssh",
        "/home/user/.aws/credentials",
        "/home/user/.gnupg",
        "/home/user/projects/.kube/config",
        "/opt/tools/.docker/config.json",
        "/srv/.azure/accessTokens.json",
        "/data/.gcloud/credentials.db",
        "C:\\Users\\u\\.ssh\\config",
    ]
    for target in sensitive_targets:
        _assert_safety_rejected(Path(target), None)


def test_validate_workspace_host_path_happy_path(tmp_path: Path) -> None:
    """Verify a clean project directory validates to its resolved absolute path."""
    project = tmp_path / "target-app"
    project.mkdir()
    (project / "app.py").write_text("print('hi')\n", encoding="utf-8")

    resolved = validate_workspace_host_path(project)

    assert resolved == project.resolve()
    assert resolved.is_absolute()


def test_validate_workspace_host_path_missing_or_file(tmp_path: Path) -> None:
    """Verify nonexistent paths and plain files are rejected as workspaces."""
    with pytest.raises(SandboxWorkspaceError):
        validate_workspace_host_path(tmp_path / "does-not-exist")

    some_file = tmp_path / "notes.txt"
    some_file.write_text("data", encoding="utf-8")
    with pytest.raises(SandboxWorkspaceError):
        validate_workspace_host_path(some_file)


def test_validate_workspace_host_path_rejects_sensitive_children(tmp_path: Path) -> None:
    """Verify directories exposing credentials/keys/.env files cannot be mounted."""
    sensitive_entries = [
        ".env",
        ".env.production",
        "id_rsa",
        "id_ed25519",
        "deploy-key.pem",
        "server.key",
        "credentials.json",
        ".git-credentials",
        ".netrc",
        ".npmrc",
        ".htpasswd",
        "registry.pfx",
        "app.keystore",
        "daemon.sock",
        "docker.sock",
    ]
    for entry in sensitive_entries:
        candidate = tmp_path / f"ws-{abs(hash(entry))}"
        candidate.mkdir()
        (candidate / entry).write_text("secret", encoding="utf-8")
        with pytest.raises(SandboxWorkspaceError):
            validate_workspace_host_path(candidate)

    sensitive_dirs = [".ssh", ".aws", ".gnupg", ".kube", ".docker", ".azure"]
    for entry in sensitive_dirs:
        candidate = tmp_path / f"dir-{abs(hash(entry))}"
        candidate.mkdir()
        (candidate / entry).mkdir()
        with pytest.raises(SandboxWorkspaceError):
            validate_workspace_host_path(candidate)

    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "src").mkdir()
    (clean / "src" / "main.py").write_text("x = 1\n", encoding="utf-8")
    assert validate_workspace_host_path(clean) == clean.resolve()


def test_workspace_mount_model_volume_spec(tmp_path: Path) -> None:
    """Verify WorkspaceMount builds Docker volume mappings with safe defaults."""
    project = tmp_path / "project"
    project.mkdir()

    default_mount = WorkspaceMount(host_path=project)
    assert default_mount.read_only is True
    assert default_mount.container_path == "/workspace"
    assert default_mount.volume_spec() == {
        str(project.resolve()): {"bind": "/workspace", "mode": "ro"}
    }

    writable = WorkspaceMount(
        host_path=project,
        container_path="/workspace/app",
        read_only=False,
    )
    spec = writable.volume_spec()
    mode = next(iter(spec.values()))["mode"]
    bind = next(iter(spec.values()))["bind"]
    assert mode == "rw"
    assert bind == "/workspace/app"


def test_workspace_mount_model_validates_on_construction(tmp_path: Path) -> None:
    """Verify WorkspaceMount construction enforces both host and container rules."""
    with pytest.raises(Exception):  # noqa: B017 - pydantic wraps into ValidationError
        WorkspaceMount(host_path=tmp_path / "missing-dir")

    project = tmp_path / "project"
    project.mkdir()
    with pytest.raises(Exception):  # noqa: B017 - pydantic wraps into ValidationError
        WorkspaceMount(host_path=project, container_path="/etc")
