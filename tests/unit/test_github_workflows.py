"""Structural validity checks for the Phase 5 GitHub Actions integration."""

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "security-scan.yml"
ACTION_PATH = REPO_ROOT / ".github" / "actions" / "mugiwara-scan" / "action.yml"


def _load_yaml(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    assert isinstance(data, dict), f"{path} must parse to a mapping"
    return data


def _iter_steps(job: dict[str, object]) -> list[dict[str, object]]:
    steps = job.get("steps")
    assert isinstance(steps, list), "job must declare steps"
    return [step for step in steps if isinstance(step, dict)]


def test_workflow_declares_least_privilege_permissions() -> None:
    workflow = _load_yaml(WORKFLOW_PATH)
    permissions = workflow["permissions"]
    assert isinstance(permissions, dict)
    assert permissions["contents"] == "read"
    assert permissions["security-events"] == "write"


def test_workflow_uploads_sarif_to_code_scanning() -> None:
    workflow = _load_yaml(WORKFLOW_PATH)
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict) and jobs
    job = next(iter(jobs.values()))
    assert isinstance(job, dict)
    uses = [
        str(step.get("uses", "")) for step in _iter_steps(job) if isinstance(step.get("uses"), str)
    ]
    assert any(u.startswith("actions/checkout@") for u in uses)
    assert any(u.startswith("github/codeql-action/upload-sarif@v3") for u in uses), (
        "SARIF must be uploaded for GitHub Code Scanning"
    )


def test_workflow_invokes_local_composite_action() -> None:
    workflow = _load_yaml(WORKFLOW_PATH)
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    job = next(iter(jobs.values()))
    assert isinstance(job, dict)
    refs = [str(step.get("uses")) for step in _iter_steps(job) if isinstance(step.get("uses"), str)]
    assert "./.github/actions/mugiwara-scan" in refs


def test_composite_action_is_valid_and_minimal() -> None:
    action = _load_yaml(ACTION_PATH)
    runs = action["runs"]
    assert isinstance(runs, dict)
    assert runs["using"] == "composite"

    inputs = action["inputs"]
    assert isinstance(inputs, dict)
    for expected in ("target", "sarif-output", "python-version", "sandbox", "fail-on-findings"):
        assert expected in inputs, f"missing input: {expected}"

    outputs = action["outputs"]
    assert isinstance(outputs, dict)
    assert "exit_code" in outputs and "sarif_file" in outputs

    steps = runs.get("steps")
    assert isinstance(steps, list) and steps
    for step in steps:
        assert isinstance(step, dict)
        if "run" in step:
            assert step.get("shell") == "bash", "every run step needs an explicit shell"


def test_composite_scan_step_tolerates_clean_and_findings_codes_only() -> None:
    action = _load_yaml(ACTION_PATH)
    runs = action["runs"]
    assert isinstance(runs, dict)
    steps = runs.get("steps")
    assert isinstance(steps, list)
    scan_steps = [s for s in steps if isinstance(s, dict) and s.get("id") == "scan"]
    assert len(scan_steps) == 1
    run_script = str(scan_steps[0].get("run"))
    assert "--provider mock" in run_script
    assert "--format sarif" in run_script
    assert "0|2)" in run_script, "exit codes 0 (clean) and 2 (findings) must be tolerated"
