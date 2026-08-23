"""Browser-DOM regression tests for the Workbench frontend.

The real ``index.html`` + ``app.js`` are executed inside jsdom by
``tests/js/workbench_dom.test.mjs`` (run via ``node --test``). That suite
reproduces the ZIP-upload flow whose first poll snapshot used to crash the
page with:

    TypeError: Failed to execute 'appendChild' on 'Node':
    parameter 1 is not of type 'Node'.

This wrapper keeps the JS suite inside the normal pytest gates. It is skipped
with an actionable reason when Node.js or the jsdom dev dependency is absent
(install once with ``npm ci``).
"""

import shutil
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_JS_TEST = _REPO_ROOT / "tests" / "js" / "workbench_dom.test.mjs"


def _node_binary() -> str | None:
    """Return the node executable path when available."""
    return shutil.which("node")


def _jsdom_resolvable(node: str) -> bool:
    """Check whether the jsdom package can be imported by Node."""
    probe = subprocess.run(
        [node, "-e", "import('jsdom').then(() => process.exit(0)).catch(() => process.exit(1))"],
        cwd=_REPO_ROOT,
        capture_output=True,
        timeout=120,
    )
    return probe.returncode == 0


@pytest.mark.skipif(_node_binary() is None, reason="Node.js is not installed")
def test_workbench_dom_regressions() -> None:
    """Run the jsdom suite covering scan progress, failure, and findings DOM."""
    node = _node_binary()
    assert node is not None
    if not _JS_TEST.is_file():
        raise AssertionError(f"DOM regression suite missing: {_JS_TEST}")
    if not _jsdom_resolvable(node):
        pytest.skip("jsdom is unavailable; run 'npm ci' to enable Workbench DOM tests")

    proc = subprocess.run(
        [node, "--test", str(_JS_TEST)],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    assert proc.returncode == 0, (
        f"Workbench DOM suite failed\n--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"
    )
