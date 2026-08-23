"""Unit tests for the pure patch-application primitives."""

from mugiwara.remediation.patches import build_unified_diff, sha256_text, validate_python_source

ORIGINAL = "line1\nline2\nline3\n"
PATCHED = "line1\nline2 patched\nline3\n"


def test_unified_diff_headers_and_content() -> None:
    """Diffs use a/ b/ headers and mark both sides of the change."""
    diff = build_unified_diff(ORIGINAL, PATCHED, "app.py")
    assert "--- a/app.py" in diff
    assert "+++ b/app.py" in diff
    assert "-line2\n" in diff
    assert "+line2 patched\n" in diff


def test_unified_diff_empty_for_identical_content() -> None:
    """Identical contents produce an empty diff (caught before apply anyway)."""
    assert build_unified_diff(ORIGINAL, ORIGINAL, "app.py") == ""


def test_sha256_text_is_stable_hex() -> None:
    """Digest is deterministic lowercase hex of the UTF-8 bytes."""
    first = sha256_text("poc")
    assert first == sha256_text("poc")
    assert first != sha256_text("poc2")
    assert len(first) == 64
    int(first, 16)


def test_validate_python_source_accepts_valid() -> None:
    """Syntactically valid Python passes with no reason."""
    assert validate_python_source("x = 1\n", "app.py") is None


def test_validate_python_source_rejects_broken() -> None:
    """Syntax errors return a reason mentioning the check and the line."""
    reason = validate_python_source("def broken(:\n", "app.py")
    assert reason is not None
    assert "syntax check" in reason
    assert "line 1" in reason


def test_validate_python_source_skips_non_python() -> None:
    """Non-.py targets bypass the AST gate."""
    assert validate_python_source("anything { not python", "config.yaml") is None
