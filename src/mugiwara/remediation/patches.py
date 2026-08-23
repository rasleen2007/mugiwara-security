"""Pure patch-application primitives for isolated remediation copies."""

import ast
import difflib
import hashlib


def build_unified_diff(original: str, patched: str, file_path: str) -> str:
    """Return a unified diff between original and patched content.

    The diff is always computed locally from the exact byte contents; LLM
    output is never trusted to describe its own patch.

    Args:
        original: Original full file content.
        patched: Proposed full replacement content.
        file_path: Relative path used in the diff headers.

    Returns:
        Unified diff text (possibly empty when the contents are identical).
    """
    return "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
        )
    )


def sha256_text(text: str) -> str:
    """Return the hex SHA-256 digest of a text blob."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def validate_python_source(content: str, filename: str) -> str | None:
    """Structurally check patched Python content before it can run anywhere.

    Args:
        content: Candidate replacement content.
        filename: Relative target path (non-Python files are accepted as-is).

    Returns:
        ``None`` when the content is acceptable, otherwise a failure reason.
    """
    if not filename.endswith(".py"):
        return None
    try:
        ast.parse(content, filename=filename)
    except SyntaxError as exc:
        return f"patched content failed the Python syntax check: {exc.msg} (line {exc.lineno})"
    return None
