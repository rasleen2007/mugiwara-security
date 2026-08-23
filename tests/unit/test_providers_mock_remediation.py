"""Unit tests for the deterministic mock remediation plan builder."""

import ast

import pytest

from mugiwara.core.exceptions import ProviderExecutionError
from mugiwara.providers.mock_remediation import (
    build_default_remediation_plan,
    extract_category_from_prompt,
    extract_vulnerable_source,
    parameterize_fstring_execute,
)

VULNERABLE_SOURCE = '''\
"""Demo vulnerable module."""

import sqlite3


def lookup(cursor, username):
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cursor.fetchall()
'''

EXPECTED_PATCHED_SEGMENT = """\
    cursor.execute(
        "SELECT * FROM users WHERE name = ?",
        (username,),
    )"""


def _prompt(category: str = "sql_injection", file_path: str = "app.py") -> str:
    """Compose a remediation prompt shaped exactly like the service renders it."""
    return (
        "Propose a minimal fix...\n\n"
        f"category: {category}\n"
        f"file_path: {file_path}\n"
        "---BEGIN VULNERABLE SOURCE---\n"
        f"{VULNERABLE_SOURCE}"
        "---END VULNERABLE SOURCE---\n"
        "Return a RemediationPlan."
    )


def test_parameterize_demo_line_exact() -> None:
    """The demo f-string execute becomes the canonical parameterized form."""
    patched, params = parameterize_fstring_execute(VULNERABLE_SOURCE)
    assert params == ["username"]
    assert EXPECTED_PATCHED_SEGMENT in patched
    assert "'{username}'" not in patched
    ast.parse(patched)


def test_single_quotes_also_supported() -> None:
    """f-strings delimited by single quotes transform identically."""
    source = "cursor.execute(f'SELECT * FROM users WHERE id = {uid}')\n"
    patched, params = parameterize_fstring_execute(source)
    assert params == ["uid"]
    assert '"SELECT * FROM users WHERE id = ?"' in patched
    assert "(uid,)" in patched


def test_multi_placeholder_statement_raises() -> None:
    """Statements with several interpolations are honestly refused."""
    source = 'cursor.execute(f"SELECT * FROM t WHERE a = {x} AND b = {y}")\n'
    with pytest.raises(ProviderExecutionError, match="single-parameter"):
        parameterize_fstring_execute(source)


def test_source_without_pattern_raises() -> None:
    """A clean source yields no fabricated transformation."""
    with pytest.raises(ProviderExecutionError, match="no convertible"):
        parameterize_fstring_execute("value = compute(x)\n")


def test_wrong_category_raises() -> None:
    """Non-SQLi findings are never patched by the mock builder."""
    with pytest.raises(ProviderExecutionError, match="sql_injection"):
        build_default_remediation_plan(_prompt(category="command_injection"))


def test_missing_source_block_raises() -> None:
    """A prompt without the sentinel block fails loudly."""
    with pytest.raises(ProviderExecutionError, match="source block"):
        extract_vulnerable_source("no markers here")


def test_extract_category_defaults_to_other() -> None:
    """Undeclared categories map to 'other' and are then rejected upstream."""
    assert extract_category_from_prompt("nothing useful") == "other"


def test_build_default_plan_happy_path() -> None:
    """End-to-end prompt -> plan: confined path, real patch, honest explanation."""
    plan = build_default_remediation_plan(_prompt())
    assert plan.finding_ref == 0
    assert plan.file_path == "app.py"
    assert '"SELECT * FROM users WHERE name = ?"' in plan.patched_content
    assert "(username,)" in plan.patched_content
    assert "parameterized" in plan.explanation.lower()
    ast.parse(plan.patched_content)


def test_build_default_plan_missing_file_path_raises() -> None:
    """A prompt without file_path metadata cannot produce a confined plan."""
    broken = _prompt().replace("file_path: app.py\n", "")
    with pytest.raises(ProviderExecutionError, match="file_path"):
        build_default_remediation_plan(broken)
