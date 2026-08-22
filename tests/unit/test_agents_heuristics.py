"""Unit tests for the deterministic heuristic rule engine."""

from pathlib import Path

import pytest

from mugiwara.agents.heuristics import RULES, scan_heuristics
from mugiwara.agents.sources import SourceFile
from mugiwara.models.finding import Severity, VulnerabilityCategory


def _source(content: str, name: str = "app.py") -> SourceFile:
    """Build a SourceFile directly from raw content."""
    return SourceFile(
        relative_path=name,
        absolute_path=Path(name),
        size_bytes=len(content),
        line_count=len(content.splitlines()),
        content=content,
    )


def test_rule_registry_has_exactly_ten_focused_rules() -> None:
    """Verify the rule set stays intentionally small."""
    assert len(RULES) == 10
    assert len({rule.rule_id for rule in RULES}) == 10
    assert all(rule.severity == Severity.HIGH for rule in RULES)
    assert all(rule.cwe_id is not None for rule in RULES)


_RCE = VulnerabilityCategory.REMOTE_CODE_EXECUTION
_CMDI = VulnerabilityCategory.COMMAND_INJECTION
_SQLI = VulnerabilityCategory.SQL_INJECTION
_SECRET = VulnerabilityCategory.HARDCODED_SECRET


@pytest.mark.parametrize(
    ("snippet", "rule_id", "category", "cwe"),
    [
        ("result = eval(user_input)", "PY_EVAL_EXEC", _RCE, "CWE-95"),
        ("exec(compiled_code)", "PY_EVAL_EXEC", _RCE, "CWE-95"),
        ("os.system('ls ' + path)", "PY_OS_SYSTEM", _CMDI, "CWE-78"),
        ("subprocess.run(cmd, shell=True)", "PY_SUBPROCESS_SHELL_TRUE", _CMDI, "CWE-78"),
        (
            "cursor.execute(f\"SELECT * FROM t WHERE x = '{v}'\")",
            "SQL_DYNAMIC_EXECUTE",
            _SQLI,
            "CWE-89",
        ),
        (
            "cursor.execute('SELECT * FROM t WHERE x = ' + value)",
            "SQL_DYNAMIC_EXECUTE",
            _SQLI,
            "CWE-89",
        ),
        ("obj = pickle.loads(blob)", "PY_PICKLE_LOADS", _RCE, "CWE-502"),
        ("cfg = yaml.load(handle)", "YAML_UNSAFE_LOAD", _RCE, "CWE-502"),
        ('API_KEY = "sk-live-abcdef123456"', "HARDCODED_SECRET", _SECRET, "CWE-798"),
        ("admin_password = 'Sup3rS3cret!'", "HARDCODED_SECRET", _SECRET, "CWE-798"),
        ("app.run(debug=True)", "FLASK_DEBUG_TRUE", _RCE, "CWE-489"),
        (
            "User.objects.raw(f'SELECT * FROM users WHERE a={a}')",
            "DJANGO_RAW_SQL",
            _SQLI,
            "CWE-89",
        ),
        ("const out = eval(expr);", "JS_EVAL", _RCE, "CWE-95"),
    ],
)
def test_rules_fire_on_expected_snippets(
    snippet: str,
    rule_id: str,
    category: VulnerabilityCategory,
    cwe: str,
) -> None:
    """Verify each rule matches its canonical dangerous pattern."""
    extension = ".js" if rule_id == "JS_EVAL" else ".py"
    hits = scan_heuristics([_source(snippet, f"sample{extension}")])

    assert len(hits) == 1
    hit = hits[0]
    assert hit.rule_id == rule_id
    assert hit.category is category
    assert hit.cwe_id == cwe
    assert hit.line_number == 1
    assert hit.matched_line == snippet


@pytest.mark.parametrize(
    "snippet",
    [
        "model.eval()",
        "safe_eval(expression, globals_map)",
        "yaml.safe_load(handle)",
        "yaml.load(stream, Loader=yaml.SafeLoader)",
        "subprocess.run(['ls', path], shell=False)",
        "cursor.execute('SELECT * FROM t WHERE id = ?', (user_id,))",
        "password_hash = hash_value(stored)",
        "app.run(port=8080)",
        "pickle.dumps(state)",
        "const parsed = JSON.parse(text);",
    ],
)
def test_benign_snippets_produce_no_hits(snippet: str) -> None:
    """Verify safe equivalents do not trigger any rule."""
    hits = scan_heuristics([_source(snippet)])
    assert hits == []


def test_language_gating_prevents_cross_extension_matches() -> None:
    """Verify Python-only rules fire only on Python files and vice versa."""
    hits = scan_heuristics([_source("eval(input)", "script.js"), _source("eval(x)", "main.py")])

    assert {(hit.rule_id, hit.file_path) for hit in hits} == {
        ("JS_EVAL", "script.js"),
        ("PY_EVAL_EXEC", "main.py"),
    }


def test_line_numbers_and_multiple_hits_reported() -> None:
    """Verify multi-line content yields accurate line numbers per match."""
    content = "\n".join(
        [
            "import os",
            "",
            "def run(cmd):",
            "    os.system(cmd)",
            "    return eval(cmd)",
        ]
    )
    hits = scan_heuristics([_source(content)])

    by_rule = {hit.rule_id: hit.line_number for hit in hits}
    assert by_rule["PY_OS_SYSTEM"] == 4
    assert by_rule["PY_EVAL_EXEC"] == 5


def test_duplicate_match_on_same_line_deduplicated() -> None:
    """Verify one rule firing twice on a single line yields one hit."""
    hits = scan_heuristics([_source("os.system(a) or os.system(b)")])

    assert len(hits) == 1


def test_hits_sorted_by_file_then_line_then_rule() -> None:
    """Verify deterministic ordering of returned hits."""
    files = [
        _source("x = pickle.loads(data)\ny = os.system(cmd)", "b_second.py"),
        _source("z = eval(expr)", "a_first.py"),
    ]

    hits = scan_heuristics(files)

    keys = [(hit.file_path, hit.line_number, hit.rule_id) for hit in hits]
    assert keys == sorted(keys)


def test_matched_line_truncated_to_two_hundred_chars() -> None:
    """Verify overly long matching lines are truncated in the hit record."""
    long_line = "os.system(" + "a" * 500 + ")"

    hits = scan_heuristics([_source(long_line)])

    assert len(hits[0].matched_line) <= 200


def test_empty_input_returns_empty_list() -> None:
    """Verify no files produce no hits."""
    assert scan_heuristics([]) == []
