"""Deterministic regex-based dangerous-pattern detection.

Heuristics run entirely offline and produce high-confidence candidate
locations that seed both the reconnaissance hints and the semantic discovery
prompt. They never execute target code and never read the filesystem; they
operate only on content already collected by :class:`WorkspaceCollector`.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from mugiwara.agents.models import HeuristicHit
from mugiwara.agents.sources import SourceFile
from mugiwara.models.finding import Severity, VulnerabilityCategory

_MAX_MATCHED_LINE_CHARS = 200

_PY = frozenset({".py"})
_JS_FAMILY = frozenset({".js", ".ts", ".jsx", ".tsx"})
_MULTI_LANG = frozenset({".py", ".js", ".ts", ".jsx", ".tsx", ".rb", ".go", ".java", ".php", ".cs"})


@dataclass(frozen=True)
class Rule:
    """One static heuristic pattern with its vulnerability classification."""

    rule_id: str
    pattern: re.Pattern[str]
    extensions: frozenset[str]
    category: VulnerabilityCategory
    severity: Severity
    cwe_id: str | None
    message: str


RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="PY_EVAL_EXEC",
        pattern=re.compile(r"(?<![\w.])(?:eval|exec)\s*\("),
        extensions=_PY,
        category=VulnerabilityCategory.REMOTE_CODE_EXECUTION,
        severity=Severity.HIGH,
        cwe_id="CWE-95",
        message="Dynamic evaluation of code via eval/exec can execute attacker-controlled input.",
    ),
    Rule(
        rule_id="PY_OS_SYSTEM",
        pattern=re.compile(r"\bos\.system\s*\("),
        extensions=_PY,
        category=VulnerabilityCategory.COMMAND_INJECTION,
        severity=Severity.HIGH,
        cwe_id="CWE-78",
        message="os.system invokes a shell command string that may embed untrusted input.",
    ),
    Rule(
        rule_id="PY_SUBPROCESS_SHELL_TRUE",
        pattern=re.compile(
            r"subprocess\.(?:run|call|check_call|check_output|Popen)\s*\([^)]*shell\s*=\s*True\b"
        ),
        extensions=_PY,
        category=VulnerabilityCategory.COMMAND_INJECTION,
        severity=Severity.HIGH,
        cwe_id="CWE-78",
        message="subprocess call with shell=True passes the command through a shell interpreter.",
    ),
    Rule(
        rule_id="SQL_DYNAMIC_EXECUTE",
        pattern=re.compile(
            r"(?:execute|executemany)\s*\(\s*"
            r"(?:f['\"]|['\"][^'\"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^'\"]*['\"]\s*\+)",
            re.IGNORECASE,
        ),
        extensions=_PY,
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=Severity.HIGH,
        cwe_id="CWE-89",
        message="SQL statement built by string formatting or concatenation before execution.",
    ),
    Rule(
        rule_id="PY_PICKLE_LOADS",
        pattern=re.compile(r"\bpickle\.loads?\s*\("),
        extensions=_PY,
        category=VulnerabilityCategory.REMOTE_CODE_EXECUTION,
        severity=Severity.HIGH,
        cwe_id="CWE-502",
        message="Pickle deserialization of untrusted data enables arbitrary code execution.",
    ),
    Rule(
        rule_id="YAML_UNSAFE_LOAD",
        pattern=re.compile(r"yaml\.load\s*\((?![^)]*Loader\s*=)"),
        extensions=_PY,
        category=VulnerabilityCategory.REMOTE_CODE_EXECUTION,
        severity=Severity.HIGH,
        cwe_id="CWE-502",
        message="yaml.load without an explicit safe Loader permits arbitrary object construction.",
    ),
    Rule(
        rule_id="HARDCODED_SECRET",
        pattern=re.compile(
            r"(?<![A-Za-z0-9])(?:password|passwd|pwd|api_key|apikey|auth_token"
            r"|access_token|secret)\b\s*=\s*['\"][^'\"]{6,}['\"]",
            re.IGNORECASE,
        ),
        extensions=_MULTI_LANG,
        category=VulnerabilityCategory.HARDCODED_SECRET,
        severity=Severity.HIGH,
        cwe_id="CWE-798",
        message="Credential-looking literal assigned directly in source code.",
    ),
    Rule(
        rule_id="FLASK_DEBUG_TRUE",
        pattern=re.compile(r"app\.run\s*\([^)]*debug\s*=\s*True\b"),
        extensions=_PY,
        category=VulnerabilityCategory.REMOTE_CODE_EXECUTION,
        severity=Severity.HIGH,
        cwe_id="CWE-489",
        message="Flask/Werkzeug debug mode exposes an interactive debugger reachable remotely.",
    ),
    Rule(
        rule_id="DJANGO_RAW_SQL",
        pattern=re.compile(
            r"\.raw\s*\(\s*f?['\"][^'\"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b", re.IGNORECASE
        ),
        extensions=_PY,
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=Severity.HIGH,
        cwe_id="CWE-89",
        message="Django raw SQL query potentially interpolating untrusted values.",
    ),
    Rule(
        rule_id="JS_EVAL",
        pattern=re.compile(r"(?<![\w.$])eval\s*\("),
        extensions=_JS_FAMILY,
        category=VulnerabilityCategory.REMOTE_CODE_EXECUTION,
        severity=Severity.HIGH,
        cwe_id="CWE-95",
        message="JavaScript eval executes arbitrary code from its argument string.",
    ),
)


def scan_heuristics(files: Sequence[SourceFile]) -> list[HeuristicHit]:
    """Run every applicable rule over collected file contents.

    Args:
        files: Collected source files with preloaded content.

    Returns:
        Deterministically ordered heuristic hits, deduplicated per
        (rule, file, line).
    """
    hits: list[HeuristicHit] = []
    seen: set[tuple[str, str, int]] = set()
    for source in files:
        suffix = Path(source.relative_path).suffix.lower()
        for line_number, raw_line in enumerate(source.content.splitlines(), start=1):
            stripped = raw_line.strip()
            if not stripped:
                continue
            for rule in RULES:
                if suffix not in rule.extensions:
                    continue
                if not rule.pattern.search(stripped):
                    continue
                key = (rule.rule_id, source.relative_path, line_number)
                if key in seen:
                    continue
                seen.add(key)
                hits.append(
                    HeuristicHit(
                        rule_id=rule.rule_id,
                        file_path=source.relative_path,
                        line_number=line_number,
                        matched_line=stripped[:_MAX_MATCHED_LINE_CHARS],
                        category=rule.category,
                        severity=rule.severity,
                        cwe_id=rule.cwe_id,
                        message=rule.message,
                    )
                )
    hits.sort(key=lambda hit: (hit.file_path, hit.line_number, hit.rule_id))
    return hits
