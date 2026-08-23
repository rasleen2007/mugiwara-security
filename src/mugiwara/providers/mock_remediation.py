"""Deterministic RemediationPlan synthesis for the mock LLM provider."""

import re

from mugiwara.agents.models import RemediationPlan
from mugiwara.core.exceptions import ProviderExecutionError

_SOURCE_BEGIN = "---BEGIN VULNERABLE SOURCE---"
_SOURCE_END = "---END VULNERABLE SOURCE---"

_CATEGORY_RE = re.compile(
    r"^category:\s*([a-zA-Z_]+)",
    re.MULTILINE,
)

# IMPORTANT:
# There are TWO file_path lines in the remediation prompt:
#
#   file_path: app.py          <- finding block
#   ...
#   file_path: app.py          <- source block
#
# We specifically want the file_path immediately before the vulnerable
# source block, so don't just take the first file_path in the prompt.
_SOURCE_PATH_RE = re.compile(
    r"file_path:\s*(\S+)\s*"
    r"---BEGIN VULNERABLE SOURCE---",
    re.MULTILINE,
)

_FSTRING_EXECUTE_RE = re.compile(
    r"^(?P<indent>[ \t]*)"
    r"(?P<call>[\w.]+\.execute)"
    r"\(\s*f(?P<q>[\"'])"
    r"(?P<sql>.*?\{(?P<var>[A-Za-z_]\w*)\}.*?)"
    r"(?P=q)\s*\)\s*:?[ \t]*$",
)

_PLACEHOLDER_RE = re.compile(r"\{[A-Za-z_]\w*\}")


def extract_vulnerable_source(prompt: str) -> str:
    """Return the vulnerable source embedded in the remediation prompt."""
    try:
        _, rest = prompt.split(_SOURCE_BEGIN, 1)
        source, _ = rest.split(_SOURCE_END, 1)
    except ValueError as exc:
        raise ProviderExecutionError(
            "remediation prompt did not contain the vulnerable source block."
        ) from exc

    return source.strip("\n")


def extract_category_from_prompt(prompt: str) -> str:
    """Return the finding category."""
    match = _CATEGORY_RE.search(prompt)
    return match.group(1) if match else "other"


def extract_source_file_path(prompt: str) -> str:
    """Return the relative path belonging to the vulnerable source block."""
    match = _SOURCE_PATH_RE.search(prompt)

    if match is None:
        raise ProviderExecutionError(
            "remediation prompt did not declare the vulnerable source file_path."
        )

    return match.group(1)


def parameterize_fstring_execute(source: str) -> tuple[str, list[str]]:
    """Rewrite one-parameter f-string SQL execute calls."""
    params: list[str] = []

    def _replace(match: re.Match[str]) -> str:
        indent = match.group("indent")
        call = match.group("call")
        sql = match.group("sql")
        var = match.group("var")

        if len(_PLACEHOLDER_RE.findall(sql)) != 1:
            raise ProviderExecutionError(
                "mock remediation only converts single-parameter f-string statements."
            )

        patched_sql = _PLACEHOLDER_RE.sub("?", sql)

        # Turn:
        #     "SELECT ... '?'"
        # into:
        #     "SELECT ... ?"
        patched_sql = re.sub(
            r"""([\"'])\s*\?\s*\1""",
            "?",
            patched_sql,
        )

        params.append(var)

        return f'{indent}{call}(\n{indent}    "{patched_sql}",\n{indent}    ({var},),\n{indent})'

    patched_lines = []

    for line in source.splitlines():
        match = _FSTRING_EXECUTE_RE.match(line)

        if match:
            patched_lines.append(_replace(match))
        else:
            patched_lines.append(line)

    if not params:
        raise ProviderExecutionError(
            "mock remediation found no convertible f-string execute statement."
        )

    return "\n".join(patched_lines), params


def build_default_remediation_plan(prompt: str) -> RemediationPlan:
    """Build a deterministic parameterized-SQL remediation."""
    category = extract_category_from_prompt(prompt)

    if category != "sql_injection":
        raise ProviderExecutionError(
            "mock remediation supports only sql_injection findings "
            f"(got '{category}'); refusing to fabricate a fix."
        )

    source = extract_vulnerable_source(prompt)
    file_path = extract_source_file_path(prompt)

    patched_content, params = parameterize_fstring_execute(source)

    explanation = (
        "Replaced dynamic f-string SQL construction with a parameterized query: "
        f"the untrusted value(s) {', '.join(params)} now bind to placeholder(s) "
        "instead of being interpolated into the SQL text, eliminating injection "
        "while keeping query semantics identical."
    )

    return RemediationPlan(
        finding_ref=0,
        file_path=file_path,
        patched_content=patched_content,
        explanation=explanation,
    )
