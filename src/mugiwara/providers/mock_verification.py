"""Deterministic VerificationPlan synthesis for the mock LLM provider.

The mock provider cannot reason about findings, but demo and integration runs
still need a schema-valid, safety-screenable probe for every verification
candidate so the full Phase 4 path (synthesis -> screening -> sandbox
execution -> evaluation -> evidence) can be exercised without network access.
Templates read the target URL and canary token from the environment contract,
perform only harmless observations, and report an honest verdict based on what
the running target actually returns.
"""

import re

from mugiwara.agents.models import VerificationPlan

_CATEGORY_RE = re.compile(r"^category:\s*([a-zA-Z_]+)", re.MULTILINE)

SQL_INJECTION_TEMPLATE = """\
import json
import os
import urllib.error
import urllib.parse
import urllib.request

base = os.environ["MUGIWARA_TARGET_URL"]
canary = os.environ["MUGIWARA_CANARY"]


def fetch(path):
    url = base.rstrip("/") + path
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except Exception as exc:
        return None, repr(exc)


baseline_status, baseline_body = fetch("/users?username=mugiarabaseline")
status, body = fetch("/users?username=" + urllib.parse.quote("'" + canary))
observed = body[:500]
trace = {
    "method": "GET",
    "url": base.rstrip("/") + "/users",
    "http_status": status,
    "response_body_snippet": observed[:300],
}
print("MUGIWARA_HTTP_TRACE: " + json.dumps(trace))
reflected = canary in observed
differential = (baseline_status, baseline_body) != (status, body)
verdict = {
    "canary_found": reflected or differential,
    "http_status": status,
    "notes": "canary reflected: {}; response differential vs baseline: {}".format(
        reflected, differential
    ),
}
print("MUGIWARA_VERDICT: " + json.dumps(verdict))
"""

GENERIC_TEMPLATE = """\
import json
import os
import urllib.error
import urllib.request

base = os.environ["MUGIWARA_TARGET_URL"]
canary = os.environ["MUGIWARA_CANARY"]


def fetch(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except Exception as exc:
        return None, repr(exc)


observed = ""
status = None
for path in ("/", "/ping", "/health"):
    status, body = fetch(base.rstrip("/") + path)
    observed = observed + body[:500]
    if canary in observed:
        break
trace = {
    "method": "GET",
    "url": base.rstrip("/") + "/",
    "http_status": status,
    "response_body_snippet": observed[:300],
}
print("MUGIWARA_HTTP_TRACE: " + json.dumps(trace))
verdict = {
    "canary_found": canary in observed,
    "http_status": status,
    "notes": "generic reflection sweep across common paths",
}
print("MUGIWARA_VERDICT: " + json.dumps(verdict))
"""

_TEMPLATES = {
    "sql_injection": SQL_INJECTION_TEMPLATE,
}

_STEPS_BY_TEMPLATE = {
    SQL_INJECTION_TEMPLATE: [
        "Run the staged target application inside the isolated sandbox.",
        "Request /users?username=<single-quote plus canary token>.",
        "Compare the response against a benign baseline request.",
        "Observe whether the canary or a parser-level differential appears.",
    ],
    GENERIC_TEMPLATE: [
        "Run the staged target application inside the isolated sandbox.",
        "Fetch common paths (/ , /ping, /health).",
        "Check every response for the canary token echo.",
    ],
}


def extract_category(prompt: str) -> str:
    """Return the finding category declared in the rendered prompt block."""
    match = _CATEGORY_RE.search(prompt)
    if match is None:
        return "other"
    return match.group(1)


def build_default_verification_plan(prompt: str, finding_ref: int) -> VerificationPlan:
    """Build a deterministic, screening-safe plan for one verification candidate."""
    template = _TEMPLATES.get(extract_category(prompt), GENERIC_TEMPLATE)
    return VerificationPlan(
        finding_ref=finding_ref,
        poc_language="python3",
        poc_script=template,
        reproduction_steps=list(_STEPS_BY_TEMPLATE[template]),
        expected_canary=(
            "Canary token echoed by the target, or a reproducible response "
            "differential induced solely by the injected expression."
        ),
        max_readiness_wait_seconds=5,
    )
