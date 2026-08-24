"""Structural security tests for the Supabase SaaS migrations (Phase 1).

The migrations cannot run inside hermetic unit tests (no Postgres daemon),
so these tests enforce the *security-critical structure* of the SQL the same
way ``test_github_workflows.py`` enforces CI structure:

- every user-owned table exists and is RLS-enabled,
- every policy is owner-scoped on ``auth.uid()`` and no policy is granted to
  ``anon``,
- job inserts cannot point at another user's storage objects,
- storage buckets are private and object policies are uid-path scoped,
- integrity constraints keep stored envelopes/bundles schema-genuine,
- queue/lease indexes exist for SKIP LOCKED polling,
- signup provisioning is SECURITY DEFINER with a pinned search path,
- no secret material or public exposure sneaks into config/env templates.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SUPABASE_DIR = REPO_ROOT / "supabase"
INIT_SQL = SUPABASE_DIR / "migrations" / "0001_init.sql"
RLS_SQL = SUPABASE_DIR / "migrations" / "0002_rls.sql"
STORAGE_SQL = SUPABASE_DIR / "migrations" / "0003_storage.sql"
CONFIG_TOML = SUPABASE_DIR / "config.toml"
ENV_EXAMPLE = REPO_ROOT / ".env.example"

USER_OWNED_TABLES = (
    "profiles",
    "projects",
    "scan_jobs",
    "reports",
    "remediation_runs",
    "user_quotas",
)

# Grammar accepted by the running engine for report identifiers
# (src/mugiwara/ui/server.py _REPORT_ID_RE).
REPORT_ID_GRAMMAR = r"^[0-9]{8}T[0-9]{6}-[0-9a-f]{10}(-[0-9]+)?$"


def _read(path: Path) -> str:
    assert path.is_file(), f"missing required file: {path}"
    return path.read_text(encoding="utf-8")


def _policy_blocks(rls_sql: str) -> list[str]:
    """Return one text block per CREATE POLICY statement."""
    parts = re.split(r"(?=create\s+policy)", rls_sql, flags=re.IGNORECASE)
    return [p for p in parts if re.match(r"\s*create\s+policy", p, flags=re.IGNORECASE)]


# --------------------------------------------------------------- tables


def test_all_user_owned_tables_created() -> None:
    init_sql = _read(INIT_SQL)
    for table in USER_OWNED_TABLES:
        pattern = rf"create table if not exists public\.{table}\s*\("
        assert re.search(pattern, init_sql, flags=re.IGNORECASE), f"table missing: {table}"


def test_owner_columns_default_to_auth_uid() -> None:
    """User-insertable rows must self-attribute via DEFAULT auth.uid().
    profiles and user_quotas are trigger/service provisioned instead."""
    init_sql = _read(INIT_SQL)
    expected_columns = {
        "projects": "owner_id",
        "scan_jobs": "owner_id",
        "reports": "owner_id",
        "remediation_runs": "owner_id",
    }
    for table, column in expected_columns.items():
        block = re.search(
            rf"create table if not exists public\.{table}\s*\(.*?\);",
            init_sql,
            flags=re.IGNORECASE | re.DOTALL,
        )
        assert block is not None, f"table block not found: {table}"
        pattern = rf"{column}[^,]*default\s+auth\.uid\(\)"
        assert re.search(pattern, block.group(0), flags=re.IGNORECASE), (
            f"{table}.{column} must default to auth.uid()"
        )
    for table, key in (("profiles", "id"), ("user_quotas", "user_id")):
        block = re.search(
            rf"create table if not exists public\.{table}\s*\(.*?\);",
            init_sql,
            flags=re.IGNORECASE | re.DOTALL,
        )
        assert block is not None
        assert re.search(
            rf"{key}\s+uuid\s+primary\s+key\s+references\s+auth\.users\s*\(id\)\s+"
            r"on\s+delete\s+cascade",
            block.group(0),
            flags=re.IGNORECASE,
        ), f"{table}.{key} must mirror auth.users with cascading delete"


# ------------------------------------------------------------------- RLS


def test_rls_enabled_on_every_user_owned_table() -> None:
    rls_sql = _read(RLS_SQL)
    for table in USER_OWNED_TABLES:
        pattern = rf"alter table public\.{table}\s+enable row level security"
        assert re.search(pattern, rls_sql, flags=re.IGNORECASE), f"RLS not enabled: {table}"


def test_select_policies_are_owner_scoped_on_auth_uid() -> None:
    rls_sql = _read(RLS_SQL)
    select_policies = [
        p for p in _policy_blocks(rls_sql) if re.search(r"for\s+select", p, flags=re.IGNORECASE)
    ]
    assert select_policies, "no SELECT policies found"
    for policy in select_policies:
        assert re.search(r"auth\.uid\(\)", policy), (
            f"SELECT policy without auth.uid() scoping: {policy.splitlines()[0]}"
        )
    covered = {
        m.group(1)
        for p in select_policies
        for m in [re.search(r"on\s+(?:public\.)?(\w+)", p, flags=re.IGNORECASE)]
        if m
    }
    for table in USER_OWNED_TABLES:
        assert table in covered, f"{table} has no owner-scoped SELECT policy"


def test_no_anon_role_receives_any_policy() -> None:
    rls_sql = _read(RLS_SQL)
    storage_sql = _read(STORAGE_SQL)
    combined = "\n".join(
        statement
        for statement in (rls_sql + "\n" + storage_sql).splitlines()
        if not statement.strip().startswith("--")
    )
    offenders = re.findall(r"to\s+anon\b[^(;]*", combined, flags=re.IGNORECASE)
    assert offenders == [], f"anon role must never receive a policy: {offenders}"


def test_end_users_cannot_update_jobs_reports_or_results() -> None:
    """Status/result writes are worker-only; users get read/delete at most."""
    rls_sql = _read(RLS_SQL)
    for table in ("scan_jobs", "reports", "remediation_runs"):
        updates = [
            p
            for p in _policy_blocks(rls_sql)
            if re.search(rf"on\s+public\.{table}\b", p, flags=re.IGNORECASE)
            and re.search(r"for\s+update", p, flags=re.IGNORECASE)
        ]
        assert updates == [], f"end users must have no UPDATE policy on {table}"


def test_scan_job_insert_enforces_storage_path_ownership() -> None:
    """A user can only enqueue jobs whose source key lives under their own
    uid-prefixed folder - closing the queue-poisoning IDOR vector."""
    rls_sql = _read(RLS_SQL)
    insert_policies = [
        p
        for p in _policy_blocks(rls_sql)
        if re.search(r"on\s+public\.scan_jobs\b", p, flags=re.IGNORECASE)
        and re.search(r"for\s+insert", p, flags=re.IGNORECASE)
    ]
    assert len(insert_policies) == 1, "exactly one scan_jobs INSERT policy expected"
    policy = insert_policies[0]
    assert "with check" in policy.lower()
    assert "auth.uid()" in policy
    assert "source_key like auth.uid()::text || '/%'" in policy.lower()
    assert "source_bucket = 'scan-uploads'" in policy


# --------------------------------------------------------------- storage


def test_storage_buckets_are_private_with_engine_matching_cap() -> None:
    storage_sql = _read(STORAGE_SQL)
    upload_block = re.search(
        r"insert into storage\.buckets.*?scan-uploads.*?;",
        storage_sql,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert upload_block is not None, "scan-uploads bucket must be created"
    block = upload_block.group(0).lower()
    assert re.search(r"\bfalse\b", block), "buckets must be private (public = false)"
    assert "536870912" in block, "upload cap must match engine _MAX_UPLOAD_BYTES (512 MiB)"
    # The export bucket must exist and stay private too.
    exports = re.search(
        r"insert into storage\.buckets.*?report-exports.*?;",
        storage_sql,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert exports is not None
    assert re.search(r"\bfalse\b", exports.group(0).lower())


def test_storage_object_policies_scoped_to_uid_path_prefix() -> None:
    storage_sql = _read(STORAGE_SQL)
    policies = _policy_blocks(storage_sql)
    assert policies, "storage object policies missing"
    for policy in policies:
        assert "(storage.foldername(name))[1] = auth.uid()::text" in policy, (
            f"storage policy not uid-path scoped: {policy.splitlines()[0]}"
        )
    actions = {
        action: any(re.search(rf"for\s+{action}\b", p, flags=re.IGNORECASE) for p in policies)
        for action in ("insert", "select", "delete")
    }
    assert all(actions.values()), f"missing storage policy action(s): {actions}"
    updates = [p for p in policies if re.search(r"for\s+update\b", p, flags=re.IGNORECASE)]
    assert updates == [], "uploaded objects must be immutable for end users (no UPDATE policy)"


# ----------------------------------------------------- integrity & indexes


def test_report_id_format_constraint_matches_engine_grammar() -> None:
    init_sql = _read(INIT_SQL)
    match = re.search(r"report_id ~ '([^']+)'", init_sql)
    assert match is not None, "reports.report_id format CHECK missing"
    assert match.group(1) == REPORT_ID_GRAMMAR


def test_schema_integrity_checks_pin_engine_schemas() -> None:
    init_sql = _read(INIT_SQL).lower()
    assert "envelope ->> 'schema' = 'mugiwara.scan-report'" in init_sql
    assert "bundle ->> 'schema' = 'mugiwara.fix-bundle'" in init_sql
    assert re.search(r"jsonb_typeof\(phases\) = 'array'", init_sql)


def test_queue_polling_and_lease_indexes_present() -> None:
    init_sql = _read(INIT_SQL).lower()
    assert re.search(
        r"create index if not exists idx_scan_jobs_queue_poll\s+"
        r"on public\.scan_jobs \(created_at\)\s+where status = 'queued'",
        init_sql,
    )
    assert re.search(
        r"create index if not exists idx_scan_jobs_expired_leases\s+"
        r"on public\.scan_jobs \(worker_lease_until\)\s+where status = 'running'",
        init_sql,
    )
    assert "create index if not exists idx_reports_owner_created" in init_sql


def test_signup_trigger_is_security_definer_with_pinned_search_path() -> None:
    init_sql = _read(INIT_SQL)
    fn = re.search(
        r"create or replace function public\.handle_new_user\(\).*?\$\$;",
        init_sql,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert fn is not None, "handle_new_user function missing"
    body = fn.group(0)
    assert re.search(r"security\s+definer", body, flags=re.IGNORECASE)
    assert re.search(r"set\s+search_path\s*=\s*''", body, flags=re.IGNORECASE)
    assert re.search(r"after\s+insert\s+on\s+auth\.users", init_sql, flags=re.IGNORECASE)


# ------------------------------------------------------------ config/env


def test_env_example_keeps_service_key_server_side_only() -> None:
    env = _read(ENV_EXAMPLE)
    assert "SUPABASE_SERVICE_ROLE_KEY=" in env
    assert "SERVER-SIDE ONLY" in env.upper()
    assert "NEVER" in env.upper()
    browser_vars = re.findall(r"^NEXT_PUBLIC_[A-Z_]+=", env, flags=re.MULTILINE)
    assert sorted(browser_vars) == [
        "NEXT_PUBLIC_MUGIWARA_API_URL=",
        "NEXT_PUBLIC_SUPABASE_ANON_KEY=",
        "NEXT_PUBLIC_SUPABASE_URL=",
    ]
    for forbidden in ("NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY", "NEXT_PUBLIC_DATABASE_URL"):
        assert forbidden not in env


def test_local_supabase_config_binds_loopback_only() -> None:
    config = _read(CONFIG_TOML)
    assert 'site_url = "http://localhost:3000"' in config
    assert not re.search(r"host\s*=\s*\"0\.0\.0\.0\"", config)
    assert "enable_anonymous_sign_ins = false" in config
