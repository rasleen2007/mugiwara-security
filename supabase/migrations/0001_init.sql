-- Mugiwara Security SaaS - initial schema (Phase 1).
--
-- Design rules:
-- * Every user-owned table carries `owner_id uuid NOT NULL DEFAULT auth.uid()`
--   so a direct PostgREST insert can never attribute rows to someone else.
-- * Row Level Security (0002_rls.sql) is the outer boundary; this file only
--   defines structure. The FastAPI service and the worker connect with the
--   Supabase service role, which bypasses RLS, so the API re-scopes every
--   query by the verified JWT `sub` claim (defense in depth).
-- * The full scan envelope is stored verbatim (`reports.envelope`) using the
--   existing `mugiwara.scan-report` schema so engine parsers/exporters keep
--   working unchanged.
-- * No credentials are ever stored here: LLM keys stay in engine SecretStr
--   settings and never enter these tables.

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------------
-- profiles: public identity mirror of auth.users (1:1).
-- ---------------------------------------------------------------------------

create table if not exists public.profiles (
    id          uuid primary key references auth.users (id) on delete cascade,
    display_name text not null default '',
    created_at  timestamptz not null default now()
);

comment on table public.profiles is
    'Per-user profile; id equals auth.users.id. Cascade-deleted with the user.';

-- ---------------------------------------------------------------------------
-- projects: user-owned grouping of scan activity.
-- ---------------------------------------------------------------------------

create table if not exists public.projects (
    id         uuid primary key default gen_random_uuid(),
    owner_id   uuid not null default auth.uid() references auth.users (id) on delete cascade,
    name       text not null,
    created_at timestamptz not null default now(),
    constraint projects_name_length check (char_length(name) between 1 and 200),
    constraint projects_unique_name_per_owner unique (owner_id, name)
);

comment on table public.projects is
    'User-owned project container. owner_id always comes from auth.uid().';

-- ---------------------------------------------------------------------------
-- scan_jobs: async queue rows for scans and remediation runs.
--
-- Workers lease rows with FOR UPDATE SKIP LOCKED (no Redis/Kafka). The
-- Postgres instance IS the initial queue, per the approved architecture.
-- ---------------------------------------------------------------------------

create table if not exists public.scan_jobs (
    id                uuid primary key default gen_random_uuid(),
    owner_id          uuid not null default auth.uid()
                          references auth.users (id) on delete cascade,
    project_id        uuid references public.projects (id) on delete set null,
    kind              text not null default 'scan'
                          check (kind in ('scan', 'fix')),
    -- For kind='fix': the report whose verified findings should be remediated.
    -- FK is added below (reports is created afterwards).
    target_report_id  text,
    status            text not null default 'queued'
                          check (status in ('queued', 'running', 'completed',
                                            'failed', 'cancelled')),
    target_kind       text not null default 'zip'
                          check (target_kind in ('zip')),
    -- Storage coordinates. The key MUST be prefixed with the owner's uid;
    -- the RLS layer enforces that prefix for user-submitted rows, and the
    -- API derives it from the verified JWT identity for its own inserts.
    source_bucket     text not null default 'scan-uploads',
    source_key        text not null,
    source_sha256     text check (source_sha256 is null
                                  or char_length(source_sha256) = 64),
    source_bytes      bigint check (source_bytes is null or source_bytes >= 0),
    scan_profile      text not null default 'standard'
                          check (scan_profile in ('fast', 'standard', 'deep')),
    -- Secret-free phase progress strings emitted by the engine observer
    -- (counts only; never file contents, PoCs, tokens, or evidence).
    phases            jsonb not null default '[]'::jsonb
                          check (jsonb_typeof(phases) = 'array'),
    error             text,
    attempts          integer not null default 0,
    worker_id         text,
    worker_lease_until timestamptz,
    created_at        timestamptz not null default now(),
    started_at        timestamptz,
    completed_at      timestamptz,
    constraint scan_jobs_attempts_positive check (attempts >= 0)
);

comment on table public.scan_jobs is
    'Postgres-backed job queue (SKIP LOCKED). Status transitions are performed '
    'exclusively by the API/worker via the service role; end users get no '
    'UPDATE policy.';

-- ---------------------------------------------------------------------------
-- reports: one row per persisted mugiwara.scan-report envelope.
-- ---------------------------------------------------------------------------

create table if not exists public.reports (
    report_id     text primary key,
    owner_id      uuid not null default auth.uid()
                      references auth.users (id) on delete cascade,
    project_id    uuid references public.projects (id) on delete set null,
    -- FK to scan_jobs added below (created after this table).
    job_id        uuid,
    origin        text not null check (origin in ('archive', 'directory')),
    -- Display-only label (original archive name). Never a worker-local path.
    target_label  text not null default '',
    configuration jsonb not null check (jsonb_typeof(configuration) = 'object'),
    summary       jsonb not null check (jsonb_typeof(summary) = 'object'),
    -- Verbatim StoredScanReport document; validated again on read by the
    -- existing engine parser (parse_stored_report).
    envelope      jsonb not null
                      check (jsonb_typeof(envelope) = 'object'
                             and envelope ->> 'schema' = 'mugiwara.scan-report'),
    created_at    timestamptz not null default now(),
    constraint reports_report_id_format check (
        report_id ~ '^[0-9]{8}T[0-9]{6}-[0-9a-f]{10}(-[0-9]+)?$'
    )
);

comment on table public.reports is
    'Canonical scan results. envelope stores the exact mugiwara.scan-report '
    'JSON produced by ReportStore.build/save semantics; exports are rendered '
    'from it on demand.';

-- ---------------------------------------------------------------------------
-- remediation_runs: generated fix bundles (mugiwara.fix-bundle documents).
-- ---------------------------------------------------------------------------

create table if not exists public.remediation_runs (
    id         uuid primary key default gen_random_uuid(),
    owner_id   uuid not null default auth.uid()
                   references auth.users (id) on delete cascade,
    report_id  text not null references public.reports (report_id)
                   on delete cascade,
    job_id     uuid references public.scan_jobs (id) on delete set null,
    bundle     jsonb not null
                   check (jsonb_typeof(bundle) = 'object'
                          and bundle ->> 'schema' = 'mugiwara.fix-bundle'),
    created_at timestamptz not null default now()
);

comment on table public.remediation_runs is
    'Fix bundles produced by the worker through the unchanged fail-closed '
    'RemediationService. VERIFIED_FIXED claims inside bundles remain bound to '
    'the sea-trial evidence recorded by the engine.';

-- Circular references (jobs <-> reports) resolved now that both exist.

alter table public.scan_jobs
    drop constraint if exists scan_jobs_target_report_fk;
alter table public.scan_jobs
    add constraint scan_jobs_target_report_fk
    foreign key (target_report_id) references public.reports (report_id)
    on delete set null;

alter table public.reports
    drop constraint if exists reports_job_fk;
alter table public.reports
    add constraint reports_job_fk
    foreign key (job_id) references public.scan_jobs (id)
    on delete set null;

-- ---------------------------------------------------------------------------
-- user_quotas: abuse/cost control consumed by the API before accepting jobs.
-- ---------------------------------------------------------------------------

create table if not exists public.user_quotas (
    user_id                     uuid primary key
                                    references auth.users (id) on delete cascade,
    max_concurrent_running_jobs integer not null default 2
                                    check (max_concurrent_running_jobs between 1 and 100),
    max_queued_jobs             integer not null default 10
                                    check (max_queued_jobs between 1 and 1000),
    -- Matches the engine upload cap (_MAX_UPLOAD_BYTES = 512 MiB).
    max_source_bytes            bigint not null default 536870912
                                    check (max_source_bytes > 0),
    max_jobs_per_day            integer not null default 50
                                    check (max_jobs_per_day between 1 and 100000),
    updated_at                  timestamptz not null default now()
);

comment on table public.user_quotas is
    'Per-user limits enforced server-side by the API. Rows are provisioned by '
    'the on-signup trigger; users have SELECT only.';

-- ---------------------------------------------------------------------------
-- Automatic provisioning on signup (Supabase convention). SECURITY DEFINER is
-- required because auth.users is not writable by the authenticated role; the
-- empty search_path pins every reference and avoids injection via search_path.
-- ---------------------------------------------------------------------------

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
    insert into public.profiles (id, display_name)
    values (
        new.id,
        coalesce(
            new.raw_user_meta_data ->> 'display_name',
            split_part(coalesce(new.email, 'user'), '@', 1)
        )
    )
    on conflict (id) do nothing;

    insert into public.user_quotas (user_id)
    values (new.id)
    on conflict (user_id) do nothing;

    return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
    after insert on auth.users
    for each row execute function public.handle_new_user();

-- ---------------------------------------------------------------------------
-- Indexes. The queue-poll and lease indexes are partial: they cover exactly
-- the predicates the workers query (queued rows; expired running leases).
-- ---------------------------------------------------------------------------

create index if not exists idx_projects_owner on public.projects (owner_id);

create index if not exists idx_scan_jobs_owner_created
    on public.scan_jobs (owner_id, created_at desc);

create index if not exists idx_scan_jobs_queue_poll
    on public.scan_jobs (created_at)
    where status = 'queued';

create index if not exists idx_scan_jobs_expired_leases
    on public.scan_jobs (worker_lease_until)
    where status = 'running';

create index if not exists idx_reports_owner_created
    on public.reports (owner_id, created_at desc);

create index if not exists idx_reports_project
    on public.reports (project_id);

create index if not exists idx_remediation_runs_report
    on public.remediation_runs (report_id, created_at desc);

create index if not exists idx_remediation_runs_owner
    on public.remediation_runs (owner_id, created_at desc);
