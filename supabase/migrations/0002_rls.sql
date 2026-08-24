-- Mugiwara Security SaaS - Row Level Security (Phase 1).
--
-- Threat model: a malicious authenticated user with direct PostgREST access
-- must never read or write another user's rows. Every policy below is
-- owner-scoped on auth.uid(). The `anon` role receives NO policies anywhere
-- (deny by default). The API and worker use the service role, which bypasses
-- RLS; they re-scope every query server-side from the verified JWT `sub`.
--
-- Deliberate omissions (deny-by-default):
-- * No UPDATE policy for end users on scan_jobs / reports / remediation_runs:
--   job status transitions and result writes are worker-only operations.
-- * No INSERT policy for end users on reports / remediation_runs: only the
--   worker publishes results.
-- * No DELETE policy for end users on user_quotas or profiles.id changes.

alter table public.profiles         enable row level security;
alter table public.projects         enable row level security;
alter table public.scan_jobs        enable row level security;
alter table public.reports          enable row level security;
alter table public.remediation_runs enable row level security;
alter table public.user_quotas      enable row level security;

-- ---------------------------------------------------------------------------
-- profiles
-- ---------------------------------------------------------------------------

create policy "profiles_select_own" on public.profiles
    for select to authenticated
    using (id = auth.uid());

create policy "profiles_update_own" on public.profiles
    for update to authenticated
    using (id = auth.uid())
    with check (id = auth.uid());

-- ---------------------------------------------------------------------------
-- projects: full CRUD for the owning user only.
-- ---------------------------------------------------------------------------

create policy "projects_select_own" on public.projects
    for select to authenticated
    using (owner_id = auth.uid());

create policy "projects_insert_own" on public.projects
    for insert to authenticated
    with check (owner_id = auth.uid());

create policy "projects_update_own" on public.projects
    for update to authenticated
    using (owner_id = auth.uid())
    with check (owner_id = auth.uid());

create policy "projects_delete_own" on public.projects
    for delete to authenticated
    using (owner_id = auth.uid());

-- ---------------------------------------------------------------------------
-- scan_jobs
--
-- The INSERT policy is also a storage-ownership guard: the source object key
-- MUST live under a folder named after the caller's own uid. This makes it
-- impossible for one user to enqueue a job that points at another user's
-- uploaded archive, even when inserting directly through PostgREST. The API
-- derives the same key shape from the verified JWT identity server-side.
-- ---------------------------------------------------------------------------

create policy "scan_jobs_select_own" on public.scan_jobs
    for select to authenticated
    using (owner_id = auth.uid());

create policy "scan_jobs_insert_own" on public.scan_jobs
    for insert to authenticated
    with check (
        owner_id = auth.uid()
        and source_bucket = 'scan-uploads'
        and source_key like auth.uid()::text || '/%'
    );

create policy "scan_jobs_delete_own_nonrunning" on public.scan_jobs
    for delete to authenticated
    using (owner_id = auth.uid() and status <> 'running');

-- ---------------------------------------------------------------------------
-- reports: read/delete own; inserts are worker-only.
-- ---------------------------------------------------------------------------

create policy "reports_select_own" on public.reports
    for select to authenticated
    using (owner_id = auth.uid());

create policy "reports_delete_own" on public.reports
    for delete to authenticated
    using (owner_id = auth.uid());

-- ---------------------------------------------------------------------------
-- remediation_runs: read/delete own; inserts are worker-only.
-- ---------------------------------------------------------------------------

create policy "remediation_runs_select_own" on public.remediation_runs
    for select to authenticated
    using (owner_id = auth.uid());

create policy "remediation_runs_delete_own" on public.remediation_runs
    for delete to authenticated
    using (owner_id = auth.uid());

-- ---------------------------------------------------------------------------
-- user_quotas: visible to their owner so the UI can render limits; writes are
-- provisioning/administration only (signup trigger + service role).
-- ---------------------------------------------------------------------------

create policy "user_quotas_select_own" on public.user_quotas
    for select to authenticated
    using (user_id = auth.uid());
