-- Mugiwara Security SaaS - private storage buckets and object policies (Phase 1).
--
-- * Buckets are PRIVATE. No `public` bucket exists; nothing is world-readable.
-- * Ownership is enforced by path convention, NOT by the storage.objects owner
--   column: every key must start with `<auth.uid()>/`. This keeps policies
--   independent of Supabase storage schema versions (owner vs owner_id) and
--   makes signed-URL issuance auditable: the API derives keys from the
--   verified JWT identity, never from browser input.
-- * Objects are immutable for users (no UPDATE policy): an uploaded archive
--   cannot be swapped after a job references it.
-- * Signed upload/download URLs are minted by the FastAPI service with the
--   service role AFTER server-side authorization; possession of the URL grants
--   time-limited access to that single object.

-- ---------------------------------------------------------------------------
-- Buckets
-- ---------------------------------------------------------------------------

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
    'scan-uploads',
    'scan-uploads',
    false,
    536870912,  -- 512 MiB, matches the engine's _MAX_UPLOAD_BYTES cap
    array[
        'application/zip',
        'application/x-zip-compressed',
        'application/octet-stream'
    ]
)
on conflict (id) do update
    set public = false,
        file_size_limit = excluded.file_size_limit,
        allowed_mime_types = excluded.allowed_mime_types;

insert into storage.buckets (id, name, public, file_size_limit)
values ('report-exports', 'report-exports', false, 104857600)  -- 100 MiB cache cap
on conflict (id) do update
    set public = false,
        file_size_limit = excluded.file_size_limit;

-- ---------------------------------------------------------------------------
-- Object policies (authenticated role only; anon gets nothing).
-- ---------------------------------------------------------------------------

-- Upload: only into your own uid-prefixed folder of scan-uploads.
create policy "scan_uploads_insert_own" on storage.objects
    for insert to authenticated
    with check (
        bucket_id = 'scan-uploads'
        and (storage.foldername(name))[1] = auth.uid()::text
    );

-- Read: own objects in either private bucket.
create policy "mugiwara_objects_select_own" on storage.objects
    for select to authenticated
    using (
        bucket_id in ('scan-uploads', 'report-exports')
        and (storage.foldername(name))[1] = auth.uid()::text
    );

-- Delete: only your own raw uploads. Export-cache objects are managed by the
-- service (lifecycle/retention), never by end users.
create policy "scan_uploads_delete_own" on storage.objects
    for delete to authenticated
    using (
        bucket_id = 'scan-uploads'
        and (storage.foldername(name))[1] = auth.uid()::text
    );
