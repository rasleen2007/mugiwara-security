"""Mugiwara Security cloud (SaaS) API package.

This package is intentionally isolated from the local engine: importing
``mugiwara`` never imports this subpackage, so missing cloud configuration or
dependencies cannot affect ``uv run mugiwara ui`` or any CLI workflow.

Security posture:
- The FastAPI service and its configuration are server-side only.
- Every database query is scoped by the owner id taken from a verified Supabase
  JWT subject; client-supplied owner fields are never accepted as authority.
- Service-role credentials are held in ``SecretStr`` values and never logged,
  returned in responses, or embedded into frontend-facing artifacts.
"""
