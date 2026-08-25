"""Environment-driven configuration for the Mugiwara cloud API.

All settings come from environment variables matching ``.env.example``.
Instantiating :class:`CloudSettings` fails fast with a clear message when
required values are missing; local (non-cloud) code never imports this
module, so an unconfigured machine keeps working unchanged.

Secrets use ``pydantic.SecretStr`` so accidental ``repr``/``str``/log output
shows ``**********`` instead of credential material.
"""

from pydantic import SecretStr, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MAX_UPLOAD_BYTES = 512 * 1024 * 1024


class CloudSettings(BaseSettings):
    """Server-side configuration for the FastAPI service and worker."""

    model_config = SettingsConfigDict(extra="ignore", frozen=True)

    supabase_url: str
    supabase_anon_key: SecretStr = SecretStr("")
    supabase_service_role_key: SecretStr
    database_url: SecretStr

    upload_bucket: str = "scan-uploads"
    export_bucket: str = "report-exports"

    jwt_audience: str = "authenticated"
    jwt_leeway_seconds: int = 30
    jwks_cache_ttl_seconds: int = 600
    jwks_min_refresh_seconds: int = 5
    http_timeout_seconds: float = 10.0

    upload_url_ttl_seconds: int = 900
    download_url_ttl_seconds: int = 300

    cors_origins: list[str] = ["http://localhost:3000"]

    worker_lease_seconds: int = 900
    worker_max_attempts: int = 3
    worker_poll_interval_seconds: float = 5.0
    worker_scratch_dir: str | None = None
    max_download_bytes: int = MAX_UPLOAD_BYTES

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _parse_cors_origins(cls, v: str | list[str]) -> list[str]:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    @property
    def issuer(self) -> str:
        return f"{self.supabase_url.rstrip('/')}/auth/v1"

    @property
    def jwks_url(self) -> str:
        return f"{self.issuer}/.well-known/jwks.json"


class CloudConfigError(RuntimeError):
    """Raised when required cloud configuration is missing or invalid."""


def load_settings() -> CloudSettings:
    """Build :class:`CloudSettings` from the process environment.

    Raises:
        CloudConfigError: If any required environment variable is absent,
            including a list of the offending names.
    """
    try:
        return CloudSettings.model_validate({})
    except ValidationError as exc:
        missing = sorted(
            {
                str(err["loc"][0])
                for err in exc.errors()
                if err.get("type") == "missing" and err.get("loc")
            }
        )
        names = ", ".join(name.upper() for name in missing) or "invalid configuration"
        msg = (
            "Cloud API is not configured; set the required environment "
            f"variables first ({names}). See .env.example. Local commands "
            "(mugiwara ui / CLI) do not need these values."
        )
        raise CloudConfigError(msg) from exc
