from secrets import compare_digest

from fastapi import Header, HTTPException, status

from app.core.config import settings


def _require_api_key(
    *,
    configured_key: str,
    received_key: str | None,
    role: str,
    allow_insecure_dev_auth: bool = False,
) -> None:
    if not configured_key:
        if allow_insecure_dev_auth:
            return
        raise RuntimeError(
            f"{role} API key is required. Set ALLOW_INSECURE_DEV_AUTH=true only for local development."
        )

    if received_key and compare_digest(received_key, configured_key):
        return

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=f"{role} API key is invalid",
    )


def require_analyzer_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> None:
    _require_api_key(
        configured_key=settings.analyzer_api_key,
        received_key=x_api_key,
        role="analyzer",
        allow_insecure_dev_auth=settings.allow_insecure_dev_auth,
    )


def require_admin_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> None:
    _require_api_key(
        configured_key=settings.admin_api_key,
        received_key=x_api_key,
        role="admin",
        allow_insecure_dev_auth=settings.allow_insecure_dev_auth,
    )
