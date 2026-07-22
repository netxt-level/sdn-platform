import base64
import hashlib
import hmac
import json
import time
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
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"{role} API authentication is not configured",
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


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def issue_websocket_token(now: int | None = None) -> tuple[str, int]:
    secret = settings.websocket_token_secret
    if not secret:
        if settings.allow_insecure_dev_auth:
            return "insecure-development-token", 0
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="WebSocket token signing is not configured",
        )

    issued_at = int(time.time()) if now is None else now
    expires_at = issued_at + settings.websocket_token_ttl_seconds
    payload = _base64url_encode(
        json.dumps(
            {"aud": "sdn-realtime", "iat": issued_at, "exp": expires_at},
            separators=(",", ":"),
        ).encode("utf-8")
    )
    signature = _base64url_encode(
        hmac.new(secret.encode("utf-8"), payload.encode("ascii"), hashlib.sha256).digest()
    )
    return f"{payload}.{signature}", expires_at


def verify_websocket_token(token: str, now: int | None = None) -> bool:
    if settings.allow_insecure_dev_auth and not settings.websocket_token_secret:
        return token == "insecure-development-token"
    if not settings.websocket_token_secret:
        return False
    try:
        payload, signature = token.split(".", 1)
        expected_signature = _base64url_encode(
            hmac.new(
                settings.websocket_token_secret.encode("utf-8"),
                payload.encode("ascii"),
                hashlib.sha256,
            ).digest()
        )
        if not compare_digest(signature, expected_signature):
            return False
        claims = json.loads(_base64url_decode(payload).decode("utf-8"))
        current_time = int(time.time()) if now is None else now
        return (
            claims.get("aud") == "sdn-realtime"
            and int(claims.get("iat", 0)) <= current_time
            and int(claims.get("exp", 0)) >= current_time
        )
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
        return False
