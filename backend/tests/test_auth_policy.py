import sys
import types

import pytest

try:
    from fastapi import HTTPException
except ImportError:
    class HTTPException(Exception):
        def __init__(self, status_code: int, detail: str):
            self.status_code = status_code
            self.detail = detail

    fastapi_stub = types.ModuleType("fastapi")
    fastapi_stub.Header = lambda default=None, alias=None: default
    fastapi_stub.HTTPException = HTTPException
    fastapi_stub.status = types.SimpleNamespace(
        HTTP_401_UNAUTHORIZED=401,
        HTTP_503_SERVICE_UNAVAILABLE=503,
    )
    sys.modules.setdefault("fastapi", fastapi_stub)

from app.core.auth import _require_api_key
from app.core.auth import issue_websocket_token
from app.core.auth import verify_websocket_token


def test_api_key_rejects_missing_configuration():
    with pytest.raises(HTTPException) as error:
        _require_api_key(
            configured_key="",
            received_key=None,
            role="admin",
        )
    assert error.value.status_code == 503


def test_api_key_rejects_invalid_key():
    with pytest.raises(HTTPException) as error:
        _require_api_key(
            configured_key="expected",
            received_key="wrong",
            role="admin",
        )
    assert error.value.status_code == 401


def test_api_key_accepts_constant_time_match():
    _require_api_key(
        configured_key="expected",
        received_key="expected",
        role="admin",
    )


def test_websocket_token_is_signed_and_expires(monkeypatch):
    monkeypatch.setenv("WEBSOCKET_TOKEN_SECRET", "test-signing-secret")
    monkeypatch.setenv("WEBSOCKET_TOKEN_TTL_SECONDS", "60")

    token, expires_at = issue_websocket_token(now=100)

    assert expires_at == 160
    assert verify_websocket_token(token, now=159) is True
    assert verify_websocket_token(token, now=161) is False
    assert verify_websocket_token(f"{token}tampered", now=120) is False


def test_websocket_token_cannot_use_empty_secret(monkeypatch):
    monkeypatch.delenv("WEBSOCKET_TOKEN_SECRET", raising=False)
    monkeypatch.setenv("ALLOW_INSECURE_DEV_AUTH", "false")

    assert verify_websocket_token("forged.payload", now=100) is False
