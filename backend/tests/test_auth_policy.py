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
    fastapi_stub.status = types.SimpleNamespace(HTTP_401_UNAUTHORIZED=401)
    fastapi_stub.WebSocket = object
    encoders_stub = types.ModuleType("fastapi.encoders")
    encoders_stub.jsonable_encoder = lambda value: value
    sys.modules.setdefault("fastapi", fastapi_stub)
    sys.modules.setdefault("fastapi.encoders", encoders_stub)

dotenv_stub = types.ModuleType("dotenv")
dotenv_stub.load_dotenv = lambda: None
sys.modules.setdefault("dotenv", dotenv_stub)

from app.core.auth import _require_api_key  # noqa: E402


def test_api_key_check_requires_key_by_default():
    with pytest.raises(RuntimeError):
        _require_api_key(
            configured_key="",
            received_key=None,
            role="analyzer",
        )


def test_api_key_check_allows_empty_key_only_in_explicit_dev_mode():
    _require_api_key(
        configured_key="",
        received_key=None,
        role="analyzer",
        allow_insecure_dev_auth=True,
    )


def test_api_key_check_rejects_invalid_key():
    with pytest.raises(HTTPException):
        _require_api_key(
            configured_key="expected",
            received_key="wrong",
            role="analyzer",
        )


def test_api_key_check_accepts_matching_key():
    _require_api_key(
        configured_key="expected",
        received_key="expected",
        role="analyzer",
    )
