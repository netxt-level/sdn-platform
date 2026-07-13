import json
from collections.abc import Awaitable, Callable
from typing import Any

Message = dict[str, Any]
Scope = dict[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class RequestBodyTooLarge(Exception):
    pass


class RequestBodySizeLimitMiddleware:
    """대형 JSON 요청이 Pydantic 검증 전에 메모리에 올라가는 일을 줄인다."""

    def __init__(self, app: ASGIApp):
        self.app = app
        self.path_limits = {
            "/api/analyzer/status": 64 * 1024,
            "/api/analyzer/packet-summary": 512 * 1024,
            "/api/analyzer/detection-summary": 128 * 1024,
            "/api/security/events": 1024 * 1024,
            "/api/flows": 64 * 1024,
        }

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = str(scope.get("method") or "").upper()
        limit = self.path_limits.get(str(scope.get("path") or ""))
        if method not in {"POST", "PUT", "PATCH"} or limit is None:
            await self.app(scope, receive, send)
            return

        if self._content_length(scope) > limit:
            await self._send_too_large(scope, receive, send, limit)
            return

        limited_receive = self._limited_receive(receive, limit)
        try:
            await self.app(scope, limited_receive, send)
        except RequestBodyTooLarge:
            await self._send_too_large(scope, receive, send, limit)

    def _limited_receive(self, receive: Receive, limit: int) -> Receive:
        received_bytes = 0

        async def receive_with_limit() -> Message:
            nonlocal received_bytes

            message = await receive()
            if message["type"] == "http.request":
                received_bytes += len(message.get("body", b""))
                if received_bytes > limit:
                    raise RequestBodyTooLarge()
            return message

        return receive_with_limit

    def _content_length(self, scope: Scope) -> int:
        headers = dict(scope.get("headers") or [])
        raw_value = headers.get(b"content-length")
        if not raw_value:
            return 0

        try:
            return int(raw_value)
        except ValueError:
            return 0

    async def _send_too_large(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        limit: int,
    ) -> None:
        body = json.dumps(
            {"detail": f"요청 본문 크기는 최대 {limit} bytes까지 허용됩니다."},
            ensure_ascii=False,
        ).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json; charset=utf-8"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        })
        await send({
            "type": "http.response.body",
            "body": body,
        })
