import asyncio

from app.middleware.body_size import RequestBodySizeLimitMiddleware


async def _ok_app(scope, receive, send):
    while True:
        message = await receive()
        if message["type"] == "http.request" and not message.get("more_body"):
            break
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"{}"})


def _post(path: str, body: bytes) -> list[dict]:
    sent_messages = []
    delivered = False

    async def receive():
        nonlocal delivered
        if delivered:
            return {"type": "http.request", "body": b"", "more_body": False}
        delivered = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        sent_messages.append(message)

    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": [(b"content-length", str(len(body)).encode("ascii"))],
    }
    asyncio.run(RequestBodySizeLimitMiddleware(_ok_app)(scope, receive, send))
    return sent_messages


def _status(messages: list[dict]) -> int:
    return next(
        message["status"]
        for message in messages
        if message["type"] == "http.response.start"
    )


def test_security_event_body_size_limit_allows_small_request():
    assert _status(_post("/api/security/events", b"x" * 1024)) == 200


def test_security_event_body_size_limit_rejects_large_request():
    body = b"x" * (1024 * 1024 + 1)
    assert _status(_post("/api/security/events", body)) == 413


def test_analyzer_status_has_smaller_limit():
    body = b"x" * (64 * 1024 + 1)
    assert _status(_post("/api/analyzer/status", body)) == 413
