"""Bounded, idempotent REST client for the OpenFlow controller."""

import json
import socket
import time
from typing import Any
from urllib.error import HTTPError
from urllib.error import URLError
from urllib.request import Request
from urllib.request import urlopen
from urllib.parse import quote
from urllib.parse import urlencode

from app.core.config import settings


class ControllerClientError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        response: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.response = response


class ControllerClient:
    def __init__(
        self,
        *,
        base_url: str | None = None,
        timeout_seconds: float | None = None,
        max_attempts: int | None = None,
        retry_delay_seconds: float = 0.2,
    ):
        self.base_url = (
            settings.controller_base_url if base_url is None else base_url
        ).rstrip("/")
        self.timeout_seconds = (
            settings.controller_timeout_seconds
            if timeout_seconds is None
            else timeout_seconds
        )
        self.max_attempts = (
            settings.controller_max_attempts
            if max_attempts is None
            else max_attempts
        )
        self.retry_delay_seconds = retry_delay_seconds

    def install_flow_rule(self, flow_rule: dict[str, Any]) -> dict[str, Any]:
        payload = {
            "rule_id": flow_rule["id"],
            "switch_id": flow_rule["switch_id"],
            "match": flow_rule["match"],
            "action": flow_rule["action"],
            "priority": flow_rule["priority"],
            "idle_timeout": flow_rule.get("idle_timeout"),
            "hard_timeout": flow_rule.get("hard_timeout"),
            "rate_limit_pps": flow_rule.get("rate_limit_pps"),
        }
        return self._request(
            "POST",
            "/flow-rules",
            payload,
            expected_status="APPLIED",
        )

    def delete_flow_rule(self, flow_rule: dict[str, Any]) -> dict[str, Any]:
        path = f"/flow-rules/{quote(flow_rule['id'], safe='')}"
        switch_id = flow_rule.get("switch_id")
        if switch_id:
            path = f"{path}?{urlencode({'switch_id': switch_id})}"
        return self._request(
            "DELETE",
            path,
            None,
            expected_status="REMOVED",
        )

    def list_flow_rules(self) -> list[dict[str, Any]]:
        response = self._request(
            "GET",
            "/flow-rules",
            None,
            expected_status=None,
        )
        items = response.get("items")
        if not isinstance(items, list) or not all(
            isinstance(item, dict) for item in items
        ):
            raise ControllerClientError(
                "controller returned an invalid Flow Rule list",
                response=response,
            )
        return items

    def get_topology(self) -> dict[str, Any]:
        return self._request("GET", "/topology", None, expected_status=None)

    def get_stats(self) -> dict[str, Any]:
        return self._request("GET", "/stats", None, expected_status=None)

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
        *,
        expected_status: str | None,
    ) -> dict[str, Any]:
        request = Request(
            f"{self.base_url}{path}",
            data=(
                None
                if payload is None
                else json.dumps(payload).encode("utf-8")
            ),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            method=method,
        )

        for attempt in range(1, self.max_attempts + 1):
            try:
                with urlopen(
                    request,
                    timeout=self.timeout_seconds,
                ) as response:
                    body = self._decode_json(response.read())
                if expected_status is not None and (
                    body.get("status") != expected_status
                    or not body.get("controller_rule_id")
                ):
                    raise ControllerClientError(
                        "controller did not confirm Flow Rule "
                        f"{method.lower()} operation",
                        response=body,
                    )
                return body
            except HTTPError as error:
                body = self._decode_json(error.read())
                detail = body.get("detail", body)
                response = detail if isinstance(detail, dict) else body
                message = (
                    str(detail)
                    if isinstance(detail, str)
                    else str(
                        response.get("error")
                        or response.get("detail")
                        or f"controller returned HTTP {error.code}"
                    )
                )
                raise ControllerClientError(
                    message,
                    response=response,
                ) from error
            except (TimeoutError, socket.timeout, URLError) as error:
                if attempt >= self.max_attempts:
                    raise ControllerClientError(
                        "controller request failed after "
                        f"{self.max_attempts} attempt(s): {error}"
                    ) from error
                time.sleep(self.retry_delay_seconds)

        raise AssertionError("controller request loop ended unexpectedly")

    @staticmethod
    def _decode_json(raw_body: bytes) -> dict[str, Any]:
        if not raw_body:
            return {}
        try:
            decoded = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ControllerClientError(
                "controller returned an invalid JSON response"
            ) from error
        if not isinstance(decoded, dict):
            raise ControllerClientError(
                "controller returned a non-object JSON response"
            )
        return decoded
