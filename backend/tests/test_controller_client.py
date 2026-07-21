import io
import json
from urllib.error import HTTPError
from urllib.error import URLError
from unittest.mock import patch

import pytest

from app.clients.controller import ControllerClient
from app.clients.controller import ControllerClientError


class FakeResponse:
    def __init__(self, body):
        self.body = json.dumps(body).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self.body


def test_install_sends_stable_backend_rule_id_to_controller():
    client = ControllerClient(
        base_url="http://controller:8080",
        timeout_seconds=1,
        max_attempts=1,
    )
    response = {
        "controller_rule_id": "rule-1",
        "status": "APPLIED",
    }

    with patch(
        "app.clients.controller.urlopen",
        return_value=FakeResponse(response),
    ) as urlopen:
        result = client.install_flow_rule({
            "id": "rule-1",
            "switch_id": "s1",
            "match": {"ipv4_src": "10.0.0.2"},
            "action": "DROP",
            "priority": 500,
            "idle_timeout": None,
            "hard_timeout": None,
            "rate_limit_pps": 100,
        })

    request = urlopen.call_args.args[0]
    payload = json.loads(request.data)
    assert result == response
    assert payload["rule_id"] == "rule-1"
    assert payload["rate_limit_pps"] == 100
    assert request.full_url == "http://controller:8080/flow-rules"


def test_http_error_preserves_controller_failure_response():
    client = ControllerClient(
        base_url="http://controller:8080",
        timeout_seconds=1,
        max_attempts=1,
    )
    body = {
        "detail": {
            "status": "FAILED",
            "error": "OpenFlow rejected the rule",
        }
    }
    error = HTTPError(
        "http://controller:8080/flow-rules",
        502,
        "Bad Gateway",
        {},
        io.BytesIO(json.dumps(body).encode("utf-8")),
    )

    with patch("app.clients.controller.urlopen", side_effect=error):
        with pytest.raises(
            ControllerClientError,
            match="OpenFlow rejected the rule",
        ) as raised:
            client.install_flow_rule({
                "id": "rule-1",
                "switch_id": "s1",
                "match": {"ipv4_src": "10.0.0.2"},
                "action": "DROP",
                "priority": 500,
            })

    assert raised.value.response == body["detail"]


def test_transient_connection_error_is_retried_with_same_request():
    client = ControllerClient(
        base_url="http://controller:8080",
        timeout_seconds=1,
        max_attempts=2,
        retry_delay_seconds=0,
    )
    response = {
        "controller_rule_id": "rule-1",
        "status": "APPLIED",
    }

    with patch(
        "app.clients.controller.urlopen",
        side_effect=[URLError("unavailable"), FakeResponse(response)],
    ) as urlopen:
        result = client.install_flow_rule({
            "id": "rule-1",
            "switch_id": "s1",
            "match": {"ipv4_src": "10.0.0.2"},
            "action": "DROP",
            "priority": 500,
        })

    assert result == response
    assert urlopen.call_count == 2


def test_delete_sends_rule_id_and_switch_and_requires_removed_status():
    client = ControllerClient(
        base_url="http://controller:8080",
        timeout_seconds=1,
        max_attempts=1,
    )
    response = {
        "controller_rule_id": "rule/1",
        "switch_id": "s1",
        "status": "REMOVED",
    }

    with patch(
        "app.clients.controller.urlopen",
        return_value=FakeResponse(response),
    ) as urlopen:
        result = client.delete_flow_rule({
            "id": "rule/1",
            "switch_id": "s1",
        })

    request = urlopen.call_args.args[0]
    assert result == response
    assert request.method == "DELETE"
    assert request.data is None
    assert request.full_url == (
        "http://controller:8080/flow-rules/rule%2F1?switch_id=s1"
    )


def test_list_flow_rules_parses_controller_items():
    client = ControllerClient(
        base_url="http://controller:8080",
        timeout_seconds=1,
        max_attempts=1,
    )
    body = {
        "items": [
            {"controller_rule_id": "rule-1", "status": "EXPIRED"},
        ],
    }

    with patch(
        "app.clients.controller.urlopen",
        return_value=FakeResponse(body),
    ) as urlopen:
        result = client.list_flow_rules()

    assert result == body["items"]
    request = urlopen.call_args.args[0]
    assert request.method == "GET"
    assert request.full_url == "http://controller:8080/flow-rules"


def test_recalculate_paths_sends_preferred_path():
    client = ControllerClient(
        base_url="http://controller:8080",
        timeout_seconds=1,
        max_attempts=1,
    )
    body = {"status": "RECALCULATED", "preferred_path": "backup"}

    with patch(
        "app.clients.controller.urlopen",
        return_value=FakeResponse(body),
    ) as urlopen:
        result = client.recalculate_paths("backup")

    request = urlopen.call_args.args[0]
    assert result == body
    assert request.method == "POST"
    assert json.loads(request.data) == {"preferred_path": "backup"}
    assert request.full_url == "http://controller:8080/paths/recalculate"
