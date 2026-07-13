import requests

from analyzer.app.analyzer_status import AnalyzerStatus
from analyzer.app.backend_client import BackendClient


def test_analysis_error_does_not_mark_backend_disconnected():
    status = AnalyzerStatus(analyzer_id="analyzer-1", interface="eth0")
    status.mark_summary_sent()

    status.mark_analysis_failed("analysis loop failed")

    assert status.backend_connected is True
    assert status.status == "error"
    assert status.error_message == "analysis loop failed"


def test_backend_success_does_not_clear_analysis_error():
    status = AnalyzerStatus(analyzer_id="analyzer-1", interface="eth0")

    status.mark_analysis_failed("analysis loop failed: boom")
    status.mark_summary_sent()

    assert status.backend_connected is True
    assert status.status == "error"
    assert status.error_message == "analysis loop failed: boom"


def test_successful_analysis_recovers_analysis_error():
    status = AnalyzerStatus(analyzer_id="analyzer-1", interface="eth0")

    status.mark_analysis_failed("analysis loop failed: boom")
    status.mark_analysis_succeeded()

    assert status.status == "running"
    assert status.error_message is None


def test_backend_failure_does_not_hide_analysis_error():
    status = AnalyzerStatus(analyzer_id="analyzer-1", interface="eth0")

    status.mark_analysis_failed("analysis loop failed: boom")
    status.mark_backend_failed("failed to send analyzer status")

    assert status.backend_connected is False
    assert status.status == "error"
    assert status.error_message == "analysis loop failed: boom"


def test_backend_client_sends_api_key_header(monkeypatch):
    captured = {}

    class Response:
        status_code = 200

        def raise_for_status(self):
            return None

    def fake_post(url, *, json, headers, timeout):
        captured["url"] = url
        captured["headers"] = headers
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr(requests, "post", fake_post)

    client = BackendClient(
        base_url="http://backend:8000",
        timeout_sec=1.5,
        api_key="test-key",
    )

    result = client.send_analyzer_status({"ok": True})

    assert result.success is True
    assert result.status_code == 200
    assert captured["url"] == "http://backend:8000/api/analyzer/status"
    assert captured["headers"] == {"X-API-Key": "test-key"}
    assert captured["timeout"] == 1.5


def test_backend_client_returns_http_error_status_per_request(monkeypatch):
    class Response:
        status_code = 413

        def raise_for_status(self):
            raise requests.exceptions.HTTPError(response=self)

    monkeypatch.setattr(
        requests,
        "post",
        lambda url, *, json, headers, timeout: Response(),
    )

    client = BackendClient(base_url="http://backend:8000")

    result = client.send_security_events({"events": []})

    assert result.success is False
    assert result.status_code == 413
    assert result.error == "http_error"
