import unittest
from unittest.mock import Mock, patch

from analyzer.app.backend_client import BackendClient


class BackendClientAuthTest(unittest.TestCase):
    @patch("analyzer.app.backend_client.requests.post")
    def test_api_key_is_sent_with_analyzer_payload(self, post):
        response = Mock()
        response.raise_for_status.return_value = None
        post.return_value = response
        client = BackendClient(
            "http://backend:8000",
            api_key="analyzer-secret",
        )

        result = client.send_packet_summary({"total_packets": 1})

        self.assertTrue(result)
        self.assertEqual(
            {"X-API-Key": "analyzer-secret"},
            post.call_args.kwargs["headers"],
        )


if __name__ == "__main__":
    unittest.main()
