import unittest

from app.config import ControllerSettings
from app.config import load_settings


class ControllerSettingsTests(unittest.TestCase):
    def test_uses_documented_defaults(self):
        self.assertEqual(
            ControllerSettings(
                openflow_port=6653,
                rest_host="0.0.0.0",
                rest_port=8080,
            ),
            load_settings({}),
        )

    def test_reads_custom_ports_and_rest_host(self):
        settings = load_settings(
            {
                "CONTROLLER_OPENFLOW_PORT": "16653",
                "CONTROLLER_REST_HOST": "127.0.0.1",
                "CONTROLLER_REST_PORT": "18080",
            }
        )

        self.assertEqual(16653, settings.openflow_port)
        self.assertEqual("127.0.0.1", settings.rest_host)
        self.assertEqual(18080, settings.rest_port)

    def test_rejects_non_numeric_port(self):
        with self.assertRaisesRegex(
            ValueError,
            "CONTROLLER_REST_PORT must be an integer",
        ):
            load_settings({"CONTROLLER_REST_PORT": "invalid"})

    def test_rejects_out_of_range_port(self):
        with self.assertRaisesRegex(
            ValueError,
            "CONTROLLER_OPENFLOW_PORT must be between 1 and 65535",
        ):
            load_settings({"CONTROLLER_OPENFLOW_PORT": "0"})


if __name__ == "__main__":
    unittest.main()
