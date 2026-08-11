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
                stats_interval_seconds=1.0,
            ),
            load_settings({}),
        )

    def test_reads_custom_ports_and_rest_host(self):
        settings = load_settings(
            {
                "CONTROLLER_OPENFLOW_PORT": "16653",
                "CONTROLLER_REST_HOST": "127.0.0.1",
                "CONTROLLER_REST_PORT": "18080",
                "CONTROLLER_STATS_INTERVAL_SECONDS": "2.5",
                "PATH_DISTRIBUTION_THRESHOLD_PPS": "1200",
                "PATH_DISTRIBUTION_RECOVERY_PPS": "900",
            }
        )

        self.assertEqual(16653, settings.openflow_port)
        self.assertEqual("127.0.0.1", settings.rest_host)
        self.assertEqual(18080, settings.rest_port)
        self.assertEqual(2.5, settings.stats_interval_seconds)
        self.assertEqual(1200.0, settings.path_distribution_threshold_pps)
        self.assertEqual(900.0, settings.path_distribution_recovery_pps)

    def test_reads_api_auth_settings(self):
        settings = load_settings({
            "CONTROLLER_API_KEY": "secret",
            "ALLOW_INSECURE_DEV_AUTH": "true",
        })

        self.assertEqual("secret", settings.api_key)
        self.assertTrue(settings.allow_insecure_dev_auth)

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

    def test_rejects_distribution_recovery_at_or_above_threshold(self):
        with self.assertRaisesRegex(
            ValueError,
            "PATH_DISTRIBUTION_RECOVERY_PPS",
        ):
            load_settings({
                "PATH_DISTRIBUTION_THRESHOLD_PPS": "1000",
                "PATH_DISTRIBUTION_RECOVERY_PPS": "1000",
            })


if __name__ == "__main__":
    unittest.main()
