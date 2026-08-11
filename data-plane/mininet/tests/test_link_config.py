from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from link_config import canonical_link_name
from link_config import delay_to_milliseconds
from link_config import parse_link_config
from link_config import parse_link_configs


class LinkConfigParsingTests(unittest.TestCase):
    def test_parses_all_supported_parameters(self):
        link, parameters = parse_link_config(
            "s1-s2:bw=10,delay=5ms,loss=1.5"
        )

        self.assertEqual("s1-s2", link)
        self.assertEqual(
            {"bw": 10.0, "delay": "5ms", "loss": 1.5},
            parameters,
        )

    def test_normalizes_reverse_link_and_parameter_case(self):
        link, parameters = parse_link_config("S4-S2:BW=20")

        self.assertEqual("s2-s4", link)
        self.assertEqual({"bw": 20.0}, parameters)

    def test_repeated_specs_create_per_link_configuration(self):
        configurations = parse_link_configs(
            ["s1-s2:bw=10", "s3-s4:delay=2ms,loss=0"]
        )

        self.assertEqual(
            {
                "s1-s2": {"bw": 10.0},
                "s3-s4": {"delay": "2ms", "loss": 0.0},
            },
            configurations,
        )

    def test_rejects_unknown_link_or_parameter(self):
        with self.assertRaisesRegex(ValueError, "unknown configurable link"):
            parse_link_config("s1-s4:bw=10")
        with self.assertRaisesRegex(ValueError, "unsupported link parameter"):
            parse_link_config("s1-s2:jitter=1ms")

    def test_rejects_invalid_bandwidth_and_loss(self):
        for specification in (
            "s1-s2:bw=0",
            "s1-s2:bw=-1",
            "s1-s2:bw=nan",
            "s1-s2:loss=-1",
            "s1-s2:loss=101",
            "s1-s2:loss=inf",
        ):
            with self.subTest(specification=specification):
                with self.assertRaises(ValueError):
                    parse_link_config(specification)

    def test_rejects_invalid_delay_format(self):
        for specification in (
            "s1-s2:delay=5",
            "s1-s2:delay=-1ms",
            "s1-s2:delay=fast",
            "s1-s2:delay=1msec",
        ):
            with self.subTest(specification=specification):
                with self.assertRaisesRegex(ValueError, "invalid link delay"):
                    parse_link_config(specification)

    def test_rejects_duplicate_parameter_or_link(self):
        with self.assertRaisesRegex(ValueError, "duplicate link parameter"):
            parse_link_config("s1-s2:bw=10,bw=20")
        with self.assertRaisesRegex(ValueError, "duplicate link config"):
            parse_link_configs(["s1-s2:bw=10", "s2-s1:delay=5ms"])

    def test_converts_supported_delay_units_to_milliseconds(self):
        self.assertEqual(0.5, delay_to_milliseconds("500us"))
        self.assertEqual(5.0, delay_to_milliseconds("5ms"))
        self.assertEqual(1500.0, delay_to_milliseconds("1.5s"))


class CanonicalLinkNameTests(unittest.TestCase):
    def test_sorts_endpoints(self):
        self.assertEqual("s1-s3", canonical_link_name("s3", "s1"))

    def test_rejects_empty_or_identical_endpoint(self):
        with self.assertRaises(ValueError):
            canonical_link_name("s1", "s1")
        with self.assertRaises(ValueError):
            canonical_link_name("", "s1")


if __name__ == "__main__":
    unittest.main()
