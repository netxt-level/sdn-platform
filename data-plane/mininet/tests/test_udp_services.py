import socket
import struct
import unittest

from udp_services import build_dns_response


def dns_query(name="shop.local", transaction_id=0x1234):
    labels = b"".join(
        bytes([len(label)]) + label.encode("ascii")
        for label in name.split(".")
    ) + b"\x00"
    return (
        struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
        + labels
        + struct.pack("!HH", 1, 1)
    )


class DnsResponseTests(unittest.TestCase):
    def test_returns_a_record_for_the_web_host(self):
        response = build_dns_response(dns_query())

        transaction_id, flags, questions, answers, _, _ = struct.unpack(
            "!HHHHHH",
            response[:12],
        )
        self.assertEqual(0x1234, transaction_id)
        self.assertEqual(0x8180, flags)
        self.assertEqual(1, questions)
        self.assertEqual(1, answers)
        self.assertEqual(socket.inet_aton("10.0.0.100"), response[-4:])

    def test_rejects_malformed_queries(self):
        with self.assertRaises(ValueError):
            build_dns_response(b"short")


if __name__ == "__main__":
    unittest.main()
