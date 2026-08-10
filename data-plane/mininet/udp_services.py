#!/usr/bin/env python3
"""Serve isolated DNS and telemetry UDP traffic for the Mininet web host."""

from __future__ import annotations

import argparse
import selectors
import signal
import socket
import struct


DEFAULT_LISTEN_HOST = "10.0.0.100"
DEFAULT_DNS_PORT = 53
DEFAULT_TELEMETRY_PORT = 8125
DEFAULT_DNS_ADDRESS = "10.0.0.100"


def _question_end(packet):
    offset = 12
    while offset < len(packet):
        label_length = packet[offset]
        offset += 1
        if label_length == 0:
            break
        if label_length & 0xC0 or offset + label_length > len(packet):
            raise ValueError("compressed or malformed DNS question")
        offset += label_length
    if offset + 4 > len(packet):
        raise ValueError("DNS question is missing type or class")
    return offset + 4


def build_dns_response(packet, address=DEFAULT_DNS_ADDRESS):
    """Build one authoritative-looking A response for a valid DNS query."""
    if len(packet) < 12:
        raise ValueError("DNS packet is shorter than its header")
    transaction_id, flags, questions = struct.unpack("!HHH", packet[:6])
    if flags & 0x8000 or questions != 1:
        raise ValueError("expected one DNS query question")
    question_end = _question_end(packet)
    header = struct.pack(
        "!HHHHHH",
        transaction_id,
        0x8180,
        1,
        1,
        0,
        0,
    )
    answer = (
        b"\xc0\x0c"
        + struct.pack("!HHIH", 1, 1, 60, 4)
        + socket.inet_aton(address)
    )
    return header + packet[12:question_end] + answer


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen-host", default=DEFAULT_LISTEN_HOST)
    parser.add_argument("--dns-port", type=int, default=DEFAULT_DNS_PORT)
    parser.add_argument(
        "--telemetry-port",
        type=int,
        default=DEFAULT_TELEMETRY_PORT,
    )
    parser.add_argument("--dns-address", default=DEFAULT_DNS_ADDRESS)
    return parser.parse_args()


def bind_udp(host, port):
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_socket.bind((host, port))
    return udp_socket


def main():
    args = parse_args()
    selector = selectors.DefaultSelector()
    dns_socket = bind_udp(args.listen_host, args.dns_port)
    telemetry_socket = bind_udp(args.listen_host, args.telemetry_port)
    selector.register(dns_socket, selectors.EVENT_READ, "dns")
    selector.register(telemetry_socket, selectors.EVENT_READ, "telemetry")
    stopping = False

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        while not stopping:
            for key, _mask in selector.select(timeout=1.0):
                packet, client = key.fileobj.recvfrom(4096)
                if key.data == "dns":
                    try:
                        response = build_dns_response(packet, args.dns_address)
                    except ValueError:
                        continue
                    key.fileobj.sendto(response, client)
                else:
                    # StatsD-style telemetry is intentionally fire-and-forget.
                    packet.decode("utf-8", errors="ignore")
    finally:
        selector.close()
        dns_socket.close()
        telemetry_socket.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
