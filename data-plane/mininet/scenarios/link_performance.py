#!/usr/bin/env python3
"""Validate TCLink bandwidth and delay with ICMP and iperf3."""

import argparse
import json
from pathlib import Path
import re
from subprocess import DEVNULL
from subprocess import PIPE
from subprocess import TimeoutExpired
import sys
import time


MININET_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MININET_DIR))

from link_config import delay_to_milliseconds  # noqa: E402
from link_config import parse_link_configs  # noqa: E402
from topology import create_network  # noqa: E402
from topology import print_connection_status  # noqa: E402
from topology import wait_for_controller_connections  # noqa: E402


class PerformanceFailure(RuntimeError):
    """Raised when one configured link characteristic is not observed."""


def parse_args():
    parser = argparse.ArgumentParser(
        description="Validate Mininet TCLink bandwidth and delay settings.",
    )
    parser.add_argument("--controller-host", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6653)
    parser.add_argument("--bandwidth", type=float, default=10.0)
    parser.add_argument("--delay", default="5ms")
    parser.add_argument("--duration", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()

    try:
        args.link_configs = parse_link_configs([
            (
                f"s1-s2:bw={args.bandwidth},delay={args.delay},loss=0"
            ),
            (
                f"s2-s4:bw={args.bandwidth},delay={args.delay},loss=0"
            ),
        ])
        args.delay_ms = delay_to_milliseconds(args.delay.lower())
    except ValueError as error:
        parser.error(str(error))
    if args.duration <= 0:
        parser.error("duration must be greater than zero")
    return args


def checkpoint(number, message):
    print(f"[{number}/4] PASS {message}")


def measure_average_rtt(source, destination):
    output = source.cmd(
        "ping",
        "-c",
        "4",
        "-W",
        "1",
        "-q",
        destination.IP(),
    )
    match = re.search(r"= [0-9.]+/([0-9.]+)/[0-9.]+/", output)
    if match is None or "0% packet loss" not in output:
        raise PerformanceFailure(f"delay ping failed:\n{output}")
    return float(match.group(1))


def measure_tcp_bandwidth(source, destination, duration):
    server = destination.popen(
        ["iperf3", "-s", "-1"],
        stdout=DEVNULL,
        stderr=PIPE,
    )
    try:
        time.sleep(0.5)
        output = source.cmd(
            "iperf3",
            "-c",
            destination.IP(),
            "-t",
            str(duration),
            "--json",
        )
        try:
            payload = json.loads(output)
            return float(payload["end"]["sum_received"]["bits_per_second"])
        except (KeyError, TypeError, ValueError) as error:
            raise PerformanceFailure(
                f"invalid iperf3 result:\n{output}"
            ) from error
    finally:
        try:
            server.wait(timeout=duration + 5)
        except TimeoutExpired:
            server.kill()
            server.wait(timeout=2)


def run(args):
    network = create_network(
        controller_host=args.controller_host,
        controller_port=args.controller_port,
        link_configs=args.link_configs,
    )

    try:
        network.build()
        network.start()
        if not wait_for_controller_connections(network, args.timeout):
            print_connection_status(network)
            raise PerformanceFailure("not all switches connected to Controller")
        checkpoint(1, "shaped Primary links started with OpenFlow 1.3")

        h1 = network.get("h1")
        web = network.get("web")
        average_rtt = measure_average_rtt(h1, web)
        minimum_expected_rtt = args.delay_ms * 4 * 0.6
        if average_rtt < minimum_expected_rtt:
            raise PerformanceFailure(
                f"average RTT {average_rtt:.2f} ms is below expected "
                f"minimum {minimum_expected_rtt:.2f} ms"
            )
        checkpoint(2, f"average RTT reflects configured delay: {average_rtt:.2f} ms")

        bits_per_second = measure_tcp_bandwidth(h1, web, args.duration)
        measured_mbps = bits_per_second / 1_000_000
        minimum_mbps = args.bandwidth * 0.5
        maximum_mbps = args.bandwidth * 1.3
        if not minimum_mbps <= measured_mbps <= maximum_mbps:
            raise PerformanceFailure(
                f"iperf3 measured {measured_mbps:.2f} Mbps outside "
                f"{minimum_mbps:.2f}-{maximum_mbps:.2f} Mbps"
            )
        checkpoint(
            3,
            f"iperf3 respected {args.bandwidth:.2f} Mbps cap: "
            f"{measured_mbps:.2f} Mbps",
        )
        return 0
    except PerformanceFailure as error:
        print(f"FAIL {error}", file=sys.stderr)
        return 1
    finally:
        network.stop()
        checkpoint(4, "shaped Mininet network stopped and interfaces removed")


def main():
    return run(parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
