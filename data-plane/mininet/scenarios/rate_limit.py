#!/usr/bin/env python3
"""Validate OVS Meter packet-rate limiting and automatic cleanup."""

import argparse
import json
from pathlib import Path
import subprocess
from subprocess import DEVNULL
from subprocess import PIPE
from subprocess import TimeoutExpired
import sys
import time
from urllib.request import Request
from urllib.request import urlopen


MININET_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MININET_DIR))

from topology import create_network  # noqa: E402
from topology import wait_for_controller_connections  # noqa: E402


class ScenarioFailure(RuntimeError):
    pass


def parse_args():
    parser = argparse.ArgumentParser(
        description="Validate RATE_LIMIT with an OVS packet-per-second meter.",
    )
    parser.add_argument("--controller-host", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6653)
    parser.add_argument("--controller-rest-port", type=int, default=8080)
    parser.add_argument("--rate-pps", type=int, default=100)
    parser.add_argument("--duration", type=int, default=3)
    parser.add_argument("--hard-timeout", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()
    if args.rate_pps <= 0:
        parser.error("--rate-pps must be positive")
    if args.duration <= 0:
        parser.error("--duration must be positive")
    if args.hard_timeout <= args.duration:
        parser.error("--hard-timeout must exceed --duration")
    return args


def controller_request(args, method, path, payload=None):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(
        (
            f"http://{args.controller_host}:"
            f"{args.controller_rest_port}{path}"
        ),
        data=body,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    with urlopen(request, timeout=args.timeout) as response:
        return json.load(response)


def measure_udp_bandwidth(source, destination, duration):
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
            "--udp",
            "--bitrate",
            "100M",
            "--length",
            "1200",
            "--json",
        )
        try:
            payload = json.loads(output)
            return float(payload["end"]["sum_received"]["bits_per_second"])
        except (KeyError, TypeError, ValueError) as error:
            raise ScenarioFailure(f"invalid iperf3 result:\n{output}") from error
    finally:
        try:
            server.wait(timeout=duration + 5)
        except TimeoutExpired:
            server.kill()
            server.wait(timeout=2)


def require_meter(switch, meter_id, rate_pps):
    output = switch.cmd(
        "ovs-ofctl",
        "-O",
        "OpenFlow13",
        "dump-meters",
        switch.name,
    ).lower()
    required = (
        f"meter={meter_id}",
        "pktps",
        "type=drop",
        f"rate={rate_pps}",
    )
    if not all(value in output for value in required):
        raise ScenarioFailure(f"OVS meter was not installed:\n{output}")


def wait_for_cleanup(args, switch, rule_id, meter_id):
    deadline = time.monotonic() + args.timeout
    last_state = None
    last_meters = None
    while time.monotonic() < deadline:
        rules = controller_request(args, "GET", "/flow-rules")["items"]
        current = next(
            (item for item in rules if item["controller_rule_id"] == rule_id),
            None,
        )
        last_state = None if current is None else current["status"]
        last_meters = switch.cmd(
            "ovs-ofctl",
            "-O",
            "OpenFlow13",
            "dump-meters",
            switch.name,
        ).lower()
        if (
            last_state == "EXPIRED"
            and f"meter={meter_id}" not in last_meters
        ):
            return
        time.sleep(0.2)
    raise ScenarioFailure(
        "rate-limit cleanup timed out: "
        f"rule_state={last_state} meters={last_meters}"
    )


def run(args):
    network = create_network(
        controller_host=args.controller_host,
        controller_port=args.controller_port,
    )
    started = False
    try:
        network.build()
        network.start()
        started = True
        if not wait_for_controller_connections(network, args.timeout):
            raise ScenarioFailure("switches did not connect to Controller")

        h1 = network.get("h1")
        web = network.get("web")
        baseline_bps = measure_udp_bandwidth(h1, web, args.duration)

        rule_id = "mininet-rate-limit-smoke"
        response = controller_request(args, "POST", "/flow-rules", {
            "rule_id": rule_id,
            "switch_id": "s1",
            "match": {
                "ipv4_src": "10.0.0.1",
                "ipv4_dst": "10.0.0.100",
                "ip_proto": 17,
            },
            "action": "RATE_LIMIT",
            "priority": 500,
            "hard_timeout": args.hard_timeout,
            "rate_limit_pps": args.rate_pps,
        })
        if response.get("status") != "APPLIED":
            raise ScenarioFailure(f"RATE_LIMIT was not applied: {response}")

        meter_id = response["meter_id"]
        require_meter(network.get("s1"), meter_id, args.rate_pps)
        limited_bps = measure_udp_bandwidth(h1, web, args.duration)
        if limited_bps >= min(baseline_bps * 0.5, 5_000_000):
            raise ScenarioFailure(
                "RATE_LIMIT did not sufficiently reduce bandwidth: "
                f"baseline={baseline_bps:.0f}bps limited={limited_bps:.0f}bps"
            )

        wait_for_cleanup(args, network.get("s1"), rule_id, meter_id)
        print(
            "RATE_LIMIT validation passed: "
            f"meter_id={meter_id} rate={args.rate_pps}pps "
            f"baseline={baseline_bps / 1_000_000:.2f}Mbps "
            f"limited={limited_bps / 1_000_000:.2f}Mbps cleanup=passed"
        )
    finally:
        if started:
            network.stop()
        subprocess.run(
            ["mn", "-c"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


if __name__ == "__main__":
    run(parse_args())
