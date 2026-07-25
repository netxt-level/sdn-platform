#!/usr/bin/env python3
"""Validate real Analyzer ICMP detection through automatic RATE_LIMIT."""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import time
from urllib.parse import urlencode
from urllib.request import urlopen


MININET_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MININET_DIR))

from sensor import SensorConfig  # noqa: E402
from sensor import attach_mirror  # noqa: E402
from sensor import detach_mirror  # noqa: E402
from sensor import ensure_sensor_veth  # noqa: E402
from topology import create_network  # noqa: E402
from topology import wait_for_controller_connections  # noqa: E402


class ScenarioFailure(RuntimeError):
    pass


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller-host", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6653)
    parser.add_argument("--backend-url", default="http://127.0.0.1:8000")
    parser.add_argument("--analyzer-id", required=True)
    parser.add_argument("--timeout", type=float, default=30.0)
    return parser.parse_args()


def get_json(args, path, query=None):
    url = f"{args.backend_url.rstrip('/')}{path}"
    if query:
        url = f"{url}?{urlencode(query)}"
    with urlopen(url, timeout=3) as response:
        return json.load(response)


def wait_for_analyzer(args):
    deadline = time.monotonic() + args.timeout
    last_status = None
    while time.monotonic() < deadline:
        items = get_json(
            args,
            "/api/analyzer/status",
            {"analyzer_id": args.analyzer_id},
        )["items"]
        last_status = items[0] if items else None
        if (
            last_status
            and last_status.get("capture_active") is True
            and last_status.get("backend_connected") is True
        ):
            return
        time.sleep(0.5)
    raise ScenarioFailure(f"Analyzer did not become ready: {last_status}")


def list_matching_flows(args):
    return [
        flow
        for flow in get_json(
            args,
            "/api/flows",
            {"src_ip": "10.0.0.3"},
        )["items"]
        if flow.get("analyzer_id") == args.analyzer_id
        and flow.get("action") == "RATE_LIMIT"
    ]


def wait_for_applied_flow(args, existing_flow_ids):
    deadline = time.monotonic() + args.timeout
    last_flow = None
    while time.monotonic() < deadline:
        last_flow = next(
            (
                flow
                for flow in list_matching_flows(args)
                if flow["id"] not in existing_flow_ids
            ),
            None,
        )
        if last_flow and last_flow.get("status") in {"APPLIED", "FAILED"}:
            return last_flow
        time.sleep(0.5)
    raise ScenarioFailure(f"Analyzer Flow Rule did not arrive: {last_flow}")


def find_response(args, flow):
    responses = get_json(
        args,
        "/api/security/responses",
        {"limit": 100},
    )["items"]
    return next(
        (
            response
            for response in responses
            if response.get("id") == flow.get("security_response_id")
        ),
        None,
    )


def run(args):
    sensor = SensorConfig()
    network = create_network(
        controller_host=args.controller_host,
        controller_port=args.controller_port,
    )
    started = False
    mirror_attached = False
    try:
        ensure_sensor_veth(sensor)
        wait_for_analyzer(args)
        network.build()
        network.start()
        started = True
        if not wait_for_controller_connections(network, args.timeout):
            raise ScenarioFailure("switches did not connect to Controller")
        attach_mirror(sensor)
        mirror_attached = True
        existing_flow_ids = {
            flow["id"]
            for flow in list_matching_flows(args)
        }

        output = network.get("h3").cmd(
            "ping",
            "-f",
            "-c",
            "500",
            "-W",
            "1",
            "10.0.0.100",
        )
        if (
            "500 packets transmitted" not in output
            or "500 received" not in output
        ):
            raise ScenarioFailure(f"ICMP flood generation failed:\n{output}")

        flow = wait_for_applied_flow(args, existing_flow_ids)
        response = find_response(args, flow)
        if (
            flow["status"] != "APPLIED"
            or flow.get("switch_id") != "s1"
            or not (flow.get("controller_response") or {}).get("meter_id")
            or response is None
            or response.get("status") != "APPLIED"
        ):
            raise ScenarioFailure(
                f"automatic response failed: flow={flow} response={response}"
            )

        meter_id = flow["controller_response"]["meter_id"]
        meter_dump = network.get("s1").cmd(
            "ovs-ofctl",
            "-O",
            "OpenFlow13",
            "dump-meters",
            "s1",
        ).lower()
        if f"meter={meter_id}" not in meter_dump:
            raise ScenarioFailure(f"Analyzer meter is missing:\n{meter_dump}")

        print(
            "Analyzer automatic response passed: "
            f"analyzer={args.analyzer_id} flow={flow['id']} "
            f"response={response['id']} switch=s1 meter_id={meter_id}"
        )
    finally:
        if mirror_attached:
            detach_mirror(sensor)
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
