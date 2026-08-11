#!/usr/bin/env python3
"""Validate protected-server lateral-movement detection and response."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.parse import urlencode
from urllib.request import Request
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
    """Raised when an end-to-end validation checkpoint fails."""


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller-host", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6653)
    parser.add_argument("--backend-url", default="http://127.0.0.1:8000")
    parser.add_argument("--analyzer-id", default="analyzer-1")
    parser.add_argument(
        "--mode",
        choices=("detect", "respond"),
        required=True,
        help="Disable or enable automatic response before sending traffic.",
    )
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument(
        "--admin-api-key",
        default=os.environ.get("ADMIN_API_KEY", ""),
    )
    return parser.parse_args()


def request_json(args, method, path, payload=None, query=None):
    url = f"{args.backend_url.rstrip('/')}{path}"
    if query:
        url = f"{url}?{urlencode(query)}"
    data = None
    headers = {"Accept": "application/json"}
    if args.admin_api_key:
        headers["X-API-Key"] = args.admin_api_key
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(url, data=data, headers=headers, method=method)
    with urlopen(request, timeout=5) as response:
        return json.load(response)


def set_response_mode(args):
    current = request_json(args, "GET", "/api/settings")
    enabled = args.mode == "respond"
    updated = request_json(
        args,
        "PUT",
        "/api/settings",
        {
            "congestion_threshold_percent": current[
                "congestion_threshold_percent"
            ],
            "automatic_response_enabled": enabled,
        },
    )
    if bool(updated["automatic_response_enabled"]) is not enabled:
        raise ScenarioFailure(f"response mode update failed: {updated}")


def wait_for_analyzer(args):
    deadline = time.monotonic() + args.timeout
    last_status = None
    while time.monotonic() < deadline:
        items = request_json(
            args,
            "GET",
            "/api/analyzer/status",
            query={"analyzer_id": args.analyzer_id},
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


def list_events(args):
    return request_json(
        args,
        "GET",
        "/api/security/events",
        query={"limit": 500},
    )["items"]


def list_flows(args):
    return request_json(
        args,
        "GET",
        "/api/flows",
        query={"src_ip": "10.0.0.100"},
    )["items"]


def wait_for_lateral_event(args, existing_event_ids):
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        event = next(
            (
                item
                for item in list_events(args)
                if item.get("event_id") not in existing_event_ids
                and item.get("attack_type") == "LATERAL_MOVEMENT"
                and item.get("src_ip") == "10.0.0.100"
            ),
            None,
        )
        if event is not None:
            return event
        time.sleep(0.5)
    raise ScenarioFailure("new LATERAL_MOVEMENT event did not arrive")


def wait_for_flow(args, event_id):
    deadline = time.monotonic() + args.timeout
    last_flow = None
    while time.monotonic() < deadline:
        last_flow = next(
            (
                item
                for item in list_flows(args)
                if item.get("source_event_id") == event_id
                and item.get("action") == "DROP"
            ),
            None,
        )
        if last_flow is not None:
            if args.mode == "detect" or last_flow.get("status") in {
                "APPLIED",
                "FAILED",
            }:
                return last_flow
        time.sleep(0.5)
    raise ScenarioFailure(f"linked DROP Flow did not settle: {last_flow}")


def confirm_no_flow(args, event_id):
    deadline = time.monotonic() + min(args.timeout, 5.0)
    while time.monotonic() < deadline:
        flow = next(
            (
                item
                for item in list_flows(args)
                if item.get("source_event_id") == event_id
            ),
            None,
        )
        if flow is not None:
            raise ScenarioFailure(
                f"detection-only mode created a Flow candidate: {flow}"
            )
        time.sleep(0.5)


def generate_lateral_traffic(network):
    web = network.get("web")
    for target in ("10.0.0.1", "10.0.0.2"):
        output = web.cmd("ping", "-c", "1", "-W", "1", target)
        if "1 received" not in output:
            raise ScenarioFailure(f"host-learning ping failed for {target}:\n{output}")

    commands = (
        "timeout 1 bash -c 'echo >/dev/tcp/10.0.0.1/8001' "
        ">/dev/null 2>&1 || true",
        "timeout 1 bash -c 'echo >/dev/tcp/10.0.0.2/8002' "
        ">/dev/null 2>&1 || true",
        "timeout 1 bash -c 'echo >/dev/tcp/10.0.0.2/8003' "
        ">/dev/null 2>&1 || true",
    )
    for command in commands:
        web.cmd(command)


def validate_result(args, event, flow=None):
    evidence = event.get("evidence") or {}
    destinations = set(evidence.get("destination_ips") or [])
    if (
        evidence.get("connection_count", 0) < 3
        or not {"10.0.0.1", "10.0.0.2"}.issubset(destinations)
    ):
        raise ScenarioFailure(f"event evidence is incomplete: {event}")

    if args.mode == "detect":
        if flow is not None:
            raise ScenarioFailure(f"detection-only mode created a Flow: {flow}")
    elif flow is None or flow.get("status") != "APPLIED" or not flow.get(
        "controller_rule_id"
    ):
        raise ScenarioFailure(f"automatic DROP was not applied: {flow}")


def run(args):
    sensor = SensorConfig()
    network = create_network(
        controller_host=args.controller_host,
        controller_port=args.controller_port,
    )
    started = False
    mirror_attached = False
    try:
        set_response_mode(args)
        ensure_sensor_veth(sensor)
        wait_for_analyzer(args)
        existing_event_ids = {
            item["event_id"]
            for item in list_events(args)
        }

        network.build()
        network.start()
        started = True
        if not wait_for_controller_connections(network, args.timeout):
            raise ScenarioFailure("switches did not connect to Controller")
        attach_mirror(sensor)
        mirror_attached = True

        generate_lateral_traffic(network)
        event = wait_for_lateral_event(args, existing_event_ids)
        if args.mode == "detect":
            confirm_no_flow(args, event["event_id"])
            flow = None
        else:
            flow = wait_for_flow(args, event["event_id"])
        validate_result(args, event, flow)
        print(json.dumps({
            "result": "passed",
            "mode": args.mode,
            "event_id": event["event_id"],
            "event_status": event.get("status"),
            "attack_type": event["attack_type"],
            "destinations": event["evidence"]["destination_ips"],
            "flow_id": flow["id"] if flow else None,
            "flow_status": flow["status"] if flow else None,
            "controller_rule_id": (
                flow.get("controller_rule_id") if flow else None
            ),
            "switch_id": flow.get("switch_id") if flow else None,
        }, sort_keys=True))
        return 0
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
    raise SystemExit(run(parse_args()))
