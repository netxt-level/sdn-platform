#!/usr/bin/env python3
"""Validate backend-style Flow Rule installation in the isolated Mininet lab."""

import argparse
import json
from pathlib import Path
import subprocess
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
        description="Validate external DROP Flow Rule installation.",
    )
    parser.add_argument("--controller-host", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6653)
    parser.add_argument("--controller-rest-port", type=int, default=8080)
    parser.add_argument("--timeout", type=float, default=20.0)
    return parser.parse_args()


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


def install_drop_rule(args):
    return controller_request(args, "POST", "/flow-rules", {
        "rule_id": "mininet-external-drop-smoke",
        "switch_id": "s1",
        "match": {
            "ipv4_src": "10.0.0.1",
            "ipv4_dst": "10.0.0.100",
            "ip_proto": 1,
        },
        "action": "DROP",
        "priority": 500,
        "hard_timeout": 30,
    })


def dump_flows(switch):
    return switch.cmd("ovs-ofctl -O OpenFlow13 dump-flows", switch.name)


def require_ping_success(source, destination):
    output = source.cmd("ping", "-c", "2", "-W", "1", destination.IP())
    if "2 received" not in output or "0% packet loss" not in output:
        raise ScenarioFailure(f"baseline ping failed:\n{output}")


def require_ping_blocked(source, destination):
    output = source.cmd("ping", "-c", "2", "-W", "1", destination.IP())
    if "0 received" not in output and "100% packet loss" not in output:
        raise ScenarioFailure(f"DROP rule did not block ICMP traffic:\n{output}")


def require_drop_flow(switch, cookie):
    expected_cookie = cookie.lower()
    flow_dump = dump_flows(switch).lower()
    required = (
        expected_cookie,
        "priority=500",
        "nw_src=10.0.0.1",
        "nw_dst=10.0.0.100",
        "actions=drop",
    )
    if not all(value in flow_dump for value in required):
        raise ScenarioFailure(
            "installed DROP flow was not found on s1:\n" + flow_dump
        )


def require_flow_removed(switch, cookie):
    flow_dump = dump_flows(switch).lower()
    if cookie.lower() in flow_dump:
        raise ScenarioFailure(
            "deleted DROP flow still exists on s1:\n" + flow_dump
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
        require_ping_success(h1, web)
        deadline = time.monotonic() + args.timeout
        stats = {"switches": []}
        while time.monotonic() < deadline:
            stats = controller_request(args, "GET", "/stats")
            if len(stats.get("switches", [])) == 4:
                break
            time.sleep(0.2)
        if len(stats.get("switches", [])) != 4:
            raise ScenarioFailure(f"Controller stats are incomplete: {stats}")

        response = install_drop_rule(args)
        if response.get("status") != "APPLIED":
            raise ScenarioFailure(
                f"Controller did not confirm the Flow Rule: {response}"
            )
        require_drop_flow(network.get("s1"), response["cookie"])
        require_ping_blocked(h1, web)

        topology = controller_request(args, "GET", "/topology")
        if (
            len(topology.get("switches", [])) != 4
            or not any(
                link["source"] == "s1"
                and link["destination"] == "s2"
                and link["state"] == "active"
                for link in topology.get("links", [])
            )
        ):
            raise ScenarioFailure(
                f"Controller topology response is invalid: {topology}"
            )
        recalculated = controller_request(
            args,
            "POST",
            "/paths/recalculate",
        )
        if (
            recalculated.get("status") != "RECALCULATED"
            or recalculated.get("invalidated_switches") != 4
        ):
            raise ScenarioFailure(
                f"path recalculation failed: {recalculated}"
            )

        removed = controller_request(
            args,
            "DELETE",
            (
                f"/flow-rules/{response['controller_rule_id']}"
                "?switch_id=s1"
            ),
        )
        if removed.get("status") != "REMOVED":
            raise ScenarioFailure(
                f"Controller did not confirm Flow Rule removal: {removed}"
            )
        require_flow_removed(network.get("s1"), response["cookie"])
        require_ping_success(h1, web)
        print(
            "External Flow Rule validation passed: "
            f"rule_id={response['controller_rule_id']} "
            f"cookie={response['cookie']} "
            f"install={response['status']} delete={removed['status']} "
            "topology=passed recalculate=passed"
            " stats=passed"
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
