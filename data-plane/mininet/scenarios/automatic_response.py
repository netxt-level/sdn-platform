#!/usr/bin/env python3
"""Validate analyzer-event to Backend to Controller automatic mitigation."""

import argparse
from datetime import datetime
from datetime import timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlencode
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
        description="Validate automatic RATE_LIMIT from a security event.",
    )
    parser.add_argument("--controller-host", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6653)
    parser.add_argument("--backend-url", default="http://127.0.0.1:8000")
    parser.add_argument("--rate-pps", type=int, default=100)
    parser.add_argument("--timeout", type=float, default=20.0)
    return parser.parse_args()


def request_json(args, method, path, payload=None, query=None):
    url = f"{args.backend_url.rstrip('/')}{path}"
    if query:
        url = f"{url}?{urlencode(query)}"
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    with urlopen(request, timeout=args.timeout) as response:
        return json.load(response)


def build_event(args):
    timestamp = datetime.now(timezone.utc)
    fingerprint = hashlib.sha256(
        f"automatic-response:{timestamp.isoformat()}".encode("utf-8")
    ).hexdigest()
    event = {
        "event_id": f"auto-{fingerprint[:16]}",
        "event_fingerprint": fingerprint,
        "dedup_key": fingerprint,
        "timestamp": timestamp.isoformat(),
        "analyzer_id": "automatic-response-smoke",
        "attack_category": "DOS",
        "attack_type": "ICMP_FLOOD",
        "severity": "high",
        "confidence": "high",
        "status": "detected",
        "src_ip": "10.0.0.3",
        "dst_ip": "10.0.0.100",
        "protocol": "ICMP",
        "detection_rule": "automatic_response_smoke",
        "recommended_action": "rate_limit",
        "response_level": "L2",
        "evidence": {
            "packet_rate": 2000,
            "threshold": 1000,
        },
        "mitigation": {
            "action": "RATE_LIMIT",
            "target": "flow",
            "match": {
                "eth_type": 2048,
                "ipv4_src": "10.0.0.3",
                "ipv4_dst": "10.0.0.100",
                "ip_proto": 1,
            },
            "priority": 500,
            "idle_timeout": 30,
            "hard_timeout": 60,
            "rate_limit_pps": args.rate_pps,
        },
    }
    return {
        "timestamp": timestamp.isoformat(),
        "analyzer_id": event["analyzer_id"],
        "events": [event],
    }, fingerprint


def require_ping(source, destination):
    output = source.cmd("ping", "-c", "2", "-W", "1", destination.IP())
    if "2 received" not in output or "0% packet loss" not in output:
        raise ScenarioFailure(f"host-learning ping failed:\n{output}")


def find_by_fingerprint(items, fingerprint):
    return next(
        (
            item
            for item in items
            if item.get("source_event_fingerprint") == fingerprint
        ),
        None,
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

        require_ping(network.get("h3"), network.get("web"))
        payload, fingerprint = build_event(args)
        result = request_json(args, "POST", "/api/security/events", payload)
        if result != {"ok": True}:
            raise ScenarioFailure(f"unexpected Backend response: {result}")

        flows = request_json(
            args,
            "GET",
            "/api/flows",
            query={"src_ip": "10.0.0.3"},
        )["items"]
        flow = find_by_fingerprint(flows, fingerprint)
        if (
            flow is None
            or flow.get("status") != "APPLIED"
            or flow.get("switch_id") != "s1"
            or not (flow.get("controller_response") or {}).get("meter_id")
        ):
            raise ScenarioFailure(f"automatic Flow Rule was not applied: {flow}")

        responses = request_json(
            args,
            "GET",
            "/api/security/responses",
            query={"limit": 100},
        )["items"]
        response = find_by_fingerprint(responses, fingerprint)
        if (
            response is None
            or response.get("status") != "APPLIED"
            or response.get("approved_by") != "automatic-policy"
            or (response.get("response_payload") or {}).get("flow_rule_id")
            != flow["id"]
        ):
            raise ScenarioFailure(
                f"Security Response was not synchronized: {response}"
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
            raise ScenarioFailure(f"automatic meter is missing:\n{meter_dump}")

        print(
            "Automatic response validation passed: "
            f"event={payload['events'][0]['event_id']} "
            f"flow={flow['id']} response={response['id']} "
            f"switch={flow['switch_id']} meter_id={meter_id}"
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
