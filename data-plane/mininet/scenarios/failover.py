#!/usr/bin/env python3
"""Automated Primary, Backup, and recovery validation for the SDN lab."""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import urlopen


MININET_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MININET_DIR))

from topology import create_network  # noqa: E402
from topology import print_connection_status  # noqa: E402
from topology import print_topology_status  # noqa: E402
from topology import wait_for_controller_connections  # noqa: E402


H1_MAC = "00:00:00:00:00:01"
WEB_MAC = "00:00:00:00:01:00"
WEB_IP = "10.0.0.100"
H1_IP = "10.0.0.1"
L2_COOKIE_PREFIX = "cookie=0x53444e10"
L2_COOKIE_MATCH = "cookie=0x53444e1000000000/0xffffffff00000000"

PRIMARY_OUTPUTS = {
    "s1": 4,
    "s2": 2,
    "s4": 3,
}
BACKUP_OUTPUTS = {
    "s1": 5,
    "s3": 2,
    "s4": 3,
}


class ScenarioFailure(RuntimeError):
    """Raised when one failover checkpoint does not meet its criteria."""


def parse_args():
    parser = argparse.ArgumentParser(
        description="Validate Primary, Backup, and recovered SDN paths.",
    )
    parser.add_argument("--controller-host", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6653)
    parser.add_argument("--controller-rest-port", type=int, default=8080)
    parser.add_argument("--controller-container", default="sdn-controller")
    parser.add_argument("--timeout", type=float, default=20.0)
    return parser.parse_args()


def checkpoint(number, message):
    print(f"[{number}/9] PASS {message}")


def wait_for_controller_health(host, port, expected_switches, timeout):
    deadline = time.monotonic() + timeout
    url = f"http://{host}:{port}/health"
    last_error = "health endpoint did not respond"

    while time.monotonic() < deadline:
        try:
            with urlopen(url, timeout=1) as response:
                payload = json.load(response)
            if (
                payload.get("status") == "ready"
                and payload.get("connected_switches") == expected_switches
            ):
                return payload
            last_error = f"unexpected health response: {payload}"
        except (OSError, URLError, ValueError) as error:
            last_error = str(error)
        time.sleep(0.2)

    raise ScenarioFailure(last_error)


def dump_flows(switch):
    return switch.cmd("ovs-ofctl -O OpenFlow13 dump-flows", switch.name)


def is_forward_flow(line, switch_name, output_port):
    flow_matches = all(
        value in line
        for value in (
            "priority=100,ip",
            f"dl_src={H1_MAC}",
            f"dl_dst={WEB_MAC}",
        )
    )
    output_actions = (
        f"actions=output:{output_port}",
        f'actions=output:"{switch_name}-eth{output_port}"',
    )
    return flow_matches and any(action in line for action in output_actions)


def has_host_forward_flow(switch, output_port=None):
    for line in dump_flows(switch).splitlines():
        if output_port is None:
            if all(
                value in line
                for value in (
                    "priority=100,ip",
                    f"dl_src={H1_MAC}",
                    f"dl_dst={WEB_MAC}",
                )
            ):
                return True
        elif is_forward_flow(line, switch.name, output_port):
            return True
    return False


def has_managed_l2_flow(switch):
    return any(
        L2_COOKIE_PREFIX in line
        for line in dump_flows(switch).splitlines()
    )


def wait_for_l2_flow_removal(network, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not any(has_managed_l2_flow(item) for item in network.switches):
            return
        time.sleep(0.1)
    raise ScenarioFailure("Controller-managed L2 flows were not invalidated")


def delete_managed_l2_flows(network, timeout):
    for switch in network.switches:
        switch.cmd(
            f"ovs-ofctl -O OpenFlow13 del-flows {switch.name} "
            f"'{L2_COOKIE_MATCH}'"
        )
    wait_for_l2_flow_removal(network, timeout)


def clear_arp(source, destination):
    source.cmd("arp", "-d", destination.IP())
    destination.cmd("arp", "-d", source.IP())


def clear_all_arp(network):
    for source in network.hosts:
        for destination in network.hosts:
            if source is not destination:
                source.cmd("arp", "-d", destination.IP())


def restart_controller(container, timeout):
    try:
        subprocess.run(
            ["docker", "restart", "--time", "5", container],
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise ScenarioFailure(
            f"Controller restart exceeded {timeout} seconds"
        ) from error
    except subprocess.CalledProcessError as error:
        reason = error.stderr.strip() or error.stdout.strip() or str(error)
        raise ScenarioFailure(f"Controller restart failed: {reason}") from error
    except OSError as error:
        raise ScenarioFailure(f"Controller restart failed: {error}") from error


def require_ping(source, destination, count=3):
    output = source.cmd(
        "ping",
        "-c",
        str(count),
        "-W",
        "1",
        destination.IP(),
    )
    if f"{count} received" not in output or "0% packet loss" not in output:
        raise ScenarioFailure(
            f"ping failed from {source.name} to {destination.name}:\n{output}"
        )


def require_path(network, expected_outputs, excluded_switch):
    for switch_name, output_port in expected_outputs.items():
        switch = network.get(switch_name)
        if not has_host_forward_flow(switch, output_port):
            raise ScenarioFailure(
                f"{switch_name} does not have h1-to-web output:{output_port}"
            )

    if has_host_forward_flow(network.get(excluded_switch)):
        raise ScenarioFailure(
            f"excluded switch {excluded_switch} contains an h1-to-web flow"
        )


def print_flow_diagnostics(network):
    for switch in sorted(network.switches, key=lambda item: item.name):
        print(f"--- {switch.name} flows ---", file=sys.stderr)
        print(dump_flows(switch), file=sys.stderr)


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
            print_connection_status(network)
            raise ScenarioFailure("not all switches connected to Controller")
        checkpoint(1, "four OpenFlow 1.3 switches connected")

        if not print_topology_status(network):
            raise ScenarioFailure("host or switch port topology is invalid")
        checkpoint(2, "fixed host identities and switch ports validated")

        wait_for_controller_health(
            args.controller_host,
            args.controller_rest_port,
            expected_switches=4,
            timeout=args.timeout,
        )
        checkpoint(3, "Controller health reports four connected switches")

        if network.pingAll(timeout=1) != 0.0:
            raise ScenarioFailure("initial pingall failed")
        require_path(network, PRIMARY_OUTPUTS, excluded_switch="s3")
        checkpoint(4, "Primary path s1-s2-s4 installed")

        network.configLinkStatus("s1", "s2", "down")
        wait_for_l2_flow_removal(network, args.timeout)
        clear_arp(network.get("h1"), network.get("web"))
        require_ping(network.get("h1"), network.get("web"))
        require_path(network, BACKUP_OUTPUTS, excluded_switch="s2")
        checkpoint(5, "Primary failure rerouted traffic over s1-s3-s4")

        network.configLinkStatus("s1", "s2", "up")
        wait_for_l2_flow_removal(network, args.timeout)
        clear_arp(network.get("h1"), network.get("web"))
        require_ping(network.get("h1"), network.get("web"))
        require_path(network, PRIMARY_OUTPUTS, excluded_switch="s3")
        checkpoint(6, "Primary recovery restored path s1-s2-s4")

        restart_controller(args.controller_container, args.timeout)
        if not wait_for_controller_connections(network, args.timeout):
            print_connection_status(network)
            raise ScenarioFailure(
                "switches did not reconnect after Controller restart"
            )
        wait_for_controller_health(
            args.controller_host,
            args.controller_rest_port,
            expected_switches=4,
            timeout=args.timeout,
        )
        checkpoint(7, "Controller restarted and four switches reconnected")

        delete_managed_l2_flows(network, args.timeout)
        clear_all_arp(network)
        if network.pingAll(timeout=1) != 0.0:
            raise ScenarioFailure("post-restart pingall failed")
        require_path(network, PRIMARY_OUTPUTS, excluded_switch="s3")
        checkpoint(8, "host learning and Primary flows recovered after restart")
        return 0
    except ScenarioFailure as error:
        print(f"FAIL {error}", file=sys.stderr)
        if started:
            print_flow_diagnostics(network)
        return 1
    finally:
        network.stop()
        checkpoint(9, "Mininet network stopped and interfaces removed")


def main():
    return run(parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
