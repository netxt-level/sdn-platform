#!/usr/bin/env python3
"""Validate fixed host bindings against access-port MAC spoofing."""

import argparse
from pathlib import Path
import subprocess
import sys
import time


MININET_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MININET_DIR))

from topology import HOSTS  # noqa: E402
from topology import create_network  # noqa: E402
from topology import wait_for_controller_connections  # noqa: E402


H1_MAC = HOSTS["h1"]["mac"]
H1_IP = HOSTS["h1"]["ip"].split("/", maxsplit=1)[0]
H3_MAC = HOSTS["h3"]["mac"]
H3_IP = HOSTS["h3"]["ip"].split("/", maxsplit=1)[0]
WEB_IP = HOSTS["web"]["ip"].split("/", maxsplit=1)[0]


class ScenarioFailure(RuntimeError):
    """Raised when one host-spoofing checkpoint fails."""


def parse_args():
    parser = argparse.ArgumentParser(
        description="Validate fixed MAC/IP bindings in the Mininet lab.",
    )
    parser.add_argument("--controller-host", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6653)
    parser.add_argument("--timeout", type=float, default=20.0)
    return parser.parse_args()


def checkpoint(number, message):
    print(f"[{number}/7] PASS {message}")


def require_ping(source, destination, count=2):
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


def require_spoofed_ping_blocked(attacker, web, source_mac, source_ip):
    capture = web.popen(
        [
            "tcpdump",
            "-nn",
            "-l",
            "-c",
            "1",
            "-i",
            web.defaultIntf().name,
            f"ether src {source_mac} and icmp[icmptype] == icmp-echo "
            f"and src host {source_ip}",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(0.5)

    output = attacker.cmd("ping", "-c", "2", "-W", "1", WEB_IP)
    if "0 received" not in output or "100% packet loss" not in output:
        capture.terminate()
        capture.communicate(timeout=2)
        raise ScenarioFailure(f"spoofed ping unexpectedly succeeded:\n{output}")

    try:
        captured, error = capture.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        capture.terminate()
        capture.communicate(timeout=2)
        return

    if capture.returncode != 0:
        raise ScenarioFailure(f"tcpdump failed while checking spoof: {error}")
    if captured.strip():
        raise ScenarioFailure(
            "web observed an ICMP echo request from the spoofing host:\n"
            f"{captured}"
        )
    raise ScenarioFailure("tcpdump exited before the spoof check completed")


def run(args):
    network = create_network(
        controller_host=args.controller_host,
        controller_port=args.controller_port,
    )
    h3 = None

    try:
        network.build()
        network.start()

        if not wait_for_controller_connections(network, args.timeout):
            raise ScenarioFailure("not all switches connected to Controller")
        checkpoint(1, "four OpenFlow switches connected")

        if network.pingAll(timeout=1) != 0.0:
            raise ScenarioFailure("baseline pingall failed")
        checkpoint(2, "baseline host identities and L2 flows established")

        h1 = network.get("h1")
        h3 = network.get("h3")
        web = network.get("web")
        h3.setMAC(H1_MAC, intf=h3.defaultIntf())
        require_spoofed_ping_blocked(h3, web, H1_MAC, H3_IP)
        checkpoint(3, "h3 traffic using h1 MAC was blocked before web")

        require_ping(h1, web)
        checkpoint(4, "legitimate h1 traffic remained reachable")

        h3.setMAC(H3_MAC, intf=h3.defaultIntf())
        require_ping(h3, web)
        checkpoint(5, "h3 connectivity recovered after restoring its MAC")

        h3.setIP(H1_IP, prefixLen=24)
        require_spoofed_ping_blocked(h3, web, H3_MAC, H1_IP)
        h3.setIP(H3_IP, prefixLen=24)
        require_ping(h3, web)
        checkpoint(6, "h3 source-IP spoof was blocked and recovery succeeded")
        return 0
    except (OSError, ScenarioFailure, subprocess.TimeoutExpired) as error:
        print(f"FAIL {error}", file=sys.stderr)
        return 1
    finally:
        if h3 is not None:
            h3.setMAC(H3_MAC, intf=h3.defaultIntf())
            h3.setIP(H3_IP, prefixLen=24)
        network.stop()
        checkpoint(7, "Mininet network stopped and interfaces removed")


def main():
    return run(parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
