#!/usr/bin/env python3
"""Validate primary and backup ICMP traffic on the OVS sensor Mirror."""

import argparse
from pathlib import Path
from subprocess import PIPE
from subprocess import Popen
from subprocess import TimeoutExpired
import sys
import time


MININET_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MININET_DIR))

from sensor import SensorConfig  # noqa: E402
from sensor import SensorError  # noqa: E402
from sensor import attach_mirror  # noqa: E402
from sensor import detach_mirror  # noqa: E402
from sensor import ensure_sensor_veth  # noqa: E402
from sensor import inspect_interface  # noqa: E402
from sensor import validate_mirror  # noqa: E402
from topology import create_network  # noqa: E402
from topology import print_connection_status  # noqa: E402
from topology import wait_for_controller_connections  # noqa: E402


H1_IP = "10.0.0.1"
WEB_IP = "10.0.0.100"


class MirrorCaptureFailure(RuntimeError):
    """Raised when mirrored traffic does not meet a validation checkpoint."""


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller-host", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6653)
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--sensor-interface", default="sdn-sensor0")
    parser.add_argument("--mirror-interface", default="sdn-mirror0")
    return parser.parse_args()


def checkpoint(number, message):
    print(f"[{number}/7] PASS {message}")


def require_interface_state(config):
    sensor = inspect_interface(config.sensor_interface)
    mirror = inspect_interface(config.mirror_interface)
    for state in (sensor, mirror):
        if state is None or state.kind != "veth" or not state.up:
            name = "missing" if state is None else state.name
            raise MirrorCaptureFailure(f"sensor veth is not ready: {name}")
        if state.promiscuity < 1:
            raise MirrorCaptureFailure(
                f"promiscuous mode is disabled: {state.name}"
            )


def ping_succeeded(output):
    return "1 received" in output and "0% packet loss" in output


def capture_bidirectional_ping(network, config, timeout):
    capture = Popen(
        [
            "tcpdump",
            "-nn",
            "-l",
            "-i",
            config.sensor_interface,
            "icmp",
            "and",
            "host",
            H1_IP,
            "and",
            "host",
            WEB_IP,
        ],
        stdout=PIPE,
        stderr=PIPE,
        text=True,
    )
    output = ""
    error_output = ""
    try:
        time.sleep(0.4)
        deadline = time.monotonic() + timeout
        last_ping = "ping was not attempted"
        while time.monotonic() < deadline:
            last_ping = network.get("h1").cmd(
                "ping", "-c", "1", "-W", "1", WEB_IP
            )
            if ping_succeeded(last_ping):
                time.sleep(0.2)
                break
            time.sleep(0.2)
        else:
            raise MirrorCaptureFailure(f"h1-to-web ping failed:\n{last_ping}")
    finally:
        capture.terminate()
        try:
            output, error_output = capture.communicate(timeout=2)
        except TimeoutExpired:
            capture.kill()
            output, error_output = capture.communicate(timeout=2)

    expected = (
        f"{H1_IP} > {WEB_IP}: ICMP echo request",
        f"{WEB_IP} > {H1_IP}: ICMP echo reply",
    )
    missing = [description for description in expected if description not in output]
    if missing:
        diagnostics = error_output.strip() or "tcpdump returned no diagnostics"
        raise MirrorCaptureFailure(
            f"sensor capture is missing {missing}:\n{output}\n{diagnostics}"
        )


def run(args):
    config = SensorConfig(
        sensor_interface=args.sensor_interface,
        mirror_interface=args.mirror_interface,
    )
    network = create_network(
        controller_host=args.controller_host,
        controller_port=args.controller_port,
    )
    started = False
    mirror_attached = False

    try:
        ensure_sensor_veth(config)
        require_interface_state(config)
        checkpoint(1, "persistent sensor veth exists, is UP, and is promiscuous")

        network.build()
        network.start()
        started = True
        if not wait_for_controller_connections(network, args.timeout):
            print_connection_status(network)
            raise MirrorCaptureFailure("not all switches connected to Controller")
        checkpoint(2, "four OpenFlow 1.3 switches connected")

        attach_mirror(config)
        mirror_attached = True
        validate_mirror(config)
        checkpoint(3, "s1 ingress ports 1 through 5 mirror to fixed port 6")

        capture_bidirectional_ping(network, config, args.timeout)
        checkpoint(4, "primary-path ICMP request and reply reached the sensor")

        network.configLinkStatus("s1", "s2", "down")
        network.get("h1").cmd("arp", "-d", WEB_IP)
        network.get("web").cmd("arp", "-d", H1_IP)
        capture_bidirectional_ping(network, config, args.timeout)
        checkpoint(5, "backup-path ICMP request and reply reached the sensor")
        return 0
    except (MirrorCaptureFailure, SensorError) as error:
        print(f"FAIL {error}", file=sys.stderr)
        return 1
    finally:
        if mirror_attached:
            detach_mirror(config)
            checkpoint(6, "transient OVS Mirror and output port removed")
        if started:
            network.stop()
        sensor = inspect_interface(config.sensor_interface)
        mirror = inspect_interface(config.mirror_interface)
        if sensor is not None and mirror is not None:
            checkpoint(7, "persistent sensor veth retained for Analyzer capture")


def main():
    return run(parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
