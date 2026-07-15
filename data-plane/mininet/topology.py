#!/usr/bin/env python3
"""Four-switch Mininet topology for the SDN data-plane lab."""

import argparse
import time

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.node import RemoteController
from mininet.topo import Topo


SWITCH_DPIDS = {
    "s1": "0000000000000001",
    "s2": "0000000000000002",
    "s3": "0000000000000003",
    "s4": "0000000000000004",
}


class FourSwitchTopology(Topo):
    """Diamond topology with fixed DPIDs and explicit switch ports."""

    def build(self):
        switches = {
            name: self.addSwitch(
                name,
                dpid=dpid,
                protocols="OpenFlow13",
                failMode="secure",
            )
            for name, dpid in SWITCH_DPIDS.items()
        }

        self.addLink(switches["s1"], switches["s2"], port1=1, port2=1)
        self.addLink(switches["s1"], switches["s3"], port1=2, port2=1)
        self.addLink(switches["s2"], switches["s4"], port1=2, port2=1)
        self.addLink(switches["s3"], switches["s4"], port1=2, port2=2)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Start the four-switch OpenFlow 1.3 topology.",
    )
    parser.add_argument("--controller-host", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6653)
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify all switches connect, then exit without opening the CLI.",
    )
    parser.add_argument("--verify-timeout", type=float, default=10.0)
    return parser.parse_args()


def wait_for_controller_connections(net, timeout):
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        if all(switch.connected() for switch in net.switches):
            return True
        time.sleep(0.2)

    return False


def print_connection_status(net):
    for switch in sorted(net.switches, key=lambda item: item.name):
        state = "connected" if switch.connected() else "disconnected"
        print(f"{switch.name} {SWITCH_DPIDS[switch.name]} {state}")


def run(args):
    topology = FourSwitchTopology()
    network = Mininet(
        topo=topology,
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        build=False,
    )
    network.addController(
        "c0",
        controller=RemoteController,
        ip=args.controller_host,
        port=args.controller_port,
    )

    try:
        network.build()
        network.start()

        if args.verify:
            connected = wait_for_controller_connections(
                network,
                args.verify_timeout,
            )
            print_connection_status(network)
            return 0 if connected else 1

        CLI(network)
        return 0
    finally:
        network.stop()


def main():
    setLogLevel("info")
    return run(parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
