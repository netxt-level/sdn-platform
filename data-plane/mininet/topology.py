#!/usr/bin/env python3
"""Four-switch, four-host Mininet topology for the SDN data-plane lab."""

import argparse
import time

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.node import RemoteController
from mininet.topo import Topo

from link_config import canonical_link_name
from link_config import parse_link_configs
from sensor import DEFAULT_MIRROR_INTERFACE
from sensor import DEFAULT_MIRROR_NAME
from sensor import DEFAULT_MIRROR_PORT
from sensor import DEFAULT_SENSOR_INTERFACE
from sensor import DEFAULT_SOURCE_PORTS
from sensor import DEFAULT_SWITCH
from sensor import SensorConfig
from sensor import attach_mirror
from sensor import detach_mirror
from web_service import WebServiceConfig
from web_service import WebServiceProxy


SWITCH_DPIDS = {
    "s1": "0000000000000001",
    "s2": "0000000000000002",
    "s3": "0000000000000003",
    "s4": "0000000000000004",
}

HOSTS = {
    "h1": {
        "role": "user",
        "ip": "10.0.0.1/24",
        "mac": "00:00:00:00:00:01",
    },
    "h2": {
        "role": "administrator",
        "ip": "10.0.0.2/24",
        "mac": "00:00:00:00:00:02",
    },
    "h3": {
        "role": "attacker",
        "ip": "10.0.0.3/24",
        "mac": "00:00:00:00:00:03",
    },
    "web": {
        "role": "web-server",
        "ip": "10.0.0.100/24",
        "mac": "00:00:00:00:01:00",
    },
}

SWITCH_PORTS = {
    "s1": {1: "h1", 2: "h2", 3: "h3", 4: "s2", 5: "s3"},
    "s2": {1: "s1", 2: "s4"},
    "s3": {1: "s1", 2: "s4"},
    "s4": {1: "s2", 2: "s3", 3: "web"},
}


class FourSwitchTopology(Topo):
    """Diamond topology with fixed host identities and explicit ports."""

    def build(self, link_configs=None):
        link_configs = link_configs or {}

        def transit_parameters(first, second):
            link_name = canonical_link_name(first, second)
            return dict(link_configs.get(link_name, {}))

        switches = {
            name: self.addSwitch(
                name,
                dpid=dpid,
                protocols="OpenFlow13",
                failMode="secure",
            )
            for name, dpid in SWITCH_DPIDS.items()
        }

        hosts = {
            name: self.addHost(name, ip=config["ip"], mac=config["mac"])
            for name, config in HOSTS.items()
        }

        self.addLink(hosts["h1"], switches["s1"], port1=0, port2=1)
        self.addLink(hosts["h2"], switches["s1"], port1=0, port2=2)
        self.addLink(hosts["h3"], switches["s1"], port1=0, port2=3)
        self.addLink(
            switches["s1"],
            switches["s2"],
            port1=4,
            port2=1,
            **transit_parameters("s1", "s2"),
        )
        self.addLink(
            switches["s1"],
            switches["s3"],
            port1=5,
            port2=1,
            **transit_parameters("s1", "s3"),
        )
        self.addLink(
            switches["s2"],
            switches["s4"],
            port1=2,
            port2=1,
            **transit_parameters("s2", "s4"),
        )
        self.addLink(
            switches["s3"],
            switches["s4"],
            port1=2,
            port2=2,
            **transit_parameters("s3", "s4"),
        )
        self.addLink(switches["s4"], hosts["web"], port1=3, port2=0)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Start the four-switch OpenFlow 1.3 topology.",
    )
    parser.add_argument("--controller-host", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6653)
    parser.add_argument(
        "--link-config",
        action="append",
        default=[],
        metavar="LINK:key=value[,key=value]",
        help=(
            "Configure one transit link with bw (Mbps), delay (us/ms/s), "
            "and loss (percent); may be repeated."
        ),
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help=(
            "Verify switch connections, topology layout, and pingall, then "
            "exit without opening the CLI."
        ),
    )
    parser.add_argument("--verify-timeout", type=float, default=10.0)
    parser.add_argument(
        "--sensor-mirror",
        action="store_true",
        help="Attach the persistent sensor veth as an ingress-only OVS Mirror.",
    )
    parser.add_argument("--sensor-interface", default=DEFAULT_SENSOR_INTERFACE)
    parser.add_argument("--mirror-interface", default=DEFAULT_MIRROR_INTERFACE)
    parser.add_argument("--mirror-switch", default=DEFAULT_SWITCH)
    parser.add_argument("--mirror-name", default=DEFAULT_MIRROR_NAME)
    parser.add_argument("--mirror-port", type=int, default=DEFAULT_MIRROR_PORT)
    parser.add_argument(
        "--mirror-source-port",
        type=int,
        action="append",
        dest="mirror_source_ports",
        help="Ingress source port to mirror; repeat for multiple ports.",
    )
    parser.add_argument(
        "--mutillidae-proxy",
        action="store_true",
        help=(
            "Expose the loopback-only Mutillidae service as web:80 through "
            "an isolated management veth."
        ),
    )
    parser.add_argument(
        "--mutillidae-host-port",
        type=int,
        default=8088,
        help="VM loopback port published by the Mutillidae container.",
    )
    args = parser.parse_args()
    try:
        args.link_configs = parse_link_configs(args.link_config)
        args.sensor_config = SensorConfig(
            sensor_interface=args.sensor_interface,
            mirror_interface=args.mirror_interface,
            switch=args.mirror_switch,
            mirror_name=args.mirror_name,
            mirror_port=args.mirror_port,
            source_ports=tuple(args.mirror_source_ports or DEFAULT_SOURCE_PORTS),
        )
    except ValueError as error:
        parser.error(str(error))
    return args


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


def get_switch_port_map(switch):
    ports = {}

    for interface, port in switch.ports.items():
        if interface.link is None:
            continue
        peer = (
            interface.link.intf2
            if interface.link.intf1 is interface
            else interface.link.intf1
        )
        ports[port] = peer.node.name

    return ports


def print_topology_status(net):
    valid = True

    for host in sorted(net.hosts, key=lambda item: item.name):
        config = HOSTS[host.name]
        expected_ip = config["ip"].split("/", maxsplit=1)[0]
        host_valid = (
            host.IP() == expected_ip
            and host.MAC().lower() == config["mac"]
        )
        valid = valid and host_valid
        state = "valid" if host_valid else "invalid"
        print(
            f"{host.name} role={config['role']} ip={host.IP()} "
            f"mac={host.MAC()} {state}"
        )

    for switch in sorted(net.switches, key=lambda item: item.name):
        actual_ports = get_switch_port_map(switch)
        switch_valid = actual_ports == SWITCH_PORTS[switch.name]
        valid = valid and switch_valid
        state = "valid" if switch_valid else "invalid"
        port_list = ",".join(
            f"{port}={peer}" for port, peer in sorted(actual_ports.items())
        )
        print(f"{switch.name} ports={port_list} {state}")

    return valid


def create_network(
    controller_host="127.0.0.1",
    controller_port=6653,
    link_configs=None,
):
    """Create the configured Mininet network without starting it."""
    topology = FourSwitchTopology(link_configs=link_configs or {})
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
        ip=controller_host,
        port=controller_port,
    )
    return network


def run(args):
    network = create_network(
        controller_host=args.controller_host,
        controller_port=args.controller_port,
        link_configs=args.link_configs,
    )

    mirror_attached = False
    web_service = None
    try:
        network.build()
        network.start()

        if args.mutillidae_proxy:
            web_service = WebServiceProxy(
                network.get("web"),
                WebServiceConfig(target_port=args.mutillidae_host_port),
            )
            web_service.start()
            print(
                "Mutillidae proxy ready: "
                f"web 10.0.0.100:80 -> VM loopback:{args.mutillidae_host_port}"
            )

        if args.sensor_mirror:
            attach_mirror(args.sensor_config)
            mirror_attached = True
            print(
                f"OVS Mirror {args.sensor_config.mirror_name} ready: "
                f"{args.sensor_config.switch} ports "
                f"{args.sensor_config.source_ports} -> "
                f"{args.sensor_config.sensor_interface}"
            )

        if args.verify:
            connected = wait_for_controller_connections(
                network,
                args.verify_timeout,
            )
            print_connection_status(network)
            topology_valid = print_topology_status(network)
            if not connected or not topology_valid:
                return 1
            packet_loss = network.pingAll(timeout=1)
            return 0 if packet_loss == 0.0 else 1

        CLI(network)
        return 0
    finally:
        if web_service is not None:
            web_service.stop()
        if mirror_attached:
            detach_mirror(args.sensor_config)
        network.stop()


def main():
    setLogLevel("info")
    return run(parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
