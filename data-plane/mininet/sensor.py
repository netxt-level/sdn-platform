#!/usr/bin/env python3
"""Manage the persistent Analyzer veth pair and the transient OVS Mirror."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import re
import subprocess
import time


DEFAULT_SENSOR_INTERFACE = "sdn-sensor0"
DEFAULT_MIRROR_INTERFACE = "sdn-mirror0"
DEFAULT_SWITCH = "s1"
DEFAULT_MIRROR_NAME = "sdn-analyzer-mirror"
DEFAULT_MIRROR_PORT = 6
DEFAULT_SOURCE_PORTS = (1, 2, 3, 4, 5)
UUID_PATTERN = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


class SensorError(RuntimeError):
    """Raised when the sensor path cannot be created or validated safely."""


@dataclass(frozen=True)
class SensorConfig:
    sensor_interface: str = DEFAULT_SENSOR_INTERFACE
    mirror_interface: str = DEFAULT_MIRROR_INTERFACE
    switch: str = DEFAULT_SWITCH
    mirror_name: str = DEFAULT_MIRROR_NAME
    mirror_port: int = DEFAULT_MIRROR_PORT
    source_ports: tuple[int, ...] = DEFAULT_SOURCE_PORTS

    def __post_init__(self):
        for interface in (self.sensor_interface, self.mirror_interface):
            if not interface or len(interface) > 15:
                raise ValueError(
                    f"Linux interface name must contain 1-15 characters: {interface!r}"
                )
        if self.sensor_interface == self.mirror_interface:
            raise ValueError("sensor and mirror interfaces must be different")
        if self.mirror_port <= 0:
            raise ValueError("mirror port must be greater than zero")
        if not self.source_ports or any(port <= 0 for port in self.source_ports):
            raise ValueError("source ports must contain positive port numbers")
        if self.mirror_port in self.source_ports:
            raise ValueError("mirror output port cannot also be a source port")
        if len(set(self.source_ports)) != len(self.source_ports):
            raise ValueError("source ports must not contain duplicates")


@dataclass(frozen=True)
class InterfaceState:
    name: str
    kind: str | None
    ifindex: int
    peer_ifindex: int | None
    peer_name: str | None
    up: bool
    promiscuity: int


def run_command(command, *, check=True):
    """Run one command without a shell and return its completed result."""
    try:
        return subprocess.run(
            command,
            check=check,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as error:
        raise SensorError(f"required command is missing: {command[0]}") from error
    except subprocess.CalledProcessError as error:
        reason = error.stderr.strip() or error.stdout.strip() or str(error)
        raise SensorError(f"command failed ({' '.join(command)}): {reason}") from error


def inspect_interface(name, *, runner=run_command):
    result = runner(
        ["ip", "-details", "-json", "link", "show", "dev", name],
        check=False,
    )
    if result.returncode != 0:
        return None

    try:
        payload = json.loads(result.stdout)[0]
        link_info = payload.get("linkinfo") or {}
        peer_ifindex = payload.get("link_index", payload.get("iflink"))
        return InterfaceState(
            name=name,
            kind=link_info.get("info_kind"),
            ifindex=int(payload["ifindex"]),
            peer_ifindex=int(peer_ifindex) if peer_ifindex is not None else None,
            peer_name=(
                payload.get("link")
                if isinstance(payload.get("link"), str)
                else None
            ),
            up="UP" in payload.get("flags", []),
            promiscuity=int(payload.get("promiscuity", 0)),
        )
    except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise SensorError(f"could not parse interface state for {name}") from error


def validate_veth_pair(sensor, mirror):
    if sensor.kind != "veth" or mirror.kind != "veth":
        raise SensorError(
            "sensor interface names already exist but are not both veth devices"
        )
    indexes_match = (
        sensor.peer_ifindex == mirror.ifindex
        and mirror.peer_ifindex == sensor.ifindex
    )
    names_match = (
        sensor.peer_name == mirror.name
        and mirror.peer_name == sensor.name
    )
    if not indexes_match and not names_match:
        raise SensorError(
            f"{sensor.name} and {mirror.name} exist but are not veth peers"
        )


def ensure_sensor_veth(config=SensorConfig(), *, runner=run_command):
    """Create or safely reuse the persistent, address-free sensor veth pair."""
    sensor = inspect_interface(config.sensor_interface, runner=runner)
    mirror = inspect_interface(config.mirror_interface, runner=runner)

    if (sensor is None) != (mirror is None):
        existing = config.mirror_interface if sensor is None else config.sensor_interface
        missing = config.sensor_interface if sensor is None else config.mirror_interface
        raise SensorError(
            f"{existing} exists without expected veth peer {missing}; refusing to replace it"
        )

    if sensor is None:
        runner([
            "ip",
            "link",
            "add",
            config.sensor_interface,
            "type",
            "veth",
            "peer",
            "name",
            config.mirror_interface,
        ])
        sensor = inspect_interface(config.sensor_interface, runner=runner)
        mirror = inspect_interface(config.mirror_interface, runner=runner)
        if sensor is None or mirror is None:
            raise SensorError("veth command succeeded but the sensor pair is missing")

    validate_veth_pair(sensor, mirror)
    for interface in (config.sensor_interface, config.mirror_interface):
        runner(["ip", "address", "flush", "dev", interface])
        runner(["ip", "link", "set", "dev", interface, "promisc", "on", "up"])

    return (
        inspect_interface(config.sensor_interface, runner=runner),
        inspect_interface(config.mirror_interface, runner=runner),
    )


def _bridge_exists(bridge, *, runner=run_command):
    return runner(["ovs-vsctl", "br-exists", bridge], check=False).returncode == 0


def _mirror_uuids(name, *, runner=run_command):
    result = runner([
        "ovs-vsctl",
        "--bare",
        "--columns=_uuid",
        "find",
        "Mirror",
        f"name={name}",
    ])
    return UUID_PATTERN.findall(result.stdout)


def _bridge_names(*, runner=run_command):
    result = runner(["ovs-vsctl", "list-br"])
    return tuple(
        name.strip()
        for name in result.stdout.splitlines()
        if name.strip()
    )


def detach_mirror(config=SensorConfig(), *, runner=run_command):
    """Remove only the managed Mirror and its OVS port; keep the veth pair."""
    bridges = _bridge_names(runner=runner)
    for mirror_uuid in _mirror_uuids(config.mirror_name, runner=runner):
        command = ["ovs-vsctl"]
        for bridge in bridges:
            command.extend([
                "--",
                "--if-exists",
                "remove",
                "Bridge",
                bridge,
                "mirrors",
                mirror_uuid,
            ])
        command.extend([
            "--",
            "--if-exists",
            "destroy",
            "Mirror",
            mirror_uuid,
        ])
        runner(command)

    runner([
        "ovs-vsctl",
        "--if-exists",
        "del-port",
        config.mirror_interface,
    ])


def _require_ovs_port(port_name, *, runner=run_command):
    result = runner(
        ["ovs-vsctl", "--if-exists", "get", "Port", port_name, "name"]
    )
    if result.stdout.strip().strip('"') != port_name:
        raise SensorError(f"required OVS source port is missing: {port_name}")


def _wait_for_ofport(config, *, runner=run_command, timeout=3.0):
    deadline = time.monotonic() + timeout
    last_value = "missing"
    while time.monotonic() < deadline:
        result = runner(
            [
                "ovs-vsctl",
                "--if-exists",
                "get",
                "Interface",
                config.mirror_interface,
                "ofport",
            ]
        )
        last_value = result.stdout.strip()
        if last_value == str(config.mirror_port):
            return
        time.sleep(0.05)
    raise SensorError(
        f"{config.mirror_interface} did not acquire OpenFlow port "
        f"{config.mirror_port}; last value: {last_value}"
    )


def attach_mirror(config=SensorConfig(), *, runner=run_command):
    """Attach the veth output to OVS and select ingress on source ports."""
    ensure_sensor_veth(config, runner=runner)
    if not _bridge_exists(config.switch, runner=runner):
        raise SensorError(f"OVS bridge does not exist: {config.switch}")

    source_names = [f"{config.switch}-eth{port}" for port in config.source_ports]
    for port_name in source_names:
        _require_ovs_port(port_name, runner=runner)

    detach_mirror(config, runner=runner)
    aliases = [f"@source{index}" for index in range(len(source_names))]
    command = [
        "ovs-vsctl",
        "--",
        "--may-exist",
        "add-port",
        config.switch,
        config.mirror_interface,
        "--",
        "set",
        "Interface",
        config.mirror_interface,
        f"ofport_request={config.mirror_port}",
    ]
    for alias, port_name in zip(aliases, source_names):
        command.extend(["--", f"--id={alias}", "get", "Port", port_name])
    command.extend([
        "--",
        "--id=@output",
        "get",
        "Port",
        config.mirror_interface,
        "--",
        "--id=@mirror",
        "create",
        "Mirror",
        f"name={config.mirror_name}",
        f"select_src_port={','.join(aliases)}",
        "output_port=@output",
        "--",
        "add",
        "Bridge",
        config.switch,
        "mirrors",
        "@mirror",
    ])

    try:
        runner(command)
        _wait_for_ofport(config, runner=runner)
        validate_mirror(config, runner=runner)
    except SensorError:
        detach_mirror(config, runner=runner)
        raise


def _get_ovs_value(table, record, column, *, runner=run_command):
    result = runner([
        "ovs-vsctl",
        "--if-exists",
        "get",
        table,
        record,
        column,
    ])
    return result.stdout.strip()


def validate_mirror(config=SensorConfig(), *, runner=run_command):
    """Validate source/output port references and the requested OpenFlow port."""
    mirror_uuids = _mirror_uuids(config.mirror_name, runner=runner)
    if len(mirror_uuids) != 1:
        raise SensorError(
            f"expected one {config.mirror_name} Mirror, found {len(mirror_uuids)}"
        )

    output_uuid = _get_ovs_value(
        "Mirror", config.mirror_name, "output_port", runner=runner
    )
    expected_output_uuid = _get_ovs_value(
        "Port", config.mirror_interface, "_uuid", runner=runner
    )
    if UUID_PATTERN.findall(output_uuid) != UUID_PATTERN.findall(expected_output_uuid):
        raise SensorError("OVS Mirror output does not reference the sensor veth port")

    selected = set(UUID_PATTERN.findall(_get_ovs_value(
        "Mirror", config.mirror_name, "select_src_port", runner=runner
    )))
    expected = {
        UUID_PATTERN.findall(_get_ovs_value(
            "Port", f"{config.switch}-eth{port}", "_uuid", runner=runner
        ))[0]
        for port in config.source_ports
    }
    if selected != expected:
        raise SensorError(
            f"OVS Mirror source ports do not match {config.source_ports}"
        )

    ofport = _get_ovs_value(
        "Interface", config.mirror_interface, "ofport", runner=runner
    )
    if ofport != str(config.mirror_port):
        raise SensorError(
            f"expected {config.mirror_interface} ofport {config.mirror_port}, got {ofport}"
        )


def cleanup_sensor(config=SensorConfig(), *, runner=run_command):
    """Remove the transient Mirror first, then delete the persistent pair."""
    detach_mirror(config, runner=runner)
    if inspect_interface(config.sensor_interface, runner=runner) is not None:
        runner(["ip", "link", "delete", "dev", config.sensor_interface])


def print_status(config=SensorConfig(), *, runner=run_command):
    for name in (config.sensor_interface, config.mirror_interface):
        state = inspect_interface(name, runner=runner)
        if state is None:
            print(f"{name}: missing")
        else:
            print(
                f"{name}: kind={state.kind} up={state.up} "
                f"promiscuity={state.promiscuity} ifindex={state.ifindex} "
                f"peer_ifindex={state.peer_ifindex} peer_name={state.peer_name}"
            )
    mirror_count = len(_mirror_uuids(config.mirror_name, runner=runner))
    print(f"{config.mirror_name}: rows={mirror_count}")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("setup", "attach", "detach", "cleanup", "status"))
    parser.add_argument("--sensor-interface", default=DEFAULT_SENSOR_INTERFACE)
    parser.add_argument("--mirror-interface", default=DEFAULT_MIRROR_INTERFACE)
    parser.add_argument("--switch", default=DEFAULT_SWITCH)
    parser.add_argument("--mirror-name", default=DEFAULT_MIRROR_NAME)
    parser.add_argument("--mirror-port", type=int, default=DEFAULT_MIRROR_PORT)
    parser.add_argument(
        "--source-port",
        type=int,
        action="append",
        dest="source_ports",
        help="Ingress source port to mirror; repeat for multiple ports.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        config = SensorConfig(
            sensor_interface=args.sensor_interface,
            mirror_interface=args.mirror_interface,
            switch=args.switch,
            mirror_name=args.mirror_name,
            mirror_port=args.mirror_port,
            source_ports=tuple(args.source_ports or DEFAULT_SOURCE_PORTS),
        )
        if args.action == "setup":
            ensure_sensor_veth(config)
        elif args.action == "attach":
            attach_mirror(config)
        elif args.action == "detach":
            detach_mirror(config)
        elif args.action == "cleanup":
            cleanup_sensor(config)
        else:
            print_status(config)
        return 0
    except (SensorError, ValueError) as error:
        print(f"sensor setup failed: {error}", file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
