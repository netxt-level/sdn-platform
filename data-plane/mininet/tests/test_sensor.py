from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sensor import InterfaceState
from sensor import SensorConfig
from sensor import SensorError
from sensor import detach_mirror
from sensor import validate_veth_pair


def interface(name, kind, ifindex, peer_ifindex, peer_name=None):
    return InterfaceState(
        name=name,
        kind=kind,
        ifindex=ifindex,
        peer_ifindex=peer_ifindex,
        peer_name=peer_name,
        up=True,
        promiscuity=1,
    )


class CommandResult:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


class SensorConfigTests(unittest.TestCase):
    def test_uses_s1_ingress_ports_and_dedicated_output_by_default(self):
        config = SensorConfig()

        self.assertEqual("s1", config.switch)
        self.assertEqual((1, 2, 3, 4, 5), config.source_ports)
        self.assertEqual(6, config.mirror_port)
        self.assertEqual("sdn-sensor0", config.sensor_interface)
        self.assertEqual("sdn-mirror0", config.mirror_interface)

    def test_rejects_output_port_as_source(self):
        with self.assertRaisesRegex(ValueError, "cannot also be a source"):
            SensorConfig(source_ports=(1, 6))

    def test_rejects_invalid_or_duplicate_source_ports(self):
        for ports in ((), (0,), (1, 1)):
            with self.subTest(ports=ports):
                with self.assertRaises(ValueError):
                    SensorConfig(source_ports=ports)


class VethValidationTests(unittest.TestCase):
    def test_accepts_mutually_linked_veth_pair(self):
        sensor = interface("sdn-sensor0", "veth", 10, 11)
        mirror = interface("sdn-mirror0", "veth", 11, 10)

        validate_veth_pair(sensor, mirror)

    def test_accepts_iproute_json_peer_names(self):
        sensor = interface("sdn-sensor0", "veth", 10, None, "sdn-mirror0")
        mirror = interface("sdn-mirror0", "veth", 11, None, "sdn-sensor0")

        validate_veth_pair(sensor, mirror)

    def test_rejects_same_names_owned_by_other_link_type(self):
        sensor = interface("sdn-sensor0", "dummy", 10, 11)
        mirror = interface("sdn-mirror0", "veth", 11, 10)

        with self.assertRaisesRegex(SensorError, "not both veth"):
            validate_veth_pair(sensor, mirror)

    def test_rejects_veth_devices_that_are_not_peers(self):
        sensor = interface("sdn-sensor0", "veth", 10, 99)
        mirror = interface("sdn-mirror0", "veth", 11, 98)

        with self.assertRaisesRegex(SensorError, "not veth peers"):
            validate_veth_pair(sensor, mirror)


class MirrorCleanupTests(unittest.TestCase):
    def test_removes_managed_mirror_from_every_bridge_before_destroy(self):
        commands = []
        mirror_uuid = "12345678-1234-1234-1234-123456789abc"

        def runner(command, check=True):
            commands.append(command)
            if command == ["ovs-vsctl", "list-br"]:
                return CommandResult("s1\ns4\n")
            if command[:4] == [
                "ovs-vsctl",
                "--bare",
                "--columns=_uuid",
                "find",
            ]:
                return CommandResult(f"{mirror_uuid}\n")
            return CommandResult()

        detach_mirror(runner=runner)

        cleanup_command = commands[2]
        command_windows = [
            cleanup_command[index:index + 5]
            for index in range(len(cleanup_command))
        ]
        self.assertIn(
            ["remove", "Bridge", "s1", "mirrors", mirror_uuid],
            command_windows,
        )
        self.assertIn(
            ["remove", "Bridge", "s4", "mirrors", mirror_uuid],
            command_windows,
        )
        self.assertIn("destroy", cleanup_command)
        self.assertEqual(
            [
                "ovs-vsctl",
                "--if-exists",
                "del-port",
                "sdn-mirror0",
            ],
            commands[-1],
        )

if __name__ == "__main__":
    unittest.main()
