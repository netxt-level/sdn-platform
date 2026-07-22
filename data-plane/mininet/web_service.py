"""Attach a loopback-only VM service to the Mininet web host."""

import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from mininet.link import Link
from mininet.node import Node


ROOT_INTERFACE = "mut-root0"
WEB_INTERFACE = "mut-web0"
ROOT_IP = "169.254.100.1"
WEB_MANAGEMENT_IP = "169.254.100.2"
MANAGEMENT_PREFIX = 30
ROOT_RELAY_PORT = 18080
WEB_IP = "10.0.0.100"
WEB_PORT = 80


@dataclass(frozen=True)
class WebServiceConfig:
    """Addresses used by the isolated web-host relay."""

    target_host: str = "127.0.0.1"
    target_port: int = 8088
    web_host: str = WEB_IP
    web_port: int = WEB_PORT


class WebServiceProxy:
    """Own the management veth and both relay processes."""

    def __init__(self, web, config=None):
        self.web = web
        self.config = config or WebServiceConfig()
        self.root = None
        self.link = None
        self.processes = []

    def start(self, timeout=10.0):
        proxy_script = str(Path(__file__).with_name("tcp_proxy.py"))
        self.root = Node("mut-root", inNamespace=False)
        self.link = Link(
            self.root,
            self.web,
            intfName1=ROOT_INTERFACE,
            intfName2=WEB_INTERFACE,
        )
        self.root.setIP(
            f"{ROOT_IP}/{MANAGEMENT_PREFIX}",
            intf=ROOT_INTERFACE,
        )
        self.web.setIP(
            f"{WEB_MANAGEMENT_IP}/{MANAGEMENT_PREFIX}",
            intf=WEB_INTERFACE,
        )

        self.processes.append(
            self.root.popen(
                "python3",
                proxy_script,
                "--listen-host",
                ROOT_IP,
                "--listen-port",
                str(ROOT_RELAY_PORT),
                "--target-host",
                self.config.target_host,
                "--target-port",
                str(self.config.target_port),
            )
        )
        self.processes.append(
            self.web.popen(
                "python3",
                proxy_script,
                "--listen-host",
                self.config.web_host,
                "--listen-port",
                str(self.config.web_port),
                "--target-host",
                ROOT_IP,
                "--target-port",
                str(ROOT_RELAY_PORT),
            )
        )
        self._wait_until_ready(timeout)

    def stop(self):
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
        self.processes.clear()

        if self.link is not None:
            self.link.delete()
            self.link = None
        if self.root is not None:
            self.root.terminate()
            self.root = None

    def _wait_until_ready(self, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if any(process.poll() is not None for process in self.processes):
                raise RuntimeError("Mutillidae relay exited before becoming ready")
            try:
                with socket.create_connection(
                    (ROOT_IP, ROOT_RELAY_PORT),
                    timeout=0.2,
                ):
                    return
            except OSError:
                time.sleep(0.1)
        raise TimeoutError("Timed out waiting for the Mutillidae relay")
