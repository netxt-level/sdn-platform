#!/usr/bin/env python3
"""Generate continuous mixed-protocol shopping traffic inside the isolated lab."""

from __future__ import annotations

import argparse
from collections import Counter
import http.client
import json
import random
import signal
import socket
import struct
import subprocess
import threading
import time
from urllib.parse import urlencode


DEFAULT_TARGET_HOST = "10.0.0.100"
DEFAULT_TARGET_PORT = 80
DEFAULT_HOST_HEADER = "mutillidae.localhost"
DEFAULT_DNS_PORT = 53
DEFAULT_TELEMETRY_PORT = 8125
DEFAULT_HTTP_SHARE = 0.85
DEFAULT_DNS_SHARE = 0.08
DEFAULT_TELEMETRY_SHARE = 0.05
USER_AGENTS = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 Firefox/127.0",
)
SHOPPING_JOURNEYS = (
    (
        "/",
        "/index.php?page=home.php",
        "/index.php?page=view-someones-blog.php",
    ),
    (
        "/",
        "/index.php?page=documentation/vulnerabilities.php",
        "/index.php?page=user-info.php",
    ),
    (
        "/",
        "/index.php?page=login.php",
        "/index.php?page=home.php",
    ),
)
SEARCH_TERMS = ("laptop", "headphones", "camera", "keyboard", "monitor")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--users", type=int, required=True)
    parser.add_argument("--target-host", default=DEFAULT_TARGET_HOST)
    parser.add_argument("--target-port", type=int, default=DEFAULT_TARGET_PORT)
    parser.add_argument("--host-header", default=DEFAULT_HOST_HEADER)
    parser.add_argument("--client-label", default="mininet-host")
    parser.add_argument("--dns-port", type=int, default=DEFAULT_DNS_PORT)
    parser.add_argument(
        "--telemetry-port",
        type=int,
        default=DEFAULT_TELEMETRY_PORT,
    )
    parser.add_argument("--http-share", type=float, default=DEFAULT_HTTP_SHARE)
    parser.add_argument("--dns-share", type=float, default=DEFAULT_DNS_SHARE)
    parser.add_argument(
        "--telemetry-share",
        type=float,
        default=DEFAULT_TELEMETRY_SHARE,
    )
    parser.add_argument("--think-min", type=float, default=5.0)
    parser.add_argument("--think-max", type=float, default=15.0)
    parser.add_argument("--spawn-rate", type=float, default=1.7)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--report-interval", type=float, default=10.0)
    args = parser.parse_args()

    if not 1 <= args.users <= 500:
        parser.error("--users must be between 1 and 500")
    if not 1 <= args.target_port <= 65535:
        parser.error("--target-port must be between 1 and 65535")
    if not 1 <= args.dns_port <= 65535 or not 1 <= args.telemetry_port <= 65535:
        parser.error("UDP ports must be between 1 and 65535")
    if args.think_min < 0 or args.think_max < args.think_min:
        parser.error("--think-max must be greater than or equal to --think-min")
    if args.spawn_rate <= 0 or args.timeout <= 0 or args.report_interval <= 0:
        parser.error("rates, timeout, and report interval must be positive")
    shares = (args.http_share, args.dns_share, args.telemetry_share)
    if any(share < 0 for share in shares) or sum(shares) > 1:
        parser.error("protocol shares must be non-negative and sum to at most 1")
    return args


def build_dns_query(name, transaction_id):
    labels = b"".join(
        bytes([len(label)]) + label.encode("ascii")
        for label in name.split(".")
    ) + b"\x00"
    return (
        struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
        + labels
        + struct.pack("!HH", 1, 1)
    )


class Metrics:
    def __init__(self):
        self._lock = threading.Lock()
        self._values = Counter()

    def add(self, kind, *, status=None, received=0, latency=0.0, error=None):
        with self._lock:
            self._values["actions"] += 1
            self._values[f"{kind}_actions"] += 1
            if kind == "http":
                self._values["requests"] += 1
            self._values["bytes"] += received
            self._values["latency_ms_total"] += int(latency * 1000)
            if status is not None:
                self._values[f"status_{status}"] += 1
            if error is not None:
                self._values["failures"] += 1
                self._values[f"{kind}_failures"] += 1
                self._values[f"error_{type(error).__name__}"] += 1

    def snapshot(self):
        with self._lock:
            values = dict(self._values)
        actions = values.get("actions", 0)
        values["average_latency_ms"] = round(
            values.get("latency_ms_total", 0) / actions,
            2,
        ) if actions else 0.0
        return values


class VirtualShopper:
    def __init__(self, worker_id, args, metrics, stop_event):
        self.worker_id = worker_id
        self.args = args
        self.metrics = metrics
        self.stop_event = stop_event
        self.random = random.Random((time.time_ns() << 8) ^ worker_id)
        self.cookie = ""
        self.connection = None
        self.journey = []
        self.journey_index = 0

    def _connect(self):
        if self.connection is None:
            self.connection = http.client.HTTPConnection(
                self.args.target_host,
                self.args.target_port,
                timeout=self.args.timeout,
            )

    def _close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def _request(self, path):
        headers = {
            "Host": self.args.host_header,
            "User-Agent": self.random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5",
            "Accept-Language": "ko-KR,ko;q=0.9,en;q=0.7",
            "Connection": "keep-alive",
            "X-Lab-Virtual-User": str(self.worker_id),
        }
        if self.cookie:
            headers["Cookie"] = self.cookie

        started_at = time.monotonic()
        for attempt in range(2):
            try:
                self._connect()
                self.connection.request("GET", path, headers=headers)
                response = self.connection.getresponse()
                received = 0
                while True:
                    chunk = response.read(64 * 1024)
                    if not chunk:
                        break
                    received += len(chunk)
                set_cookie = response.getheader("Set-Cookie")
                if set_cookie:
                    self.cookie = set_cookie.split(";", 1)[0]
                latency = time.monotonic() - started_at
                error = None if 200 <= response.status < 400 else RuntimeError(
                    f"HTTP {response.status}"
                )
                self.metrics.add(
                    "http",
                    status=response.status,
                    received=received,
                    latency=latency,
                    error=error,
                )
                if response.will_close:
                    self._close()
                return
            except http.client.RemoteDisconnected as error:
                self._close()
                if attempt == 0:
                    continue
                self.metrics.add(
                    "http",
                    latency=time.monotonic() - started_at,
                    error=error,
                )
                return
            except (OSError, TimeoutError, http.client.HTTPException) as error:
                self.metrics.add(
                    "http",
                    latency=time.monotonic() - started_at,
                    error=error,
                )
                self._close()
                return

    def _dns_query(self):
        transaction_id = self.random.randrange(0, 65536)
        query = build_dns_query("shop.local", transaction_id)
        started_at = time.monotonic()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns_socket:
                dns_socket.settimeout(self.args.timeout)
                dns_socket.sendto(
                    query,
                    (self.args.target_host, self.args.dns_port),
                )
                response, _peer = dns_socket.recvfrom(4096)
            response_id = struct.unpack("!H", response[:2])[0] if len(response) >= 2 else -1
            if len(response) < 12 or response_id != transaction_id:
                raise ValueError("DNS response transaction ID does not match")
            self.metrics.add(
                "dns",
                received=len(response),
                latency=time.monotonic() - started_at,
            )
        except (OSError, TimeoutError, ValueError) as error:
            self.metrics.add(
                "dns",
                latency=time.monotonic() - started_at,
                error=error,
            )

    def _send_telemetry(self):
        payload = (
            "shop.page_view:1|c|#client:"
            f"{self.args.client_label},user:{self.worker_id}"
        ).encode("utf-8")
        started_at = time.monotonic()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
                udp_socket.sendto(
                    payload,
                    (self.args.target_host, self.args.telemetry_port),
                )
            self.metrics.add(
                "telemetry",
                latency=time.monotonic() - started_at,
            )
        except OSError as error:
            self.metrics.add(
                "telemetry",
                latency=time.monotonic() - started_at,
                error=error,
            )

    def _icmp_probe(self):
        started_at = time.monotonic()
        try:
            result = subprocess.run(
                ["ping", "-q", "-c", "1", "-W", "1", self.args.target_host],
                capture_output=True,
                check=False,
                timeout=self.args.timeout,
            )
            received = len(result.stdout)
            error = None if result.returncode == 0 else RuntimeError(
                "ICMP probe failed"
            )
        except (OSError, subprocess.TimeoutExpired) as probe_error:
            received = 0
            error = probe_error
        self.metrics.add(
            "icmp",
            received=received,
            latency=time.monotonic() - started_at,
            error=error,
        )

    def _next_http_path(self):
        if self.journey_index >= len(self.journey):
            self.journey = list(self.random.choice(SHOPPING_JOURNEYS))
            if self.random.random() < 0.35:
                query = urlencode({"q": self.random.choice(SEARCH_TERMS)})
                self.journey.insert(1, f"/index.php?{query}")
            self.journey_index = 0
        path = self.journey[self.journey_index]
        self.journey_index += 1
        return path

    def run(self):
        initial_delay = self.worker_id / self.args.spawn_rate
        if self.stop_event.wait(initial_delay):
            return
        try:
            while not self.stop_event.is_set():
                action = self.random.random()
                http_limit = self.args.http_share
                dns_limit = http_limit + self.args.dns_share
                telemetry_limit = dns_limit + self.args.telemetry_share
                if action < http_limit:
                    self._request(self._next_http_path())
                elif action < dns_limit:
                    self._dns_query()
                elif action < telemetry_limit:
                    self._send_telemetry()
                else:
                    self._icmp_probe()
                self.stop_event.wait(
                    self.random.uniform(
                        self.args.think_min,
                        self.args.think_max,
                    )
                )
        finally:
            self._close()


def main():
    args = parse_args()
    stop_event = threading.Event()
    metrics = Metrics()

    def stop(_signum, _frame):
        stop_event.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    workers = [
        threading.Thread(
            target=VirtualShopper(
                worker_id,
                args,
                metrics,
                stop_event,
            ).run,
            name=f"shopper-{worker_id}",
            daemon=True,
        )
        for worker_id in range(args.users)
    ]
    for worker in workers:
        worker.start()

    started_at = time.monotonic()
    while not stop_event.wait(args.report_interval):
        snapshot = metrics.snapshot()
        snapshot.update({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "users": args.users,
            "target": f"{args.target_host}:{args.target_port}",
            "elapsed_seconds": round(time.monotonic() - started_at, 1),
        })
        print(json.dumps(snapshot, sort_keys=True), flush=True)

    for worker in workers:
        worker.join(timeout=args.timeout + args.think_max + 1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
