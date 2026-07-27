#!/usr/bin/env python3
"""Generate bounded HTTP connections for isolated path-distribution tests."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
import random
import socket
from threading import Lock
import time


TARGET_HOST = "10.0.0.100"
TARGET_PORT = 80
REQUEST = (
    b"GET / HTTP/1.1\r\n"
    b"Host: mutillidae.localhost\r\n"
    b"Connection: close\r\n\r\n"
)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=100)
    parser.add_argument("--duration", type=float, default=10.0)
    parser.add_argument("--socket-timeout", type=float, default=2.0)
    parser.add_argument("--think-min", type=float, default=2.0)
    parser.add_argument("--think-max", type=float, default=5.0)
    args = parser.parse_args()
    if not 1 <= args.workers <= 200:
        parser.error("--workers must be between 1 and 200")
    if not 1 <= args.duration <= 60:
        parser.error("--duration must be between 1 and 60 seconds")
    if args.socket_timeout <= 0:
        parser.error("--socket-timeout must be positive")
    if args.think_min < 0 or args.think_max < args.think_min:
        parser.error("--think-max must be greater than or equal to --think-min")
    return args


def main():
    args = parse_args()
    deadline = time.monotonic() + args.duration
    counters = {"requests": 0, "failures": 0, "bytes": 0}
    lock = Lock()

    def worker(worker_id):
        local = {"requests": 0, "failures": 0, "bytes": 0}
        randomizer = random.Random(os.getpid() * 1000 + worker_id)
        initial_delay = randomizer.uniform(0, args.think_max)
        time.sleep(min(initial_delay, max(0.0, deadline - time.monotonic())))
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(
                    (TARGET_HOST, TARGET_PORT),
                    timeout=args.socket_timeout,
                ) as connection:
                    connection.settimeout(args.socket_timeout)
                    connection.sendall(REQUEST)
                    received = 0
                    while True:
                        chunk = connection.recv(65536)
                        if not chunk:
                            break
                        received += len(chunk)
                local["requests"] += 1
                local["bytes"] += received
            except (OSError, TimeoutError):
                local["failures"] += 1
            remaining = deadline - time.monotonic()
            if remaining > 0:
                think_time = randomizer.uniform(
                    args.think_min,
                    args.think_max,
                )
                time.sleep(min(think_time, remaining))
        with lock:
            for key, value in local.items():
                counters[key] += value

    started_at = time.monotonic()
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [
            executor.submit(worker, worker_id)
            for worker_id in range(args.workers)
        ]
        for future in futures:
            future.result()

    elapsed = time.monotonic() - started_at
    print(json.dumps({
        **counters,
        "workers": args.workers,
        "elapsed_seconds": round(elapsed, 3),
        "target": f"{TARGET_HOST}:{TARGET_PORT}",
    }))


if __name__ == "__main__":
    main()
