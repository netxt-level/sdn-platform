#!/usr/bin/env python3
"""Small TCP relay used to keep lab web traffic inside the Mininet path."""

import argparse
import socket
import socketserver
import threading


BUFFER_SIZE = 64 * 1024


def copy_stream(source, destination):
    """Copy one half of a TCP stream and close the opposite write side."""
    try:
        while True:
            data = source.recv(BUFFER_SIZE)
            if not data:
                break
            destination.sendall(data)
    except (ConnectionError, OSError):
        pass
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class ProxyHandler(socketserver.BaseRequestHandler):
    """Relay a client connection to the server's configured target."""

    def handle(self):
        with socket.create_connection(
            self.server.target,
            timeout=self.server.connect_timeout,
        ) as upstream:
            self.request.settimeout(None)
            upstream.settimeout(None)
            client_to_upstream = threading.Thread(
                target=copy_stream,
                args=(self.request, upstream),
                daemon=True,
            )
            upstream_to_client = threading.Thread(
                target=copy_stream,
                args=(upstream, self.request),
                daemon=True,
            )
            client_to_upstream.start()
            upstream_to_client.start()
            client_to_upstream.join()
            upstream_to_client.join()


class ThreadingTCPProxy(socketserver.ThreadingTCPServer):
    """Thread-per-connection TCP proxy with a fixed upstream target."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, listen, target, connect_timeout=5.0):
        self.target = target
        self.connect_timeout = connect_timeout
        super().__init__(listen, ProxyHandler)


def parse_args():
    parser = argparse.ArgumentParser(description="Relay TCP connections.")
    parser.add_argument("--listen-host", required=True)
    parser.add_argument("--listen-port", required=True, type=int)
    parser.add_argument("--target-host", required=True)
    parser.add_argument("--target-port", required=True, type=int)
    parser.add_argument("--connect-timeout", type=float, default=5.0)
    return parser.parse_args()


def main():
    args = parse_args()
    with ThreadingTCPProxy(
        (args.listen_host, args.listen_port),
        (args.target_host, args.target_port),
        args.connect_timeout,
    ) as proxy:
        proxy.serve_forever()


if __name__ == "__main__":
    main()
