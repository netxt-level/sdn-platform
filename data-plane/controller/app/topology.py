"""Configured port roles for the initial fixed Mininet topology."""


HOST_FACING_PORTS = {
    1: frozenset({1, 2, 3}),
    4: frozenset({3}),
}


def is_host_facing_port(dpid, port):
    """Return whether a switch port is an allowed host attachment point."""
    return port in HOST_FACING_PORTS.get(dpid, ())

