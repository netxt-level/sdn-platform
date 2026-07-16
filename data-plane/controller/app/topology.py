"""Configured port roles for the initial fixed Mininet topology."""


HOST_FACING_PORTS = {
    1: frozenset({1, 2, 3}),
    4: frozenset({3}),
}

SWITCH_LINK_PORTS = {
    1: {2: 4, 3: 5},
    2: {1: 1, 4: 2},
    3: {1: 1, 4: 2},
    4: {2: 1, 3: 2},
}

PRIMARY_SWITCH_GRAPH = {
    1: (2, 3),
    2: (1, 4),
    3: (1,),
    4: (2,),
}

FLOOD_TREE_PORTS = {
    1: frozenset({1, 2, 3, 4, 5}),
    2: frozenset({1, 2}),
    3: frozenset({1}),
    4: frozenset({1, 3}),
}


def is_host_facing_port(dpid, port):
    """Return whether a switch port is an allowed host attachment point."""
    return port in HOST_FACING_PORTS.get(dpid, ())


def get_flood_output_ports(dpid, in_port):
    """Return deterministic loop-free flood ports, excluding the ingress."""
    tree_ports = FLOOD_TREE_PORTS.get(dpid)
    if tree_ports is None or in_port not in tree_ports:
        return ()
    return tuple(sorted(tree_ports - {in_port}))
