"""Configured port roles and active state for the Mininet topology."""


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

WEIGHTED_SWITCH_GRAPH = {
    1: {2: 1, 3: 10},
    2: {1: 1, 4: 1},
    3: {1: 10, 4: 10},
    4: {2: 1, 3: 10},
}

FLOOD_TREE_PORTS = {
    1: frozenset({1, 2, 3, 4, 5}),
    2: frozenset({1, 2}),
    3: frozenset({1}),
    4: frozenset({1, 3}),
}


class ActiveTopology:
    """Build weighted graph snapshots from connected switches and live links."""

    def __init__(self, configured_graph):
        self._configured_graph = {
            switch: dict(neighbors)
            for switch, neighbors in configured_graph.items()
        }
        self._validate_configured_graph()
        self._connected_switches = set()
        self._active_links = {
            self._link_key(source, destination)
            for source, neighbors in self._configured_graph.items()
            for destination in neighbors
        }

    def connect_switch(self, dpid):
        """Mark a configured switch connected and return whether state changed."""
        self._require_switch(dpid)
        previous_count = len(self._connected_switches)
        self._connected_switches.add(dpid)
        return len(self._connected_switches) != previous_count

    def disconnect_switch(self, dpid):
        """Mark a configured switch disconnected and return whether it existed."""
        self._require_switch(dpid)
        if dpid not in self._connected_switches:
            return False
        self._connected_switches.remove(dpid)
        return True

    def set_link_state(self, source, destination, active):
        """Update one configured bidirectional link and return whether it changed."""
        if not isinstance(active, bool):
            raise ValueError("link active state must be a boolean")
        self._require_link(source, destination)
        link = self._link_key(source, destination)

        was_active = link in self._active_links
        if active:
            self._active_links.add(link)
        else:
            self._active_links.discard(link)
        return was_active != active

    def snapshot(self):
        """Return a defensive weighted graph containing only usable links."""
        connected = set(self._connected_switches)
        active_links = set(self._active_links)

        return {
            source: {
                destination: cost
                for destination, cost in neighbors.items()
                if destination in connected
                and self._link_key(source, destination) in active_links
            }
            for source, neighbors in self._configured_graph.items()
            if source in connected
        }

    def _validate_configured_graph(self):
        for source, neighbors in self._configured_graph.items():
            for destination, cost in neighbors.items():
                if destination not in self._configured_graph:
                    raise ValueError(
                        f"link from switch {source} references unknown switch "
                        f"{destination}"
                    )
                reverse_cost = self._configured_graph[destination].get(source)
                if reverse_cost != cost:
                    raise ValueError(
                        f"link cost must be symmetric between switches "
                        f"{source} and {destination}"
                    )

    def _require_switch(self, dpid):
        if dpid not in self._configured_graph:
            raise ValueError(f"unknown configured switch: {dpid}")

    def _require_link(self, source, destination):
        self._require_switch(source)
        self._require_switch(destination)
        if destination not in self._configured_graph[source]:
            raise ValueError(
                f"unknown configured link: {source}-{destination}"
            )

    @staticmethod
    def _link_key(source, destination):
        return tuple(sorted((source, destination)))


def is_host_facing_port(dpid, port):
    """Return whether a switch port is an allowed host attachment point."""
    return port in HOST_FACING_PORTS.get(dpid, ())


def get_flood_output_ports(dpid, in_port):
    """Return deterministic loop-free flood ports, excluding the ingress."""
    tree_ports = FLOOD_TREE_PORTS.get(dpid)
    if tree_ports is None or in_port not in tree_ports:
        return ()
    return tuple(sorted(tree_ports - {in_port}))
