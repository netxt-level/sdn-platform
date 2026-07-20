"""Configured host bindings, port roles, and active Mininet topology."""

from dataclasses import dataclass
from threading import RLock


@dataclass(frozen=True)
class HostBinding:
    name: str
    mac: str
    ipv4: str


HOST_BINDINGS = {
    1: {
        1: HostBinding("h1", "00:00:00:00:00:01", "10.0.0.1"),
        2: HostBinding("h2", "00:00:00:00:00:02", "10.0.0.2"),
        3: HostBinding("h3", "00:00:00:00:00:03", "10.0.0.3"),
    },
    4: {
        3: HostBinding("web", "00:00:00:00:01:00", "10.0.0.100"),
    },
}

HOST_FACING_PORTS = {
    dpid: frozenset(bindings)
    for dpid, bindings in HOST_BINDINGS.items()
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
        self._inactive_link_endpoints = set()
        self._lock = RLock()

    def connect_switch(self, dpid):
        """Connect a switch with transit ports pending state synchronization."""
        self._require_switch(dpid)
        with self._lock:
            previous_count = len(self._connected_switches)
            self._connected_switches.add(dpid)
            changed = len(self._connected_switches) != previous_count
            if changed:
                self._inactive_link_endpoints.update(
                    (dpid, neighbor)
                    for neighbor in self._configured_graph[dpid]
                )
            return changed

    def disconnect_switch(self, dpid):
        """Mark a configured switch disconnected and return whether it existed."""
        self._require_switch(dpid)
        with self._lock:
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

        with self._lock:
            was_active = self._is_link_usable(link)
            if active:
                self._active_links.add(link)
            else:
                self._active_links.discard(link)
            return was_active != self._is_link_usable(link)

    def set_link_port_state(self, source, destination, active):
        """Update one link endpoint and report a link usability transition."""
        if not isinstance(active, bool):
            raise ValueError("link port active state must be a boolean")
        self._require_link(source, destination)
        link = self._link_key(source, destination)
        endpoint = (source, destination)
        with self._lock:
            was_active = self._is_link_usable(link)

            if active:
                self._inactive_link_endpoints.discard(endpoint)
            else:
                self._inactive_link_endpoints.add(endpoint)

            return was_active != self._is_link_usable(link)

    def snapshot(self):
        """Return a defensive weighted graph containing only usable links."""
        with self._lock:
            connected = set(self._connected_switches)
            active_links = set(self._active_links)
            inactive_endpoints = set(self._inactive_link_endpoints)

        return {
            source: {
                destination: cost
                for destination, cost in neighbors.items()
                if destination in connected
                and self._link_key(source, destination) in active_links
                and (source, destination) not in inactive_endpoints
                and (destination, source) not in inactive_endpoints
            }
            for source, neighbors in self._configured_graph.items()
            if source in connected
        }

    def get_flood_output_ports(self, dpid, in_port):
        """Return loop-free flood ports for the current active topology."""
        graph = self.snapshot()
        if dpid not in graph:
            return ()

        tree_ports = {
            switch: set(HOST_FACING_PORTS.get(switch, ()))
            for switch in graph
        }
        for source, destination in calculate_flood_tree_links(graph):
            tree_ports[source].add(SWITCH_LINK_PORTS[source][destination])
            tree_ports[destination].add(SWITCH_LINK_PORTS[destination][source])

        if in_port not in tree_ports[dpid]:
            return ()
        return tuple(sorted(tree_ports[dpid] - {in_port}))

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

    def _is_link_usable(self, link):
        source, destination = link
        return (
            link in self._active_links
            and source in self._connected_switches
            and destination in self._connected_switches
            and (source, destination) not in self._inactive_link_endpoints
            and (destination, source) not in self._inactive_link_endpoints
        )

    @staticmethod
    def _link_key(source, destination):
        return tuple(sorted((source, destination)))


def calculate_flood_tree_links(graph):
    """Calculate a deterministic minimum spanning forest for broadcasts."""
    parents = {switch: switch for switch in graph}

    def find(switch):
        while parents[switch] != switch:
            parents[switch] = parents[parents[switch]]
            switch = parents[switch]
        return switch

    edges = sorted(
        (cost, source, destination)
        for source, neighbors in graph.items()
        for destination, cost in neighbors.items()
        if source < destination
    )
    tree_links = []

    for _cost, source, destination in edges:
        source_root = find(source)
        destination_root = find(destination)
        if source_root == destination_root:
            continue
        parents[destination_root] = source_root
        tree_links.append((source, destination))

    return tuple(tree_links)


def is_host_facing_port(dpid, port):
    """Return whether a switch port is an allowed host attachment point."""
    return port in HOST_FACING_PORTS.get(dpid, ())


def get_host_binding(dpid, port):
    """Return the fixed host identity assigned to one access port."""
    return HOST_BINDINGS.get(dpid, {}).get(port)


def validate_host_source(dpid, port, mac, ipv4):
    """Return a rejection reason when a source violates its fixed binding."""
    binding = get_host_binding(dpid, port)
    if binding is None:
        return "unknown_attachment"
    if not isinstance(mac, str) or mac.lower() != binding.mac:
        return "mac_mismatch"
    if ipv4 != binding.ipv4:
        return "ipv4_mismatch"
    return None


def get_neighbor_switch(dpid, port):
    """Return the configured neighbor reached through one switch port."""
    for neighbor, output_port in SWITCH_LINK_PORTS.get(dpid, {}).items():
        if output_port == port:
            return neighbor
    return None


def get_flood_output_ports(dpid, in_port):
    """Return deterministic loop-free flood ports, excluding the ingress."""
    tree_ports = FLOOD_TREE_PORTS.get(dpid)
    if tree_ports is None or in_port not in tree_ports:
        return ()
    return tuple(sorted(tree_ports - {in_port}))
