"""Pure path and output-port calculation for the fixed topology."""

from collections import deque
from dataclasses import dataclass
import heapq
import math


class RoutingError(ValueError):
    """Raised when a route cannot be calculated from topology data."""


@dataclass(frozen=True)
class PathHop:
    dpid: int
    output_port: int


@dataclass(frozen=True)
class Route:
    switches: tuple[int, ...]
    hops: tuple[PathHop, ...]


@dataclass(frozen=True)
class BidirectionalRoutes:
    forward: Route
    reverse: Route


@dataclass(frozen=True)
class WeightedPath:
    switches: tuple[int, ...]
    cost: int | float


def calculate_unweighted_path(graph, source_dpid, destination_dpid):
    """Calculate a deterministic shortest path on an unweighted graph."""
    if source_dpid not in graph:
        raise RoutingError(f"unknown source switch: {source_dpid}")
    if destination_dpid not in graph:
        raise RoutingError(f"unknown destination switch: {destination_dpid}")
    if source_dpid == destination_dpid:
        return (source_dpid,)

    parents = {source_dpid: None}
    pending = deque([source_dpid])

    while pending:
        current = pending.popleft()
        for neighbor in sorted(graph[current]):
            if neighbor in parents:
                continue
            parents[neighbor] = current
            if neighbor == destination_dpid:
                path = [destination_dpid]
                while parents[path[-1]] is not None:
                    path.append(parents[path[-1]])
                return tuple(reversed(path))
            pending.append(neighbor)

    raise RoutingError(
        f"no path from switch {source_dpid} to {destination_dpid}"
    )


def calculate_dijkstra_path(graph, source_dpid, destination_dpid):
    """Calculate a deterministic minimum-cost path with Dijkstra's algorithm."""
    if source_dpid not in graph:
        raise RoutingError(f"unknown source switch: {source_dpid}")
    if destination_dpid not in graph:
        raise RoutingError(f"unknown destination switch: {destination_dpid}")
    if source_dpid == destination_dpid:
        return WeightedPath(switches=(source_dpid,), cost=0)

    initial_path = (source_dpid,)
    best = {source_dpid: (0, initial_path)}
    pending = [(0, initial_path, source_dpid)]

    while pending:
        cost, path, current = heapq.heappop(pending)
        if best.get(current) != (cost, path):
            continue
        if current == destination_dpid:
            return WeightedPath(switches=path, cost=cost)

        for neighbor in sorted(graph[current]):
            if neighbor not in graph:
                raise RoutingError(
                    f"link from switch {current} references unknown switch "
                    f"{neighbor}"
                )
            weight = graph[current][neighbor]
            if (
                isinstance(weight, bool)
                or not isinstance(weight, (int, float))
                or not math.isfinite(weight)
                or weight < 0
            ):
                raise RoutingError(
                    f"invalid link cost from switch {current} to {neighbor}: "
                    f"{weight}"
                )

            candidate = (cost + weight, path + (neighbor,))
            if neighbor not in best or candidate < best[neighbor]:
                best[neighbor] = candidate
                heapq.heappush(
                    pending,
                    (candidate[0], candidate[1], neighbor),
                )

    raise RoutingError(
        f"no path from switch {source_dpid} to {destination_dpid}"
    )


def calculate_output_hops(path, link_ports, destination_port):
    """Convert a switch path into each switch's output-port instruction."""
    if not path:
        raise RoutingError("switch path must not be empty")
    if not isinstance(destination_port, int) or destination_port <= 0:
        raise RoutingError(f"invalid destination port: {destination_port}")

    hops = []
    for current, next_hop in zip(path, path[1:]):
        try:
            output_port = link_ports[current][next_hop]
        except KeyError as error:
            raise RoutingError(
                f"missing output port from switch {current} to {next_hop}"
            ) from error
        hops.append(PathHop(dpid=current, output_port=output_port))

    hops.append(PathHop(dpid=path[-1], output_port=destination_port))
    return tuple(hops)


def calculate_route(
    graph,
    link_ports,
    source_dpid,
    destination_dpid,
    destination_port,
):
    """Calculate a path and output ports toward one destination host."""
    path = calculate_unweighted_path(
        graph,
        source_dpid,
        destination_dpid,
    )
    return Route(
        switches=path,
        hops=calculate_output_hops(path, link_ports, destination_port),
    )


def calculate_bidirectional_routes(
    graph,
    link_ports,
    source_dpid,
    source_port,
    destination_dpid,
    destination_port,
):
    """Calculate forward and reverse host-to-host routes."""
    return BidirectionalRoutes(
        forward=calculate_route(
            graph,
            link_ports,
            source_dpid,
            destination_dpid,
            destination_port,
        ),
        reverse=calculate_route(
            graph,
            link_ports,
            destination_dpid,
            source_dpid,
            source_port,
        ),
    )
