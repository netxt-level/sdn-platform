import { getPathStatus } from "@/lib/pathApi";
import type { PathStatus, SwitchUtilization } from "@/types/path";
import type { NodeStatus, TopologyState } from "@/types/topology";

function toSwitchStatus(
  state: string,
  utilization?: SwitchUtilization
): NodeStatus {
  if (state !== "connected" || utilization?.status === "disconnected") {
    return "offline";
  }
  if (utilization?.status === "critical") return "blocked";
  if (utilization?.status === "warning") return "warning";
  return "normal";
}

export function toTopologyState(pathStatus: PathStatus): TopologyState {
  const controllerTopology = pathStatus.controller?.topology;
  if (!controllerTopology) {
    return {
      active_path: pathStatus.active_path,
      nodes: [],
      links: []
    };
  }

  const utilizationBySwitch = new Map(
    pathStatus.switches.map((item) => [item.switch_id, item])
  );
  const connectedSwitches = new Set(
    controllerTopology.switches
      .filter((item) => item.state === "connected")
      .map((item) => item.switch_id)
  );

  const switchNodes = controllerTopology.switches.map((item) => ({
    id: item.switch_id,
    label: item.switch_id,
    type: "switch" as const,
    status: toSwitchStatus(item.state, utilizationBySwitch.get(item.switch_id))
  }));

  const hostsWithDisplayIds = controllerTopology.hosts.map((item, index) => ({
    item,
    id: item.name || `host-${index + 1}`
  }));
  const hostNodes = hostsWithDisplayIds.map(({ item, id }) => ({
    id,
    label: id,
    type: "host" as const,
    status: connectedSwitches.has(item.switch_id)
      ? ("normal" as const)
      : ("offline" as const)
  }));

  const pathLinks = pathStatus.links.map((item) => ({
    id: item.id,
    source: item.source,
    target: item.target,
    path: item.path,
    state:
      item.state === "active"
        ? ("up" as const)
        : item.state === "inactive"
          ? ("down" as const)
          : ("unknown" as const),
    selected: item.selected,
    active: item.state === "active",
    bps: item.bps,
    utilization: item.utilization,
    sampled: item.sampled
  }));
  const accessLinks = hostsWithDisplayIds.map(({ item: host, id: hostId }) => {
    const switchUsage = utilizationBySwitch.get(host.switch_id);
    const portUsage = switchUsage?.ports.find(
      (port) => port.port_no === host.port
    );
    const active = connectedSwitches.has(host.switch_id);

    return {
      id: `${hostId}-${host.switch_id}`,
      source: hostId,
      target: host.switch_id,
      path: "access" as const,
      state: active ? ("up" as const) : ("down" as const),
      selected: active,
      active,
      bps: portUsage?.bps ?? 0,
      utilization: portUsage?.utilization ?? 0,
      sampled: portUsage?.sampled ?? false
    };
  });

  return {
    active_path: pathStatus.active_path,
    nodes: [...hostNodes, ...switchNodes],
    links: [...accessLinks, ...pathLinks]
  };
}

export async function getTopologyState(): Promise<TopologyState> {
  return toTopologyState(await getPathStatus());
}
