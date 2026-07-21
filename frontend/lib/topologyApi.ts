import { getPathStatus } from "@/lib/pathApi";
import type { PathStatus, SwitchUtilization } from "@/types/path";
import type { NodeStatus, TopologyState } from "@/types/topology";

const hostRoles: Record<string, string> = {
  h1: "일반 사용자",
  h2: "관리자",
  h3: "공격 테스트",
  web: "웹 서버"
};

const switchRoles: Record<string, string> = {
  s1: "진입 / 미러링",
  s2: "기본 경로",
  s3: "우회 경로",
  s4: "목적지 연결"
};

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
    role: switchRoles[item.switch_id] ?? item.dpid,
    type: "switch" as const,
    status: toSwitchStatus(item.state, utilizationBySwitch.get(item.switch_id))
  }));

  const hostNodes = controllerTopology.hosts.map((item) => ({
    id: item.name,
    label: item.name,
    role: `${hostRoles[item.name] ?? "호스트"} · ${item.ipv4}`,
    type: "host" as const,
    status: connectedSwitches.has(item.switch_id)
      ? ("normal" as const)
      : ("offline" as const)
  }));

  const pathLinks = pathStatus.links.map((item) => ({ ...item }));
  const accessLinks = controllerTopology.hosts.map((host) => ({
    id: `${host.name}-${host.switch_id}`,
    source: host.name,
    target: host.switch_id,
    path: "access" as const,
    active: connectedSwitches.has(host.switch_id),
    utilization: utilizationBySwitch.get(host.switch_id)?.utilization ?? 0
  }));

  return {
    active_path: pathStatus.active_path,
    nodes: [...hostNodes, ...switchNodes],
    links: [...accessLinks, ...pathLinks]
  };
}

export async function getTopologyState(): Promise<TopologyState> {
  return toTopologyState(await getPathStatus());
}
