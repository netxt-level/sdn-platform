export type NodeStatus = "normal" | "warning" | "blocked" | "offline";

export type TopologyNode = {
  id: string;
  label: string;
  role: string;
  type: "host" | "switch";
  status: NodeStatus;
};

export type TopologyLink = {
  id: string;
  source: string;
  target: string;
  path: "access" | "primary" | "backup";
  state: "up" | "down" | "unknown";
  selected: boolean;
  active: boolean;
  bps: number;
  utilization: number;
  sampled: boolean;
};

export type TopologyState = {
  nodes: TopologyNode[];
  links: TopologyLink[];
  active_path: "primary" | "backup";
};
