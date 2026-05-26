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
  active: boolean;
  utilization: number;
};

export type TopologyState = {
  nodes: TopologyNode[];
  links: TopologyLink[];
  active_path: "primary" | "backup";
};
