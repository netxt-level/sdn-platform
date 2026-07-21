export type PathLink = {
  id: string;
  source: string;
  target: string;
  path: "primary" | "backup";
  source_port: number | null;
  target_port: number | null;
  state: "active" | "inactive" | "unknown";
  selected: boolean;
  active: boolean;
  bps: number;
  rx_bps: number;
  tx_bps: number;
  utilization: number;
  capacity_bps: number;
  sampled: boolean;
};

export type PathInfo = {
  name: "primary" | "backup";
  nodes: string[];
  utilization: number;
  active: boolean;
};

export type PathHistoryItem = {
  id: string;
  time?: string | null;
  from: string;
  to: string;
  reason: string;
  status: string;
};

export type PortUtilization = {
  port_no: number;
  bps: number;
  rx_bps: number;
  tx_bps: number;
  utilization: number;
  capacity_bps: number;
  sampled: boolean;
};

export type SwitchUtilization = {
  switch_id: string;
  dpid?: string | null;
  state: string;
  bps: number;
  rx_bps: number;
  tx_bps: number;
  utilization: number;
  capacity_bps: number;
  sample_interval_seconds?: number | null;
  sampled: boolean;
  ports: PortUtilization[];
  status: "sampling" | "normal" | "warning" | "critical" | "disconnected";
};

export type ControllerSwitch = {
  switch_id: string;
  dpid: string;
  state: string;
};

export type ControllerLink = {
  source: string;
  destination: string;
  source_port: number;
  destination_port: number;
  cost: number;
  state: string;
};

export type ControllerHost = {
  name: string | null;
  mac: string;
  ipv4: string;
  switch_id: string;
  port: number;
};

export type ControllerTopology = {
  switches: ControllerSwitch[];
  links: ControllerLink[];
  hosts: ControllerHost[];
};

export type PathStatus = {
  active_path: "primary" | "backup";
  network_status: "normal" | "warning" | "critical";
  paths: {
    primary: PathInfo;
    backup: PathInfo;
  };
  links: PathLink[];
  switches: SwitchUtilization[];
  utilization_source: "openflow_port_counter_delta";
  congestion_threshold_percent: number;
  history: PathHistoryItem[];
  controller: {
    topology: ControllerTopology;
    stats: unknown;
  } | null;
};
