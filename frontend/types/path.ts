export type PathLink = {
  id: string;
  source: string;
  target: string;
  path: "primary" | "backup";
  active: boolean;
  utilization: number;
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
  status: "sampling" | "normal" | "warning" | "critical" | "disconnected";
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
  history: PathHistoryItem[];
};
