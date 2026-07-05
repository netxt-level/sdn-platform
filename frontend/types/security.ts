export type AttackType =
  | "ICMP_FLOOD"
  | "SYN_FLOOD"
  | "UDP_FLOOD"
  | "PORT_SCAN"
  | "ARP_SPOOFING"
  | "ARP_REPLY_STORM"
  | "CONGESTION"
  | "LINK_FAILURE"
  | "UNKNOWN";

export type SecuritySeverity = "low" | "medium" | "high" | "critical";

export type SecurityEventStatus = "detected" | "blocked" | "ignored" | "resolved";

export type SecurityEvent = {
  id: string;
  event_id?: string;
  occurred_at: string;
  created_at?: string;
  attack_type: AttackType;
  severity: SecuritySeverity;
  status: SecurityEventStatus;
  src_ip: string;
  src_mac?: string;
  dst_ip: string;
  dst_port?: number | null;
  protocol: string;
  pps: number;
  bps: number;
  action: "none" | "block" | "reroute";
  mitigation_action?: "DROP" | "RATE_LIMIT" | "REROUTE" | "MONITOR_ONLY";
  metric_name?: string;
  metric_value?: number | string | null;
  threshold?: number | string | null;
  evidence?: Record<string, unknown>;
  flow_rule?: Record<string, unknown> | null;
};

export type SecurityRule = {
  id: string;
  type: "ip" | "mac" | "port" | "protocol";
  value: string;
  enabled: boolean;
  created_at: string;
};
