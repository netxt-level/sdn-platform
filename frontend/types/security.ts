export type AttackType =
  | "ICMP_FLOOD"
  | "SYN_FLOOD"
  | "UDP_FLOOD"
  | "PORT_SCAN"
  | "UNKNOWN";

export type SecuritySeverity = "low" | "medium" | "high" | "critical";

export type SecurityEventStatus = "detected" | "blocked" | "ignored" | "resolved";

export type SecurityEvent = {
  id: string;
  occurred_at: string;
  attack_type: AttackType;
  severity: SecuritySeverity;
  status: SecurityEventStatus;
  src_ip: string;
  dst_ip: string;
  protocol: string;
  pps: number;
  bps: number;
  action: "none" | "block" | "reroute";
};

export type SecurityRule = {
  id: string;
  type: "ip" | "mac" | "port" | "protocol";
  value: string;
  enabled: boolean;
  created_at: string;
};
