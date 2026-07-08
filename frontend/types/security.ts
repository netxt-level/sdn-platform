export type AttackType =
  | "ICMP_FLOOD"
  | "PORT_SCAN"
  | string;

export type SecuritySeverity = "low" | "medium" | "high" | "critical";

export type SecurityEventStatus = "detected" | "blocked" | "ignored" | "resolved";

export type SecurityEvent = {
  id: string;
  event_id?: string;
  event_fingerprint?: string;
  analyzer_id?: string;
  occurred_at: string;
  attack_type: AttackType;
  severity: SecuritySeverity;
  status: SecurityEventStatus;
  src_ip: string;
  dst_ip: string;
  src_port?: number | null;
  dst_port?: number | null;
  port_summary: string;
  protocol: string;
  detection_rule?: string;
  recommended_action?: string;
  response_level?: string;
  confidence?: string;
  evidence?: Record<string, unknown>;
  mitigation?: Record<string, unknown> | null;
  pps: number;
  bps: number;
  action: "none" | "block" | "reroute";
};

export type RawSecurityEvent = {
  id?: string;
  event_id?: string;
  event_fingerprint?: string;
  timestamp?: string;
  "@timestamp"?: string;
  analyzer_id?: string;
  attack_type?: string;
  severity?: string;
  status?: string;
  src_ip?: string;
  dst_ip?: string;
  src_port?: number | null;
  dst_port?: number | null;
  protocol?: string;
  detection_rule?: string;
  recommended_action?: string;
  response_level?: string;
  confidence?: string;
  evidence?: Record<string, unknown>;
  mitigation?: Record<string, unknown> | null;
};

export type SecurityRule = {
  id: string;
  type: "ip" | "mac" | "port" | "protocol";
  value: string;
  enabled: boolean;
  created_at: string;
};
