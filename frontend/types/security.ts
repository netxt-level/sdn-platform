// 현재 보안 담당 범위에서 화면에 노출하는 탐지 유형만 명시한다.
// DDoS, 링크 장애, 혼잡은 이 목록에 포함하지 않는다.
export type AttackType =
  | "ICMP_FLOOD"
  | "PORT_SCAN"
  | "ARP_SPOOFING";

export type SecuritySeverity = "low" | "medium" | "high" | "critical";

export type SecurityEventStatus = "detected" | "blocked" | "ignored" | "resolved";

export type SecurityEvent = {
  // id는 화면 목록의 식별자, event_id는 Analyzer가 만든 원본 식별자다.
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
  // action은 UI용 단순 값이고, 실제 정책 종류는 mitigation_action으로 구분한다.
  mitigation_action?: "DROP" | "RATE_LIMIT" | "REROUTE" | "MONITOR_ONLY";
  metric_name?: string;
  metric_value?: number | string | null;
  threshold?: number | string | null;
  evidence?: Record<string, unknown>;
  // flow_rule은 Controller 적용 완료 결과가 아니라 적용 가능한 정책 후보다.
  flow_rule?: Record<string, unknown> | null;
};

export type SecurityRule = {
  id: string;
  type: "ip" | "mac" | "port" | "protocol";
  value: string;
  enabled: boolean;
  created_at: string;
};
