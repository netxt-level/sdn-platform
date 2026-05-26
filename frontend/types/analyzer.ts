export type NetworkStatus = "normal" | "warning" | "critical";

export type AnalyzerStatus = {
  timestamp: string;
  analyzer_id: string;
  status: string;
  interface: string;
  capture_active: boolean;
  backend_connected: boolean;
  last_packet_at?: string | null;
  last_summary_sent_at?: string | null;
  error_message?: string | null;
};

export type HostStat = {
  src_host?: string | null;
  src_ip?: string | null;
  dst_host?: string | null;
  dst_ip?: string | null;
  protocol: string;
  packet_count: number;
  bit_count: number;
};

export type PacketSummary = {
  timestamp: string;
  analyzer_id: string;
  window_sec: number;
  total_packets: number;
  total_bits: number;
  protocol_stats: Record<string, number>;
  host_stats: HostStat[];
};

export type SuspiciousHost = {
  host?: string | null;
  ip: string;
  protocol: string;
  bps: number;
  pps: number;
  reasons: string[];
};

export type DetectionSummary = {
  timestamp: string;
  analyzer_id: string;
  network_status: NetworkStatus;
  total_bps: number;
  total_pps: number;
  active_flow_count: number;
  suspicious_host_count: number;
  suspicious_hosts: SuspiciousHost[];
};
