import type {
  AnalyzerStatus,
  DetectionSummary,
  PacketSummary
} from "@/types/analyzer";
import type { SecurityEvent, SecurityRule } from "@/types/security";

const now = new Date().toISOString();

export const mockAnalyzerStatus: AnalyzerStatus = {
  timestamp: now,
  analyzer_id: "analyzer-1",
  status: "running",
  interface: "en0",
  capture_active: true,
  backend_connected: true,
  last_packet_at: now,
  last_summary_sent_at: now,
  error_message: null
};

export const mockPacketSummary: PacketSummary = {
  timestamp: now,
  analyzer_id: "analyzer-1",
  window_sec: 1,
  total_packets: 1284,
  total_bits: 8179200,
  protocol_stats: {
    TCP: 920,
    UDP: 248,
    ICMP: 96,
    UNKNOWN: 20
  },
  host_stats: [
    {
      src_host: "h1",
      src_ip: "10.0.0.1",
      dst_host: "h4",
      dst_ip: "10.0.0.4",
      protocol: "TCP",
      packet_count: 430,
      bit_count: 2714000
    },
    {
      src_host: "h2",
      src_ip: "10.0.0.2",
      dst_host: "h4",
      dst_ip: "10.0.0.4",
      protocol: "ICMP",
      packet_count: 96,
      bit_count: 614400
    },
    {
      src_host: "h3",
      src_ip: "10.0.0.3",
      dst_host: "h4",
      dst_ip: "10.0.0.4",
      protocol: "UDP",
      packet_count: 210,
      bit_count: 1432000
    },
    {
      src_host: "h1",
      src_ip: "10.0.0.1",
      dst_host: "h4",
      dst_ip: "10.0.0.4",
      protocol: "ICMP",
      packet_count: 44,
      bit_count: 281600
    },
    {
      src_host: "h2",
      src_ip: "10.0.0.2",
      dst_host: "h4",
      dst_ip: "10.0.0.4",
      protocol: "TCP",
      packet_count: 182,
      bit_count: 1172480
    }
  ]
};

export const mockDetectionSummary: DetectionSummary = {
  timestamp: now,
  analyzer_id: "analyzer-1",
  network_status: "warning",
  total_bps: 8179200,
  total_pps: 1284,
  active_flow_count: 18,
  suspicious_host_count: 1,
  suspicious_hosts: [
    {
      host: "h2",
      ip: "10.0.0.2",
      protocol: "ICMP",
      bps: 614400,
      pps: 96,
      reasons: ["ICMP PPS threshold exceeded", "Repeated requests to h4"]
    }
  ]
};

export const mockSecurityEvents: SecurityEvent[] = [
  {
    id: "evt-1042",
    occurred_at: now,
    attack_type: "ICMP_FLOOD",
    severity: "high",
    status: "detected",
    src_ip: "10.0.0.2",
    dst_ip: "10.0.0.4",
    port_summary: "-",
    protocol: "ICMP",
    pps: 96,
    bps: 614400,
    action: "none"
  },
  {
    id: "evt-1041",
    occurred_at: new Date(Date.now() - 1000 * 60 * 4).toISOString(),
    attack_type: "PORT_SCAN",
    severity: "medium",
    status: "blocked",
    src_ip: "10.0.0.2",
    dst_ip: "10.0.0.4",
    port_summary: "22, 80, 443",
    protocol: "TCP",
    pps: 42,
    bps: 172000,
    action: "block"
  }
];

export const mockRules: SecurityRule[] = [
  {
    id: "rule-ip-001",
    type: "ip",
    value: "10.0.0.2",
    enabled: true,
    created_at: now
  },
  {
    id: "rule-proto-001",
    type: "protocol",
    value: "ICMP",
    enabled: false,
    created_at: now
  },
  {
    id: "rule-port-001",
    type: "port",
    value: "TCP/22",
    enabled: true,
    created_at: new Date(Date.now() - 1000 * 60 * 21).toISOString()
  },
  {
    id: "rule-mac-001",
    type: "mac",
    value: "00:00:00:00:00:02",
    enabled: true,
    created_at: new Date(Date.now() - 1000 * 60 * 46).toISOString()
  }
];
