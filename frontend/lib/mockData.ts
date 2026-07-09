import type {
  AnalyzerStatus,
  DetectionSummary,
  PacketSummary
} from "@/types/analyzer";
import type { SecurityEvent, SecurityRule } from "@/types/security";
import type { TopologyState } from "@/types/topology";

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
    attack_type: "ARP_SPOOFING",
    severity: "critical",
    status: "detected",
    src_ip: "",
    src_mac: "00:00:00:00:00:02",
    dst_ip: "10.0.0.11",
    port_summary: "-",
    protocol: "ARP",
    pps: 0,
    bps: 0,
    action: "block",
    mitigation: {
      action: "DROP",
      target: "flow",
      match: {
        eth_type: 2054,
        eth_src: "00:00:00:00:00:02",
        arp_spa: "10.0.0.1"
      },
      priority: 650,
      idle_timeout: 60,
      hard_timeout: 300
    },
    evidence: {
      gateway_ip: "10.0.0.1",
      trusted_gateway_mac: "00:00:00:00:00:01",
      observed_sender_mac: "00:00:00:00:00:02",
      matched_conditions: [
        "arp_reply",
        "sender_ip_matches_gateway",
        "sender_mac_mismatch"
      ],
      score: 100
    }
  },
  {
    id: "evt-1041",
    occurred_at: new Date(Date.now() - 1000 * 60 * 4).toISOString(),
    attack_type: "ICMP_FLOOD",
    severity: "high",
    status: "detected",
    src_ip: "10.0.0.2",
    dst_ip: "10.0.0.4",
    port_summary: "-",
    protocol: "ICMP",
    pps: 96,
    bps: 614400,
    action: "block",
    mitigation: {
      action: "RATE_LIMIT",
      target: "flow",
      match: {
        eth_type: 2048,
        ipv4_src: "10.0.0.2",
        ipv4_dst: "10.0.0.4",
        ip_proto: 1
      },
      priority: 500,
      idle_timeout: 60,
      hard_timeout: 300,
      rate_limit_pps: 100
    },
    evidence: {
      matched_conditions: ["icmp_pps_threshold"],
      score: 60,
      response_level: "rate_limit_candidate"
    }
  },
  {
    id: "evt-1040",
    occurred_at: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
    attack_type: "PORT_SCAN",
    severity: "medium",
    status: "detected",
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

export const mockTopology: TopologyState = {
  active_path: "primary",
  nodes: [
    { id: "h1", label: "h1", role: "정상 사용자", type: "host", status: "normal" },
    { id: "h2", label: "h2", role: "공격자", type: "host", status: "warning" },
    { id: "h3", label: "h3", role: "관리자", type: "host", status: "normal" },
    { id: "h4", label: "h4", role: "수신 서버", type: "host", status: "normal" },
    { id: "s1", label: "s1", role: "진입/미러링", type: "switch", status: "normal" },
    { id: "s2", label: "s2", role: "기본 경로", type: "switch", status: "normal" },
    { id: "s3", label: "s3", role: "우회 경로", type: "switch", status: "normal" },
    { id: "s4", label: "s4", role: "목적지 연결", type: "switch", status: "normal" }
  ],
  links: [
    { id: "h1-s1", source: "h1", target: "s1", path: "access", active: true, utilization: 34 },
    { id: "h2-s1", source: "h2", target: "s1", path: "access", active: true, utilization: 68 },
    { id: "h3-s1", source: "h3", target: "s1", path: "access", active: true, utilization: 26 },
    { id: "s1-s2", source: "s1", target: "s2", path: "primary", active: true, utilization: 72 },
    { id: "s2-s4", source: "s2", target: "s4", path: "primary", active: true, utilization: 70 },
    { id: "s1-s3", source: "s1", target: "s3", path: "backup", active: false, utilization: 18 },
    { id: "s3-s4", source: "s3", target: "s4", path: "backup", active: false, utilization: 12 },
    { id: "s4-h4", source: "s4", target: "h4", path: "access", active: true, utilization: 58 }
  ]
};
