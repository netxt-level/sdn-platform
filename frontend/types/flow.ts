export type FlowRule = {
  id: string;
  source_event_id?: string | null;
  switch_id?: string | null;
  match: Record<string, unknown>;
  action: string;
  priority: number;
  packet_count?: number | null;
  byte_count?: number | null;
  status: string;
  error_message?: string | null;
};

export type ControllerSwitch = {
  switch_id: string;
  dpid?: string;
  state: string;
};

export type ControllerLink = {
  source: string;
  destination: string;
  state: string;
};

export type ControllerHost = {
  name?: string | null;
  mac: string;
  ipv4?: string | null;
  switch_id: string;
  port: number;
};

export type FlowControllerState = {
  available: boolean;
  updated_at?: string | null;
  switches: ControllerSwitch[];
  links: ControllerLink[];
  hosts: ControllerHost[];
  error?: string | null;
};

export type FlowRulesResponse = {
  items: FlowRule[];
  total: number;
  controller: FlowControllerState;
};

export type FlowRuleCreatePayload = {
  switch_id: string;
  match: Record<string, string | number>;
  action: string;
  priority: number;
  rate_limit_pps?: number;
};
