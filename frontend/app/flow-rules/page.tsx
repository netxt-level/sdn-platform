"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";
import { Ban, GitBranch, Plus, Repeat2, ShieldAlert, Trash2, Workflow } from "lucide-react";

import { MetricCard } from "@/components/dashboard/MetricCard";
import { PageHeader } from "@/components/layout/PageHeader";
import { Panel } from "@/components/ui/Panel";
import { StatusBadge } from "@/components/ui/StatusBadge";
import {
  createFlowRule,
  FlowApiError,
  getFlowRules,
  removeFlowRule
} from "@/lib/flowApi";
import { formatNumber } from "@/lib/format";
import type {
  FlowControllerState,
  FlowRule,
  FlowRulesResponse
} from "@/types/flow";

const emptyControllerState: FlowControllerState = {
  available: false,
  switches: [],
  links: [],
  hosts: []
};

type MatchProtocol = "TCP" | "UDP" | "ICMP";

const protocolNumbers: Record<MatchProtocol, number> = {
  TCP: 6,
  UDP: 17,
  ICMP: 1
};

const commonPorts: Record<Exclude<MatchProtocol, "ICMP">, { value: string; label: string }[]> = {
  TCP: [
    { value: "80", label: "80 · HTTP" },
    { value: "443", label: "443 · HTTPS" },
    { value: "22", label: "22 · SSH" },
    { value: "8080", label: "8080 · HTTP 대체" }
  ],
  UDP: [
    { value: "53", label: "53 · DNS" },
    { value: "123", label: "123 · NTP" },
    { value: "500", label: "500 · IKE" }
  ]
};

function formatMatch(match: Record<string, unknown>) {
  const entries = Object.entries(match);

  if (!entries.length) {
    return "-";
  }

  return entries.map(([key, value]) => `${key}=${String(value)}`).join(", ");
}

function statusTone(status: string) {
  if (["FAILED", "REMOVE_FAILED"].includes(status)) {
    return "critical" as const;
  }
  if (["PENDING", "APPLYING", "REMOVING"].includes(status)) {
    return "warning" as const;
  }
  return status === "APPLIED" ? "normal" as const : "muted" as const;
}

export default function FlowRulesPage() {
  const [flowRules, setFlowRules] = useState<FlowRule[]>([]);
  const [controller, setController] = useState<FlowControllerState>(
    emptyControllerState
  );
  const [selectedSwitch, setSelectedSwitch] = useState("ALL");
  const [sourceIp, setSourceIp] = useState("");
  const [protocol, setProtocol] = useState<MatchProtocol>("TCP");
  const [portOption, setPortOption] = useState("80");
  const [customPort, setCustomPort] = useState("");
  const [action, setAction] = useState("DROP");
  const [priority, setPriority] = useState("500");
  const [rateLimitPps, setRateLimitPps] = useState("100");
  const [message, setMessage] = useState("");
  const [deletingRuleId, setDeletingRuleId] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [loading, setLoading] = useState(true);
  const selectedRule = flowRules[0];
  const filteredRules = useMemo(
    () =>
      selectedSwitch === "ALL"
        ? flowRules
        : flowRules.filter((rule) => rule.switch_id === selectedSwitch),
    [flowRules, selectedSwitch]
  );
  const dropCount = flowRules.filter((rule) => rule.action.toUpperCase() === "DROP").length;
  const forwardCount = flowRules.filter((rule) => rule.action.toLowerCase().startsWith("output")).length;
  const rateLimitCount = flowRules.filter((rule) => rule.action.toUpperCase() === "RATE_LIMIT").length;
  const connectedSwitches = useMemo(
    () => controller.switches.filter((item) => item.state === "connected"),
    [controller.switches]
  );
  const sourceHosts = useMemo(
    () => controller.hosts.filter(
      (host) => Boolean(host.ipv4) && host.name?.toLowerCase() !== "web"
    ),
    [controller.hosts]
  );
  const selectedSource = useMemo(
    () => sourceHosts.find((host) => host.ipv4 === sourceIp),
    [sourceHosts, sourceIp]
  );
  const webHost = useMemo(
    () => controller.hosts.find(
      (host) => host.name?.toLowerCase() === "web" && Boolean(host.ipv4)
    ),
    [controller.hosts]
  );
  const selectedSwitchId = selectedSource?.switch_id ?? "";
  const selectedPort = protocol === "ICMP"
    ? null
    : portOption === "CUSTOM"
      ? customPort
      : portOption;
  const matchPreview = useMemo(() => {
    if (!selectedSource?.ipv4 || !webHost?.ipv4) return null;

    const match: Record<string, string | number> = {
      eth_type: 2048,
      ipv4_src: selectedSource.ipv4,
      ipv4_dst: webHost.ipv4,
      ip_proto: protocolNumbers[protocol]
    };
    if (protocol !== "ICMP" && selectedPort) {
      match[`${protocol.toLowerCase()}_dst`] = Number(selectedPort);
    }
    return match;
  }, [protocol, selectedPort, selectedSource, webHost]);
  const switchFilters = useMemo(
    () => [
      "ALL",
      ...new Set([
        ...controller.switches.map((item) => item.switch_id),
        ...flowRules
          .map((rule) => rule.switch_id)
          .filter((value): value is string => Boolean(value))
      ])
    ],
    [controller.switches, flowRules]
  );
  const outputActions = useMemo(() => {
    const targets = controller.links.flatMap((link) => {
      if (link.state !== "active") {
        return [];
      }
      if (link.source === selectedSwitchId) {
        return [link.destination];
      }
      if (link.destination === selectedSwitchId) {
        return [link.source];
      }
      return [];
    });
    return [...new Set(targets)].map((target) => `OUTPUT:${target}`);
  }, [controller.links, selectedSwitchId]);

  function applyFlowRulesResponse(data: FlowRulesResponse) {
    const items = data.items ?? [];
    const nextController = {
      ...(data.controller ?? emptyControllerState),
      hosts: data.controller?.hosts ?? []
    };
    setFlowRules(items);
    setController(nextController);
    setSelectedSwitch((current) =>
      current === "ALL"
      || nextController.switches.some((item) => item.switch_id === current)
      || items.some((item) => item.switch_id === current)
        ? current
        : "ALL"
    );
    setSourceIp((current) =>
      nextController.hosts.some(
        (host) => host.ipv4 === current && host.name?.toLowerCase() !== "web"
      )
        ? current
        : nextController.hosts.find(
          (host) => Boolean(host.ipv4) && host.name?.toLowerCase() !== "web"
        )?.ipv4 ?? ""
    );
  }

  async function loadFlowRules() {
    applyFlowRulesResponse(await getFlowRules());
  }

  useEffect(() => {
    let ignored = false;

    async function load() {
      try {
        const data = await getFlowRules();
        if (!ignored) applyFlowRulesResponse(data);
      } catch (error) {
        if (!ignored) {
          setMessage(
            `Flow Rule 조회 실패: ${
              error instanceof Error ? error.message : "Backend 연결 오류"
            }`
          );
        }
      } finally {
        if (!ignored) {
          setLoading(false);
        }
      }
    }

    load();
    const intervalId = window.setInterval(load, 5000);
    return () => {
      ignored = true;
      window.clearInterval(intervalId);
    };
  }, []);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage("");

    if (!selectedSource?.ipv4) {
      setMessage("출발지 호스트를 선택하세요.");
      return;
    }

    if (!webHost?.ipv4) {
      setMessage("목적지 web 호스트가 아직 Controller에 학습되지 않았습니다.");
      return;
    }

    if (!connectedSwitches.some(
      (item) => item.switch_id === selectedSource.switch_id
    )) {
      setMessage(`출발지 스위치 ${selectedSource.switch_id}가 연결되어 있지 않습니다.`);
      return;
    }

    const port = selectedPort == null ? null : Number(selectedPort);
    if (protocol !== "ICMP" && (
      port == null || !Number.isInteger(port) || port < 1 || port > 65535
    )) {
      setMessage("포트는 1에서 65535 사이의 정수로 입력하세요.");
      return;
    }

    const match: Record<string, string | number> = {
      eth_type: 2048,
      ipv4_src: selectedSource.ipv4,
      ipv4_dst: webHost.ipv4,
      ip_proto: protocolNumbers[protocol]
    };
    if (protocol !== "ICMP" && port != null) {
      match[`${protocol.toLowerCase()}_dst`] = port;
    }

    const payload = {
      switch_id: selectedSource.switch_id,
      match,
      action,
      priority: Number(priority)
    };

    if (action.toUpperCase() === "RATE_LIMIT" && rateLimitPps) {
      Object.assign(payload, { rate_limit_pps: Number(rateLimitPps) });
    }

    setSubmitting(true);
    try {
      const created = await createFlowRule(payload);
      await loadFlowRules();
      if (created.status === "APPLIED") {
        setMessage("Flow Rule이 저장되고 스위치에 적용되었습니다.");
      } else {
        setMessage(
          `Flow Rule은 저장되었지만 적용에 실패했습니다: ${
            created.error_message ?? created.status
          }`
        );
      }
    } catch (error) {
      setMessage(
        `Flow Rule 추가 실패: ${
          error instanceof FlowApiError ? error.message : "Backend 연결 오류"
        }`
      );
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDelete(rule: FlowRule) {
    if (!window.confirm(`Flow Rule ${rule.id}를 삭제하시겠습니까?`)) {
      return;
    }

    setDeletingRuleId(rule.id);
    setMessage("");
    try {
      await removeFlowRule(rule.id);
      await loadFlowRules();
      setMessage("Flow Rule이 스위치에서 제거되었습니다.");
    } catch (error) {
      setMessage(
        `Flow Rule 삭제 실패: ${
          error instanceof Error ? error.message : "Backend 연결 오류"
        }`
      );
    } finally {
      setDeletingRuleId(null);
    }
  }

  return (
    <>
      <PageHeader
        title="Flow Rules"
        description="Backend에 저장된 Flow Rule 상태와 Controller의 실시간 OpenFlow 통계를 함께 확인합니다."
        connected={!loading && controller.available}
        source={loading ? "waiting" : controller.available ? "controller" : "history"}
      />

      <div className="grid grid-cols-5 gap-4 max-xl:grid-cols-2 max-sm:grid-cols-1">
        <MetricCard label="전체 Flow Rule" value={formatNumber(flowRules.length)} foot="DB 조회" icon={GitBranch} tone="blue" />
        <MetricCard label="DROP Rule" value={formatNumber(dropCount)} foot="차단 규칙" icon={Ban} tone="red" />
        <MetricCard label="FORWARD Rule" value={formatNumber(forwardCount)} foot="전달 규칙" icon={Repeat2} tone="teal" />
        <MetricCard label="RATE LIMIT" value={formatNumber(rateLimitCount)} foot="속도 제한" icon={ShieldAlert} tone="amber" />
        <MetricCard label="Active Switch" value={formatNumber(connectedSwitches.length)} foot="Controller 연결 기준" icon={Workflow} tone="teal" />
      </div>

      {!loading && !controller.available && (
        <div className="font-mono-ui mt-4 rounded border border-yellow/40 bg-[var(--yellow-dim)] px-4 py-3 text-[11px] text-yellow">
          Controller 통계를 가져오지 못했습니다. DB 이력만 표시합니다.
          {controller.error ? ` (${controller.error})` : ""}
        </div>
      )}

      <div className="mt-4 grid grid-cols-[1fr_340px] gap-4 max-xl:grid-cols-1">
        <Panel
          title="스위치 Flow Rule"
          action={
            <div className="flex flex-wrap gap-2">
              {switchFilters.map((sw) => (
                <button
                  key={sw}
                  type="button"
                  onClick={() => setSelectedSwitch(sw)}
                  className={`font-mono-ui rounded border px-3 py-1 text-[10px] ${selectedSwitch === sw ? "border-accent bg-[var(--accent-dim)] text-accent" : "border-line2 text-muted"}`}
                >
                  {sw}
                </button>
              ))}
            </div>
          }
        >
          <div className="overflow-x-auto">
            <table className="font-mono-ui w-full border-collapse text-[11px]">
              <thead>
                <tr className="border-b border-line bg-sidebar text-left text-[9px] uppercase tracking-[0.15em] text-faint">
                  <th className="px-3 py-3 font-black">Switch</th>
                  <th className="px-3 py-3 font-black">Match</th>
                  <th className="px-3 py-3 font-black">Action</th>
                  <th className="px-3 py-3 text-right font-black">Priority</th>
                  <th className="px-3 py-3 text-right font-black">Packets</th>
                  <th className="px-3 py-3 text-right font-black">Bytes</th>
                  <th className="px-3 py-3 font-black">상태</th>
                  <th className="px-3 py-3 text-right font-black">작업</th>
                </tr>
              </thead>
              <tbody>
                {filteredRules.map((rule) => (
                  <tr key={rule.id} className="border-b border-line last:border-0">
                    <td className="px-3 py-3 font-black">{rule.switch_id ?? "-"}</td>
                    <td className="px-3 py-3">{formatMatch(rule.match)}</td>
                    <td className={`px-3 py-3 ${rule.action.toUpperCase() === "DROP" ? "text-red" : "text-accent"}`}>{rule.action}</td>
                    <td className="px-3 py-3 text-right">{rule.priority}</td>
                    <td className="px-3 py-3 text-right">{rule.packet_count == null ? "-" : formatNumber(rule.packet_count)}</td>
                    <td className="px-3 py-3 text-right">{rule.byte_count == null ? "-" : formatNumber(rule.byte_count)}</td>
                    <td className="px-3 py-3"><StatusBadge value={rule.status.toLowerCase()} tone={statusTone(rule.status)} /></td>
                    <td className="px-3 py-3 text-right">
                      <button
                        type="button"
                        onClick={() => handleDelete(rule)}
                        disabled={
                          deletingRuleId === rule.id
                          || ["REMOVING", "REMOVED", "EXPIRED"].includes(rule.status)
                        }
                        className="inline-flex items-center gap-1 rounded border border-red/40 px-2 py-1 text-[9px] font-black text-red disabled:cursor-not-allowed disabled:opacity-40"
                      >
                        <Trash2 className="h-3 w-3" />
                        {deletingRuleId === rule.id ? "삭제 중" : "삭제"}
                      </button>
                    </td>
                  </tr>
                ))}
                {!filteredRules.length && (
                  <tr>
                    <td colSpan={8} className="px-3 py-6 text-center text-muted">
                      {loading ? "Flow Rule 조회 중" : "Flow Rule이 없습니다."}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Panel>

        <div className="grid gap-4">
          <Panel title="Rule 상세">
            {selectedRule ? (
              <div className="font-mono-ui grid gap-3 text-[11px]">
                <div className="flex justify-between"><span className="text-faint">Switch</span><strong>{selectedRule.switch_id ?? "-"}</strong></div>
                <div className="flex justify-between"><span className="text-faint">Priority</span><strong>{selectedRule.priority}</strong></div>
                <div className="rounded border border-line bg-sidebar p-3 leading-6">
                  <span className="text-faint">match</span><br />
                  <span className="text-accent">{formatMatch(selectedRule.match)}</span>
                </div>
                <div className="rounded border border-line bg-sidebar p-3">
                  <span className="text-faint">action </span>
                  <strong className={selectedRule.action.toUpperCase() === "DROP" ? "text-red" : "text-accent"}>{selectedRule.action}</strong>
                </div>
              </div>
            ) : (
              <div className="font-mono-ui rounded border border-line bg-sidebar p-4 text-[11px] text-muted">
                선택 가능한 Flow Rule이 없습니다.
              </div>
            )}
          </Panel>

          <Panel title="Flow Rule 추가" action={<Plus className="h-4 w-4 text-accent" />}>
            <form className="grid gap-3" onSubmit={handleSubmit}>
              <label className="grid gap-1">
                <span className="font-mono-ui text-[9px] font-black uppercase tracking-[0.12em] text-faint">출발지</span>
                <select value={sourceIp} onChange={(event) => {
                  setSourceIp(event.target.value);
                  if (action.toUpperCase().startsWith("OUTPUT:")) setAction("DROP");
                }} disabled={!sourceHosts.length} className="font-mono-ui h-9 rounded border border-line2 bg-sidebar px-3 text-[11px] disabled:cursor-not-allowed disabled:opacity-50">
                  {!sourceHosts.length && <option value="">학습된 출발지 없음</option>}
                  {sourceHosts.map((host) => (
                    <option key={host.mac} value={host.ipv4 ?? ""}>
                      {host.name ?? host.mac} · {host.ipv4} ({host.switch_id})
                    </option>
                  ))}
                </select>
              </label>

              <div className="grid grid-cols-2 gap-2">
                <label className="grid gap-1">
                  <span className="font-mono-ui text-[9px] font-black uppercase tracking-[0.12em] text-faint">프로토콜</span>
                  <select value={protocol} onChange={(event) => {
                    const nextProtocol = event.target.value as MatchProtocol;
                    setProtocol(nextProtocol);
                    if (nextProtocol === "TCP") setPortOption("80");
                    if (nextProtocol === "UDP") setPortOption("53");
                  }} className="font-mono-ui h-9 rounded border border-line2 bg-sidebar px-3 text-[11px]">
                    <option>TCP</option>
                    <option>UDP</option>
                    <option>ICMP</option>
                  </select>
                </label>

                <label className="grid gap-1">
                  <span className="font-mono-ui text-[9px] font-black uppercase tracking-[0.12em] text-faint">목적지 포트</span>
                  {protocol === "ICMP" ? (
                    <div className="font-mono-ui flex h-9 items-center rounded border border-line bg-sidebar px-3 text-[10px] text-faint">포트 없음</div>
                  ) : (
                    <select value={portOption} onChange={(event) => setPortOption(event.target.value)} className="font-mono-ui h-9 rounded border border-line2 bg-sidebar px-3 text-[11px]">
                      {commonPorts[protocol].map((port) => (
                        <option key={port.value} value={port.value}>{port.label}</option>
                      ))}
                      <option value="CUSTOM">직접 입력</option>
                    </select>
                  )}
                </label>
              </div>

              {protocol !== "ICMP" && portOption === "CUSTOM" && (
                <label className="grid gap-1">
                  <span className="font-mono-ui text-[9px] font-black uppercase tracking-[0.12em] text-faint">포트 직접 입력</span>
                  <input value={customPort} onChange={(event) => setCustomPort(event.target.value)} type="number" min="1" max="65535" className="font-mono-ui h-9 rounded border border-line2 bg-sidebar px-3 text-[11px] outline-none" placeholder="1 - 65535" />
                </label>
              )}

              <div className="font-mono-ui rounded border border-line bg-sidebar p-3 text-[10px] leading-5">
                <div className="flex justify-between gap-3">
                  <span className="text-faint">목적지</span>
                  <strong>{webHost?.name ?? "web"} · {webHost?.ipv4 ?? "학습 대기 중"}</strong>
                </div>
                <div className="flex justify-between gap-3">
                  <span className="text-faint">적용 스위치</span>
                  <strong>{selectedSwitchId || "출발지 선택 필요"}</strong>
                </div>
                <div className="mt-2 border-t border-line pt-2 text-accent">
                  {matchPreview ? formatMatch(matchPreview) : "Match 조건을 생성할 수 없습니다."}
                </div>
              </div>

              <select value={action} onChange={(event) => setAction(event.target.value)} className="font-mono-ui h-9 rounded border border-line2 bg-sidebar px-3 text-[11px]">
                <option>RATE_LIMIT</option>
                <option>DROP</option>
                {outputActions.map((outputAction) => (
                  <option key={outputAction}>{outputAction}</option>
                ))}
              </select>
              <input value={priority} onChange={(event) => setPriority(event.target.value)} type="number" min="1" max="65535" className="font-mono-ui h-9 rounded border border-line2 bg-sidebar px-3 text-[11px] outline-none" placeholder="priority" />
              {action.toUpperCase() === "RATE_LIMIT" && (
                <input value={rateLimitPps} onChange={(event) => setRateLimitPps(event.target.value)} type="number" min="1" className="font-mono-ui h-9 rounded border border-line2 bg-sidebar px-3 text-[11px] outline-none" placeholder="rate_limit_pps" />
              )}
              <button type="submit" disabled={submitting || !selectedSource || !webHost || !connectedSwitches.length} className="font-mono-ui rounded border border-line2 bg-[var(--accent-dim)] px-3 py-2 text-[11px] text-accent disabled:cursor-not-allowed disabled:opacity-50">
                {submitting ? "적용 중" : "규칙 추가"}
              </button>
              {message && <p className="font-mono-ui text-[10px] text-muted">{message}</p>}
            </form>
          </Panel>
        </div>
      </div>
    </>
  );
}
