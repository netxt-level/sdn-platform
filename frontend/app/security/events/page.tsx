"use client";

import { useEffect, useMemo, useState } from "react";
import { PageHeader } from "@/components/layout/PageHeader";
import { SecurityEventsTable } from "@/components/security/SecurityEventsTable";
import { MetricCard } from "@/components/dashboard/MetricCard";
import { Panel } from "@/components/ui/Panel";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { formatBitsPerSecond, formatDateTime, formatNumber } from "@/lib/format";
import { useRealtime } from "@/hooks/useRealtime";
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  ChevronDown,
  Radio,
  ShieldAlert
} from "lucide-react";

const ALL_EVENT_SCOPE = "ALL";
const URGENT_EVENT_SCOPE = "URGENT";
const COMPLETED_EVENT_SCOPE = "COMPLETED";

type EventScopeFilter =
  | typeof ALL_EVENT_SCOPE
  | typeof URGENT_EVENT_SCOPE
  | typeof COMPLETED_EVENT_SCOPE;

function isUrgentEvent(event: { severity: string }) {
  return (
    event.severity === "high" ||
    event.severity === "critical"
  );
}

function isCompletedEvent(event: { status: string }) {
  return (
    event.status === "blocked" ||
    event.status === "resolved" ||
    event.status === "ignored"
  );
}

export default function SecurityEventsPage() {
  const state = useRealtime();
  const [eventScopeFilter, setEventScopeFilter] =
    useState<EventScopeFilter>(ALL_EVENT_SCOPE);
  const [selectedAttackTypes, setSelectedAttackTypes] = useState<string[]>([]);
  const [attackTypeDropdownOpen, setAttackTypeDropdownOpen] = useState(false);
  const [ipSearch, setIpSearch] = useState("");
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const visibleEvents = useMemo(
    () =>
      state.securityEvents.filter((event) => {
        const matchesScope =
          eventScopeFilter === ALL_EVENT_SCOPE ||
          (eventScopeFilter === URGENT_EVENT_SCOPE && isUrgentEvent(event)) ||
          (eventScopeFilter === COMPLETED_EVENT_SCOPE && isCompletedEvent(event));
        const matchesAttackType =
          selectedAttackTypes.length === 0 ||
          selectedAttackTypes.includes(event.attack_type);
        const normalizedSearch = ipSearch.trim();
        const matchesSearch =
          normalizedSearch.length === 0 ||
          event.src_ip.includes(normalizedSearch) ||
          event.dst_ip.includes(normalizedSearch);

        return matchesScope && matchesAttackType && matchesSearch;
      }),
    [eventScopeFilter, ipSearch, selectedAttackTypes, state.securityEvents]
  );
  const selectedEvent =
    visibleEvents.find((event) => event.id === selectedEventId) ??
    visibleEvents[0];
  const criticalCount = state.securityEvents.filter((event) => event.severity === "critical").length;
  const highCount = state.securityEvents.filter((event) => event.severity === "high").length;
  const resolvedCount = state.securityEvents.filter((event) => event.status === "resolved").length;
  const urgentCount = state.securityEvents.filter(isUrgentEvent).length;
  const completedCount = state.securityEvents.filter(isCompletedEvent).length;
  const attackTypeOptions = useMemo(
    () =>
      Array.from(
        new Set(state.securityEvents.map((event) => event.attack_type))
      ).sort(),
    [state.securityEvents]
  );
  const attackTypeFilterLabel =
    selectedAttackTypes.length === 0
      ? "전체 유형"
      : selectedAttackTypes.length === 1
        ? selectedAttackTypes[0].replaceAll("_", " ")
        : `유형 ${selectedAttackTypes.length}개`;
  const attackCounts = Object.entries(
    state.securityEvents.reduce<Record<string, number>>((counts, event) => {
      counts[event.attack_type] = (counts[event.attack_type] ?? 0) + 1;

      return counts;
    }, {})
  );

  useEffect(() => {
    if (
      selectedEventId &&
      visibleEvents.some((event) => event.id === selectedEventId)
    ) {
      return;
    }

    setSelectedEventId(visibleEvents[0]?.id ?? null);
  }, [selectedEventId, visibleEvents]);

  return (
    <>
      <PageHeader
        title="보안 이벤트"
        description="ICMP Flood, Port Scan 탐지 이벤트와 대응 상태를 관리합니다."
        connected={state.connected}
        source={state.source}
      />

      <div className="grid grid-cols-4 gap-4 max-xl:grid-cols-2 max-sm:grid-cols-1">
        <MetricCard label="전체 이벤트" value={formatNumber(state.securityEvents.length)} foot="최근 100개 API 조회" icon={ShieldAlert} tone="blue" />
        <MetricCard label="Critical" value={formatNumber(criticalCount)} foot="즉시 대응 필요" icon={AlertTriangle} tone="red" />
        <MetricCard label="High" value={formatNumber(highCount)} foot="우선 대응 대상" icon={Radio} tone="amber" />
        <MetricCard label="해소됨" value={formatNumber(resolvedCount)} foot="정상 복귀" icon={CheckCircle2} tone="teal" />
      </div>

      <div className="mt-4 grid items-start grid-cols-[1fr_360px] gap-4 max-xl:grid-cols-1">
        <Panel
          title="보안 이벤트 목록"
          action={
            <div className="flex flex-wrap items-center justify-end gap-2">
              <div className="font-mono-ui flex rounded border border-line2 bg-sidebar p-0.5 text-[10px]">
                {[
                  [ALL_EVENT_SCOPE, `전체 ${state.securityEvents.length}`],
                  [URGENT_EVENT_SCOPE, `긴급 처리 ${urgentCount}`],
                  [COMPLETED_EVENT_SCOPE, `처리 완료 ${completedCount}`]
                ].map(([scope, label]) => (
                  <button
                    key={scope}
                    type="button"
                    onClick={() => setEventScopeFilter(scope as EventScopeFilter)}
                    className={[
                      "rounded px-2.5 py-1",
                      eventScopeFilter === scope
                        ? "bg-[var(--red-dim)] text-red"
                        : "text-muted"
                    ].join(" ")}
                  >
                    {label}
                  </button>
                ))}
              </div>
              <div className="font-mono-ui relative text-[10px]">
                <button
                  type="button"
                  onClick={() => setAttackTypeDropdownOpen((open) => !open)}
                  className="flex h-8 min-w-36 items-center justify-between gap-2 rounded border border-line2 bg-sidebar px-3 text-left text-muted outline-none hover:border-accent hover:text-accent"
                >
                  <span>{attackTypeFilterLabel}</span>
                  <ChevronDown size={13} />
                </button>

                {attackTypeDropdownOpen ? (
                  <div className="absolute right-0 top-[calc(100%+4px)] z-30 grid w-52 gap-1 rounded border border-line2 bg-panel2 p-1 shadow-xl">
                    <button
                      type="button"
                      onClick={() => {
                        setSelectedAttackTypes([]);
                        setAttackTypeDropdownOpen(false);
                      }}
                      className={[
                        "flex items-center justify-between rounded px-2.5 py-2 text-left",
                        selectedAttackTypes.length === 0
                          ? "bg-[var(--accent-dim)] text-accent"
                          : "text-muted"
                      ].join(" ")}
                    >
                      <span>전체 유형</span>
                      {selectedAttackTypes.length === 0 ? <Check size={13} /> : null}
                    </button>
                    {attackTypeOptions.map((attackType) => {
                      const selected = selectedAttackTypes.includes(attackType);

                      return (
                        <button
                          key={attackType}
                          type="button"
                          onClick={() =>
                            setSelectedAttackTypes((prev) =>
                              selected
                                ? prev.filter((item) => item !== attackType)
                                : [...prev, attackType]
                            )
                          }
                          className={[
                            "flex items-center justify-between rounded px-2.5 py-2 text-left",
                            selected
                              ? "bg-[var(--accent-dim)] text-accent"
                              : "text-muted hover:bg-sidebar hover:text-ink"
                          ].join(" ")}
                        >
                          <span>{attackType.replaceAll("_", " ")}</span>
                          {selected ? <Check size={13} /> : null}
                        </button>
                      );
                    })}
                  </div>
                ) : null}
              </div>
              <input
                value={ipSearch}
                onChange={(event) => setIpSearch(event.target.value)}
                className="font-mono-ui h-8 w-40 rounded border border-line2 bg-sidebar px-3 text-[11px] outline-none"
                placeholder="IP 검색"
              />
            </div>
          }
        >
          <SecurityEventsTable
            events={visibleEvents}
            selectedEventId={selectedEvent?.id}
            onSelectEvent={(event) => setSelectedEventId(event.id)}
          />
        </Panel>

        <div className="grid items-start gap-4">
          <Panel title="이벤트 상세" bodyClassName="!p-4 !pb-4">
            {selectedEvent ? (
              <div className="font-mono-ui grid gap-4 text-[11px]">
                <div className="flex items-center justify-between">
                  <span className="text-faint">공격 유형</span>
                  <StatusBadge value={selectedEvent.attack_type} tone="critical" />
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-faint">위험도</span>
                  <StatusBadge value={selectedEvent.severity} tone="critical" />
                </div>
                <div className="flex items-center justify-between gap-3">
                  <span className="text-faint">출발지 / 목적지</span>
                  <strong className="truncate text-right">
                    <span className="text-accent">{selectedEvent.src_ip}</span>
                    <span className="mx-2 text-faint">→</span>
                    <span className="text-yellow">{selectedEvent.dst_ip}</span>
                  </strong>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-faint">트래픽</span>
                  <strong>{formatNumber(selectedEvent.pps)} pps · {formatBitsPerSecond(selectedEvent.bps)}</strong>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-faint">포트</span>
                  <strong>{selectedEvent.port_summary}</strong>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-faint">발생 시간</span>
                  <strong>{formatDateTime(selectedEvent.occurred_at)}</strong>
                </div>
                {selectedEvent.severity === "critical" ? (
                  <button className="rounded border border-red bg-[var(--red-dim)] px-3 py-2 text-center text-red">
                    처리 확인
                  </button>
                ) : isCompletedEvent(selectedEvent) ? (
                  <div className="flex items-center justify-between rounded border border-green bg-[var(--green-dim)] px-3 py-2 text-green">
                    <span>처리 완료</span>
                    <StatusBadge value={selectedEvent.status} tone="normal" />
                  </div>
                ) : (
                  <div className="grid grid-cols-3 gap-2 max-sm:grid-cols-1">
                    <button className="rounded border border-red bg-[var(--red-dim)] px-3 py-2 text-center text-red">차단</button>
                    <button className="rounded border border-line2 bg-[var(--yellow-dim)] px-3 py-2 text-center text-yellow">무시</button>
                    <button className="rounded border border-line2 bg-[var(--green-dim)] px-3 py-2 text-center text-green">해결</button>
                  </div>
                )}
              </div>
            ) : (
              <div className="font-mono-ui rounded border border-line bg-sidebar p-4 text-[11px] text-muted">
                수신된 보안 이벤트가 없습니다.
              </div>
            )}
          </Panel>

          <Panel title="공격 유형 분포">
            <div className="grid gap-3">
              {attackCounts.length ? (
                attackCounts.map(([label, value]) => (
                  <div key={label} className="font-mono-ui">
                    <div className="mb-1 flex justify-between text-[11px]">
                      <span className="text-muted">{label}</span>
                      <span>{value}</span>
                    </div>
                    <div className="h-1.5 rounded bg-sidebar">
                      <div className="h-full rounded bg-red" style={{ width: `${Math.max(value * 8, 4)}%` }} />
                    </div>
                  </div>
                ))
              ) : (
                <div className="font-mono-ui rounded border border-line bg-sidebar p-4 text-[11px] text-muted">
                  수신된 공격 유형이 없습니다.
                </div>
              )}
            </div>
          </Panel>
        </div>
      </div>
    </>
  );
}
