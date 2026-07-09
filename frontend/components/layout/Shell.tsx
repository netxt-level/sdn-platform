"use client";

import { useEffect, useState, type ReactNode } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Bell,
  GitBranch,
  LayoutDashboard,
  Network,
  Route,
} from "lucide-react";

const navItems = [
  { section: "Overview", href: "/", label: "대시보드", icon: LayoutDashboard },
  { section: "Overview", href: "/topology", label: "토폴로지", icon: Network },
  { section: "Monitoring", href: "/security/events", label: "보안 이벤트", icon: Bell },
  { section: "Monitoring", href: "/path", label: "경로 제어", icon: Route },
  { section: "Monitoring", href: "/flow-rules", label: "Flow Rule", icon: GitBranch }
];

const titles: Record<string, string> = {
  "/": "대시보드",
  "/topology": "토폴로지 시각화",
  "/security/events": "보안 이벤트 관리",
  "/path": "경로 제어",
  "/flow-rules": "Flow Rule 관리",
  "/settings": "설정"
};

type SecurityEventsResponse = {
  items?: Array<{
    severity?: string;
    status?: string;
  }>;
};

function isUnhandledHighRiskEvent(event: NonNullable<SecurityEventsResponse["items"]>[number]) {
  const severity = event.severity?.toLowerCase();
  const status = event.status?.toLowerCase();
  const isHighRisk = severity === "high" || severity === "critical";
  const isHandled =
    status === "blocked" ||
    status === "resolved" ||
    status === "ignored";

  return isHighRisk && !isHandled;
}

function hasUnhandledHighRiskEvent(events: SecurityEventsResponse["items"] = []) {
  return events.some((event) => {
    return isUnhandledHighRiskEvent(event);
  });
}

export function Shell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const [hasSecurityAlert, setHasSecurityAlert] = useState(false);
  const currentTitle =
    titles[pathname] ??
    Object.entries(titles).find(([href]) => href !== "/" && pathname.startsWith(href))?.[1] ??
    "대시보드";
  let section = "";

  useEffect(() => {
    let ignored = false;

    async function loadSecurityAlert() {
      try {
        const response = await fetch("/api/security/events?limit=100", {
          cache: "no-store"
        });

        if (!response.ok) {
          return;
        }

        const data = (await response.json()) as SecurityEventsResponse;

        if (!ignored) {
          setHasSecurityAlert(hasUnhandledHighRiskEvent(data.items));
        }
      } catch {
        // Keep the previous alert state when the sidebar refresh fails briefly.
      }
    }

    loadSecurityAlert();
    const intervalId = window.setInterval(loadSecurityAlert, 15000);

    return () => {
      ignored = true;
      window.clearInterval(intervalId);
    };
  }, []);

  return (
    <div className="min-h-screen bg-surface text-ink">
      <aside className="fixed left-0 top-0 z-40 flex h-screen w-[220px] flex-col border-r border-line bg-sidebar pb-6 max-md:static max-md:h-auto max-md:w-full max-md:flex-row max-md:items-center max-md:overflow-x-auto max-md:pb-0">
        <div className="border-b border-line px-5 py-7 max-md:border-b-0 max-md:border-r max-md:py-4">
          <div className="font-mono-ui text-lg font-black tracking-normal text-accent">
            SDN-GUARD
          </div>
          <div className="font-mono-ui mt-1 text-[10px] uppercase tracking-[0.2em] text-faint">
            Network Security
          </div>
        </div>

        <nav className="flex-1 py-3 max-md:flex max-md:min-w-max max-md:py-0" aria-label="주요 화면">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active =
              item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
            const showSection = section !== item.section;
            section = item.section;

            return (
              <div key={item.href} className="max-md:flex">
                {showSection && (
                  <div className="font-mono-ui px-3 pb-2 pt-4 text-[9px] uppercase tracking-[0.2em] text-faint max-md:hidden">
                    {item.section}
                  </div>
                )}
                <Link
                  href={item.href}
                  className={[
                    "flex min-h-10 items-center gap-2 border-l-2 px-5 text-[13px]",
                    active
                      ? "border-accent bg-[var(--accent-dim)] text-accent"
                      : "border-transparent text-muted hover:bg-panel hover:text-ink",
                    "max-md:h-14 max-md:border-l-0 max-md:border-b-2 max-md:px-4"
                  ].join(" ")}
                  title={item.label}
                >
                  <Icon className="h-4 w-4 shrink-0 opacity-80" />
                  <span className="whitespace-nowrap">{item.label}</span>
                  {item.href === "/security/events" && hasSecurityAlert && (
                    <span
                      className="ml-auto h-2 w-2 rounded-full bg-red max-md:ml-1"
                      aria-label="처리되지 않은 High 이상 보안 이벤트 있음"
                    />
                  )}
                </Link>
              </div>
            );
          })}
        </nav>

        <div className="mt-auto border-t border-line px-5 py-4 max-md:hidden">
          <span className="mr-2 inline-block h-[7px] w-[7px] rounded-full bg-green" />
          <span className="font-mono-ui text-[11px] text-muted">컨트롤러 연결됨</span>
        </div>
      </aside>

      <div className="ml-[220px] min-h-screen max-md:ml-0">
        <header className="sticky top-0 z-30 flex h-14 items-center border-b border-line bg-sidebar px-7 max-md:px-4">
          <div className="font-mono-ui text-sm text-muted">
            SDN-GUARD / <span className="text-ink">{currentTitle}</span>
          </div>
          <div className="ml-auto font-mono-ui rounded border border-line2 bg-[var(--accent-dim)] px-2.5 py-1 text-xs text-accent">
            LIVE READY
          </div>
        </header>

        <main className="min-w-0 p-7 max-md:p-4">{children}</main>
      </div>
    </div>
  );
}
