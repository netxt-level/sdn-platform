"use client";

import type { ReactNode } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  Bell,
  GitBranch,
  LayoutDashboard,
  Network,
  Route,
  Shield,
} from "lucide-react";

const navItems = [
  { section: "Overview", href: "/", label: "대시보드", icon: LayoutDashboard },
  { section: "Overview", href: "/topology", label: "토폴로지", icon: Network },
  { section: "Monitoring", href: "/traffic", label: "트래픽 분석", icon: Activity },
  { section: "Monitoring", href: "/security/events", label: "보안 이벤트", icon: Bell, badge: "7" },
  { section: "Monitoring", href: "/security/rules", label: "규칙 관리", icon: Shield },
  { section: "Network", href: "/path", label: "경로 제어", icon: Route },
  { section: "Network", href: "/flow-rules", label: "Flow Rule", icon: GitBranch }
];

const titles: Record<string, string> = {
  "/": "대시보드",
  "/topology": "토폴로지 시각화",
  "/traffic": "트래픽 분석",
  "/security/events": "보안 이벤트 관리",
  "/security/rules": "규칙 관리",
  "/path": "경로 제어",
  "/flow-rules": "Flow Rule 관리",
  "/settings": "설정"
};

export function Shell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const currentTitle =
    titles[pathname] ??
    Object.entries(titles).find(([href]) => href !== "/" && pathname.startsWith(href))?.[1] ??
    "대시보드";
  let section = "";

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
                  {item.badge && (
                    <span className="font-mono-ui ml-auto rounded-full bg-red px-1.5 py-0.5 text-[10px] text-white max-md:ml-1">
                      {item.badge}
                    </span>
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
