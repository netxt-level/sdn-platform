import { PageHeader } from "@/components/layout/PageHeader";
import { Panel } from "@/components/ui/Panel";

export default function SettingsPage() {
  return (
    <>
      <PageHeader
        title="설정"
        description="WebSocket 주소, 트래픽 임계값, 자동 대응 정책을 관리합니다."
      />

      <div className="grid grid-cols-12 gap-4">
        <Panel title="연결 설정" className="col-span-6 max-lg:col-span-12">
          <div className="grid gap-4">
            <label className="grid gap-2">
              <span className="text-xs font-black text-muted">WebSocket URL</span>
              <input
                className="font-mono-ui h-10 rounded border border-line2 bg-sidebar px-3 text-[11px] outline-none"
                defaultValue="ws://localhost:8000/ws/analyzer"
              />
            </label>
            <label className="grid gap-2">
              <span className="text-xs font-black text-muted">API Base URL</span>
              <input
                className="font-mono-ui h-10 rounded border border-line2 bg-sidebar px-3 text-[11px] outline-none"
                defaultValue="http://localhost:8000"
              />
            </label>
          </div>
        </Panel>

        <Panel title="탐지 임계값" className="col-span-6 max-lg:col-span-12">
          <div className="grid gap-4">
            <label className="grid gap-2">
              <span className="text-xs font-black text-muted">혼잡 임계값</span>
              <input className="font-mono-ui h-10 rounded border border-line2 bg-sidebar px-3 text-[11px] outline-none" defaultValue="70%" />
            </label>
            <label className="grid gap-2">
              <span className="text-xs font-black text-muted">ICMP Flood PPS</span>
              <input className="font-mono-ui h-10 rounded border border-line2 bg-sidebar px-3 text-[11px] outline-none" defaultValue="80" />
            </label>
          </div>
        </Panel>
      </div>
    </>
  );
}
