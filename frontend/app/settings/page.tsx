"use client";

import { useEffect, useState } from "react";
import { PageHeader } from "@/components/layout/PageHeader";
import { Panel } from "@/components/ui/Panel";

type PlatformSettings = {
  controller_base_url: string;
  congestion_threshold_percent: number;
  automatic_response_enabled: boolean;
  updated_at?: string;
};

export default function SettingsPage() {
  const [settings, setSettings] = useState<PlatformSettings | null>(null);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let ignored = false;
    fetch("/api/settings", { cache: "no-store" })
      .then(async (response) => {
        if (!response.ok) throw new Error("설정을 불러오지 못했습니다.");
        return response.json() as Promise<PlatformSettings>;
      })
      .then((payload) => {
        if (!ignored) setSettings(payload);
      })
      .catch((loadError) => {
        if (!ignored) {
          setError(loadError instanceof Error ? loadError.message : "설정 조회 실패");
        }
      });
    return () => {
      ignored = true;
    };
  }, []);

  async function saveSettings() {
    if (!settings) return;
    setSaving(true);
    setMessage(null);
    setError(null);
    try {
      const response = await fetch("/api/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          congestion_threshold_percent: settings.congestion_threshold_percent,
          automatic_response_enabled: settings.automatic_response_enabled
        })
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => null);
        throw new Error(payload?.detail ?? "설정 저장에 실패했습니다.");
      }
      setSettings(await response.json());
      setMessage("설정이 저장되었습니다.");
    } catch (saveError) {
      setError(saveError instanceof Error ? saveError.message : "설정 저장 실패");
    } finally {
      setSaving(false);
    }
  }

  return (
    <>
      <PageHeader
        title="설정"
        description="Controller 연결 정보와 실제 자동 대응 정책을 관리합니다."
      />

      <div className="grid grid-cols-12 gap-4">
        <Panel title="연결 설정" className="col-span-6 max-lg:col-span-12">
          <label className="grid gap-2">
            <span className="text-xs font-black text-muted">Controller API URL</span>
            <input
              readOnly
              value={settings?.controller_base_url ?? "불러오는 중"}
              className="font-mono-ui h-10 rounded border border-line2 bg-sidebar px-3 text-[11px] text-muted outline-none"
            />
            <span className="text-[11px] text-faint">서버 환경 변수 CONTROLLER_BASE_URL에서 관리됩니다.</span>
          </label>
        </Panel>

        <Panel title="대응 정책" className="col-span-6 max-lg:col-span-12">
          <div className="grid gap-5">
            <label className="grid gap-2">
              <span className="text-xs font-black text-muted">혼잡 임계값 (%)</span>
              <input
                type="number"
                min={1}
                max={100}
                disabled={!settings}
                value={settings?.congestion_threshold_percent ?? 70}
                onChange={(event) =>
                  setSettings((current) => current ? {
                    ...current,
                    congestion_threshold_percent: Number(event.target.value)
                  } : current)
                }
                className="font-mono-ui h-10 rounded border border-line2 bg-sidebar px-3 text-[11px] outline-none disabled:opacity-50"
              />
            </label>
            <label className="flex items-center justify-between rounded border border-line2 bg-sidebar px-3 py-3">
              <span>
                <strong className="block text-xs">자동 대응</strong>
                <span className="mt-1 block text-[11px] text-faint">Analyzer mitigation을 Controller에 자동 적용합니다.</span>
              </span>
              <input
                type="checkbox"
                disabled={!settings}
                checked={settings?.automatic_response_enabled ?? false}
                onChange={(event) =>
                  setSettings((current) => current ? {
                    ...current,
                    automatic_response_enabled: event.target.checked
                  } : current)
                }
                className="h-4 w-4 accent-[var(--accent)]"
              />
            </label>
            <button
              type="button"
              disabled={!settings || saving}
              onClick={saveSettings}
              className="rounded border border-accent bg-[var(--accent-dim)] px-4 py-2 text-sm text-accent disabled:opacity-50"
            >
              {saving ? "저장 중" : "설정 저장"}
            </button>
            {message ? <p className="text-xs text-green">{message}</p> : null}
            {error ? <p className="text-xs text-red">{error}</p> : null}
          </div>
        </Panel>
      </div>
    </>
  );
}
