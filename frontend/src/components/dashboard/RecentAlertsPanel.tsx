"use client";

import React from "react";
import { ShieldAlert, Trash2, Bell, AlertTriangle, CheckCircle, Info } from "lucide-react";
import { AlertItem } from "@/types/forensics";
import { LastUpdated } from "@/components/LastUpdated";

interface RecentAlertsPanelProps {
  alerts: AlertItem[];
  onClearAlerts?: () => void;
  onSelectAlert?: (alert: AlertItem) => void;
  lastUpdated?: number | null;
}

export function RecentAlertsPanel({
  alerts,
  onClearAlerts,
  onSelectAlert,
  lastUpdated,
}: RecentAlertsPanelProps) {
  const getSeverityStyle = (severity: AlertItem["severity"]) => {
    switch (severity) {
      case "critical":
        return {
          dot: "bg-threat-malicious shadow-[0_0_6px_#D6453D]",
          border: "border-threat-malicious/30 hover:border-threat-malicious/60",
          badge: "bg-threat-malicious/20 text-threat-malicious border-threat-malicious/40",
          icon: AlertTriangle,
        };
      case "warn":
        return {
          dot: "bg-threat-suspicious shadow-[0_0_6px_#E68A2E]",
          border: "border-threat-suspicious/30 hover:border-threat-suspicious/60",
          badge: "bg-threat-suspicious/20 text-threat-suspicious border-threat-suspicious/40",
          icon: AlertTriangle,
        };
      case "ok":
        return {
          dot: "bg-threat-clean shadow-[0_0_6px_#3D8B60]",
          border: "border-threat-clean/30 hover:border-threat-clean/60",
          badge: "bg-threat-clean/20 text-threat-clean border-threat-clean/40",
          icon: CheckCircle,
        };
      default:
        return {
          dot: "bg-threat-jit shadow-[0_0_6px_#4A7BB0]",
          border: "border-threat-jit/30 hover:border-threat-jit/60",
          badge: "bg-threat-jit/20 text-threat-jit border-threat-jit/40",
          icon: Info,
        };
    }
  };

  return (
    <div className="p-5 rounded-lg bg-card border border-border shadow-sm flex flex-col justify-between space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-border/80">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-threat-malicious" />
          <h3 className="text-sm font-semibold text-textBright tracking-tight">
            Recent Forensic Alerts
          </h3>
          {alerts.length > 0 && (
            <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono font-bold bg-threat-malicious/20 text-threat-malicious border border-threat-malicious/30 tracking-wider">
              {alerts.length}
            </span>
          )}
        </div>

        <div className="flex items-center gap-2.5">
          {alerts.length > 0 && <LastUpdated timestamp={lastUpdated} />}
          {alerts.length > 0 && onClearAlerts && (
            <button
              onClick={onClearAlerts}
              className="flex items-center gap-1 text-xs font-mono text-textFog hover:text-textBright transition-colors px-2 py-0.5 rounded hover:bg-raise font-medium"
            >
              <Trash2 className="w-3 h-3" />
              <span>Clear</span>
            </button>
          )}
        </div>
      </div>

      {/* Alerts Stream List */}
      {alerts.length === 0 ? (
        <div className="h-48 rounded-lg border border-dashed border-border/80 bg-[#FBF8F4] flex flex-col items-center justify-center gap-2 p-6 text-center">
          <Bell className="w-6 h-6 text-textDim/60" />
          <span className="text-sm font-semibold text-textBright font-sans">
            No Active Threat Alerts
          </span>
          <p className="text-xs font-sans text-textFog max-w-xs leading-relaxed">
            Live detection alerts from memory audits and WebSocket triggers will appear here in chronological order.
          </p>
        </div>
      ) : (
        <div className="space-y-2.5 max-h-[300px] overflow-y-auto pr-1">
          {alerts.map((alert) => {
            const style = getSeverityStyle(alert.severity);

            return (
              <div
                key={alert.id}
                onClick={() => onSelectAlert && onSelectAlert(alert)}
                className={`p-3 rounded-md bg-[#FAF7F2] hover:bg-white border ${style.border} transition-all cursor-pointer space-y-1.5 group shadow-2xs`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full shrink-0 ${style.dot}`} />
                    <span className="text-xs font-bold text-textBright group-hover:text-lime transition-colors">
                      {alert.title}
                    </span>
                  </div>

                  <div className="flex items-center gap-1.5 shrink-0">
                    {alert.technique && (
                      <span
                        className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border tracking-wider ${style.badge}`}
                      >
                        {alert.technique}
                      </span>
                    )}
                    <span className="text-xs font-mono text-textDim font-medium tnum">
                      {alert.timestamp}
                    </span>
                  </div>
                </div>

                <p className="text-xs font-sans text-textFog leading-relaxed pl-4">
                  {alert.message}
                </p>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
