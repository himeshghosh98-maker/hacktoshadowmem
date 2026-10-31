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
          dot: "bg-threat-malicious",
          border: "border-threat-malicious/25 hover:border-threat-malicious/50",
          badge: "bg-threat-malicious/10 text-threat-malicious border-threat-malicious/30",
          icon: AlertTriangle,
        };
      case "warn":
        return {
          dot: "bg-threat-suspicious",
          border: "border-threat-suspicious/25 hover:border-threat-suspicious/50",
          badge: "bg-threat-suspicious/10 text-threat-suspicious border-threat-suspicious/30",
          icon: AlertTriangle,
        };
      case "ok":
        return {
          dot: "bg-threat-clean",
          border: "border-threat-clean/25 hover:border-threat-clean/50",
          badge: "bg-threat-clean/10 text-threat-clean border-threat-clean/30",
          icon: CheckCircle,
        };
      default:
        return {
          dot: "bg-threat-jit",
          border: "border-threat-jit/25 hover:border-threat-jit/50",
          badge: "bg-threat-jit/10 text-threat-jit border-threat-jit/30",
          icon: Info,
        };
    }
  };

  return (
    <div className="p-5 rounded-lg bg-card border border-border shadow-xs flex flex-col justify-between space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-border">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-threat-malicious" />
          <h3 className="text-sm font-semibold text-textBright tracking-tight">
            Recent Forensic Alerts
          </h3>
          {alerts.length > 0 && (
            <span className="px-2 py-0.5 rounded-full text-xs font-mono font-bold bg-threat-malicious/10 text-threat-malicious border border-threat-malicious/30">
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
        <div className="h-48 rounded-lg border border-dashed border-border bg-background/50 flex flex-col items-center justify-center gap-2 p-6 text-center">
          <Bell className="w-6 h-6 text-textDim" />
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
                className={`p-3 rounded-md bg-background border ${style.border} transition-colors cursor-pointer text-left`}
              >
                <div className="flex items-start gap-2.5">
                  <span className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${style.dot}`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-bold text-textBright truncate font-mono">
                        {alert.title}
                      </span>
                      <span className="text-xs font-mono text-textDim shrink-0">
                        {alert.timestamp}
                      </span>
                    </div>

                    <p className="text-xs text-textFog mt-0.5 leading-relaxed">
                      {alert.message}
                    </p>

                    {alert.technique && (
                      <span
                        className={`inline-block mt-2 text-xs font-mono px-2 py-0.5 rounded border ${style.badge}`}
                      >
                        {alert.technique}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
