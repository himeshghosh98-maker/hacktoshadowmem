"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";
import { Bell, Shield, Download, AlertTriangle, CheckCircle, Info } from "lucide-react";
import { useDensity } from "@/context/DensityContext";
import { useConnection } from "@/context/ConnectionContext";
import { useNotifications } from "@/context/NotificationsContext";
import { AlertItem } from "@/types/forensics";

interface HeaderProps {
  isScanning?: boolean;
}

function getSeverityStyle(severity: AlertItem["severity"]) {
  switch (severity) {
    case "critical":
      return {
        dot: "bg-threat-malicious",
        badge: "bg-threat-malicious/10 text-threat-malicious border-threat-malicious/30",
        icon: AlertTriangle,
      };
    case "warn":
      return {
        dot: "bg-threat-suspicious",
        badge: "bg-threat-suspicious/10 text-threat-suspicious border-threat-suspicious/30",
        icon: AlertTriangle,
      };
    case "ok":
      return {
        dot: "bg-threat-clean",
        badge: "bg-threat-clean/10 text-threat-clean border-threat-clean/30",
        icon: CheckCircle,
      };
    default:
      return {
        dot: "bg-threat-jit",
        badge: "bg-threat-jit/10 text-threat-jit border-threat-jit/30",
        icon: Info,
      };
  }
}

function formatTimeAgo(timestamp: string): string {
  try {
    const alertTime = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - alertTime.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return "Just now";
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    return `${diffDays}d ago`;
  } catch {
    return timestamp;
  }
}

export function Header({ isScanning }: HeaderProps) {
  const { density, setDensity } = useDensity();
  const { isConnected } = useConnection();
  const { alerts, unreadCount, markAllRead } = useNotifications();
  const [timeStr, setTimeStr] = useState("");
  const [isNotificationsOpen, setIsNotificationsOpen] = useState(false);
  const notificationsRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTimeStr(now.toISOString().replace("T", " ").substring(0, 19) + " UTC");
    };

    updateTime();
    const timer = setInterval(updateTime, 1000);
    return () => clearInterval(timer);
  }, []);

  const handleClickOutside = useCallback(
    (event: MouseEvent) => {
      if (
        notificationsRef.current &&
        !notificationsRef.current.contains(event.target as Node)
      ) {
        setIsNotificationsOpen(false);
        markAllRead();
      }
    },
    [markAllRead]
  );

  useEffect(() => {
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [handleClickOutside]);

  const toggleNotifications = (e: React.MouseEvent) => {
    e.stopPropagation();
    setIsNotificationsOpen((prev) => !prev);
    if (!isNotificationsOpen) {
      markAllRead();
    }
  };

  const handleExportData = () => {
    try {
      const exportBlob = new Blob(
        [
          JSON.stringify(
            {
              exportedAt: new Date().toISOString(),
              alerts,
              systemState: { isConnected, isScanning },
            },
            null,
            2
          ),
        ],
        { type: "application/json" }
      );
      const url = URL.createObjectURL(exportBlob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `shadowmem-forensics-${Date.now()}.json`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error("Export failed:", e);
    }
  };

  const recentAlerts = alerts.slice(0, 5);

  return (
    <header className="h-16 px-6 bg-card/85 backdrop-blur-md border-b border-border flex items-center justify-between sticky top-0 z-20 shrink-0">
      {/* Left: Brand Identity & UTC Clock */}
      <div className="flex items-center gap-4">
        <div>
          <h1 className="text-sm font-semibold text-textBright tracking-tight">
            Forensic Command Center
          </h1>
          <p className="text-xs font-mono text-textDim flex items-center gap-1.5 mt-0.5">
            <span className="w-1.5 h-1.5 rounded-full bg-lime" />
            <span className="font-medium">{timeStr || "Synchronizing UTC..."}</span>
          </p>
        </div>
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-3">
        {/* Unified Engine Status Indicator */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-background border border-border text-xs font-mono">
          <span
            className={`w-2 h-2 rounded-full ${
              !isConnected
                ? "bg-threat-malicious"
                : isScanning
                ? "bg-lime animate-ping"
                : "bg-threat-clean"
            }`}
          />
          <span className="text-textFog font-medium">
            {!isConnected
              ? "Engine Offline"
              : isScanning
              ? "Scanning Volatile Memory..."
              : "Engine Ready"}
          </span>
        </div>

        {/* View Density Switcher */}
        <div className="flex items-center p-0.5 rounded-md bg-background border border-border text-xs font-mono">
          <button
            type="button"
            onClick={() => setDensity("detailed")}
            className={`px-2.5 py-1 rounded transition-colors ${
              density === "detailed"
                ? "bg-card text-lime font-semibold shadow-xs"
                : "text-textDim hover:text-textBright"
            }`}
            title="Detailed mode: expanded layout"
          >
            Detailed
          </button>
          <button
            type="button"
            onClick={() => setDensity("compact")}
            className={`px-2.5 py-1 rounded transition-colors ${
              density === "compact"
                ? "bg-card text-lime font-semibold shadow-xs"
                : "text-textDim hover:text-textBright"
            }`}
            title="Compact mode: condensed data view"
          >
            Compact
          </button>
        </div>

        {/* Notifications Dropdown */}
        <div className="relative" ref={notificationsRef}>
          <button
            onClick={toggleNotifications}
            className="relative p-2 rounded-md bg-card border border-border text-textFog hover:text-textBright hover:bg-raise transition-colors"
            title="Security Alerts"
            aria-expanded={isNotificationsOpen}
            aria-haspopup="true"
          >
            <Bell className="w-4 h-4" />
            {unreadCount > 0 && (
              <span className="absolute top-1 right-1 w-2 h-2 bg-threat-malicious rounded-full ring-2 ring-card" />
            )}
          </button>

          {isNotificationsOpen && (
            <div className="absolute right-0 mt-2 w-80 sm:w-96 bg-card border border-border rounded-lg shadow-lg overflow-hidden z-50">
              <div className="p-3 border-b border-border flex items-center justify-between">
                <h3 className="text-xs font-semibold text-textBright uppercase tracking-wider font-mono">
                  Security Alerts ({alerts.length})
                </h3>
                {alerts.length > 0 && (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      markAllRead();
                    }}
                    className="text-xs font-mono text-lime hover:underline px-1 py-0.5"
                  >
                    Mark all read
                  </button>
                )}
              </div>

              {recentAlerts.length === 0 ? (
                <div className="p-6 text-center">
                  <Shield className="w-8 h-8 text-textDim/40 mx-auto mb-2" />
                  <p className="text-xs font-mono text-textFog">No active security alerts</p>
                </div>
              ) : (
                <div className="max-h-72 overflow-y-auto divide-y divide-border/60">
                  {recentAlerts.map((alert) => {
                    const style = getSeverityStyle(alert.severity);

                    return (
                      <div
                        key={alert.id}
                        className="p-3 hover:bg-raise/40 text-left transition-colors"
                      >
                        <div className="flex items-start gap-2.5">
                          <span className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${style.dot}`} />
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center justify-between gap-2">
                              <span className="text-xs font-bold text-textBright truncate font-mono">
                                {alert.title}
                              </span>
                              <span className="text-xs font-mono text-textDim shrink-0">
                                {formatTimeAgo(alert.timestamp)}
                              </span>
                            </div>
                            <p className="text-xs text-textFog mt-0.5 line-clamp-2">
                              {alert.message}
                            </p>
                            {alert.technique && (
                              <span
                                className={`inline-block mt-1 text-xs font-mono px-2 py-0.5 rounded border ${style.badge}`}
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

              {alerts.length > 5 && (
                <div className="p-2 border-t border-border bg-background text-center">
                  <a
                    href="/alerts"
                    onClick={(e) => {
                      e.stopPropagation();
                      setIsNotificationsOpen(false);
                    }}
                    className="text-xs font-mono text-lime hover:underline"
                  >
                    View all {alerts.length} alerts &rarr;
                  </a>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Export Telemetry */}
        <button
          onClick={handleExportData}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-card hover:bg-raise border border-border text-xs font-medium text-textBright transition-colors"
          title="Export Forensics Telemetry as JSON"
        >
          <Download className="w-3.5 h-3.5 text-textDim" />
          <span className="hidden md:inline font-sans">Export JSON</span>
        </button>
      </div>
    </header>
  );
}
