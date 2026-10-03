"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";
import { Search, Bell, Shield, Download, AlertTriangle, CheckCircle, Info } from "lucide-react";
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
        badge: "bg-threat-malicious/20 text-threat-malicious border-threat-malicious/40",
        icon: AlertTriangle,
      };
    case "warn":
      return {
        dot: "bg-threat-suspicious",
        badge: "bg-threat-suspicious/20 text-threat-suspicious border-threat-suspicious/40",
        icon: AlertTriangle,
      };
    case "ok":
      return {
        dot: "bg-threat-clean",
        badge: "bg-threat-clean/20 text-threat-clean border-threat-clean/40",
        icon: CheckCircle,
      };
    default:
      return {
        dot: "bg-threat-jit",
        badge: "bg-threat-jit/20 text-threat-jit border-threat-jit/40",
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
  const [greeting, setGreeting] = useState("Forensic Command Center");
  const [timeStr, setTimeStr] = useState("");
  const [isNotificationsOpen, setIsNotificationsOpen] = useState(false);
  const notificationsRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      const hrs = now.getHours();
      if (hrs < 12) setGreeting("Good Morning, Forensics Team");
      else if (hrs < 18) setGreeting("Good Afternoon, Forensics Team");
      else setGreeting("Good Evening, Forensics Team");

      setTimeStr(
        now.toISOString().replace("T", " ").substring(0, 19) + " UTC"
      );
    };

    updateTime();
    const timer = setInterval(updateTime, 1000);
    return () => clearInterval(timer);
  }, []);

  const handleClickOutside = useCallback((event: MouseEvent) => {
    if (notificationsRef.current && !notificationsRef.current.contains(event.target as Node)) {
      setIsNotificationsOpen(false);
      markAllRead();
    }
  }, [markAllRead]);

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

  const recentAlerts = alerts.slice(0, 5);

  return (
    <header className="h-16 px-6 bg-[#FAF7F2]/90 backdrop-blur-md border-b border-border flex items-center justify-between sticky top-0 z-20 shrink-0">
      {/* Left: Greeting & Clock */}
      <div className="flex items-center gap-4">
        <div>
          <h1 className="text-[15px] font-bold text-textBright tracking-tight">
            {greeting}
          </h1>
          <p className="text-xs font-mono text-textDim flex items-center gap-1.5 mt-0.5">
            <span className="w-1.5 h-1.5 rounded-full bg-lime" />
            <span className="tnum font-medium">{timeStr || "Synchronizing UTC..."}</span>
          </p>
        </div>
      </div>

      {/* Center: Search */}
      <div className="flex-1 max-w-md mx-6">
        <div className="relative">
          <Search className="w-3.5 h-3.5 text-textDim absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search process name, PID, memory address, or MITRE technique..."
            className="w-full bg-[#FFFFFF] text-xs text-textBright placeholder:text-textDim pl-9 pr-4 py-1.5 rounded-md border border-border focus:outline-none focus:border-lime/60 focus:ring-1 focus:ring-lime/40 transition-all font-mono"
            disabled
          />
        </div>
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-3">
        {/* Status Pill */}
        <div className="hidden sm:flex items-center gap-2 px-2.5 py-1 rounded-full bg-card border border-border text-[11px] font-mono">
          <span
            className={`w-2 h-2 rounded-full ${
              !isConnected
                ? "bg-threat-malicious"
                : "bg-lime animate-pulse shadow-[0_0_8px_rgba(232,121,60,0.35)]"
            }`}
          />
          <span className="text-textBright font-semibold tracking-wider text-[10px]">
            {!isConnected ? "GUARD OFFLINE" : "REAL-TIME GUARD"}
          </span>
        </div>

        {/* Scan Status Pill */}
        <div className="flex items-center gap-2 px-2.5 py-1 rounded bg-[#FFFFFF] border border-borderMuted text-xs font-mono">
          <Shield className={`w-3.5 h-3.5 ${!isConnected ? "text-threat-malicious" : "text-lime"}`} />
          <span className="text-textFog font-medium">Status:</span>
          <span className={`${!isConnected ? "text-threat-malicious font-bold" : "text-lime font-bold"}`}>
            {!isConnected
              ? "Disconnected"
              : isScanning
              ? "Scanning VADs..."
              : "Nominal"}
          </span>
        </div>

        {/* Density Toggle (Detailed / Compact) */}
        <div className="flex items-center p-0.5 rounded-md bg-[#F0EBE4] border border-border text-xs font-mono">
          <button
            type="button"
            onClick={() => setDensity("detailed")}
            className={`px-2.5 py-1 rounded text-[11px] font-medium transition-all ${
              density === "detailed"
                ? "bg-[#FFFFFF] text-lime font-bold shadow-xs"
                : "text-textDim hover:text-textBright"
            }`}
            title="Detailed mode: expanded layout with full spacing"
          >
            Detailed
          </button>
          <button
            type="button"
            onClick={() => setDensity("compact")}
            className={`px-2.5 py-1 rounded text-[11px] font-medium transition-all ${
              density === "compact"
                ? "bg-[#FFFFFF] text-lime font-bold shadow-xs"
                : "text-textDim hover:text-textBright"
            }`}
            title="Compact mode: condensed row heights and tighter spacing"
          >
            Compact
          </button>
        </div>

        {/* Notifications Dropdown */}
        <div className="relative" ref={notificationsRef}>
          <button
            onClick={toggleNotifications}
            className="relative p-2 rounded-md bg-card border border-border text-textFog hover:text-textBright hover:bg-raise transition-colors"
            title="Security Notifications"
            aria-expanded={isNotificationsOpen}
            aria-haspopup="true"
          >
            <Bell className="w-4 h-4" />
            {unreadCount > 0 && (
              <span className="absolute top-1 right-1 w-2 h-2 bg-threat-malicious rounded-full" />
            )}
          </button>

          {isNotificationsOpen && (
            <div className="absolute right-0 mt-2 w-80 sm:w-96 bg-card border border-border rounded-lg shadow-lg overflow-hidden z-50 animate-in fade-in-0 zoom-in-95">
              <div className="p-3 border-b border-border flex items-center justify-between">
                <h3 className="text-sm font-semibold text-textBright">Security Notifications</h3>
                {alerts.length > 0 && (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      markAllRead();
                    }}
                    className="text-[10px] font-mono text-textFog hover:text-lime transition-colors px-2 py-0.5 rounded hover:bg-raise"
                  >
                    Mark all read
                  </button>
                )}
              </div>

              {recentAlerts.length === 0 ? (
                <div className="p-6 text-center">
                  <Bell className="w-8 h-8 text-textDim/40 mx-auto mb-2" />
                  <p className="text-xs font-mono text-textFog">No security notifications</p>
                </div>
              ) : (
                <div className="max-h-[320px] overflow-y-auto">
                  {recentAlerts.map((alert) => {
                    const style = getSeverityStyle(alert.severity);

                    return (
                      <button
                        key={alert.id}
                        onClick={(e) => e.stopPropagation()}
                        className="w-full p-3 hover:bg-raise/50 border-b border-border/50 last:border-0 text-left transition-colors"
                      >
                        <div className="flex items-start gap-2">
                          <div className="flex-shrink-0 mt-0.5">
                            <span className={`w-1.5 h-1.5 rounded-full ${style.dot}`} />
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center justify-between gap-2">
                              <span className="text-xs font-bold text-textBright truncate font-mono">{alert.title}</span>
                              <span className="text-[10px] font-mono text-textDim shrink-0">{formatTimeAgo(alert.timestamp)}</span>
                            </div>
                            <p className="text-xs font-sans text-textFog leading-relaxed mt-0.5 truncate">{alert.message}</p>
                            {alert.technique && (
                              <span className={`inline-block mt-1 text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border ${style.badge}`}>
                                {alert.technique}
                              </span>
                            )}
                          </div>
                        </div>
                      </button>
                    );
                  })}
                </div>
              )}

              {alerts.length > 5 && (
                <div className="p-2 border-t border-border bg-[#FAF7F2]/50">
                  <a
                    href="/alerts"
                    onClick={(e) => {
                      e.stopPropagation();
                      setIsNotificationsOpen(false);
                    }}
                    className="block text-center text-xs font-mono text-lime hover:underline px-2 py-1"
                  >
                    View all {alerts.length} alerts →
                  </a>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Export Button */}
        <button
          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-card hover:bg-raise border border-border text-xs font-medium text-textBright transition-colors"
          title="Export Forensics Telemetry"
        >
          <Download className="w-3.5 h-3.5 text-textDim" />
          <span className="hidden md:inline font-sans">Export JSON</span>
        </button>
      </div>
    </header>
  );
}
