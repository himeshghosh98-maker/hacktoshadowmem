"use client";

import React, { useState, useEffect } from "react";
import {
  ShieldAlert,
  AlertTriangle,
  CheckCircle,
  Info,
  Trash2,
  Play,
  Search,
  Radio,
  Loader2,
} from "lucide-react";
import { AlertItem, ProcessEntry } from "@/types/forensics";
import { connectAlertsWebSocket, fetchScan } from "@/lib/api";
import { ProcessDossierModal } from "@/components/dashboard/ProcessDossierModal";
import { LastUpdated } from "@/components/LastUpdated";
import { useNotifications } from "@/context/NotificationsContext";

type SeverityFilter = "ALL" | "critical" | "warn" | "info";

export default function AlertsPage() {
  const { alerts, addAlert, clearAlerts } = useNotifications();
  const [lastUpdated, setLastUpdated] = useState<number | null>(null);
  const [processes, setProcesses] = useState<ProcessEntry[]>([]);
  const [wsConnected, setWsConnected] = useState(false);
  const [activeFilter, setActiveFilter] = useState<SeverityFilter>("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [isSimulating, setIsSimulating] = useState(false);
  const [selectedProcess, setSelectedProcess] = useState<ProcessEntry | null>(null);

  // Connect to live WebSocket and fetch processes
  useEffect(() => {
    fetchScan()
      .then((data) => {
        setProcesses(data.processes || []);
        // Synthesize initial alerts from scan if malicious/suspicious
        const initialAlerts: AlertItem[] = (data.processes || [])
          .filter(
            (p) =>
              p.status === "Malicious (Injected)" || p.status === "Suspicious"
          )
          .map((p) => ({
            id: `init-alert-${p.pid}`,
            title:
              p.status === "Malicious (Injected)"
                ? `Critical In-Memory Threat: ${p.name}`
                : `Suspicious Allocation: ${p.name}`,
            message: `PID ${p.pid} scored ${p.threat_score.toFixed(1)}% threat confidence. ${
              p.classification?.name
                ? `Technique: ${p.classification.name}.`
                : "VAD protection anomalies detected."
            }`,
            severity: p.status === "Malicious (Injected)" ? "critical" : "warn",
            timestamp: new Date().toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit",
            }),
            technique: p.classification?.id || p.classification?.mitre_id || null,
            pid: p.pid,
          }));
        initialAlerts.forEach((a) => addAlert(a));
        if (initialAlerts.length > 0) setLastUpdated(Date.now());
      })
      .catch(() => {});

    const disconnect = connectAlertsWebSocket(
      (newAlert) => {
        addAlert(newAlert);
        setLastUpdated(Date.now());
      },
      (connected) => {
        setWsConnected(connected);
      }
    );

    return () => {
      disconnect();
    };
  }, [addAlert]);

  // Trigger simulated threat alert via POST /simulate/alert
  const handleSimulateAlert = async () => {
    setIsSimulating(true);
    try {
      await fetch("/simulate/alert", { method: "POST" });
    } catch (err) {
      console.error("Simulation error:", err);
    } finally {
      setIsSimulating(false);
    }
  };

  const getSeverityStyle = (severity: AlertItem["severity"]) => {
    switch (severity) {
      case "critical":
        return {
          badge: "bg-threat-malicious/20 text-threat-malicious border-threat-malicious/40",
          border: "border-threat-malicious/30 hover:border-threat-malicious/60",
          dot: "bg-threat-malicious shadow-[0_0_6px_#D6453D]",
          icon: AlertTriangle,
        };
      case "warn":
        return {
          badge: "bg-threat-suspicious/20 text-threat-suspicious border-threat-suspicious/40",
          border: "border-threat-suspicious/30 hover:border-threat-suspicious/60",
          dot: "bg-threat-suspicious shadow-[0_0_6px_#E68A2E]",
          icon: AlertTriangle,
        };
      case "ok":
        return {
          badge: "bg-threat-clean/20 text-threat-clean border-threat-clean/40",
          border: "border-threat-clean/30 hover:border-threat-clean/60",
          dot: "bg-threat-clean shadow-[0_0_6px_#3D8B60]",
          icon: CheckCircle,
        };
      default:
        return {
          badge: "bg-threat-jit/20 text-threat-jit border-threat-jit/40",
          border: "border-threat-jit/30 hover:border-threat-jit/60",
          dot: "bg-threat-jit shadow-[0_0_6px_#4A7BB0]",
          icon: Info,
        };
    }
  };

  const filteredAlerts = alerts.filter((a) => {
    if (activeFilter !== "ALL" && a.severity !== activeFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchTitle = a.title.toLowerCase().includes(q);
      const matchMsg = a.message.toLowerCase().includes(q);
      const matchTech = a.technique?.toLowerCase().includes(q) || false;
      const matchPid = a.pid ? a.pid.toString().includes(q) : false;
      if (!matchTitle && !matchMsg && !matchTech && !matchPid) return false;
    }
    return true;
  });

  const countCritical = alerts.filter((a) => a.severity === "critical").length;
  const countWarn = alerts.filter((a) => a.severity === "warn").length;
  const countInfo = alerts.filter((a) => a.severity === "info" || a.severity === "ok").length;

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-10">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-lg bg-card border border-border shadow-sm">
        <div>
          <div className="flex items-center gap-2.5">
            <ShieldAlert className="w-5 h-5 text-threat-malicious" />
            <h2 className="text-2xl sm:text-[26px] font-bold tracking-tight text-textBright">
              Threat Alerts & Detection Events
            </h2>
            <div className="flex items-center gap-1.5 px-2.5 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider bg-lime/15 text-lime border border-lime/30">
              <span className="w-1.5 h-1.5 rounded-full bg-lime animate-pulse" />
              <span>STREAM: /ws/alerts</span>
            </div>
            <span
              className={`hidden sm:inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-mono font-semibold tracking-wider border ${
                wsConnected
                  ? "bg-threat-clean/15 text-threat-clean border-threat-clean/30"
                  : "bg-threat-suspicious/15 text-threat-suspicious border-threat-suspicious/30"
              }`}
            >
              <Radio className="w-2.5 h-2.5" />
              {wsConnected ? "SOCKET LINKED" : "CONNECTING..."}
            </span>
          </div>
          <p className="text-sm font-normal text-textFog mt-1.5 font-sans leading-relaxed">
            Real-time WebSocket alerts stream, synthetic simulator broadcasts, MITRE classification tags & forensic remediation.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleSimulateAlert}
            disabled={isSimulating}
            className="flex items-center gap-1.5 px-3 py-2 rounded-md font-mono text-xs font-medium text-textBright bg-raise hover:bg-card border border-border transition-colors disabled:opacity-50"
            title="Dispatch simulated threat over /simulate/alert"
          >
            {isSimulating ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin text-lime" />
            ) : (
              <Play className="w-3.5 h-3.5 text-lime" />
            )}
            <span>Simulate Alert Event</span>
          </button>

          <button
            onClick={clearAlerts}
            disabled={alerts.length === 0}
            className="flex items-center gap-1.5 px-3 py-2 rounded-md font-mono text-xs font-medium text-textDim hover:text-threat-malicious bg-raise hover:bg-card border border-border transition-colors disabled:opacity-50"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Clear Stream</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-lg bg-card border border-border shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        {/* Severity Tabs */}
        <div className="flex flex-wrap items-center gap-1 bg-[#F5F1EB] p-1 rounded-md border border-border">
          {(
            [
              { key: "ALL", label: "ALL EVENTS", count: alerts.length },
              { key: "critical", label: "CRITICAL", count: countCritical },
              { key: "warn", label: "WARNINGS", count: countWarn },
              { key: "info", label: "INFO / SYS", count: countInfo },
            ] as const
          ).map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveFilter(tab.key)}
              className={`px-3 py-1.5 rounded text-xs font-mono transition-all flex items-center gap-1.5 ${
                activeFilter === tab.key
                  ? "bg-white text-lime border border-border font-bold shadow-xs"
                  : "text-textFog font-medium hover:text-textBright"
              }`}
            >
              <span>{tab.label}</span>
              <span
                className={`text-[10px] px-1.5 py-0.2 rounded-full font-semibold ${
                  activeFilter === tab.key
                    ? "bg-lime/20 text-lime"
                    : "bg-border text-textDim"
                }`}
              >
                {tab.count}
              </span>
            </button>
          ))}
        </div>

        {/* Search & Freshness */}
        <div className="flex items-center gap-3 w-full md:w-auto">
          {alerts.length > 0 && <LastUpdated timestamp={lastUpdated} />}
          <div className="relative w-full md:w-80">
            <Search className="w-3.5 h-3.5 text-textDim absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search alerts by title, message, or PID..."
              className="w-full bg-[#FAF7F2] text-xs text-textBright placeholder:text-textDim pl-9 pr-4 py-1.5 rounded-md border border-border focus:outline-none focus:border-lime/60 focus:ring-1 focus:ring-lime/40 transition-all font-mono"
            />
          </div>
        </div>
      </div>

      {/* Alerts Stream List Container */}
      <div className="p-5 rounded-lg bg-card border border-border shadow-sm space-y-3">
        {filteredAlerts.length === 0 ? (
          <div className="h-72 rounded-lg border border-dashed border-border/80 bg-[#FBF8F4] flex flex-col items-center justify-center gap-3 p-8 text-center">
            <div className="w-14 h-14 rounded-full bg-raise/60 border border-border flex items-center justify-center">
              <ShieldAlert className="w-7 h-7 text-textDim" />
            </div>
            <div className="space-y-1">
              <h3 className="text-sm font-semibold text-textBright">
                No Detection Alerts
              </h3>
              <p className="text-xs font-mono text-textDim max-w-sm">
                No alerts currently match the filter criteria. Trigger a simulated alert or run a memory audit to generate events.
              </p>
            </div>
            <button
              onClick={handleSimulateAlert}
              disabled={isSimulating}
              className="mt-2 flex items-center gap-2 px-4 py-2 rounded-md font-sans text-xs font-semibold bg-lime text-white hover:bg-lime-hover shadow-[0_2px_8px_rgba(232,121,60,0.3)] transition-colors"
            >
              <Play className="w-3.5 h-3.5 fill-white text-white" />
              <span>Dispatch Test Alert</span>
            </button>
          </div>
        ) : (
          <div className="space-y-3">
            {filteredAlerts.map((alert) => {
              const style = getSeverityStyle(alert.severity);

              return (
                <div
                  key={alert.id}
                  className={`p-4 rounded-lg bg-[#FAF7F2] hover:bg-white border ${style.border} transition-all space-y-2 group shadow-2xs`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2.5">
                      <span className={`w-2.5 h-2.5 rounded-full shrink-0 ${style.dot}`} />
                      <h4 className="text-sm font-bold text-textBright font-mono group-hover:text-lime transition-colors">
                        {alert.title}
                      </h4>
                    </div>

                    <div className="flex items-center gap-2 self-start sm:self-auto">
                      {alert.technique && (
                        <span
                          className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${style.badge}`}
                        >
                          {alert.technique}
                        </span>
                      )}
                      <span className="text-[11px] font-mono text-textDim tnum">
                        {alert.timestamp}
                      </span>
                    </div>
                  </div>

                  <p className="text-xs font-mono text-textFog leading-relaxed pl-5">
                    {alert.message}
                  </p>

                  {alert.pid && (
                    <div className="pl-5 pt-2 flex items-center gap-3">
                      <button
                        onClick={() => {
                          const matched = processes.find((p) => p.pid === alert.pid);
                          if (matched) setSelectedProcess(matched);
                        }}
                        className="text-[11px] font-mono text-lime hover:underline flex items-center gap-1"
                      >
                        <span>Inspect PID {alert.pid} in Forensic Dossier</span>
                      </button>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Forensic Dossier Modal */}
      {selectedProcess && (
        <ProcessDossierModal
          process={selectedProcess}
          onClose={() => setSelectedProcess(null)}
        />
      )}
    </div>
  );
}