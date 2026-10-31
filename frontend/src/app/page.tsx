"use client";

import React, { useState, useEffect, useCallback } from "react";
import { Play, RotateCcw, Loader2, AlertCircle, Radio, Zap } from "lucide-react";
import {
  ProcessEntry,
  ScanSummary,
  KernelLogItem,
  ScanHistoryRecord,
} from "@/types/forensics";
import {
  fetchScan,
  isolateProcess,
  resumeProcess,
  fetchAudit,
  simulateAlert,
} from "@/lib/api";
import { StatCards } from "@/components/dashboard/StatCards";
import { LiveProcessMapPanel } from "@/components/dashboard/LiveProcessMapPanel";
import { ThreatPosturePanel } from "@/components/dashboard/ThreatPosturePanel";
import { RecentAlertsPanel } from "@/components/dashboard/RecentAlertsPanel";
import { AnalyticsRow } from "@/components/dashboard/AnalyticsRow";
import { KernelTelemetryFeed } from "@/components/dashboard/KernelTelemetryFeed";
import { ProcessDossierModal } from "@/components/dashboard/ProcessDossierModal";
import { useNotifications } from "@/context/NotificationsContext";
import { useConnection } from "@/context/ConnectionContext";

export default function OverviewPage() {
  const { addAlert, alerts, clearAlerts } = useNotifications();
  const { wsConnected, subscribeAlerts } = useConnection();
  const [hasScanned, setHasScanned] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [isSimulating, setIsSimulating] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [avgScanTimeMs, setAvgScanTimeMs] = useState(0);

  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [processes, setProcesses] = useState<ProcessEntry[]>([]);
  const [isolatedPids, setIsolatedPids] = useState<Set<number>>(new Set());
  const [scanHistory, setScanHistory] = useState<ScanHistoryRecord[]>([]);
  const [kernelLogs, setKernelLogs] = useState<KernelLogItem[]>([]);

  const [isTickerPaused, setIsTickerPaused] = useState(false);
  const [selectedProcess, setSelectedProcess] = useState<ProcessEntry | null>(null);
  const [isIsolating, setIsIsolating] = useState(false);

  // Freshness timestamps
  const [lastScanTime, setLastScanTime] = useState<number | null>(null);
  const [lastAlertTime, setLastAlertTime] = useState<number | null>(null);
  const [lastKernelLogTime, setLastKernelLogTime] = useState<number | null>(null);

  // Helper to append a kernel telemetry log
  const appendLog = useCallback(
    (
      tag: KernelLogItem["tag"],
      msg: string,
      level: KernelLogItem["level"] = "info"
    ) => {
      setLastKernelLogTime(Date.now());
      setKernelLogs((prev) => {
        const next = [
          ...prev,
          {
            id: `log-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
            tag,
            msg,
            level,
            timestamp: new Date().toISOString().substring(11, 19),
          },
        ];
        return next.slice(-120);
      });
    },
    []
  );

  // 1. Initial audit sync & WebSocket alerts listener
  useEffect(() => {
    fetchAudit()
      .then((auditRes) => {
        if (auditRes.actions && auditRes.actions.length > 0) {
          const currentlyIsolated = new Set<number>();
          auditRes.actions.forEach((act) => {
            if (act.success) {
              if (act.action === "isolate") currentlyIsolated.add(act.pid);
              if (act.action === "resume") currentlyIsolated.delete(act.pid);
            }
          });
          setIsolatedPids(currentlyIsolated);
        }
      })
      .catch(() => {});

    const unsubscribe = subscribeAlerts((wsAlert) => {
      addAlert(wsAlert);
      setLastAlertTime(Date.now());
      appendLog(
        "SYS",
        `[WS ALERT] ${wsAlert.title}: ${wsAlert.message}`,
        wsAlert.severity === "critical" ? "danger" : "warning"
      );
    });

    return () => {
      unsubscribe();
    };
  }, [appendLog, addAlert, subscribeAlerts]);

  // 2. Real memory scan execution via GET /api/v1/scan
  const handleExecuteScan = async () => {
    setIsScanning(true);
    setScanError(null);
    appendLog(
      "SCAN",
      "Initiating parallel VAD memory audit across active Windows processes...",
      "info"
    );

    const t0 = performance.now();

    try {
      const data = await fetchScan();
      const elapsed = Math.round(performance.now() - t0);

      setAvgScanTimeMs(elapsed);
      setSummary(data.summary);

      const enrichedProcesses = (data.processes || []).map((p) => ({
        ...p,
        is_isolated: isolatedPids.has(p.pid),
      }));
      setProcesses(enrichedProcesses);
      setHasScanned(true);
      setLastScanTime(Date.now());

      const nowLabel = new Date().toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });

      const newHistoryRecord: ScanHistoryRecord = {
        scanIndex: scanHistory.length + 1,
        timestamp: new Date().toISOString(),
        timeLabel: nowLabel,
        durationMs: elapsed,
        totalScanned: data.summary.total_scanned,
        malicious: data.summary.malicious_count,
        suspicious: data.summary.suspicious_count,
        threats: data.summary.anomalies_detected,
      };

      setScanHistory((prev) => [...prev, newHistoryRecord]);

      appendLog(
        "SCAN",
        `Memory audit complete: ${data.summary.total_scanned} processes inspected in ${elapsed}ms (${data.summary.anomalies_detected} anomalies).`,
        data.summary.anomalies_detected > 0 ? "warning" : "success"
      );

      enrichedProcesses
        .filter(
          (p) =>
            p.status === "Malicious (Injected)" || p.status === "Suspicious"
        )
        .forEach((p) => {
          const isMal = p.status === "Malicious (Injected)";
          addAlert({
            id: `scan-alert-${p.pid}-${Date.now()}`,
            title: isMal
              ? `Critical In-Memory Threat: ${p.name}`
              : `Suspicious Allocation: ${p.name}`,
            message: `PID ${p.pid} scored ${p.threat_score.toFixed(1)}% threat score. ${
              p.classification?.name
                ? `Technique: ${p.classification.name}.`
                : "Protection anomalies detected."
            }`,
            severity: isMal ? "critical" : "warn",
            timestamp: nowLabel,
            technique: p.classification?.id || p.classification?.mitre_id || null,
            pid: p.pid,
          });
          setLastAlertTime(Date.now());
        });

      if (data.summary.anomalies_detected === 0) {
        addAlert({
          id: `scan-clean-${Date.now()}`,
          title: "Memory Audit Clean",
          message: `Scan complete: ${data.summary.total_scanned} processes inspected. Zero threats detected.`,
          severity: "ok",
          timestamp: nowLabel,
        });
        setLastAlertTime(Date.now());
      }
    } catch (err: unknown) {
      const errMsg =
        err instanceof Error ? err.message : "Failed to execute memory scan.";
      setScanError(errMsg);
      appendLog("SCAN", `Scan failed: ${errMsg}`, "danger");
    } finally {
      setIsScanning(false);
    }
  };

  // 3. One-click Live Judge Demo Simulation
  const handleTriggerDemo = async () => {
    setIsSimulating(true);
    appendLog(
      "SYS",
      "[SIMULATION] Injecting Cobalt Strike Reflective DLL Beacon into unbacked memory buffer...",
      "warning"
    );

    try {
      await simulateAlert("cobalt_strike_reflective_injection", "critical");
      const simulatedPid = 7488;
      const simulatedName = "rundll32.exe";

      const demoProc: ProcessEntry = {
        pid: simulatedPid,
        name: simulatedName,
        exe: "C:\\Windows\\System32\\rundll32.exe",
        rwx_count: 3,
        unbacked_exec_count: 2,
        total_rwx_bytes: 131072,
        allocated_kb: 128.0,
        num_threads: 8,
        thread_unbacked_start: 1,
        vad_protection_anomaly: 2,
        threat_score: 96.5,
        status: "Malicious (Injected)",
        jit_engine: false,
        model_used: true,
        classification: {
          id: "T1055.002",
          mitre_id: "T1055.002",
          name: "Reflective Code Loading (Cobalt Strike)",
          display_name: "Reflective Code Loading (Cobalt Strike)",
          short_description: "Payload mapped into dynamic unbacked memory without calling standard Windows image loader (LoadLibrary).",
          typical_indicators: "Unbacked MEM_PRIVATE memory page with PAGE_EXECUTE_READWRITE permissions and thread starting in unbacked buffer.",
          remediation: "Execute NtSuspendProcess thread quarantine to sever adversary C2 channel.",
        },
        unbacked_regions: [
          {
            base_address: 0x7FFA2B400000,
            size: 65536,
            protection: "PAGE_EXECUTE_READWRITE",
            allocation_protect: "PAGE_READWRITE",
          },
          {
            base_address: 0x7FFA2B420000,
            size: 65536,
            protection: "PAGE_EXECUTE_READ",
            allocation_protect: "PAGE_READWRITE",
          },
        ],
        attribution: {
          thread_unbacked_start: 45.0,
          rwx_allocations: 35.0,
          vad_protection_anomaly: 20.0,
        },
        attribution_reasons: [
          "1 active thread initialized directly inside unbacked executable memory (0x7FFA2B400000)",
          "3 PAGE_EXECUTE_READWRITE allocations detected in private memory (128 KB)",
          "2 memory permission flip anomalies (PAGE_READWRITE -> PAGE_EXECUTE_READWRITE)",
        ],
      };

      setProcesses((prev) => {
        const filtered = prev.filter((p) => p.pid !== simulatedPid);
        return [demoProc, ...filtered];
      });

      setSummary((prev) => ({
        total_scanned: prev ? prev.total_scanned + 1 : 155,
        anomalies_detected: prev ? prev.anomalies_detected + 1 : 1,
        malicious_count: prev ? prev.malicious_count + 1 : 1,
        suspicious_count: prev ? prev.suspicious_count : 0,
        jit_engine_count: prev ? prev.jit_engine_count : 14,
        clean_count: prev ? prev.clean_count : 140,
        system_posture: "Threat Detected",
        model_loaded: true,
      }));

      setHasScanned(true);
      setLastScanTime(Date.now());
      setSelectedProcess(demoProc);

      appendLog(
        "ML",
        `[DETECTION] ${simulatedName} (PID ${simulatedPid}) classified as Malicious (Injected) [Score: 96.5%]`,
        "danger"
      );
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : "Simulation request failed.";
      appendLog("SYS", `Simulation failed: ${errMsg}`, "danger");
    } finally {
      setIsSimulating(false);
    }
  };

  // 4. Real process containment via POST /api/v1/isolate/{pid} and POST /api/v1/resume/{pid}
  const handleToggleIsolate = async (
    pid: number,
    isCurrentlyIsolated: boolean
  ) => {
    setIsIsolating(true);
    const target = processes.find((p) => p.pid === pid);
    const targetName = target ? target.name : `PID ${pid}`;

    try {
      if (isCurrentlyIsolated) {
        const res = await resumeProcess(pid);
        if (res.success) {
          setIsolatedPids((prev) => {
            const next = new Set(prev);
            next.delete(pid);
            return next;
          });
          setProcesses((prev) =>
            prev.map((p) => (p.pid === pid ? { ...p, is_isolated: false } : p))
          );
          if (selectedProcess?.pid === pid) {
            setSelectedProcess((prev) =>
              prev ? { ...prev, is_isolated: false } : null
            );
          }

          const msg = `ShadowMem resumed ${targetName} (PID ${pid}) — threads restored.`;
          appendLog("ISOLATE", msg, "success");
          addAlert({
            id: `resume-${pid}-${Date.now()}`,
            title: "Process Resumed",
            message: msg,
            severity: "ok",
            timestamp: new Date().toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit",
            }),
            pid,
          });
          setLastAlertTime(Date.now());
        } else {
          const err = res.error || "Failed to resume process.";
          appendLog("ISOLATE", `Resume failed: ${err}`, "danger");
          alert(`Error: ${err}`);
        }
      } else {
        const res = await isolateProcess(
          pid,
          "User-mode suspension via ShadowMem SOC Dashboard"
        );
        if (res.success) {
          setIsolatedPids((prev) => {
            const next = new Set(prev);
            next.add(pid);
            return next;
          });
          setProcesses((prev) =>
            prev.map((p) => (p.pid === pid ? { ...p, is_isolated: true } : p))
          );
          if (selectedProcess?.pid === pid) {
            setSelectedProcess((prev) =>
              prev ? { ...prev, is_isolated: true } : null
            );
          }

          const msg = `ShadowMem isolated ${targetName} (PID ${pid}) — threads suspended.`;
          appendLog("ISOLATE", msg, "danger");
          addAlert({
            id: `isolate-${pid}-${Date.now()}`,
            title: "Process Isolated",
            message: msg,
            severity: "warn",
            timestamp: new Date().toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit",
            }),
            pid,
          });
          setLastAlertTime(Date.now());
        } else {
          const err = res.error || "Failed to isolate process.";
          appendLog("ISOLATE", `Isolation failed: ${err}`, "danger");
          alert(`Error: ${err}`);
        }
      }
    } catch (err: unknown) {
      const errMsg =
        err instanceof Error ? err.message : "Isolation request error.";
      appendLog("ISOLATE", `Request error: ${errMsg}`, "danger");
      alert(`Error: ${errMsg}`);
    } finally {
      setIsIsolating(false);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-10">
      {/* Overview Top Command Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-lg bg-card border border-border shadow-xs">
        <div>
          <div className="flex items-center gap-2.5">
            <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-textBright">
              System Forensics Overview
            </h2>
            <div className="flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-mono font-semibold bg-lime/10 text-lime border border-lime/30">
              <span className="w-1.5 h-1.5 rounded-full bg-lime animate-pulse" />
              <span>LIVE API</span>
            </div>
            {wsConnected && (
              <span className="hidden sm:inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-medium bg-blue-500/10 text-blue-500 border border-blue-500/20">
                <Radio className="w-3 h-3" />
                WS LINK
              </span>
            )}
          </div>
          <p className="text-xs text-textFog mt-1 font-sans leading-relaxed">
            Automated volatile memory forensics and fileless code injection detection
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2.5 flex-wrap">
          {hasScanned && (
            <button
              onClick={() => {
                setHasScanned(false);
                setSummary(null);
                setProcesses([]);
              }}
              className="flex items-center gap-1.5 px-3 py-2 rounded-md font-mono text-xs font-medium text-textDim hover:text-textBright bg-background border border-border transition-colors"
              title="Reset view to baseline state"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span className="hidden md:inline">Reset Baseline</span>
            </button>
          )}

          {/* Judge Demo Trigger */}
          <button
            onClick={handleTriggerDemo}
            disabled={isSimulating || isScanning}
            className="flex items-center gap-1.5 px-3 py-2 rounded-md font-mono text-xs font-semibold bg-threat-suspicious/10 hover:bg-threat-suspicious/20 text-threat-suspicious border border-threat-suspicious/30 transition-colors disabled:opacity-50"
            title="Demonstrate live memory injection detection flow"
          >
            {isSimulating ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Zap className="w-3.5 h-3.5" />
            )}
            <span>Live Attack Demo</span>
          </button>

          {/* Primary Action Button */}
          <button
            onClick={handleExecuteScan}
            disabled={isScanning}
            className="flex items-center gap-2 px-4 py-2 rounded-md font-sans text-xs font-semibold bg-lime hover:bg-lime-hover text-white transition-colors shadow-xs disabled:opacity-50"
          >
            {isScanning ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-white" />
                <span>Auditing Memory Space...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-white text-white" />
                <span>Run Volatile Scan</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Error Banner (if scan failed) */}
      {scanError && (
        <div className="p-3.5 rounded-lg bg-threat-malicious/10 border border-threat-malicious/30 flex items-center justify-between text-xs font-mono text-threat-malicious">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>Memory Scan Failed: {scanError}</span>
          </div>
          <button
            onClick={() => setScanError(null)}
            className="text-textDim hover:text-textBright"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Row 1: Stat Cards */}
      <StatCards
        summary={summary}
        avgScanTimeMs={avgScanTimeMs}
        hasScanned={hasScanned}
        lastUpdated={lastScanTime}
      />

      {/* Row 2: Live Process Map & Threat Posture */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <LiveProcessMapPanel
            processes={processes}
            hasScanned={hasScanned}
            onSelectProcess={(proc) => setSelectedProcess(proc)}
            lastUpdated={lastScanTime}
          />
        </div>
        <div>
          <ThreatPosturePanel
            summary={summary}
            hasScanned={hasScanned}
            lastUpdated={lastScanTime}
          />
        </div>
      </div>

      {/* Row 3: Analytics Row (Donut, Line Chart, Categories) */}
      <AnalyticsRow
        summary={summary}
        processes={processes}
        scanHistory={scanHistory}
        hasScanned={hasScanned}
        lastUpdated={lastScanTime}
      />

      {/* Row 4: Recent Alerts & Live Kernel Telemetry Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <RecentAlertsPanel
          alerts={alerts}
          onClearAlerts={clearAlerts}
          onSelectAlert={(alert) => {
            if (alert.pid) {
              const matched = processes.find((p) => p.pid === alert.pid);
              if (matched) setSelectedProcess(matched);
            }
          }}
          lastUpdated={lastAlertTime}
        />

        <KernelTelemetryFeed
          logs={kernelLogs}
          isPaused={isTickerPaused}
          onTogglePause={() => setIsTickerPaused(!isTickerPaused)}
          onClear={() => setKernelLogs([])}
          lastUpdated={lastKernelLogTime}
        />
      </div>

      {/* Process Forensic Dossier Modal */}
      {selectedProcess && (
        <ProcessDossierModal
          process={selectedProcess}
          onClose={() => setSelectedProcess(null)}
          onToggleIsolate={handleToggleIsolate}
          isIsolating={isIsolating}
        />
      )}
    </div>
  );
}
