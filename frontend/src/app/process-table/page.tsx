"use client";

import React, { useState, useEffect, useMemo } from "react";
import {
  Cpu,
  Search,
  Download,
  Play,
  Loader2,
  ArrowUpDown,
} from "lucide-react";
import { ProcessEntry, ProcessStatus } from "@/types/forensics";
import { fetchScan, isolateProcess, resumeProcess, fetchAudit } from "@/lib/api";
import { ProcessDossierModal } from "@/components/dashboard/ProcessDossierModal";
import { useDensity } from "@/context/DensityContext";
import { LastUpdated } from "@/components/LastUpdated";

type StatusTab = "ALL" | "MALICIOUS" | "SUSPICIOUS" | "JIT" | "CLEAN";
type SortField =
  | "threat_score"
  | "pid"
  | "name"
  | "rwx_count"
  | "unbacked_exec_count"
  | "allocated_kb"
  | "num_threads";
type SortDirection = "asc" | "desc";

export default function ProcessTablePage() {
  const { isCompact } = useDensity();
  const [processes, setProcesses] = useState<ProcessEntry[]>([]);
  const [isolatedPids, setIsolatedPids] = useState<Set<number>>(new Set());
  const [hasScanned, setHasScanned] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<number | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [activeTab, setActiveTab] = useState<StatusTab>("ALL");

  const [sortField, setSortField] = useState<SortField>("threat_score");
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc");

  const [selectedProcess, setSelectedProcess] = useState<ProcessEntry | null>(null);
  const [isIsolatingPid, setIsIsolatingPid] = useState<number | null>(null);

  // Sync isolated PIDs from backend audit
  useEffect(() => {
    fetchAudit()
      .then((res) => {
        if (res.actions) {
          const iso = new Set<number>();
          res.actions.forEach((a) => {
            if (a.success) {
              if (a.action === "isolate") iso.add(a.pid);
              if (a.action === "resume") iso.delete(a.pid);
            }
          });
          setIsolatedPids(iso);
        }
      })
      .catch(() => {});
  }, []);

  // Run scan
  const runScan = async () => {
    setIsScanning(true);
    try {
      const data = await fetchScan();
      const enriched = (data.processes || []).map((p) => ({
        ...p,
        is_isolated: isolatedPids.has(p.pid),
      }));
      setProcesses(enriched);
      setHasScanned(true);
      setLastUpdated(Date.now());
    } catch (err) {
      console.error(err);
    } finally {
      setIsScanning(false);
    }
  };

  // Process Isolation
  const handleToggleIsolate = async (pid: number, isCurrentlyIsolated: boolean) => {
    setIsIsolatingPid(pid);
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
        } else {
          alert(`Resume failed: ${res.error}`);
        }
      } else {
        const res = await isolateProcess(pid, "Suspended via Process Table");
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
        } else {
          alert(`Isolation failed: ${res.error}`);
        }
      }
    } catch (err) {
      alert(`Error: ${err instanceof Error ? err.message : err}`);
    } finally {
      setIsIsolatingPid(null);
    }
  };

  // Filter & Sort
  const filteredAndSortedProcesses = useMemo(() => {
    return processes
      .filter((p) => {
        // Tab filter
        if (activeTab === "MALICIOUS" && p.status !== "Malicious (Injected)") return false;
        if (activeTab === "SUSPICIOUS" && p.status !== "Suspicious") return false;
        if (activeTab === "JIT" && !p.jit_engine) return false;
        if (activeTab === "CLEAN" && p.status !== "Clean") return false;

        // Search query filter
        if (searchQuery.trim()) {
          const q = searchQuery.toLowerCase();
          const matchName = p.name.toLowerCase().includes(q);
          const matchPid = p.pid.toString().includes(q);
          const matchExe = p.exe.toLowerCase().includes(q);
          const matchTech = p.classification?.name?.toLowerCase().includes(q) || false;
          if (!matchName && !matchPid && !matchExe && !matchTech) return false;
        }

        return true;
      })
      .sort((a, b) => {
        let valA = a[sortField];
        let valB = b[sortField];

        if (typeof valA === "string") valA = (valA as string).toLowerCase();
        if (typeof valB === "string") valB = (valB as string).toLowerCase();

        if (valA < valB) return sortDirection === "asc" ? -1 : 1;
        if (valA > valB) return sortDirection === "asc" ? 1 : -1;
        return 0;
      });
  }, [processes, activeTab, searchQuery, sortField, sortDirection]);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection(sortDirection === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortDirection("desc");
    }
  };

  // CSV Export
  const exportCsv = () => {
    if (processes.length === 0) return;
    const headers = [
      "PID",
      "Process Name",
      "Executable Path",
      "Threat Score",
      "Status",
      "RWX Pages",
      "Unbacked Exec Regions",
      "Allocated KB",
      "Threads",
      "Unbacked Thread Starts",
      "VAD Protection Flips",
      "MITRE Technique",
      "Isolated",
    ];

    const rows = processes.map((p) => [
      p.pid,
      `"${p.name}"`,
      `"${p.exe}"`,
      p.threat_score,
      `"${p.status}"`,
      p.rwx_count,
      p.unbacked_exec_count,
      p.allocated_kb,
      p.num_threads,
      p.thread_unbacked_start,
      p.vad_protection_anomaly,
      `"${p.classification?.name || "N/A"}"`,
      p.is_isolated ? "Yes" : "No",
    ]);

    const csvContent =
      "data:text/csv;charset=utf-8," +
      [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute(
      "download",
      `shadowmem_forensics_scan_${new Date().toISOString().slice(0, 19)}.csv`
    );
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const getStatusBadge = (status: ProcessStatus, isIsolated?: boolean) => {
    if (isIsolated) {
      return (
        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
          SUSPENDED (ISOLATED)
        </span>
      );
    }
    switch (status) {
      case "Malicious (Injected)":
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-threat-malicious/20 text-threat-malicious border border-threat-malicious/40">
            MALICIOUS
          </span>
        );
      case "Suspicious":
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-threat-suspicious/20 text-threat-suspicious border border-threat-suspicious/40">
            SUSPICIOUS
          </span>
        );
      case "Legitimate JIT Engine":
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-threat-jit/20 text-threat-jit border border-threat-jit/40">
            JIT ENGINE
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-threat-clean/20 text-threat-clean border border-threat-clean/40">
            CLEAN
          </span>
        );
    }
  };

  const countMalicious = processes.filter(
    (p) => p.status === "Malicious (Injected)"
  ).length;
  const countSuspicious = processes.filter((p) => p.status === "Suspicious").length;
  const countJit = processes.filter((p) => p.jit_engine).length;
  const countClean = processes.filter(
    (p) => p.status === "Clean"
  ).length;

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-10">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-lg bg-card border border-border shadow-sm">
        <div>
          <div className="flex items-center gap-2.5">
            <Cpu className="w-5 h-5 text-lime" />
            <h2 className="text-2xl sm:text-[26px] font-bold tracking-tight text-textBright">
              Forensic Process Table & Inspection
            </h2>
            <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider bg-lime/15 text-lime border border-lime/30">
              7-FEATURE AUDIT
            </span>
          </div>
          <p className="text-sm font-normal text-textFog mt-1.5 font-sans leading-relaxed">
            Full user-mode memory forensics breakdown: RWX volume, unbacked PE sections, thread starts & isolation containment.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={exportCsv}
            disabled={processes.length === 0}
            className="flex items-center gap-1.5 px-3 py-2 rounded-md font-mono text-xs font-medium text-textBright bg-raise hover:bg-card border border-border transition-colors disabled:opacity-50"
            title="Download CSV report"
          >
            <Download className="w-3.5 h-3.5 text-textDim" />
            <span>Export CSV</span>
          </button>

          <button
            onClick={runScan}
            disabled={isScanning}
            className="flex items-center gap-2 px-4 py-2 rounded-md font-sans text-xs font-semibold bg-lime hover:bg-lime-hover text-white transition-all shadow-[0_2px_8px_rgba(232,121,60,0.3)] disabled:opacity-50"
          >
            {isScanning ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-white" />
                <span>Scanning VADs...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-white text-white" />
                <span>{hasScanned ? "Re-scan Processes" : "Run Forensics Scan"}</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-lg bg-card border border-border shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        {/* Filter Tabs */}
        <div className="flex flex-wrap items-center gap-1 bg-[#F5F1EB] p-1 rounded-md border border-border">
          {(
            [
              { key: "ALL", label: "ALL", count: processes.length },
              { key: "MALICIOUS", label: "MALICIOUS", count: countMalicious },
              { key: "SUSPICIOUS", label: "SUSPICIOUS", count: countSuspicious },
              { key: "JIT", label: "JIT ENGINES", count: countJit },
              { key: "CLEAN", label: "CLEAN", count: countClean },
            ] as const
          ).map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`px-3 py-1.5 rounded text-xs font-mono transition-all flex items-center gap-1.5 ${
                activeTab === tab.key
                  ? "bg-white text-lime border border-border font-bold shadow-xs"
                  : "text-textFog font-medium hover:text-textBright"
              }`}
            >
              <span>{tab.label}</span>
              <span
                className={`text-[10px] px-1.5 py-0.2 rounded-full font-semibold ${
                  activeTab === tab.key
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
          {hasScanned && processes.length > 0 && (
            <LastUpdated timestamp={lastUpdated} />
          )}
          <div className="relative w-full md:w-80">
            <Search className="w-3.5 h-3.5 text-textDim absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter by name, PID, or technique..."
              className="w-full bg-[#FAF7F2] text-xs text-textBright placeholder:text-textDim pl-9 pr-4 py-1.5 rounded-md border border-border focus:outline-none focus:border-lime/60 focus:ring-1 focus:ring-lime/40 transition-all font-mono"
            />
          </div>
        </div>
      </div>

      {/* Processes Table Container */}
      <div className="rounded-lg bg-card border border-border overflow-hidden shadow-sm">
        {!hasScanned && processes.length === 0 ? (
          <div className="h-96 flex flex-col items-center justify-center gap-4 text-center p-8 bg-[#FBF8F4]">
            <div className="w-16 h-16 rounded-full bg-raise/60 border border-border flex items-center justify-center">
              <Cpu className="w-8 h-8 text-textDim" />
            </div>
            <div className="space-y-1">
              <h3 className="text-sm font-semibold text-textBright font-sans">
                No Active Process Telemetry
              </h3>
              <p className="text-xs font-sans text-textFog max-w-sm leading-relaxed">
                Execute a volatile memory audit to populate the granular process forensic table.
              </p>
            </div>
            <button
              onClick={runScan}
              disabled={isScanning}
              className="mt-2 flex items-center gap-2 px-4 py-2 rounded-md font-sans text-xs font-semibold bg-lime text-white hover:bg-lime-hover shadow-[0_2px_8px_rgba(232,121,60,0.3)] transition-colors"
            >
              <Play className="w-3.5 h-3.5 fill-white text-white" />
              <span>Initiate Memory Scan</span>
            </button>
          </div>
        ) : filteredAndSortedProcesses.length === 0 ? (
          <div className="h-64 flex flex-col items-center justify-center gap-2 text-center p-6 text-textFog font-mono text-xs">
            <span>No processes found matching the selected filters.</span>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono border-collapse">
              <thead className="bg-[#F5F1EB] text-textFog border-b border-border select-none text-[11px] font-semibold uppercase tracking-wider">
                <tr>
                  <th
                    onClick={() => handleSort("pid")}
                    className={`${isCompact ? "py-2 px-2.5" : "p-3.5"} cursor-pointer hover:text-textBright`}
                  >
                    <div className="flex items-center gap-1.5">
                      <span>PID</span>
                      <ArrowUpDown className="w-3 h-3" />
                    </div>
                  </th>
                  <th
                    onClick={() => handleSort("name")}
                    className={`${isCompact ? "py-2 px-2.5" : "p-3.5"} cursor-pointer hover:text-textBright`}
                  >
                    <div className="flex items-center gap-1.5">
                      <span>PROCESS NAME</span>
                      <ArrowUpDown className="w-3 h-3" />
                    </div>
                  </th>
                  <th
                    onClick={() => handleSort("threat_score")}
                    className={`${isCompact ? "py-2 px-2.5" : "p-3.5"} cursor-pointer hover:text-textBright`}
                  >
                    <div className="flex items-center gap-1.5">
                      <span>THREAT SCORE</span>
                      <ArrowUpDown className="w-3 h-3" />
                    </div>
                  </th>
                  <th className={isCompact ? "py-2 px-2.5" : "p-3.5"}>STATUS</th>
                  <th
                    onClick={() => handleSort("rwx_count")}
                    className={`${isCompact ? "py-2 px-2.5" : "p-3.5"} cursor-pointer hover:text-textBright`}
                  >
                    <div className="flex items-center gap-1.5">
                      <span>RWX PAGES</span>
                      <ArrowUpDown className="w-3 h-3" />
                    </div>
                  </th>
                  <th
                    onClick={() => handleSort("unbacked_exec_count")}
                    className={`${isCompact ? "py-2 px-2.5" : "p-3.5"} cursor-pointer hover:text-textBright`}
                  >
                    <div className="flex items-center gap-1.5">
                      <span>UNBACKED REGIONS</span>
                      <ArrowUpDown className="w-3 h-3" />
                    </div>
                  </th>
                  <th
                    onClick={() => handleSort("allocated_kb")}
                    className={`${isCompact ? "py-2 px-2.5" : "p-3.5"} cursor-pointer hover:text-textBright`}
                  >
                    <div className="flex items-center gap-1.5">
                      <span>ALLOCATED (KB)</span>
                      <ArrowUpDown className="w-3 h-3" />
                    </div>
                  </th>
                  <th
                    onClick={() => handleSort("num_threads")}
                    className={`${isCompact ? "py-2 px-2.5" : "p-3.5"} cursor-pointer hover:text-textBright`}
                  >
                    <div className="flex items-center gap-1.5">
                      <span>THREADS</span>
                      <ArrowUpDown className="w-3 h-3" />
                    </div>
                  </th>
                  <th className={`${isCompact ? "py-2 px-2.5" : "p-3.5"} text-right`}>CONTAINMENT ACTIONS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60">
                {filteredAndSortedProcesses.map((proc) => {
                  const isThreat =
                    proc.status === "Malicious (Injected)" ||
                    proc.status === "Suspicious";
                  const isBusy = isIsolatingPid === proc.pid;

                  return (
                    <tr
                      key={proc.pid}
                      className={`hover:bg-[#FAF7F2] transition-colors ${
                        proc.is_isolated
                          ? "bg-amber-500/5"
                          : isThreat
                          ? "bg-red-500/5"
                          : ""
                      }`}
                    >
                      <td className={`${isCompact ? "py-1.5 px-2.5" : "p-3.5"} font-bold text-textDim`}>{proc.pid}</td>
                      <td className={isCompact ? "py-1.5 px-2.5" : "p-3.5"}>
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-textBright">
                            {proc.name}
                          </span>
                          {proc.classification && (
                            <span className="text-[9px] px-1.5 py-0.2 rounded bg-threat-malicious/15 text-threat-malicious border border-threat-malicious/30">
                              {proc.classification.name}
                            </span>
                          )}
                        </div>
                        {proc.exe && (
                          <div className="text-[10px] text-textDim truncate max-w-xs mt-0.5">
                            {proc.exe}
                          </div>
                        )}
                      </td>
                      <td className={isCompact ? "py-1.5 px-2.5" : "p-3.5"}>
                        <span
                          className={`font-bold ${
                            proc.threat_score >= 60
                              ? "text-threat-malicious text-sm"
                              : proc.threat_score >= 30
                              ? "text-threat-suspicious"
                              : "text-textDim"
                          }`}
                        >
                          {proc.threat_score.toFixed(1)}%
                        </span>
                      </td>
                      <td className={isCompact ? "py-1.5 px-2.5" : "p-3.5"}>
                        {getStatusBadge(proc.status, proc.is_isolated)}
                      </td>
                      <td className={isCompact ? "py-1.5 px-2.5" : "p-3.5"}>
                        <span
                          className={
                            proc.rwx_count > 0
                              ? "text-threat-suspicious font-bold"
                              : "text-textDim"
                          }
                        >
                          {proc.rwx_count}
                        </span>
                      </td>
                      <td className={isCompact ? "py-1.5 px-2.5" : "p-3.5"}>
                        <span
                          className={
                            proc.unbacked_exec_count > 0
                              ? "text-threat-malicious font-bold"
                              : "text-textDim"
                          }
                        >
                          {proc.unbacked_exec_count}
                        </span>
                      </td>
                      <td className={`${isCompact ? "py-1.5 px-2.5" : "p-3.5"} text-textFog`}>{proc.allocated_kb} KB</td>
                      <td className={`${isCompact ? "py-1.5 px-2.5" : "p-3.5"} text-textFog`}>{proc.num_threads}</td>
                      <td className={`${isCompact ? "py-1.5 px-2.5" : "p-3.5"} text-right space-x-2`}>
                        <button
                          onClick={() => setSelectedProcess(proc)}
                          className={`${isCompact ? "px-2 py-0.5 text-[11px]" : "px-2.5 py-1 text-xs"} rounded bg-raise hover:bg-[#1F2942] border border-border text-textBright font-sans transition-colors`}
                        >
                          Dossier
                        </button>

                        <button
                          onClick={() =>
                            handleToggleIsolate(proc.pid, !!proc.is_isolated)
                          }
                          disabled={isBusy}
                          className={`${isCompact ? "px-2 py-0.5 text-[11px]" : "px-2.5 py-1 text-xs"} rounded font-mono transition-all ${
                            proc.is_isolated
                              ? "bg-threat-clean/20 text-threat-clean border border-threat-clean/40 hover:bg-threat-clean/30"
                              : "bg-threat-malicious text-white hover:bg-red-600"
                          } disabled:opacity-50`}
                        >
                          {isBusy ? (
                            "Working..."
                          ) : proc.is_isolated ? (
                            "Resume"
                          ) : (
                            "Isolate"
                          )}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Forensic Dossier Modal */}
      {selectedProcess && (
        <ProcessDossierModal
          process={selectedProcess}
          onClose={() => setSelectedProcess(null)}
          onToggleIsolate={handleToggleIsolate}
          isIsolating={isIsolatingPid === selectedProcess.pid}
        />
      )}
    </div>
  );
}
