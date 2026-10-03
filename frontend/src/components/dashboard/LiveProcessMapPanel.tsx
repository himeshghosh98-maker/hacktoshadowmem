"use client";

import React, { useState } from "react";
import { Radio, Filter, Eye } from "lucide-react";
import { ProcessEntry } from "@/types/forensics";
import { LastUpdated } from "@/components/LastUpdated";

interface LiveProcessMapPanelProps {
  processes: ProcessEntry[];
  hasScanned: boolean;
  onSelectProcess?: (process: ProcessEntry) => void;
  lastUpdated?: number | null;
}

type FilterTab = "ALL" | "THREAT" | "JIT" | "CLEAN";

export function LiveProcessMapPanel({
  processes,
  hasScanned,
  onSelectProcess,
  lastUpdated,
}: LiveProcessMapPanelProps) {
  const [activeTab, setActiveTab] = useState<FilterTab>("ALL");
  const [hoveredProcess, setHoveredProcess] = useState<ProcessEntry | null>(null);

  const threatCount = processes.filter(
    (p) => p.status === "Malicious (Injected)" || p.status === "Suspicious"
  ).length;
  const jitCount = processes.filter((p) => p.jit_engine).length;
  const cleanCount = processes.filter((p) => p.status === "Clean (Uninfected)").length;

  const filteredProcesses = processes.filter((p) => {
    if (activeTab === "THREAT") {
      return p.status === "Malicious (Injected)" || p.status === "Suspicious";
    }
    if (activeTab === "JIT") return p.jit_engine;
    if (activeTab === "CLEAN") return p.status === "Clean (Uninfected)";
    return true;
  });

  const getStatusColor = (status: ProcessEntry["status"]) => {
    switch (status) {
      case "Malicious (Injected)":
        return "bg-threat-malicious border-red-400 text-white shadow-[0_0_8px_rgba(214,69,61,0.3)]";
      case "Suspicious":
        return "bg-threat-suspicious border-amber-400 text-white shadow-[0_0_6px_rgba(230,138,46,0.3)]";
      case "Legitimate JIT Engine":
        return "bg-threat-jit border-blue-400 text-white shadow-[0_0_6px_rgba(74,123,176,0.3)]";
      default:
        return "bg-threat-clean/25 border-emerald-600/30 text-emerald-800 hover:bg-threat-clean hover:text-white";
    }
  };

  const getPillColor = (status: ProcessEntry["status"]) => {
    switch (status) {
      case "Malicious (Injected)":
        return "border-threat-malicious/40 bg-threat-malicious/15 text-threat-malicious";
      case "Suspicious":
        return "border-threat-suspicious/40 bg-threat-suspicious/15 text-threat-suspicious";
      case "Legitimate JIT Engine":
        return "border-threat-jit/40 bg-threat-jit/15 text-threat-jit";
      default:
        return "border-threat-clean/40 bg-threat-clean/15 text-threat-clean";
    }
  };

  return (
    <div className="p-5 rounded-lg bg-card border border-border flex flex-col justify-between space-y-4">
      {/* Panel Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border/80">
        <div className="flex items-center gap-2">
          <div className="w-2.5 h-2.5 rounded-full bg-lime animate-pulse" />
          <h3 className="text-sm font-semibold text-textBright tracking-tight">
            Live Process Memory Map
          </h3>
          <span className="text-xs font-sans text-textDim hidden sm:inline">
            (Virtual Address Space Allocation)
          </span>
        </div>

        {/* Filter Tabs & Freshness */}
        <div className="flex items-center gap-3">
          {hasScanned && <LastUpdated timestamp={lastUpdated} />}
          <div className="flex items-center gap-1 bg-[#F5F1EB] p-1 rounded-md border border-border">
          {(
            [
              { key: "ALL", label: "ALL", count: processes.length },
              { key: "THREAT", label: "THREATS", count: threatCount },
              { key: "JIT", label: "JIT", count: jitCount },
              { key: "CLEAN", label: "CLEAN", count: cleanCount },
            ] as const
          ).map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`px-2.5 py-1 rounded text-xs font-mono transition-all flex items-center gap-1.5 ${
                activeTab === tab.key
                  ? "bg-white text-lime border border-border font-bold shadow-xs"
                  : "text-textFog font-medium hover:text-textBright"
              }`}
            >
              <span>{tab.label}</span>
              <span
                className={`text-[10px] px-1 rounded-full font-semibold ${
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
        </div>
      </div>

      {/* Main Map Scope Canvas */}
      {!hasScanned ? (
        <div className="h-64 rounded-lg border border-dashed border-border/80 bg-[#FBF8F4] flex flex-col items-center justify-center gap-3 p-6 text-center">
          <div className="w-12 h-12 rounded-full bg-raise/60 border border-border flex items-center justify-center">
            <Radio className="w-6 h-6 text-textDim animate-pulse" />
          </div>
          <div className="space-y-1">
            <h4 className="text-sm font-semibold text-textBright font-sans">
              Process Radar Standby
            </h4>
            <p className="text-xs font-sans text-textFog max-w-sm leading-relaxed">
              Trigger a scan to project memory regions, detect thread anomalies, and map active virtual memory topologies.
            </p>
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          {/* Spatial Grid Canvas */}
          <div className="relative min-h-[220px] max-h-[300px] overflow-y-auto p-4 rounded-lg bg-[#F8F5F0] border border-border/80">
            {filteredProcesses.length === 0 ? (
              <div className="h-48 flex flex-col items-center justify-center text-xs font-mono text-textFog gap-2">
                <Filter className="w-5 h-5 text-border" />
                <span>No processes match the selected filter tab.</span>
              </div>
            ) : (
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-4 gap-2.5">
                {filteredProcesses.map((proc) => {
                  const isHovered = hoveredProcess?.pid === proc.pid;
                  return (
                    <div
                      key={proc.pid}
                      onMouseEnter={() => setHoveredProcess(proc)}
                      onMouseLeave={() => setHoveredProcess(null)}
                      onClick={() => onSelectProcess && onSelectProcess(proc)}
                      className={`cursor-pointer p-2.5 rounded-md border transition-all text-left group ${
                        isHovered
                          ? "bg-white border-lime shadow-[0_2px_12px_rgba(232,121,60,0.18)] translate-y-[-1px]"
                          : "bg-card border-border hover:border-border/80 shadow-xs"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-1.5 mb-1.5">
                        <span className="font-mono text-xs font-semibold text-textDim">
                          PID {proc.pid}
                        </span>
                        <span
                          className={`w-2 h-2 rounded-full shrink-0 ${getStatusColor(
                            proc.status
                          )}`}
                        />
                      </div>

                      <div className="text-xs font-bold text-textBright truncate group-hover:text-lime transition-colors">
                        {proc.name}
                      </div>

                      <div className="flex items-center justify-between mt-2 pt-1.5 border-t border-border/50 text-xs font-mono">
                        <span className="text-textDim font-medium">
                          {proc.allocated_kb > 0 ? `${proc.allocated_kb} KB` : "0 KB"}
                        </span>
                        <span
                          className={`font-bold ${
                            proc.threat_score >= 60
                              ? "text-threat-malicious"
                              : proc.threat_score >= 30
                              ? "text-threat-suspicious"
                              : "text-textDim"
                          }`}
                        >
                          {proc.threat_score.toFixed(1)}%
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Active Process Inspector Bar */}
          <div className="p-3 rounded-md bg-[#FAF7F2] border border-border flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
            {hoveredProcess ? (
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-textBright font-bold">
                  {hoveredProcess.name} (PID {hoveredProcess.pid})
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${getPillColor(
                    hoveredProcess.status
                  )}`}
                >
                  {hoveredProcess.status}
                </span>
                <span className="text-textFog font-medium">
                  RWX Pages: <strong className="text-textBright font-bold">{hoveredProcess.rwx_count}</strong>
                </span>
                <span className="text-textFog font-medium">
                  Unbacked Starts: <strong className="text-textBright font-bold">{hoveredProcess.thread_unbacked_start}</strong>
                </span>
              </div>
            ) : (
              <div className="flex items-center gap-2 text-textFog text-xs font-medium">
                <Eye className="w-3.5 h-3.5 text-lime" />
                <span>Hover over any process node to inspect volatile VAD indicators</span>
              </div>
            )}

            <div className="text-xs font-medium text-textDim self-end sm:self-auto">
              Click a process to open detailed forensic dossier
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
