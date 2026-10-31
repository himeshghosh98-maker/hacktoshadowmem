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
  const cleanCount = processes.filter((p) => p.status === "Clean").length;

  const filteredProcesses = processes.filter((p) => {
    if (activeTab === "THREAT") {
      return p.status === "Malicious (Injected)" || p.status === "Suspicious";
    }
    if (activeTab === "JIT") return p.jit_engine;
    if (activeTab === "CLEAN") return p.status === "Clean";
    return true;
  });

  const getStatusDot = (status: ProcessEntry["status"]) => {
    switch (status) {
      case "Malicious (Injected)":
        return "bg-threat-malicious animate-pulse";
      case "Suspicious":
        return "bg-threat-suspicious";
      case "Legitimate JIT Engine":
        return "bg-threat-jit";
      default:
        return "bg-threat-clean";
    }
  };

  const getPillColor = (status: ProcessEntry["status"]) => {
    switch (status) {
      case "Malicious (Injected)":
        return "border-threat-malicious/30 bg-threat-malicious/10 text-threat-malicious";
      case "Suspicious":
        return "border-threat-suspicious/30 bg-threat-suspicious/10 text-threat-suspicious";
      case "Legitimate JIT Engine":
        return "border-threat-jit/30 bg-threat-jit/10 text-threat-jit";
      default:
        return "border-threat-clean/30 bg-threat-clean/10 text-threat-clean";
    }
  };

  return (
    <div className="p-5 rounded-lg bg-card border border-border flex flex-col justify-between space-y-4 shadow-xs">
      {/* Panel Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border">
        <div className="flex items-center gap-2">
          <div className="w-2.5 h-2.5 rounded-full bg-lime" />
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
          <div className="flex items-center gap-1 bg-background p-1 rounded-md border border-border">
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
                className={`px-2.5 py-1 rounded text-xs font-mono transition-colors flex items-center gap-1.5 ${
                  activeTab === tab.key
                    ? "bg-card text-lime border border-border font-semibold shadow-xs"
                    : "text-textFog font-medium hover:text-textBright"
                }`}
              >
                <span>{tab.label}</span>
                <span
                  className={`text-xs px-1 rounded font-semibold ${
                    activeTab === tab.key
                      ? "bg-lime/10 text-lime"
                      : "bg-raise text-textDim"
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
        <div className="h-64 rounded-lg border border-dashed border-border bg-background/50 flex flex-col items-center justify-center gap-3 p-6 text-center">
          <div className="w-12 h-12 rounded-full bg-card border border-border flex items-center justify-center shadow-xs">
            <Radio className="w-6 h-6 text-textDim" />
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
          <div className="relative min-h-[220px] max-h-[300px] overflow-y-auto p-4 rounded-lg bg-background border border-border">
            {filteredProcesses.length === 0 ? (
              <div className="h-48 flex flex-col items-center justify-center text-xs font-mono text-textFog gap-2">
                <Filter className="w-5 h-5 text-border" />
                <span>No processes match the selected filter tab.</span>
              </div>
            ) : (
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-4 gap-2.5">
                {filteredProcesses.map((proc) => {
                  const isHovered = hoveredProcess?.pid === proc.pid;
                  const isMalicious = proc.status === "Malicious (Injected)";
                  const isSuspicious = proc.status === "Suspicious";

                  return (
                    <div
                      key={proc.pid}
                      onMouseEnter={() => setHoveredProcess(proc)}
                      onMouseLeave={() => setHoveredProcess(null)}
                      onClick={() => onSelectProcess && onSelectProcess(proc)}
                      className={`cursor-pointer p-2.5 rounded-md border transition-all text-left group ${
                        isHovered
                          ? "bg-card border-lime shadow-sm -translate-y-0.5"
                          : isMalicious
                          ? "bg-threat-malicious/5 border-threat-malicious/40"
                          : isSuspicious
                          ? "bg-threat-suspicious/5 border-threat-suspicious/40"
                          : "bg-card border-border hover:border-border/80 shadow-xs"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-1.5 mb-1.5">
                        <span className="font-mono text-xs font-medium text-textDim">
                          PID {proc.pid}
                        </span>
                        <span
                          className={`w-2 h-2 rounded-full shrink-0 ${getStatusDot(
                            proc.status
                          )}`}
                        />
                      </div>

                      <div className="text-xs font-semibold text-textBright truncate group-hover:text-lime transition-colors">
                        {proc.name}
                      </div>

                      <div className="flex items-center justify-between mt-2 pt-1.5 border-t border-border/60 text-xs font-mono">
                        <span className="text-textDim">
                          {proc.allocated_kb > 0 ? `${proc.allocated_kb} KB` : "0 KB"}
                        </span>
                        <span
                          className={`font-semibold ${
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
          <div className="p-3 rounded-md bg-background border border-border flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
            {hoveredProcess ? (
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-textBright font-semibold">
                  {hoveredProcess.name} (PID {hoveredProcess.pid})
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-xs font-medium border ${getPillColor(
                    hoveredProcess.status
                  )}`}
                >
                  {hoveredProcess.status}
                </span>
                <span className="text-textFog">
                  RWX: <strong className="text-textBright">{hoveredProcess.rwx_count}</strong>
                </span>
                <span className="text-textFog">
                  Unbacked: <strong className="text-textBright">{hoveredProcess.thread_unbacked_start}</strong>
                </span>
              </div>
            ) : (
              <div className="flex items-center gap-2 text-textFog text-xs">
                <Eye className="w-3.5 h-3.5 text-lime" />
                <span>Hover over any process node to inspect VAD telemetry</span>
              </div>
            )}

            <div className="text-xs text-textDim self-end sm:self-auto">
              Click node to open forensic dossier
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
