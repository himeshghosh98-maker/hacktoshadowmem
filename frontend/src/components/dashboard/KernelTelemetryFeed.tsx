"use client";

import React, { useRef, useEffect } from "react";
import { Terminal, Pause, Play, Trash2, ArrowDown } from "lucide-react";
import { KernelLogItem } from "@/types/forensics";
import { useDensity } from "@/context/DensityContext";
import { LastUpdated } from "@/components/LastUpdated";

interface KernelTelemetryFeedProps {
  logs: KernelLogItem[];
  isPaused: boolean;
  onTogglePause: () => void;
  onClear: () => void;
  lastUpdated?: number | null;
}

export function KernelTelemetryFeed({
  logs,
  isPaused,
  onTogglePause,
  onClear,
  lastUpdated,
}: KernelTelemetryFeedProps) {
  const { isCompact } = useDensity();
  const containerRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = React.useState(true);

  useEffect(() => {
    if (autoScroll && containerRef.current && !isPaused) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs, autoScroll, isPaused]);

  const getTagColor = (tag: KernelLogItem["tag"], level: KernelLogItem["level"]) => {
    if (level === "danger") return "text-threat-malicious font-bold";
    if (level === "warning") return "text-threat-suspicious font-bold";
    if (level === "success") return "text-lime font-bold";
    if (level === "purple") return "text-indigo-400 font-bold";
    return "text-threat-jit font-bold";
  };

  return (
    <div className={`${isCompact ? "p-3.5 space-y-2" : "p-5 space-y-3"} rounded-lg bg-card border border-border shadow-sm`}>
      {/* Header */}
      <div className={`flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${isCompact ? "pb-2" : "pb-3"} border-b border-border/80`}>
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-lime" />
          <h3 className="text-sm font-semibold text-textBright tracking-tight">
            Live Kernel Telemetry Feed
          </h3>
          <span className="text-xs font-sans text-textDim hidden sm:inline">
            (Ring-0 Hooks & Forensic Thread Watcher)
          </span>
        </div>

        {/* Controls */}
        <div className="flex items-center gap-2">
          {logs.length > 0 && <LastUpdated timestamp={lastUpdated} />}
          {/* Pause / Resume button */}
          <button
            onClick={onTogglePause}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-medium transition-all ${
              isPaused
                ? "bg-threat-suspicious/20 text-threat-suspicious border border-threat-suspicious/40"
                : "bg-raise text-textFog hover:text-textBright border border-border"
            }`}
          >
            {isPaused ? (
              <>
                <Play className="w-3 h-3 fill-threat-suspicious" />
                <span>RESUME</span>
              </>
            ) : (
              <>
                <Pause className="w-3 h-3" />
                <span>PAUSE</span>
              </>
            )}
          </button>

          {/* Auto-scroll toggle */}
          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={`flex items-center gap-1 px-2 py-1 rounded text-xs font-mono font-medium border transition-all ${
              autoScroll
                ? "bg-lime/10 text-lime border-lime/30"
                : "bg-raise text-textDim border-border"
            }`}
            title="Toggle Auto-Scroll"
          >
            <ArrowDown className="w-3 h-3" />
            <span className="hidden md:inline">AUTO-SCROLL</span>
          </button>

          {/* Clear button */}
          <button
            onClick={onClear}
            className="flex items-center gap-1 px-2 py-1 rounded text-xs font-mono font-medium text-textDim hover:text-textBright bg-raise border border-border transition-colors"
            title="Clear Log Terminal"
          >
            <Trash2 className="w-3 h-3" />
            <span>CLEAR</span>
          </button>
        </div>
      </div>

      {/* Terminal Output Body */}
      <div
        ref={containerRef}
        className={`${
          isCompact ? "h-36 p-2.5 space-y-0.5" : "h-48 p-3.5 space-y-1.5"
        } overflow-y-auto rounded-lg bg-[#F8F5F0] border border-border font-mono text-xs scroll-smooth`}
      >
        {logs.length === 0 ? (
          <div className="h-full flex items-center justify-center text-textDim text-xs font-mono">
            Log stream buffer empty. Awaiting kernel telemetry...
          </div>
        ) : (
          logs.map((item) => (
            <div
              key={item.id}
              className={`flex items-baseline ${isCompact ? "gap-2 leading-snug" : "gap-2.5 leading-relaxed"} hover:bg-[#EFE9E1] px-1 rounded transition-colors`}
            >
              <span className="text-textDim select-none shrink-0 tnum text-[11px] font-medium">
                [{item.timestamp}]
              </span>
              <span className={`shrink-0 ${getTagColor(item.tag, item.level)}`}>
                [{item.tag}]
              </span>
              <span className="text-textFog break-all font-mono font-normal">{item.msg}</span>
            </div>
          ))
        )}
      </div>

      {/* Status Bar */}
      <div className="flex items-center justify-between text-xs font-mono text-textDim font-medium pt-1">
        <span className="flex items-center gap-2">
          <span
            className={`w-1.5 h-1.5 rounded-full ${
              isPaused ? "bg-threat-suspicious" : "bg-lime animate-pulse"
            }`}
          />
          STREAM: {isPaused ? "PAUSED" : "ACTIVE (3.8s POLLING INTERVAL)"}
        </span>
        <span>BUFFER: {logs.length} / 120 ENTRIES</span>
      </div>
    </div>
  );
}
