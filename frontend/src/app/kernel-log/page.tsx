"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  Terminal,
  Pause,
  Play,
  Trash2,
  Download,
  ArrowDown,
  Search,
  Radio,
} from "lucide-react";
import { KernelLogItem } from "@/types/forensics";
import { useDensity } from "@/context/DensityContext";
import { useConnection } from "@/context/ConnectionContext";
import LastUpdated from "@/components/LastUpdated";

type LogLevelFilter = "ALL" | "info" | "success" | "warning" | "danger";

export default function KernelLogPage() {
  const { isCompact } = useDensity();
  const { wsConnected, subscribeAlerts } = useConnection();
  const [lastUpdated, setLastUpdated] = useState<Date | null>(new Date());
  const [logs, setLogs] = useState<KernelLogItem[]>([]);

  const [isPaused, setIsPaused] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const [levelFilter, setLevelFilter] = useState<LogLevelFilter>("ALL");
  const [searchQuery, setSearchQuery] = useState("");

  const containerRef = useRef<HTMLDivElement>(null);
  const isPausedRef = useRef(isPaused);
  isPausedRef.current = isPaused;

  const appendLog = useCallback(
    (
      tag: KernelLogItem["tag"],
      msg: string,
      level: KernelLogItem["level"] = "info"
    ) => {
      setLogs((prev) => {
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
        return next.slice(-250); // Buffer up to 250 lines
      });
      setLastUpdated(new Date());
    },
    []
  );

  // Auto-scroll when new logs arrive
  useEffect(() => {
    if (autoScroll && containerRef.current && !isPaused) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs, autoScroll, isPaused]);

  // Subscribe to consolidated WebSocket alerts from ConnectionContext
  useEffect(() => {
    const unsubscribe = subscribeAlerts((wsAlert) => {
      appendLog(
        "SYS",
        `[REMOTE EVENT] ${wsAlert.title}: ${wsAlert.message}`,
        wsAlert.severity === "critical" ? "danger" : "warning"
      );
    });

    return () => unsubscribe();
  }, [appendLog, subscribeAlerts]);

  // Export logs to .log text file
  const handleExportLog = () => {
    if (logs.length === 0) return;
    const textLines = logs.map(
      (l) => `[${l.timestamp}] [${l.tag}] [${l.level.toUpperCase()}] ${l.msg}`
    );
    const blob = new Blob([textLines.join("\n")], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `shadowmem_activity_${new Date().toISOString().slice(0, 19)}.log`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const getTagColor = (tag: KernelLogItem["tag"], level: KernelLogItem["level"]) => {
    if (level === "danger") return "text-threat-malicious font-bold";
    if (level === "warning") return "text-threat-suspicious font-bold";
    if (level === "success") return "text-lime font-bold";
    if (level === "purple") return "text-indigo-400 font-bold";
    return "text-threat-jit font-bold";
  };

  const filteredLogs = logs.filter((l) => {
    if (levelFilter !== "ALL" && l.level !== levelFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      if (!l.msg.toLowerCase().includes(q) && !l.tag.toLowerCase().includes(q)) {
        return false;
      }
    }
    return true;
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-10">
      {/* Page Header */}
      <div className={`flex flex-col sm:flex-row sm:items-center justify-between ${isCompact ? "gap-3 p-3.5" : "gap-4 p-5"} rounded-lg bg-card border border-border shadow-sm`}>
        <div>
          <div className="flex items-center gap-2.5">
            <Terminal className="w-5 h-5 text-lime" />
            <h2 className="text-2xl sm:text-[26px] font-bold tracking-tight text-textBright">
              Live Activity Log & Audit Stream
            </h2>
            <div className="flex items-center gap-1.5 px-2.5 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider bg-lime/15 text-lime border border-lime/30">
              <span className="w-1.5 h-1.5 rounded-full bg-lime animate-pulse" />
              <span>USER-MODE ENGINE</span>
            </div>
            {wsConnected && (
              <span className="hidden sm:inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-mono font-semibold tracking-wider bg-blue-500/10 text-blue-500 border border-blue-500/20">
                <Radio className="w-2.5 h-2.5" />
                WS SYNC
              </span>
            )}
          </div>
          <p className="text-sm font-normal text-textFog mt-1.5 font-sans leading-relaxed">
            Direct output stream of memory page validations, thread walkthroughs, and forensic scan events.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2.5">
          <button
            onClick={() => setIsPaused(!isPaused)}
            className={`flex items-center gap-1.5 px-3 py-2 rounded-md font-mono text-xs font-medium transition-all ${
              isPaused
                ? "bg-threat-suspicious/20 text-threat-suspicious border border-threat-suspicious/40"
                : "bg-raise text-textBright border border-border hover:bg-card"
            }`}
          >
            {isPaused ? (
              <>
                <Play className="w-3.5 h-3.5 fill-threat-suspicious" />
                <span>RESUME</span>
              </>
            ) : (
              <>
                <Pause className="w-3.5 h-3.5" />
                <span>PAUSE</span>
              </>
            )}
          </button>

          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={`flex items-center gap-1.5 px-3 py-2 rounded-md font-mono text-xs font-medium border transition-all ${
              autoScroll
                ? "bg-lime/10 text-lime border-lime/30"
                : "bg-raise text-textDim border-border"
            }`}
            title="Toggle Auto-Scroll"
          >
            <ArrowDown className="w-3.5 h-3.5" />
            <span className="hidden md:inline">AUTO-SCROLL</span>
          </button>

          <button
            onClick={() => setLogs([])}
            className="flex items-center gap-1.5 px-3 py-2 rounded-md font-mono text-xs font-medium text-textDim hover:text-threat-malicious bg-raise border border-border transition-colors"
            title="Clear Log Terminal"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>CLEAR</span>
          </button>

          <button
            onClick={handleExportLog}
            disabled={logs.length === 0}
            className="flex items-center gap-1.5 px-3 py-2 rounded-md font-mono text-xs font-medium text-textBright bg-raise hover:bg-card border border-border transition-colors disabled:opacity-50"
            title="Download log file"
          >
            <Download className="w-3.5 h-3.5 text-textDim" />
            <span className="hidden sm:inline">Export .log</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className={`${isCompact ? "p-2.5 gap-3" : "p-4 gap-4"} rounded-lg bg-card border border-border shadow-sm flex flex-col md:flex-row md:items-center justify-between`}>
        {/* Severity Tabs */}
        <div className="flex flex-wrap items-center gap-1 bg-[#F5F1EB] p-1 rounded-md border border-border">
          {(
            [
              { key: "ALL", label: "ALL EVENTS" },
              { key: "success", label: "SUCCESS / OK" },
              { key: "info", label: "INFO / PROBES" },
              { key: "warning", label: "WARNINGS" },
              { key: "danger", label: "DANGER / ALERTS" },
            ] as const
          ).map((tab) => (
            <button
              key={tab.key}
              onClick={() => setLevelFilter(tab.key)}
              className={`px-3 py-1.5 rounded text-xs font-mono transition-all ${
                levelFilter === tab.key
                  ? "bg-white text-lime border border-border font-bold shadow-xs"
                  : "text-textDim hover:text-textBright"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="relative w-full md:w-80">
          <div className="relative flex items-center">
            <div className="absolute left-3 pointer-events-none flex items-center justify-center" aria-hidden="true">
              <Search className="w-3.5 h-3.5 text-textDim" />
            </div>
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search activity log message..."
              className="w-full bg-[#FAF7F2] text-xs text-textBright placeholder:text-textDim pl-9 pr-4 py-1.5 rounded-md border border-border focus:outline-none focus:border-lime/60 focus:ring-1 focus:ring-lime/40 transition-all font-mono"
            />
          </div>
        </div>
      </div>

      {/* Terminal View Container */}
      <div className={`${isCompact ? "p-3 space-y-2" : "p-5 space-y-3"} rounded-lg bg-card border border-border shadow-sm`}>
        <div className="flex items-center justify-between text-xs font-mono text-textDim pb-2 border-b border-border">
          <span className="flex items-center gap-2">
            <span
              className={`w-2 h-2 rounded-full ${
                isPaused ? "bg-threat-suspicious" : "bg-lime animate-pulse"
              }`}
            />
            <span>
              STATUS: {isPaused ? "PAUSED" : "ACTIVE"}
            </span>
          </span>
          <div className="flex items-center gap-3">
            {logs.length > 0 && <LastUpdated timestamp={lastUpdated} />}
            <span>BUFFER: {filteredLogs.length} / {logs.length} LINES</span>
          </div>
        </div>

        {/* Deep Terminal Window */}
        <div
          ref={containerRef}
          className={`${
            isCompact ? "h-[400px] p-2.5 space-y-0.5" : "h-[520px] p-4 space-y-2"
          } overflow-y-auto rounded-lg bg-[#F8F5F0] border border-border font-mono text-xs scroll-smooth select-text`}
        >
          {filteredLogs.length === 0 ? (
            <div className="h-full flex items-center justify-center text-textDim text-xs font-mono">
              Terminal buffer empty or no log lines match the filter.
            </div>
          ) : (
            filteredLogs.map((item) => (
              <div
                key={item.id}
                className={`flex items-baseline ${isCompact ? "gap-2 leading-snug" : "gap-3 leading-relaxed"} hover:bg-[#EFE9E1] px-1.5 py-0.5 rounded transition-colors`}
              >
                <span className="text-textDim select-none shrink-0 tnum text-[11px]">
                  [{item.timestamp}]
                </span>
                <span className={`shrink-0 ${getTagColor(item.tag, item.level)}`}>
                  [{item.tag}]
                </span>
                <span className="text-textFog break-all font-mono">
                  {item.msg}
                </span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
