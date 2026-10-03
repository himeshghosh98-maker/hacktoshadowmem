"use client";

import React from "react";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
} from "recharts";
import { PieChart as PieIcon, TrendingUp, ShieldAlert, ListOrdered } from "lucide-react";
import { ScanSummary, ProcessEntry, ScanHistoryRecord } from "@/types/forensics";
import { useDensity } from "@/context/DensityContext";
import { LastUpdated } from "@/components/LastUpdated";

interface AnalyticsRowProps {
  summary: ScanSummary | null;
  processes: ProcessEntry[];
  scanHistory: ScanHistoryRecord[];
  hasScanned: boolean;
  lastUpdated?: number | null;
}

export function AnalyticsRow({
  summary,
  processes,
  scanHistory,
  hasScanned,
  lastUpdated,
}: AnalyticsRowProps) {
  const { isCompact } = useDensity();
  // 1. Process Status Distribution Data
  const donutData = React.useMemo(() => {
    if (!summary) return [];
    return [
      { name: "Clean", value: summary.clean_count, color: "#3D8B60" },
      { name: "JIT Engines", value: summary.jit_engine_count, color: "#4A7BB0" },
      { name: "Suspicious", value: summary.suspicious_count, color: "#E68A2E" },
      { name: "Malicious", value: summary.malicious_count, color: "#D6453D" },
    ].filter((item) => item.value > 0);
  }, [summary]);

  // 2. Threat Categories Data
  const categoryStats = React.useMemo(() => {
    const counts: Record<string, { count: number; mitreId: string; name: string }> = {};

    processes.forEach((p) => {
      if (p.classification) {
        const key = p.classification.name || "Unknown Technique";
        if (!counts[key]) {
          counts[key] = {
            count: 0,
            mitreId: p.classification.mitre_id || p.classification.id || "T1055",
            name: key,
          };
        }
        counts[key].count += 1;
      }
    });

    const totalFlagged = Object.values(counts).reduce((acc, curr) => acc + curr.count, 0) || 1;

    return Object.values(counts)
      .map((cat) => ({
        ...cat,
        percentage: Math.round((cat.count / totalFlagged) * 100),
      }))
      .sort((a, b) => b.count - a.count);
  }, [processes]);

  return (
    <div className={`grid grid-cols-1 lg:grid-cols-3 ${isCompact ? "gap-4" : "gap-6"}`}>
      {/* 1. Donut Chart: Status Distribution */}
      <div className={`${isCompact ? "p-3.5 space-y-2.5" : "p-5 space-y-4"} rounded-lg bg-card border border-border shadow-sm flex flex-col justify-between`}>
        <div className={`flex items-center justify-between ${isCompact ? "pb-2" : "pb-3"} border-b border-border/80`}>
          <div className="flex items-center gap-2">
            <PieIcon className="w-4 h-4 text-lime" />
            <h3 className="text-sm font-semibold text-textBright tracking-tight">
              Process Status Distribution
            </h3>
          </div>
          <div className="flex items-center gap-2">
            {hasScanned && summary && <LastUpdated timestamp={lastUpdated} />}
            <span className="text-[10px] font-mono font-semibold text-textDim uppercase tracking-wider">
              DONUT BREAKDOWN
            </span>
          </div>
        </div>

        {!hasScanned || !summary ? (
          <div className="h-60 rounded-lg border border-dashed border-border/80 bg-[#FBF8F4] flex flex-col items-center justify-center gap-2 text-center p-4">
            <PieIcon className="w-8 h-8 text-textDim/50" />
            <span className="text-sm font-semibold text-textBright font-sans">
              No Process Data Yet
            </span>
            <span className="text-xs font-sans text-textFog leading-relaxed">
              Scan processes to plot allocation breakdown
            </span>
          </div>
        ) : (
          <div className={isCompact ? "space-y-2.5" : "space-y-4"}>
            <div className={`${isCompact ? "h-36" : "h-44"} relative flex items-center justify-center`}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={donutData}
                    cx="50%"
                    cy="50%"
                    innerRadius={isCompact ? 40 : 50}
                    outerRadius={isCompact ? 58 : 70}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {donutData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} stroke="#FFFFFF" strokeWidth={2} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#FFFFFF",
                      borderColor: "#EBE5DF",
                      color: "#141414",
                      fontSize: "12px",
                      borderRadius: "6px",
                      fontFamily: "monospace",
                      boxShadow: "0 4px 12px rgba(0,0,0,0.05)",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className={`${isCompact ? "text-xl" : "text-2xl"} font-extrabold font-mono text-textBright tracking-tight`}>
                  {summary.total_scanned}
                </span>
                <span className="text-[10px] font-mono text-textDim uppercase tracking-wider font-semibold">
                  Audited
                </span>
              </div>
            </div>

            {/* Legend */}
            <div className={`grid grid-cols-2 ${isCompact ? "gap-1.5 text-[11px]" : "gap-2 text-xs"} font-mono`}>
              <div className="flex items-center gap-1.5 text-textFog">
                <span className="w-2 h-2 rounded-full bg-[#3D8B60]" />
                <span>Clean: <strong className="text-textBright font-bold">{summary.clean_count}</strong></span>
              </div>
              <div className="flex items-center gap-1.5 text-textFog">
                <span className="w-2 h-2 rounded-full bg-[#4A7BB0]" />
                <span>JIT: <strong className="text-textBright font-bold">{summary.jit_engine_count}</strong></span>
              </div>
              <div className="flex items-center gap-1.5 text-textFog">
                <span className="w-2 h-2 rounded-full bg-[#E68A2E]" />
                <span>Suspicious: <strong className="text-textBright font-bold">{summary.suspicious_count}</strong></span>
              </div>
              <div className="flex items-center gap-1.5 text-textFog">
                <span className="w-2 h-2 rounded-full bg-[#D6453D]" />
                <span>Malicious: <strong className="text-textBright font-bold">{summary.malicious_count}</strong></span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* 2. Threats Detected Over Time */}
      <div className={`${isCompact ? "p-3.5 space-y-2.5" : "p-5 space-y-4"} rounded-lg bg-card border border-border shadow-sm flex flex-col justify-between`}>
        <div className={`flex items-center justify-between ${isCompact ? "pb-2" : "pb-3"} border-b border-border/80`}>
          <div className="flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-lime" />
            <h3 className="text-sm font-semibold text-textBright tracking-tight">
              Threats Over Time
            </h3>
          </div>
          <div className="flex items-center gap-2">
            {hasScanned && scanHistory.length > 0 && <LastUpdated timestamp={lastUpdated} />}
            <span className="text-[10px] font-mono font-semibold text-textDim uppercase tracking-wider">
              SCAN VELOCITY
            </span>
          </div>
        </div>

        {!hasScanned || scanHistory.length === 0 ? (
          <div className="h-60 rounded-lg border border-dashed border-border/80 bg-[#FBF8F4] flex flex-col items-center justify-center gap-2 text-center p-4">
            <TrendingUp className="w-8 h-8 text-textDim/50" />
            <span className="text-sm font-semibold text-textBright font-sans">
              Velocity Trend Awaiting Cycles
            </span>
            <span className="text-xs font-sans text-textFog leading-relaxed">
              Historical multi-scan timeline will render here
            </span>
          </div>
        ) : (
          <div className={isCompact ? "space-y-1.5" : "space-y-2"}>
            <div className={isCompact ? "h-36" : "h-44"}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                  data={scanHistory}
                  margin={{ top: 10, right: 10, left: -25, bottom: 0 }}
                >
                  <defs>
                    <linearGradient id="threatGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#E8793C" stopOpacity={0.35} />
                      <stop offset="95%" stopColor="#E8793C" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <XAxis
                    dataKey="timeLabel"
                    stroke="#6B645C"
                    fontSize={10}
                    tickLine={false}
                    fontFamily="monospace"
                  />
                  <YAxis
                    stroke="#6B645C"
                    fontSize={10}
                    tickLine={false}
                    domain={[0, "dataMax + 2"]}
                    fontFamily="monospace"
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#FFFFFF",
                      borderColor: "#EBE5DF",
                      color: "#141414",
                      fontSize: "12px",
                      borderRadius: "6px",
                      fontFamily: "monospace",
                      boxShadow: "0 4px 12px rgba(0,0,0,0.05)",
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="threats"
                    stroke="#E8793C"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#threatGradient)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
            <div className={`flex items-center justify-between ${isCompact ? "text-[11px] pt-1.5" : "text-xs pt-2"} font-mono text-textFog border-t border-border/60`}>
              <span>Recorded Scans: <strong className="text-textBright font-bold">{scanHistory.length}</strong></span>
              <span className="text-lime font-bold">Stable Forensics Baseline</span>
            </div>
          </div>
        )}
      </div>

      {/* 3. Top Threat Categories */}
      <div className={`${isCompact ? "p-3.5 space-y-2.5" : "p-5 space-y-4"} rounded-lg bg-card border border-border shadow-sm flex flex-col justify-between`}>
        <div className={`flex items-center justify-between ${isCompact ? "pb-2" : "pb-3"} border-b border-border/80`}>
          <div className="flex items-center gap-2">
            <ListOrdered className="w-4 h-4 text-lime" />
            <h3 className="text-sm font-semibold text-textBright tracking-tight">
              Top Threat Categories
            </h3>
          </div>
          <div className="flex items-center gap-2">
            {hasScanned && categoryStats.length > 0 && <LastUpdated timestamp={lastUpdated} />}
            <span className="text-[10px] font-mono font-semibold text-textDim uppercase tracking-wider">
              MITRE ATT&CK
            </span>
          </div>
        </div>

        {!hasScanned || categoryStats.length === 0 ? (
          <div className="h-60 rounded-lg border border-dashed border-border/80 bg-[#FBF8F4] flex flex-col items-center justify-center gap-2 text-center p-4">
            <ShieldAlert className="w-8 h-8 text-textDim/50" />
            <span className="text-sm font-semibold text-textBright font-sans">
              No Threat Injections Found
            </span>
            <span className="text-xs font-sans text-textFog leading-relaxed">
              All memory regions adhere to standard DEP / PE layout
            </span>
          </div>
        ) : (
          <div className={`${isCompact ? "space-y-2 max-h-[175px]" : "space-y-3.5 max-h-[240px]"} overflow-y-auto pr-1`}>
            {categoryStats.map((cat, idx) => (
              <div key={idx} className={isCompact ? "space-y-1" : "space-y-1.5"}>
                <div className="flex items-baseline justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-threat-malicious/15 text-threat-malicious border border-threat-malicious/30 tracking-wider">
                      {cat.mitreId}
                    </span>
                    <span className="font-semibold text-textBright font-sans">
                      {cat.name}
                    </span>
                  </div>
                  <span className="font-mono text-textDim text-xs font-medium">
                    {cat.count} {cat.count === 1 ? "proc" : "procs"} ({cat.percentage}%)
                  </span>
                </div>

                {/* Progress bar */}
                <div className="h-1.5 w-full bg-[#EFE9E1] rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-threat-suspicious to-threat-malicious rounded-full"
                    style={{ width: `${cat.percentage}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
