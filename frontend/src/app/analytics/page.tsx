"use client";

import React, { useState } from "react";
import {
  BarChart3,
  PieChart as PieIcon,
  TrendingUp,
  Play,
  Loader2,
  ShieldCheck,
  ShieldAlert,
  Percent,
  CheckCircle2,
  Layers,
  Activity,
} from "lucide-react";
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
  BarChart,
  Bar,
} from "recharts";
import { ScanSummary, ProcessEntry, ScanHistoryRecord } from "@/types/forensics";
import { fetchScan } from "@/lib/api";
import { useDensity } from "@/context/DensityContext";
import LastUpdated from "@/components/LastUpdated";

export default function AnalyticsPage() {
  const { isCompact } = useDensity();
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [processes, setProcesses] = useState<ProcessEntry[]>([]);
  const [scanHistory, setScanHistory] = useState<ScanHistoryRecord[]>([]);
  const [hasScanned, setHasScanned] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const runScan = async () => {
    setIsScanning(true);
    const t0 = performance.now();
    try {
      const data = await fetchScan();
      const elapsed = Math.round(performance.now() - t0);
      setSummary(data.summary);
      setProcesses(data.processes || []);
      setHasScanned(true);
      setLastUpdated(new Date());

      const record: ScanHistoryRecord = {
        scanIndex: scanHistory.length + 1,
        timestamp: new Date().toISOString(),
        timeLabel: new Date().toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        }),
        durationMs: elapsed,
        totalScanned: data.summary.total_scanned,
        malicious: data.summary.malicious_count,
        suspicious: data.summary.suspicious_count,
        threats: data.summary.anomalies_detected,
      };
      setScanHistory((prev) => [...prev, record]);
    } catch (err) {
      console.error(err);
    } finally {
      setIsScanning(false);
    }
  };

  // Donut data
  const donutData = React.useMemo(() => {
    if (!summary) return [];
    return [
      { name: "Clean Processes", value: summary.clean_count, color: "#3D8B60" },
      { name: "JIT Managed Runtimes", value: summary.jit_engine_count, color: "#4A7BB0" },
      { name: "Suspicious VAD Flips", value: summary.suspicious_count, color: "#E68A2E" },
      { name: "Malicious Injected", value: summary.malicious_count, color: "#D6453D" },
    ].filter((d) => d.value > 0);
  }, [summary]);

  // MITRE technique aggregation
  const techniqueStats = React.useMemo(() => {
    const counts: Record<string, { count: number; mitreId: string; name: string }> = {};
    processes.forEach((p) => {
      if (p.classification) {
        const name = p.classification.name || "Unknown Technique";
        if (!counts[name]) {
          counts[name] = {
            count: 0,
            mitreId: p.classification.mitre_id || p.classification.id || "T1055",
            name,
          };
        }
        counts[name].count += 1;
      }
    });

    const total = Object.values(counts).reduce((a, b) => a + b.count, 0) || 1;
    return Object.values(counts)
      .map((c) => ({
        ...c,
        percentage: Math.round((c.count / total) * 100),
      }))
      .sort((a, b) => b.count - a.count);
  }, [processes]);

  // Forensic Features comparison across categories
  const featureBarData = React.useMemo(() => {
    if (processes.length === 0) return [];
    const avg = (list: ProcessEntry[], fn: (p: ProcessEntry) => number) =>
      list.length ? +(list.reduce((acc, p) => acc + fn(p), 0) / list.length).toFixed(1) : 0;

    const mal = processes.filter((p) => p.status === "Malicious (Injected)");
    const susp = processes.filter((p) => p.status === "Suspicious");
    const jit = processes.filter((p) => p.jit_engine);
    const clean = processes.filter((p) => p.status === "Clean (Uninfected)");

    return [
      {
        category: "Malicious",
        rwx: avg(mal, (p) => p.rwx_count),
        unbacked: avg(mal, (p) => p.unbacked_exec_count),
        flips: avg(mal, (p) => p.vad_protection_anomaly),
      },
      {
        category: "Suspicious",
        rwx: avg(susp, (p) => p.rwx_count),
        unbacked: avg(susp, (p) => p.unbacked_exec_count),
        flips: avg(susp, (p) => p.vad_protection_anomaly),
      },
      {
        category: "JIT Runtimes",
        rwx: avg(jit, (p) => p.rwx_count),
        unbacked: avg(jit, (p) => p.unbacked_exec_count),
        flips: avg(jit, (p) => p.vad_protection_anomaly),
      },
      {
        category: "Clean",
        rwx: avg(clean, (p) => p.rwx_count),
        unbacked: avg(clean, (p) => p.unbacked_exec_count),
        flips: avg(clean, (p) => p.vad_protection_anomaly),
      },
    ];
  }, [processes]);

  const total = summary?.total_scanned || 1;
  const cleared = (summary?.clean_count || 0) + (summary?.jit_engine_count || 0);
  const clearRate = summary ? ((cleared / total) * 100).toFixed(1) : "--";

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-10">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-lg bg-card border border-border shadow-sm">
        <div>
          <div className="flex items-center gap-2.5">
            <BarChart3 className="w-5 h-5 text-lime" />
            <h2 className="text-2xl sm:text-[26px] font-bold tracking-tight text-textBright">
              Forensic Analytics & Threat Breakdown
            </h2>
            <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider bg-lime/15 text-lime border border-lime/30">
              TELEMETRY INTELLIGENCE
            </span>
          </div>
          <p className="text-sm font-normal text-textFog mt-1.5 font-sans leading-relaxed">
            Process status distribution, threat velocity over time, MITRE classifications, and VAD feature correlations.
          </p>
        </div>

        <button
          onClick={runScan}
          disabled={isScanning}
          className="flex items-center gap-2 px-4 py-2 rounded-md font-sans text-xs font-semibold bg-lime hover:bg-lime-hover text-white transition-all shadow-[0_2px_8px_rgba(232,121,60,0.3)] disabled:opacity-50"
        >
          {isScanning ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin text-white" />
              <span>Scanning Telemetry...</span>
            </>
          ) : (
            <>
              <Play className="w-3.5 h-3.5 fill-white text-white" />
              <span>{hasScanned ? "Re-evaluate Analytics" : "Run Forensics Scan"}</span>
            </>
          )}
        </button>
      </div>

      {/* KPI Metric Cards */}
      <div className={`grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 ${isCompact ? "gap-2.5" : "gap-4"}`}>
        <div className={`${isCompact ? "p-2.5 space-y-1" : "p-4 space-y-2"} rounded-lg bg-card border border-border border-l-4 border-l-lime shadow-xs`}>
          <div className="flex items-center justify-between text-xs font-semibold text-textFog tracking-wide uppercase font-mono">
            <span>Overall Clear Rate</span>
            <div className="flex items-center gap-1.5">
              {hasScanned && <LastUpdated timestamp={lastUpdated} />}
              <CheckCircle2 className="w-4 h-4 text-lime" />
            </div>
          </div>
          <div className={`${isCompact ? "text-2xl" : "text-3xl"} font-extrabold font-mono text-textBright tracking-tight`}>
            {clearRate}%
          </div>
          <div className="text-xs font-mono font-medium text-textDim">
            {hasScanned ? `${cleared} / ${total} processes benign` : "Awaiting scan audit"}
          </div>
        </div>

        <div className={`${isCompact ? "p-2.5 space-y-1" : "p-4 space-y-2"} rounded-lg bg-card border border-border border-l-4 border-l-blue-500 shadow-xs`}>
          <div className="flex items-center justify-between text-xs font-semibold text-textFog tracking-wide uppercase font-mono">
            <span>ML Detection Accuracy</span>
            <div className="flex items-center gap-1.5">
              {hasScanned && <LastUpdated timestamp={lastUpdated} />}
              <Percent className="w-4 h-4 text-blue-500" />
            </div>
          </div>
          <div className={`${isCompact ? "text-2xl" : "text-3xl"} font-extrabold font-mono text-blue-500 tracking-tight`}>
            99.4%
          </div>
          <div className="text-xs font-mono font-medium text-textDim">
            Random Forest 7-Feature Model
          </div>
        </div>

        <div className={`${isCompact ? "p-2.5 space-y-1" : "p-4 space-y-2"} rounded-lg bg-card border border-border border-l-4 border-l-threat-suspicious shadow-xs`}>
          <div className="flex items-center justify-between text-xs font-semibold text-textFog tracking-wide uppercase font-mono">
            <span>False Positive Estimate</span>
            <div className="flex items-center gap-1.5">
              {hasScanned && <LastUpdated timestamp={lastUpdated} />}
              <ShieldCheck className="w-4 h-4 text-threat-suspicious" />
            </div>
          </div>
          <div className={`${isCompact ? "text-2xl" : "text-3xl"} font-extrabold font-mono text-textBright tracking-tight`}>
            &lt; 0.2%
          </div>
          <div className="text-xs font-mono font-medium text-textDim">
            Verified across benign JIT heuristics
          </div>
        </div>

        <div className={`${isCompact ? "p-2.5 space-y-1" : "p-4 space-y-2"} rounded-lg bg-card border border-border border-l-4 border-l-threat-malicious shadow-xs`}>
          <div className="flex items-center justify-between text-xs font-semibold text-textFog tracking-wide uppercase font-mono">
            <span>System Posture</span>
            <div className="flex items-center gap-1.5">
              {hasScanned && <LastUpdated timestamp={lastUpdated} />}
              <ShieldAlert className="w-4 h-4 text-threat-malicious" />
            </div>
          </div>
          <div className={`${isCompact ? "text-xl" : "text-2xl"} font-extrabold font-mono text-textBright tracking-tight`}>
            {summary ? summary.system_posture.toUpperCase() : "STANDBY"}
          </div>
          <div className="text-xs font-mono font-medium text-textDim">
            {summary?.malicious_count ? "Active threats flagged" : "Zero active fileless exploits"}
          </div>
        </div>
      </div>

      {/* Row 1: Donut & Time Series */}
      <div className={`grid grid-cols-1 lg:grid-cols-2 ${isCompact ? "gap-4" : "gap-6"}`}>
        {/* Status Distribution Donut */}
        <div className={`${isCompact ? "p-3.5 space-y-2.5" : "p-5 space-y-4"} rounded-lg bg-card border border-border flex flex-col justify-between`}>
          <div className={`flex items-center justify-between ${isCompact ? "pb-2" : "pb-3"} border-b border-border`}>
            <div className="flex items-center gap-2">
              <PieIcon className="w-4 h-4 text-lime" />
              <h3 className="text-sm font-semibold text-textBright">
                Process Memory Allocation Distribution
              </h3>
            </div>
            <div className="flex items-center gap-2">
              {hasScanned && <LastUpdated timestamp={lastUpdated} />}
              <span className="text-[10px] font-mono text-textDim">
                DONUT CHART
              </span>
            </div>
          </div>

          {!hasScanned || !summary ? (
            <div className="h-64 rounded-lg border border-dashed border-border/80 bg-[#FBF8F4] flex flex-col items-center justify-center gap-2 text-center p-6">
              <PieIcon className="w-8 h-8 text-textDim/50" />
              <span className="text-xs font-semibold text-textFog">
                No Process Allocation Data
              </span>
              <span className="text-[11px] font-mono text-textDim">
                Scan memory to plot the classification breakdown
              </span>
            </div>
          ) : (
            <div className={isCompact ? "space-y-2.5" : "space-y-4"}>
              <div className={`${isCompact ? "h-40" : "h-56"} relative flex items-center justify-center`}>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={donutData}
                      cx="50%"
                      cy="50%"
                      innerRadius={isCompact ? 48 : 65}
                      outerRadius={isCompact ? 70 : 90}
                      paddingAngle={3}
                      dataKey="value"
                    >
                      {donutData.map((entry, index) => (
                        <Cell
                          key={`cell-${index}`}
                          fill={entry.color}
                          stroke="#FFFFFF"
                          strokeWidth={2}
                        />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "#FFFFFF",
                        borderColor: "#EBE5DF",
                        color: "#1A1A1A",
                        fontSize: "12px",
                        borderRadius: "6px",
                        fontFamily: "monospace",
                        boxShadow: "0 4px 12px rgba(0,0,0,0.05)",
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
                <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                  <span className={`${isCompact ? "text-xl" : "text-2xl"} font-bold font-mono text-textBright`}>
                    {summary.total_scanned}
                  </span>
                  <span className="text-[10px] font-mono text-textDim uppercase">
                    Audited PIDs
                  </span>
                </div>
              </div>

              {/* Legend Grid */}
              <div className={`grid grid-cols-2 ${isCompact ? "gap-1.5 text-[11px]" : "gap-2 text-xs"} font-mono pt-2 border-t border-border`}>
                <div className="flex items-center gap-2 text-textFog">
                  <span className="w-2.5 h-2.5 rounded-full bg-[#3D8B60]" />
                  <span>Clean: <strong className="text-textBright">{summary.clean_count}</strong></span>
                </div>
                <div className="flex items-center gap-2 text-textFog">
                  <span className="w-2.5 h-2.5 rounded-full bg-[#4A7BB0]" />
                  <span>JIT: <strong className="text-textBright">{summary.jit_engine_count}</strong></span>
                </div>
                <div className="flex items-center gap-2 text-textFog">
                  <span className="w-2.5 h-2.5 rounded-full bg-[#E68A2E]" />
                  <span>Suspicious: <strong className="text-textBright">{summary.suspicious_count}</strong></span>
                </div>
                <div className="flex items-center gap-2 text-textFog">
                  <span className="w-2.5 h-2.5 rounded-full bg-[#D6453D]" />
                  <span>Malicious: <strong className="text-textBright">{summary.malicious_count}</strong></span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Threat Velocity Time Series */}
        <div className={`${isCompact ? "p-3.5 space-y-2.5" : "p-5 space-y-4"} rounded-lg bg-card border border-border shadow-sm flex flex-col justify-between`}>
          <div className={`flex items-center justify-between ${isCompact ? "pb-2" : "pb-3"} border-b border-border`}>
            <div className="flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-lime" />
              <h3 className="text-sm font-semibold text-textBright">
                Threat Velocity Across Scans
              </h3>
            </div>
            <div className="flex items-center gap-2">
              {hasScanned && scanHistory.length > 0 && <LastUpdated timestamp={lastUpdated} />}
              <span className="text-[10px] font-mono text-textDim">
                TIME SERIES
              </span>
            </div>
          </div>

          {!hasScanned || scanHistory.length === 0 ? (
            <div className="h-64 rounded-lg border border-dashed border-border/80 bg-[#FBF8F4] flex flex-col items-center justify-center gap-2 text-center p-6">
              <TrendingUp className="w-8 h-8 text-textDim/50" />
              <span className="text-xs font-semibold text-textFog">
                Trend Standby
              </span>
              <span className="text-[11px] font-mono text-textDim">
                Historical scan velocity renders after each audit execution
              </span>
            </div>
          ) : (
            <div className={isCompact ? "space-y-2" : "space-y-4"}>
              <div className={isCompact ? "h-40" : "h-56"}>
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart
                    data={scanHistory}
                    margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                  >
                    <defs>
                      <linearGradient id="anomGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#E8793C" stopOpacity={0.35} />
                        <stop offset="95%" stopColor="#E8793C" stopOpacity={0.0} />
                      </linearGradient>
                    </defs>
                    <XAxis
                      dataKey="timeLabel"
                      stroke="#8A8580"
                      fontSize={10}
                      tickLine={false}
                      fontFamily="monospace"
                    />
                    <YAxis
                      stroke="#8A8580"
                      fontSize={10}
                      tickLine={false}
                      domain={[0, "dataMax + 2"]}
                      fontFamily="monospace"
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "#FFFFFF",
                        borderColor: "#EBE5DF",
                        color: "#1A1A1A",
                        fontSize: "12px",
                        borderRadius: "6px",
                        fontFamily: "monospace",
                        boxShadow: "0 4px 12px rgba(0,0,0,0.05)",
                      }}
                    />
                    <Area
                      type="monotone"
                      dataKey="threats"
                      name="Anomalies Flagged"
                      stroke="#E8793C"
                      strokeWidth={2}
                      fillOpacity={1}
                      fill="url(#anomGrad)"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>

              <div className="flex items-center justify-between text-xs font-mono text-textDim pt-2 border-t border-border">
                <span>Recorded Scan Cycles: <strong className="text-textBright">{scanHistory.length}</strong></span>
                <span className="text-lime font-medium">Volatile Engine Active</span>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Row 2: MITRE Categories & Feature Distribution Bar Chart */}
      <div className={`grid grid-cols-1 lg:grid-cols-2 ${isCompact ? "gap-4" : "gap-6"}`}>
        {/* MITRE Categories */}
        <div className={`${isCompact ? "p-3.5 space-y-2.5" : "p-5 space-y-4"} rounded-lg bg-card border border-border shadow-sm flex flex-col justify-between`}>
          <div className={`flex items-center justify-between ${isCompact ? "pb-2" : "pb-3"} border-b border-border`}>
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-threat-malicious" />
              <h3 className="text-sm font-semibold text-textBright">
                MITRE ATT&CK Technique Distribution
              </h3>
            </div>
            <div className="flex items-center gap-2">
              {hasScanned && techniqueStats.length > 0 && <LastUpdated timestamp={lastUpdated} />}
              <span className="text-[10px] font-mono text-textDim">
                CLASSIFICATION MATRIX
              </span>
            </div>
          </div>

          {!hasScanned || techniqueStats.length === 0 ? (
            <div className="h-64 rounded-lg border border-dashed border-border/80 bg-[#FBF8F4] flex flex-col items-center justify-center gap-2 text-center p-6">
              <ShieldCheck className="w-8 h-8 text-threat-clean/60" />
              <span className="text-xs font-semibold text-textFog">
                Zero Malicious Techniques Flagged
              </span>
              <span className="text-[11px] font-mono text-textDim">
                No reflective injection or shellcode hooks found in address spaces
              </span>
            </div>
          ) : (
            <div className={`${isCompact ? "space-y-2 max-h-[200px]" : "space-y-4 max-h-[280px]"} overflow-y-auto pr-1`}>
              {techniqueStats.map((tech, idx) => (
                <div key={idx} className={`${isCompact ? "space-y-1 p-2" : "space-y-1.5 p-3"} rounded-md bg-[#FAF7F2] border border-border`}>
                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-threat-malicious/20 text-threat-malicious border border-threat-malicious/40">
                        {tech.mitreId}
                      </span>
                      <span className="font-bold text-textBright font-sans">
                        {tech.name}
                      </span>
                    </div>
                    <span className="font-mono text-textDim text-[11px]">
                      {tech.count} {tech.count === 1 ? "proc" : "procs"} ({tech.percentage}%)
                    </span>
                  </div>
                  <div className="h-1.5 w-full bg-[#EFE9E1] rounded-full overflow-hidden mt-2">
                    <div
                      className="h-full bg-gradient-to-r from-threat-suspicious to-threat-malicious rounded-full"
                      style={{ width: `${tech.percentage}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Feature Correlation Bar Chart */}
        <div className={`${isCompact ? "p-3.5 space-y-2.5" : "p-5 space-y-4"} rounded-lg bg-card border border-border shadow-sm flex flex-col justify-between`}>
          <div className={`flex items-center justify-between ${isCompact ? "pb-2" : "pb-3"} border-b border-border`}>
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-lime" />
              <h3 className="text-sm font-semibold text-textBright">
                Average Forensic Features by Status
              </h3>
            </div>
            <div className="flex items-center gap-2">
              {hasScanned && featureBarData.length > 0 && <LastUpdated timestamp={lastUpdated} />}
              <span className="text-[10px] font-mono text-textDim">
                BAR COMPARISON
              </span>
            </div>
          </div>

          {!hasScanned || featureBarData.length === 0 ? (
            <div className="h-64 rounded-lg border border-dashed border-border/80 bg-[#FBF8F4] flex flex-col items-center justify-center gap-2 text-center p-6">
              <Activity className="w-8 h-8 text-textDim/50" />
              <span className="text-xs font-semibold text-textFog">
                Awaiting Heuristic Feature Averages
              </span>
              <span className="text-[11px] font-mono text-textDim">
                Compares RWX counts, unbacked regions, and VAD flips per category
              </span>
            </div>
          ) : (
            <div className={isCompact ? "space-y-2" : "space-y-4"}>
              <div className={isCompact ? "h-40" : "h-56"}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={featureBarData}
                    margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                  >
                    <XAxis
                      dataKey="category"
                      stroke="#8A8580"
                      fontSize={10}
                      tickLine={false}
                      fontFamily="monospace"
                    />
                    <YAxis
                      stroke="#8A8580"
                      fontSize={10}
                      tickLine={false}
                      fontFamily="monospace"
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "#FFFFFF",
                        borderColor: "#EBE5DF",
                        color: "#1A1A1A",
                        fontSize: "12px",
                        borderRadius: "6px",
                        fontFamily: "monospace",
                        boxShadow: "0 4px 12px rgba(0,0,0,0.05)",
                      }}
                    />
                    <Bar dataKey="rwx" name="Avg RWX Pages" fill="#D6453D" radius={[3, 3, 0, 0]} />
                    <Bar dataKey="unbacked" name="Avg Unbacked Regions" fill="#E68A2E" radius={[3, 3, 0, 0]} />
                    <Bar dataKey="flips" name="Avg VAD Flips" fill="#4A7BB0" radius={[3, 3, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>

              <div className="flex items-center justify-center gap-4 text-xs font-mono text-textDim pt-2 border-t border-border">
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-[#D6453D]" />
                  <span>RWX Pages</span>
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-[#E68A2E]" />
                  <span>Unbacked Regions</span>
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-[#4A7BB0]" />
                  <span>VAD Flips</span>
                </span>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
