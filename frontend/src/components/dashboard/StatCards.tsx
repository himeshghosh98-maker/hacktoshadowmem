"use client";

import React from "react";
import { Layers, AlertOctagon, Zap, Clock } from "lucide-react";
import { ScanSummary } from "@/types/forensics";
import { useDensity } from "@/context/DensityContext";
import { LastUpdated } from "@/components/LastUpdated";

interface StatCardsProps {
  summary: ScanSummary | null;
  avgScanTimeMs?: number;
  hasScanned: boolean;
  lastUpdated?: number | null;
}

export function StatCards({
  summary,
  avgScanTimeMs = 395,
  hasScanned,
  lastUpdated,
}: StatCardsProps) {
  const { isCompact } = useDensity();
  if (!hasScanned || !summary) {
    return (
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          {
            title: "Scanned Processes",
            border: "border-l-blue-500",
            icon: Layers,
            desc: "Awaiting baseline memory audit",
          },
          {
            title: "Active Threats",
            border: "border-l-threat-malicious",
            icon: AlertOctagon,
            desc: "No critical anomalies registered",
          },
          {
            title: "Injections Flagged",
            border: "border-l-threat-suspicious",
            icon: Zap,
            desc: "Memory anomaly monitoring ready",
          },
          {
            title: "Last Scan Duration",
            border: "border-l-lime",
            icon: Clock,
            desc: "Engine waiting to benchmark",
          },
        ].map((item, idx) => {
          const Icon = item.icon;
          return (
            <div
              key={idx}
              className={`p-4 rounded-lg bg-card border border-border border-l-4 ${item.border} flex flex-col justify-between h-32 transition-all shadow-xs`}
            >
              <div className="flex items-center justify-between">
                <span className="text-sm font-semibold text-textBright font-sans tracking-tight">
                  {item.title}
                </span>
                <div className="w-7 h-7 rounded bg-raise flex items-center justify-center border border-borderMuted">
                  <Icon className="w-3.5 h-3.5 text-textDim" />
                </div>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-textDim/60" />
                <span className="text-xs font-mono text-textFog font-medium">
                  {item.desc}
                </span>
              </div>
              <div className="text-xs font-mono text-textDim">
                Execute a scan to generate metrics
              </div>
            </div>
          );
        })}
      </div>
    );
  }

  const perProcessMs = summary.total_scanned > 0
    ? (avgScanTimeMs / summary.total_scanned).toFixed(1)
    : "0.0";

  const cards = [
    {
      title: "Scanned Processes",
      value: summary.total_scanned.toLocaleString(),
      unit: "processes",
      border: "border-l-blue-500",
      icon: Layers,
      trend: "+2 vs prev scan",
      trendType: "up",
      subtext: `${summary.clean_count} verified clean`,
    },
    {
      title: "Active Threats",
      value: summary.malicious_count.toString(),
      unit: "malicious PIDs",
      border: "border-l-threat-malicious",
      icon: AlertOctagon,
      valueColor: summary.malicious_count > 0 ? "text-threat-malicious" : "text-textBright",
      trend: summary.malicious_count > 0 ? "Threat containment required" : "Zero active threats",
      trendType: summary.malicious_count > 0 ? "danger" : "safe",
      subtext: summary.malicious_count > 0 ? "User-mode suspend recommended" : "No malicious allocations",
    },
    {
      title: "Injections Flagged",
      value: summary.anomalies_detected.toString(),
      unit: "anomalies",
      border: "border-l-threat-suspicious",
      icon: Zap,
      valueColor: summary.anomalies_detected > 0 ? "text-threat-suspicious" : "text-textBright",
      trend: `${summary.suspicious_count} suspicious / ${summary.jit_engine_count} JIT ignored`,
      trendType: "neutral",
      subtext: "Protection flips & unbacked exec",
    },
    {
      title: "Last Scan Duration",
      value: `${avgScanTimeMs}`,
      unit: "ms",
      border: "border-l-lime",
      icon: Clock,
      valueColor: "text-lime",
      trend: "Total scan duration",
      trendType: "safe",
      subtext: `~${perProcessMs}ms avg per process`,
    },
  ];

  return (
    <div className={`grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 ${isCompact ? "gap-2.5" : "gap-4"}`}>
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <div
            key={idx}
            className={`${
              isCompact ? "p-2.5 h-24" : "p-4 h-32"
            } rounded-lg bg-card border border-border border-l-4 ${card.border} flex flex-col justify-between hover:border-border/90 hover:bg-[#FAF7F2] transition-all shadow-xs`}
          >
            <div className="flex items-center justify-between">
              <span className="text-sm font-semibold text-textBright font-sans tracking-tight">
                {card.title}
              </span>
              <div className="flex items-center gap-2">
                <LastUpdated timestamp={lastUpdated} />
                <div className={`${isCompact ? "w-6 h-6" : "w-7 h-7"} rounded bg-raise flex items-center justify-center border border-borderMuted`}>
                  <Icon className={`${isCompact ? "w-3 h-3" : "w-3.5 h-3.5"} text-textFog`} />
                </div>
              </div>
            </div>

            <div className="flex items-baseline gap-2">
              <span className={`${isCompact ? "text-2xl" : "text-3xl"} font-extrabold font-mono tracking-tight ${card.valueColor || "text-textBright"}`}>
                {card.value}
              </span>
              <span className="text-xs font-mono font-medium text-textDim">{card.unit}</span>
            </div>

            <div className="flex items-center justify-between text-xs font-mono">
              <span
                className={`truncate ${
                  card.trendType === "danger"
                    ? "text-threat-malicious font-semibold"
                    : card.trendType === "safe"
                    ? "text-threat-clean font-medium"
                    : "text-textDim font-medium"
                }`}
              >
                {card.trend}
              </span>
            </div>
          </div>
        );
      })}
    </div>
  );
}
