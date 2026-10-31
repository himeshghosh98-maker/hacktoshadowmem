"use client";

import React from "react";
import { ShieldCheck, ShieldAlert, CheckCircle2, Shield } from "lucide-react";
import { ScanSummary } from "@/types/forensics";
import { LastUpdated } from "@/components/LastUpdated";

interface ThreatPosturePanelProps {
  summary: ScanSummary | null;
  hasScanned: boolean;
  lastUpdated?: number | null;
}

export function ThreatPosturePanel({
  summary,
  hasScanned,
  lastUpdated,
}: ThreatPosturePanelProps) {
  if (!hasScanned || !summary) {
    return (
      <div className="p-5 rounded-lg bg-card border border-border shadow-xs flex flex-col justify-between space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-border">
          <h3 className="text-sm font-semibold text-textBright">
            Threat Posture Overview
          </h3>
          <span className="text-xs font-mono px-2 py-0.5 rounded bg-background text-textDim border border-border">
            STANDBY
          </span>
        </div>

        <div className="h-64 rounded-lg border border-dashed border-border bg-background/50 flex flex-col items-center justify-center gap-3 p-6 text-center">
          <div className="w-12 h-12 rounded-full bg-card border border-border flex items-center justify-center shadow-xs">
            <ShieldCheck className="w-6 h-6 text-textDim" />
          </div>
          <div className="space-y-1">
            <h4 className="text-sm font-semibold text-textBright font-sans">
              Posture Assessment Pending
            </h4>
            <p className="text-xs font-sans text-textFog max-w-xs leading-relaxed">
              System integrity score and active threat classification calculate on first memory scan.
            </p>
          </div>
        </div>
      </div>
    );
  }

  const total = summary.total_scanned || 1;
  const cleared = summary.clean_count + summary.jit_engine_count;
  const clearRate = Math.min(100, Math.max(0, (cleared / total) * 100));
  const isThreatDetected = summary.malicious_count > 0;

  // SVG Circular Ring math
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (clearRate / 100) * circumference;

  return (
    <div className="p-5 rounded-lg bg-card border border-border shadow-xs flex flex-col justify-between space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-border">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-lime" />
          <h3 className="text-sm font-semibold text-textBright tracking-tight">
            Threat Posture Overview
          </h3>
        </div>
        <div className="flex items-center gap-2">
          <LastUpdated timestamp={lastUpdated} />
          <span
            className={`text-xs font-mono font-bold px-2 py-0.5 rounded border tracking-wider ${
              isThreatDetected
                ? "bg-threat-malicious/10 text-threat-malicious border-threat-malicious/30"
                : "bg-threat-clean/10 text-threat-clean border-threat-clean/30"
            }`}
          >
            {summary.system_posture.toUpperCase()}
          </span>
        </div>
      </div>

      {/* Circular Progress & Metrics Row */}
      <div className="flex flex-col sm:flex-row items-center justify-around gap-6 py-2">
        {/* Ring */}
        <div className="relative w-32 h-32 flex items-center justify-center shrink-0">
          <svg className="w-full h-full -rotate-90" viewBox="0 0 128 128">
            <circle
              cx="64"
              cy="64"
              r={radius}
              stroke="currentColor"
              strokeWidth="9"
              fill="transparent"
              className="text-background"
            />
            <circle
              cx="64"
              cy="64"
              r={radius}
              stroke="currentColor"
              strokeWidth="9"
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              fill="transparent"
              className={`transition-all duration-1000 ${
                isThreatDetected ? "text-threat-suspicious" : "text-lime"
              }`}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
            <span className="text-2xl font-bold font-mono text-textBright tracking-tight">
              {clearRate.toFixed(1)}%
            </span>
            <span className="text-xs font-mono text-textDim uppercase tracking-wider font-medium">
              Clear Rate
            </span>
          </div>
        </div>

        {/* Forensic Metrics Grid */}
        <div className="grid grid-cols-2 gap-3 w-full sm:w-auto flex-1 max-w-xs">
          <div className="p-3 rounded-md bg-background border border-border">
            <div className="flex items-center gap-1.5 text-xs text-textFog font-medium">
              <CheckCircle2 className="w-3.5 h-3.5 text-threat-clean" />
              <span>Processes Cleared</span>
            </div>
            <div className="text-base font-bold font-mono text-textBright mt-1">
              {cleared} / {total}
            </div>
          </div>

          <div className="p-3 rounded-md bg-background border border-border">
            <div className="flex items-center gap-1.5 text-xs text-textFog font-medium">
              <ShieldAlert className="w-3.5 h-3.5 text-threat-malicious" />
              <span>Threat Level</span>
            </div>
            <div
              className={`text-base font-bold font-mono mt-1 ${
                isThreatDetected ? "text-threat-malicious" : "text-threat-clean"
              }`}
            >
              {isThreatDetected ? "ELEVATED" : "LOW"}
            </div>
          </div>
        </div>
      </div>

      {/* Advisory Bar */}
      <div className="px-3 py-2 rounded-md bg-background border border-border text-xs font-mono text-textFog flex items-center justify-between">
        <span>Model: {summary.model_loaded ? "Random Forest (7 forensic features)" : "Heuristic Fallback"}</span>
        <span className="text-lime font-bold">SOC Operational</span>
      </div>
    </div>
  );
}
