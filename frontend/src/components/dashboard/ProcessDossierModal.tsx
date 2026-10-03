"use client";

import React from "react";
import {
  X,
  ShieldAlert,
  Cpu,
  Layers,
  Lock,
  Unlock,
} from "lucide-react";
import { ProcessEntry } from "@/types/forensics";

interface ProcessDossierModalProps {
  process: ProcessEntry | null;
  onClose: () => void;
  onToggleIsolate?: (pid: number, isCurrentlyIsolated: boolean) => void;
  isIsolating?: boolean;
}

export function ProcessDossierModal({
  process,
  onClose,
  onToggleIsolate,
  isIsolating,
}: ProcessDossierModalProps) {
  if (!process) return null;

  const isMalicious = process.status === "Malicious (Injected)";
  const isSuspicious = process.status === "Suspicious";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-xs animate-in fade-in duration-200">
      <div className="w-full max-w-2xl bg-card border border-border rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="p-5 border-b border-border flex items-center justify-between bg-[#FAF7F2]">
          <div className="flex items-center gap-3">
            <div
              className={`w-9 h-9 rounded-lg flex items-center justify-center border ${
                isMalicious
                  ? "bg-threat-malicious/20 border-threat-malicious/40 text-threat-malicious"
                  : isSuspicious
                  ? "bg-threat-suspicious/20 border-threat-suspicious/40 text-threat-suspicious"
                  : "bg-threat-clean/20 border-threat-clean/40 text-threat-clean"
              }`}
            >
              <Cpu className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-textBright font-mono">
                  {process.name}
                </h3>
                <span className="text-xs font-mono text-textDim px-1.5 py-0.5 rounded bg-card border border-border">
                  PID {process.pid}
                </span>
              </div>
              <p className="text-[11px] font-mono text-textDim truncate max-w-md">
                {process.exe || "No disk image path (in-memory unbacked module)"}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-md hover:bg-raise text-textDim hover:text-textBright transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6">
          {/* Status & Threat Score Banner */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-lg bg-[#F8F5F0] border border-border">
            <div>
              <span className="text-[11px] font-mono font-semibold uppercase text-textDim tracking-wider">
                Forensic Classification
              </span>
              <div className="flex items-center gap-2 mt-1">
                <span
                  className={`text-sm font-bold font-mono px-2.5 py-0.5 rounded border ${
                    isMalicious
                      ? "bg-threat-malicious/20 text-threat-malicious border-threat-malicious/40"
                      : isSuspicious
                      ? "bg-threat-suspicious/20 text-threat-suspicious border-threat-suspicious/40"
                      : "bg-threat-clean/20 text-threat-clean border-threat-clean/40"
                  }`}
                >
                  {process.status}
                </span>
                {process.jit_engine && (
                  <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-threat-jit/20 text-threat-jit border border-threat-jit/40">
                    Benign JIT Runtime
                  </span>
                )}
              </div>
            </div>

            <div className="text-right">
              <span className="text-[11px] font-mono font-semibold uppercase text-textDim tracking-wider">
                Threat Score
              </span>
              <div className="text-3xl font-extrabold font-mono tracking-tight text-threat-malicious">
                {process.threat_score.toFixed(1)}%
              </div>
            </div>
          </div>

          {/* 7-Feature Volatile Memory Matrix */}
          <div className="space-y-3">
            <h4 className="text-sm font-semibold text-textBright flex items-center gap-2">
              <Layers className="w-3.5 h-3.5 text-lime" />
              <span>7-Feature Volatile Memory Forensic Vector</span>
            </h4>

            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
              {[
                {
                  label: "RWX Page Count",
                  val: process.rwx_count,
                  sub: "Executable + Writable",
                  alert: process.rwx_count > 2,
                },
                {
                  label: "Unbacked Exec Regions",
                  val: process.unbacked_exec_count,
                  sub: "MEM_PRIVATE no disk PE",
                  alert: process.unbacked_exec_count > 0,
                },
                {
                  label: "RWX Allocated KB",
                  val: `${process.allocated_kb} KB`,
                  sub: `${process.total_rwx_bytes} bytes`,
                  alert: process.allocated_kb > 256,
                },
                {
                  label: "Thread Count",
                  val: process.num_threads,
                  sub: "Active execution threads",
                  alert: false,
                },
                {
                  label: "Unbacked Thread Starts",
                  val: process.thread_unbacked_start,
                  sub: "EIP/RIP in private mem",
                  alert: process.thread_unbacked_start > 0,
                },
                {
                  label: "VAD Protection Flips",
                  val: process.vad_protection_anomaly,
                  sub: "RW -> RX/RWX transitions",
                  alert: process.vad_protection_anomaly > 0,
                },
              ].map((feat, i) => (
                <div
                  key={i}
                  className={`p-3 rounded-lg border ${
                    feat.alert
                      ? "bg-threat-malicious/10 border-threat-malicious/30"
                      : "bg-[#FAF7F2] border-border"
                  }`}
                >
                  <span className="text-[11px] font-mono text-textDim uppercase tracking-wider font-semibold">
                    {feat.label}
                  </span>
                  <div
                    className={`text-xl font-bold font-mono mt-0.5 ${
                      feat.alert ? "text-threat-malicious" : "text-textBright"
                    }`}
                  >
                    {feat.val}
                  </div>
                  <span className="text-xs font-mono text-textFog truncate block font-medium">
                    {feat.sub}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* MITRE ATT&CK Classification Dossier */}
          {process.classification && (
            <div className="p-4 rounded-lg bg-[#F8F5F0] border border-border space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-threat-malicious" />
                  <span className="text-sm font-bold text-textBright font-sans">
                    MITRE ATT&CK: {process.classification.name}
                  </span>
                </div>
                <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-threat-malicious/20 text-threat-malicious border border-threat-malicious/40 tracking-wider">
                  {process.classification.id || process.classification.mitre_id}
                </span>
              </div>

              <p className="text-xs text-textFog leading-relaxed font-sans">
                {process.classification.short_description ||
                  process.classification.mechanism ||
                  "Fileless in-memory execution identified using trained multi-class forensic model."}
              </p>

              {process.classification.remediation && (
                <div className="p-2.5 rounded bg-card border border-border text-xs font-mono text-textBright leading-relaxed">
                  <strong className="text-lime font-bold">Remediation: </strong>
                  {process.classification.remediation}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Modal Footer Controls */}
        <div className="p-4 border-t border-border bg-[#FAF7F2] flex items-center justify-between">
          <div className="text-[11px] font-mono text-textDim">
            Action: Win32 User-Mode Thread Suspend
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-md bg-raise hover:bg-card border border-border text-xs text-textBright font-medium transition-colors"
            >
              Dismiss
            </button>

            {onToggleIsolate && (
              <button
                onClick={() =>
                  onToggleIsolate(process.pid, !!process.is_isolated)
                }
                disabled={isIsolating}
                className={`flex items-center gap-2 px-4 py-2 rounded-md text-xs font-semibold font-mono transition-all ${
                  process.is_isolated
                    ? "bg-threat-clean/20 text-threat-clean border border-threat-clean/40 hover:bg-threat-clean/30"
                    : "bg-threat-malicious text-white hover:bg-red-600 shadow-[0_0_10px_rgba(214,69,61,0.3)]"
                }`}
              >
                {process.is_isolated ? (
                  <>
                    <Unlock className="w-3.5 h-3.5" />
                    <span>Resume Process (Un-isolate)</span>
                  </>
                ) : (
                  <>
                    <Lock className="w-3.5 h-3.5" />
                    <span>Isolate Target Process</span>
                  </>
                )}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
