"use client";

import React, { useState, useEffect } from "react";
import {
  X,
  ShieldAlert,
  Cpu,
  Layers,
  Lock,
  Unlock,
  Binary,
  Activity,
  CheckCircle2,
  AlertTriangle,
  Loader2,
} from "lucide-react";
import { ProcessEntry, MemoryDumpResponse } from "@/types/forensics";
import { fetchMemoryDump } from "@/lib/api";

interface ProcessDossierModalProps {
  process: ProcessEntry | null;
  onClose: () => void;
  onToggleIsolate?: (pid: number, isCurrentlyIsolated: boolean) => void;
  isIsolating?: boolean;
}

type DossierTab = "attribution" | "vad_regions" | "hex_inspector";

export function ProcessDossierModal({
  process,
  onClose,
  onToggleIsolate,
  isIsolating,
}: ProcessDossierModalProps) {
  const [activeTab, setActiveTab] = useState<DossierTab>("attribution");
  const [memoryDump, setMemoryDump] = useState<MemoryDumpResponse | null>(null);
  const [isLoadingDump, setIsLoadingDump] = useState(false);
  const [dumpError, setDumpError] = useState<string | null>(null);

  useEffect(() => {
    if (!process) {
      setMemoryDump(null);
      return;
    }

    if (activeTab === "hex_inspector") {
      setIsLoadingDump(true);
      setDumpError(null);
      fetchMemoryDump(process.pid)
        .then((data) => {
          setMemoryDump(data);
          setIsLoadingDump(false);
        })
        .catch((err) => {
          setDumpError(err.message || "Failed to inspect process memory buffer");
          setIsLoadingDump(false);
        });
    }
  }, [process, activeTab]);

  if (!process) return null;

  const isMalicious = process.status === "Malicious (Injected)";
  const isSuspicious = process.status === "Suspicious";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs animate-in fade-in duration-150">
      <div className="w-full max-w-3xl bg-card border border-border rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[92vh]">
        {/* Modal Header */}
        <div className="p-4 px-6 border-b border-border flex items-center justify-between bg-card shrink-0">
          <div className="flex items-center gap-3">
            <div
              className={`w-9 h-9 rounded-lg flex items-center justify-center border ${
                isMalicious
                  ? "bg-threat-malicious/10 border-threat-malicious/30 text-threat-malicious"
                  : isSuspicious
                  ? "bg-threat-suspicious/10 border-threat-suspicious/30 text-threat-suspicious"
                  : "bg-threat-clean/10 border-threat-clean/30 text-threat-clean"
              }`}
            >
              <Cpu className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-bold text-textBright font-mono">
                  {process.name}
                </h3>
                <span className="text-xs font-mono text-textDim px-2 py-0.5 rounded bg-background border border-border font-medium">
                  PID {process.pid}
                </span>
                <span
                  className={`text-xs font-mono font-semibold px-2 py-0.5 rounded border ${
                    isMalicious
                      ? "bg-threat-malicious/10 text-threat-malicious border-threat-malicious/30"
                      : isSuspicious
                      ? "bg-threat-suspicious/10 text-threat-suspicious border-threat-suspicious/30"
                      : "bg-threat-clean/10 text-threat-clean border-threat-clean/30"
                  }`}
                >
                  {process.status}
                </span>
              </div>
              <p className="text-xs font-mono text-textDim truncate max-w-lg mt-0.5">
                {process.exe || "Unbacked in-memory executable region (zero disk backing)"}
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

        {/* Tab Navigation Header */}
        <div className="flex items-center gap-2 px-6 pt-3 border-b border-border bg-background/50 shrink-0">
          <button
            onClick={() => setActiveTab("attribution")}
            className={`flex items-center gap-2 px-3 py-2 text-xs font-mono border-b-2 transition-colors ${
              activeTab === "attribution"
                ? "border-lime text-lime font-bold"
                : "border-transparent text-textDim hover:text-textBright"
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>Forensic Explainability</span>
          </button>

          <button
            onClick={() => setActiveTab("vad_regions")}
            className={`flex items-center gap-2 px-3 py-2 text-xs font-mono border-b-2 transition-colors ${
              activeTab === "vad_regions"
                ? "border-lime text-lime font-bold"
                : "border-transparent text-textDim hover:text-textBright"
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>VAD Memory Regions ({process.unbacked_regions?.length || 0})</span>
          </button>

          <button
            onClick={() => setActiveTab("hex_inspector")}
            className={`flex items-center gap-2 px-3 py-2 text-xs font-mono border-b-2 transition-colors ${
              activeTab === "hex_inspector"
                ? "border-lime text-lime font-bold"
                : "border-transparent text-textDim hover:text-textBright"
            }`}
          >
            <Binary className="w-3.5 h-3.5" />
            <span>Live Hex & Buffer Disassembly</span>
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-5 flex-1">
          {/* TAB 1: ATTRIBUTION & FORENSICS */}
          {activeTab === "attribution" && (
            <div className="space-y-5">
              {/* Threat Score Header Card */}
              <div className="p-4 rounded-lg bg-background border border-border flex items-center justify-between">
                <div>
                  <span className="text-xs font-mono text-textDim uppercase tracking-wider font-semibold">
                    Composite ML Threat Score
                  </span>
                  <div className="flex items-baseline gap-2 mt-1">
                    <span
                      className={`text-3xl font-extrabold font-mono tracking-tight ${
                        isMalicious
                          ? "text-threat-malicious"
                          : isSuspicious
                          ? "text-threat-suspicious"
                          : "text-threat-clean"
                      }`}
                    >
                      {process.threat_score.toFixed(1)}%
                    </span>
                    <span className="text-xs font-mono text-textDim font-medium">
                      / 100 confidence
                    </span>
                  </div>
                </div>

                <div className="text-right">
                  <span className="text-xs font-mono text-textDim block">Engine Engine</span>
                  <span className="text-xs font-mono font-semibold text-textBright">
                    {process.model_used ? "Random Forest 7-Feature Model" : "Rule-Based Heuristic"}
                  </span>
                </div>
              </div>

              {/* Explainability Breakdown */}
              <div className="p-4 rounded-lg bg-background border border-border space-y-3">
                <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-textBright flex items-center gap-2">
                  <Activity className="w-3.5 h-3.5 text-lime" />
                  <span>Explainable AI — Feature Weight Attribution</span>
                </h4>

                {process.attribution && Object.keys(process.attribution).length > 0 ? (
                  <div className="space-y-2.5">
                    {Object.entries(process.attribution).map(([feat, pct]) => (
                      <div key={feat} className="space-y-1">
                        <div className="flex items-center justify-between text-xs font-mono">
                          <span className="text-textFog font-medium capitalize">
                            {feat.replace(/_/g, " ")}
                          </span>
                          <span className="text-textBright font-bold">{pct.toFixed(1)}%</span>
                        </div>
                        <div className="w-full h-1.5 rounded-full bg-card overflow-hidden border border-border/40">
                          <div
                            className={`h-full rounded-full transition-all duration-500 ${
                              isMalicious
                                ? "bg-threat-malicious"
                                : isSuspicious
                                ? "bg-threat-suspicious"
                                : "bg-threat-clean"
                            }`}
                            style={{ width: `${Math.min(100, Math.max(5, pct))}%` }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs font-mono text-textDim">
                    Attribution computed per process execution vector.
                  </div>
                )}

                {/* Attribution Rationale Bullets */}
                {process.attribution_reasons && process.attribution_reasons.length > 0 && (
                  <div className="mt-3 pt-3 border-t border-border space-y-1.5">
                    <span className="text-xs font-mono font-semibold text-textDim uppercase tracking-wider">
                      Forensic Rationale
                    </span>
                    <ul className="space-y-1">
                      {process.attribution_reasons.map((reason, i) => (
                        <li
                          key={i}
                          className="text-xs font-sans text-textFog flex items-start gap-2"
                        >
                          <span className="w-1.5 h-1.5 rounded-full bg-lime mt-1.5 shrink-0" />
                          <span>{reason}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>

              {/* 7-Feature Matrix */}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5">
                {[
                  {
                    label: "RWX Page Count",
                    val: process.rwx_count,
                    alert: process.rwx_count > 0,
                  },
                  {
                    label: "Unbacked Exec Pages",
                    val: process.unbacked_exec_count,
                    alert: process.unbacked_exec_count > 0,
                  },
                  {
                    label: "Total RWX Bytes",
                    val: `${process.allocated_kb} KB`,
                    alert: process.allocated_kb > 64,
                  },
                  {
                    label: "Thread Count",
                    val: process.num_threads,
                    alert: false,
                  },
                  {
                    label: "Unbacked Thread Starts",
                    val: process.thread_unbacked_start,
                    alert: process.thread_unbacked_start > 0,
                  },
                  {
                    label: "VAD Protection Flips",
                    val: process.vad_protection_anomaly,
                    alert: process.vad_protection_anomaly > 0,
                  },
                ].map((item, idx) => (
                  <div
                    key={idx}
                    className={`p-3 rounded-md border ${
                      item.alert
                        ? "bg-threat-malicious/5 border-threat-malicious/30"
                        : "bg-background border-border"
                    }`}
                  >
                    <span className="text-xs font-mono text-textDim block">{item.label}</span>
                    <div
                      className={`text-lg font-bold font-mono mt-1 ${
                        item.alert ? "text-threat-malicious" : "text-textBright"
                      }`}
                    >
                      {item.val}
                    </div>
                  </div>
                ))}
              </div>

              {/* MITRE ATT&CK Info */}
              {process.classification && (
                <div className="p-4 rounded-lg bg-background border border-border space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4 text-threat-malicious" />
                      <span className="text-xs font-bold font-mono text-textBright">
                        MITRE ATT&CK: {process.classification.name || process.classification.display_name}
                      </span>
                    </div>
                    <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-threat-malicious/10 text-threat-malicious border border-threat-malicious/30">
                      {process.classification.id || process.classification.mitre_id}
                    </span>
                  </div>
                  <p className="text-xs text-textFog leading-relaxed">
                    {process.classification.short_description ||
                      process.classification.typical_indicators ||
                      "Adversarial in-memory code injection technique identified."}
                  </p>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: VAD MEMORY REGIONS */}
          {activeTab === "vad_regions" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between text-xs font-mono text-textDim">
                <span>Committed MEM_PRIVATE Executable Address Allocations</span>
                <span>Count: {process.unbacked_regions?.length || 0}</span>
              </div>

              {!process.unbacked_regions || process.unbacked_regions.length === 0 ? (
                <div className="p-8 text-center rounded-lg bg-background border border-border">
                  <CheckCircle2 className="w-8 h-8 text-threat-clean mx-auto mb-2" />
                  <p className="text-xs font-mono text-textFog">
                    Zero unbacked executable memory allocations detected.
                  </p>
                </div>
              ) : (
                <div className="rounded-lg border border-border overflow-hidden bg-background">
                  <table className="w-full text-xs font-mono text-left">
                    <thead className="bg-raise border-b border-border text-textDim uppercase">
                      <tr>
                        <th className="p-2.5 font-semibold">Base Address</th>
                        <th className="p-2.5 font-semibold">Size</th>
                        <th className="p-2.5 font-semibold">Protection</th>
                        <th className="p-2.5 font-semibold">Initial Protect</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border/60">
                      {process.unbacked_regions.map((reg, idx) => (
                        <tr key={idx} className="hover:bg-card/50">
                          <td className="p-2.5 font-bold text-textBright">
                            0x{typeof reg.base_address === "number" ? reg.base_address.toString(16).toUpperCase() : reg.base_address}
                          </td>
                          <td className="p-2.5 text-textFog">
                            {reg.size ? `${(reg.size / 1024).toFixed(0)} KB` : "4 KB"}
                          </td>
                          <td className="p-2.5">
                            <span
                              className={`px-1.5 py-0.5 rounded text-xs font-medium border ${
                                reg.protection === "PAGE_EXECUTE_READWRITE"
                                  ? "bg-threat-malicious/10 text-threat-malicious border-threat-malicious/30"
                                  : "bg-threat-suspicious/10 text-threat-suspicious border-threat-suspicious/30"
                              }`}
                            >
                              {reg.protection}
                            </span>
                          </td>
                          <td className="p-2.5 text-textDim">
                            {reg.allocation_protect || "PAGE_READWRITE"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: LIVE HEX INSPECTOR */}
          {activeTab === "hex_inspector" && (
            <div className="space-y-4">
              {isLoadingDump ? (
                <div className="p-12 text-center rounded-lg bg-background border border-border">
                  <Loader2 className="w-6 h-6 animate-spin text-lime mx-auto mb-2" />
                  <p className="text-xs font-mono text-textFog">
                    Extracting virtual memory buffer via Win32 ReadProcessMemory...
                  </p>
                </div>
              ) : dumpError ? (
                <div className="p-4 rounded-lg bg-threat-malicious/10 border border-threat-malicious/30 text-xs font-mono text-threat-malicious flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>{dumpError}</span>
                </div>
              ) : memoryDump ? (
                <div className="space-y-4">
                  {/* Buffer Summary & Shannon Entropy Bar */}
                  <div className="p-3 rounded-lg bg-background border border-border flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
                    <div className="flex items-center gap-3">
                      <div>
                        <span className="text-textDim block">Base Address:</span>
                        <strong className="text-textBright">{memoryDump.base_address}</strong>
                      </div>
                      <div>
                        <span className="text-textDim block">Protection:</span>
                        <strong className="text-lime">{memoryDump.protection}</strong>
                      </div>
                    </div>

                    <div className="flex items-center gap-3">
                      <div>
                        <span className="text-textDim block">Shannon Entropy:</span>
                        <strong
                          className={
                            memoryDump.entropy > 6.0
                              ? "text-threat-malicious font-bold"
                              : "text-textBright"
                          }
                        >
                          {memoryDump.entropy.toFixed(2)} / 8.0
                        </strong>
                      </div>
                      <span
                        className={`px-2 py-0.5 rounded text-xs border font-semibold ${
                          memoryDump.is_shellcode_suspect
                            ? "bg-threat-malicious/10 text-threat-malicious border-threat-malicious/30"
                            : "bg-threat-clean/10 text-threat-clean border-threat-clean/30"
                        }`}
                      >
                        {memoryDump.is_shellcode_suspect ? "SHELLCODE SIGNATURE" : "BENIGN BUFFER"}
                      </span>
                    </div>
                  </div>

                  {/* Forensic Pattern Hints */}
                  {memoryDump.disassembly_hints && memoryDump.disassembly_hints.length > 0 && (
                    <div className="p-3 rounded-lg bg-background border border-border space-y-1">
                      <span className="text-xs font-mono font-semibold text-textDim uppercase tracking-wider">
                        Static Byte Signatures Detected
                      </span>
                      {memoryDump.disassembly_hints.map((hint, i) => (
                        <div key={i} className="text-xs font-mono text-textFog flex items-center gap-2">
                          <span className="w-1.5 h-1.5 rounded-full bg-lime shrink-0" />
                          <span>{hint}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Monospaced Hex Dump Viewer */}
                  <div className="rounded-lg bg-[#141414] text-[#E0E0E0] p-4 font-mono text-xs overflow-x-auto shadow-inner border border-border">
                    <div className="flex items-center justify-between text-neutral-500 pb-2 mb-2 border-b border-neutral-800 text-xs">
                      <span>OFFSET</span>
                      <span>HEX BYTES (16 BYTES / LINE)</span>
                      <span>ASCII DECODE</span>
                    </div>
                    <div className="space-y-1">
                      {memoryDump.hex_lines.map((line, idx) => (
                        <div key={idx} className="flex items-center justify-between gap-4 hover:bg-white/5 py-0.5 px-1 rounded">
                          <span className="text-neutral-500 select-none">{line.offset}</span>
                          <span className="text-amber-400 font-bold tracking-wider select-all">{line.hex_bytes}</span>
                          <span className="text-emerald-400 select-all tracking-widest">{line.ascii_chars}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : null}
            </div>
          )}
        </div>

        {/* Modal Footer Controls */}
        <div className="p-4 px-6 border-t border-border bg-card flex items-center justify-between shrink-0">
          <div className="text-xs font-mono text-textDim">
            Kernel Containment: NtSuspendProcess thread freeze
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-md bg-background hover:bg-raise border border-border text-xs text-textBright font-medium transition-colors"
            >
              Dismiss
            </button>

            {onToggleIsolate && (
              <button
                onClick={() =>
                  onToggleIsolate(process.pid, !!process.is_isolated)
                }
                disabled={isIsolating}
                className={`flex items-center gap-2 px-4 py-2 rounded-md text-xs font-semibold font-mono transition-colors ${
                  process.is_isolated
                    ? "bg-threat-clean/15 text-threat-clean border border-threat-clean/30 hover:bg-threat-clean/25"
                    : "bg-threat-malicious text-white hover:bg-red-700"
                }`}
              >
                {process.is_isolated ? (
                  <>
                    <Unlock className="w-3.5 h-3.5" />
                    <span>Resume Process</span>
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
