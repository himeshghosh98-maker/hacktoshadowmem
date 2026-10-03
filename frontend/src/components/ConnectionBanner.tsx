"use client";

import React from "react";
import { Loader2, AlertOctagon, CheckCircle2 } from "lucide-react";
import { useConnection } from "@/context/ConnectionContext";

export function ConnectionBanner() {
  const { isConnected, isReconnected } = useConnection();

  if (isConnected && !isReconnected) {
    return null;
  }

  if (isReconnected) {
    return (
      <div className="w-full bg-threat-clean/15 border-b border-threat-clean/30 px-6 py-2 flex items-center justify-between text-xs font-mono text-threat-clean transition-all z-30 shrink-0">
        <div className="flex items-center gap-2 font-semibold">
          <CheckCircle2 className="w-4 h-4 text-threat-clean" />
          <span>Reconnected to ShadowMem engine</span>
        </div>
        <span className="text-[11px] font-medium opacity-85">
          Telemetry active
        </span>
      </div>
    );
  }

  return (
    <div className="w-full bg-threat-malicious/15 border-b border-threat-malicious/40 px-6 py-2.5 flex items-center justify-between text-xs font-mono text-threat-malicious transition-all z-30 shrink-0 shadow-xs">
      <div className="flex items-center gap-2.5 font-bold tracking-tight">
        <span className="relative flex h-2.5 w-2.5">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-threat-malicious opacity-75" />
          <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-threat-malicious" />
        </span>
        <AlertOctagon className="w-4 h-4 text-threat-malicious shrink-0" />
        <span>Disconnected from ShadowMem engine — retrying…</span>
      </div>
      <div className="flex items-center gap-2 text-[11px] font-medium text-threat-malicious/90">
        <Loader2 className="w-3.5 h-3.5 animate-spin" />
        <span>Retrying every 3s</span>
      </div>
    </div>
  );
}
